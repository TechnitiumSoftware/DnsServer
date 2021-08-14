/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class AuthZoneManager : IDisposable
    {
        #region variables

        readonly DnsServer _dnsServer;

        string _serverDomain;

        readonly ZoneTree<AuthZone> _root = new ZoneTree<AuthZone>();

        int _totalZones;

        #endregion

        #region constructor

        public AuthZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _serverDomain = _dnsServer.ServerDomain;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                foreach (AuthZone zone in _root)
                    zone.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private void UpdateServerDomain(string serverDomain)
        {
            ThreadPool.QueueUserWorkItem(delegate (object state)
            {
                //update authoritative zone SOA and NS records
                try
                {
                    List<AuthZoneInfo> zones = ListZones();

                    foreach (AuthZoneInfo zone in zones)
                    {
                        if (zone.Type != AuthZoneType.Primary)
                            continue;

                        DnsResourceRecord record = zone.GetRecords(DnsResourceRecordType.SOA)[0];
                        DnsSOARecord soa = record.RDATA as DnsSOARecord;

                        if (soa.PrimaryNameServer.Equals(_serverDomain, StringComparison.OrdinalIgnoreCase))
                        {
                            string responsiblePerson = soa.ResponsiblePerson;
                            if (responsiblePerson.EndsWith(_serverDomain))
                                responsiblePerson = responsiblePerson.Replace(_serverDomain, serverDomain);

                            SetRecords(record.Name, record.Type, record.TtlValue, new DnsResourceRecordData[] { new DnsSOARecord(serverDomain, responsiblePerson, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum) });

                            //update NS records
                            IReadOnlyList<DnsResourceRecord> nsResourceRecords = zone.GetRecords(DnsResourceRecordType.NS);

                            foreach (DnsResourceRecord nsResourceRecord in nsResourceRecords)
                            {
                                if ((nsResourceRecord.RDATA as DnsNSRecord).NameServer.Equals(_serverDomain, StringComparison.OrdinalIgnoreCase))
                                {
                                    UpdateRecord(nsResourceRecord, new DnsResourceRecord(nsResourceRecord.Name, nsResourceRecord.Type, nsResourceRecord.Class, nsResourceRecord.TtlValue, new DnsNSRecord(serverDomain)) { Tag = nsResourceRecord.Tag });
                                    break;
                                }
                            }

                            if (zone.Internal)
                                continue; //dont save internal zones to disk

                            try
                            {
                                SaveZoneFile(zone.Name);
                            }
                            catch (Exception ex)
                            {
                                LogManager log = _dnsServer.LogManager;
                                if (log != null)
                                    log.Write(ex);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write(ex);
                }

                //update server domain
                _serverDomain = serverDomain;
            });
        }

        private AuthZone CreateEmptyZone(AuthZoneInfo zoneInfo)
        {
            AuthZone zone;

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    zone = new PrimaryZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.Secondary:
                    zone = new SecondaryZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.Stub:
                    zone = new StubZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.Forwarder:
                    zone = new ForwarderZone(zoneInfo);
                    break;

                default:
                    throw new InvalidDataException("DNS zone type not supported.");
            }

            if (_root.TryAdd(zone))
            {
                _totalZones++;
                return zone;
            }

            if (_root.TryGet(zoneInfo.Name, out AuthZone existingZone) && (existingZone is SubDomainZone))
            {
                _root[zoneInfo.Name] = zone;
                _totalZones++;
                return zone;
            }

            throw new DnsServerException("Zone already exists: " + zoneInfo.Name);
        }

        private void LoadRecords(AuthZone authZone, IReadOnlyList<DnsResourceRecord> records)
        {
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = DnsResourceRecord.GroupRecords(records);

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByTypeRecords in groupedByDomainRecords)
            {
                if (authZone.Name.Equals(groupedByTypeRecords.Key, StringComparison.OrdinalIgnoreCase))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                        authZone.LoadRecords(groupedRecords.Key, groupedRecords.Value);
                }
                else
                {
                    AuthZone zone = GetOrAddSubDomainZone(groupedByTypeRecords.Key);
                    if (zone is SubDomainZone subDomainZone)
                    {
                        foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                            zone.LoadRecords(groupedRecords.Key, groupedRecords.Value);

                        subDomainZone.AutoUpdateState();
                    }
                }
            }
        }

        private AuthZone GetOrAddSubDomainZone(string domain)
        {
            return _root.GetOrAdd(domain, delegate (string key)
            {
                _ = _root.FindZone(domain, out _, out _, out AuthZone authZone, out _);
                if (authZone == null)
                    throw new DnsServerException("Zone was not found for domain: " + domain);

                if (authZone is PrimaryZone primaryZone)
                    return new PrimarySubDomainZone(primaryZone, domain);
                else if (authZone is SecondaryZone secondaryZone)
                    return new SecondarySubDomainZone(secondaryZone, domain);
                else if (authZone is ForwarderZone forwarderZone)
                    return new ForwarderSubDomainZone(forwarderZone, domain);

                throw new DnsServerException("Zone cannot have sub domains.");
            });
        }

        private void ResolveCNAME(DnsQuestionRecord question, DnsResourceRecord lastCNAME, List<DnsResourceRecord> answerRecords)
        {
            int queryCount = 0;

            do
            {
                if (!_root.TryGet((lastCNAME.RDATA as DnsCNAMERecord).Domain, out AuthZone authZone))
                    break;

                IReadOnlyList<DnsResourceRecord> records = authZone.QueryRecords(question.Type);
                if (records.Count < 1)
                    break;

                answerRecords.AddRange(records);

                DnsResourceRecord lastRR = records[records.Count - 1];

                if (lastRR.Type != DnsResourceRecordType.CNAME)
                    break;

                lastCNAME = lastRR;
            }
            while (++queryCount < DnsServer.MAX_CNAME_HOPS);
        }

        private bool DoDNAMESubstitution(DnsQuestionRecord question, IReadOnlyList<DnsResourceRecord> answer, out IReadOnlyList<DnsResourceRecord> newAnswer)
        {
            DnsResourceRecord dnameRR = answer[0];

            string result = (dnameRR.RDATA as DnsDNAMERecord).Substitute(question.Name, dnameRR.Name);

            if (DnsClient.IsDomainNameValid(result))
            {
                DnsResourceRecord cnameRR = new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, question.Class, dnameRR.TtlValue, new DnsCNAMERecord(result));

                List<DnsResourceRecord> list = new List<DnsResourceRecord>(5)
                {
                    dnameRR,
                    cnameRR
                };

                ResolveCNAME(question, cnameRR, list);

                newAnswer = list;
                return true;
            }
            else
            {
                newAnswer = answer;
                return false;
            }
        }

        private IReadOnlyList<DnsResourceRecord> GetAdditionalRecords(IReadOnlyList<DnsResourceRecord> refRecords)
        {
            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord refRecord in refRecords)
            {
                switch (refRecord.Type)
                {
                    case DnsResourceRecordType.NS:
                        IReadOnlyList<DnsResourceRecord> glueRecords = refRecord.GetGlueRecords();
                        if (glueRecords.Count > 0)
                        {
                            additionalRecords.AddRange(glueRecords);
                        }
                        else
                        {
                            ResolveAdditionalRecords((refRecord.RDATA as DnsNSRecord).NameServer, additionalRecords);
                        }
                        break;

                    case DnsResourceRecordType.MX:
                        ResolveAdditionalRecords((refRecord.RDATA as DnsMXRecord).Exchange, additionalRecords);
                        break;

                    case DnsResourceRecordType.SRV:
                        ResolveAdditionalRecords((refRecord.RDATA as DnsSRVRecord).Target, additionalRecords);
                        break;
                }
            }

            return additionalRecords;
        }

        private void ResolveAdditionalRecords(string domain, List<DnsResourceRecord> additionalRecords)
        {
            if (_root.TryGet(domain, out AuthZone authZone) && authZone.IsActive)
            {
                {
                    IReadOnlyList<DnsResourceRecord> records = authZone.QueryRecords(DnsResourceRecordType.A);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.A))
                        additionalRecords.AddRange(records);
                }

                {
                    IReadOnlyList<DnsResourceRecord> records = authZone.QueryRecords(DnsResourceRecordType.AAAA);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.AAAA))
                        additionalRecords.AddRange(records);
                }
            }
        }

        private DnsDatagram GetReferralResponse(DnsDatagram request, AuthZone delegationZone, bool isRecursionAllowed)
        {
            IReadOnlyList<DnsResourceRecord> authority;

            if (delegationZone is StubZone)
                authority = delegationZone.GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant query
            else
                authority = delegationZone.QueryRecords(DnsResourceRecordType.NS);

            IReadOnlyList<DnsResourceRecord> additional = GetAdditionalRecords(authority);

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, null, authority, additional);
        }

        private static DnsDatagram GetForwarderResponse(DnsDatagram request, AuthZone zone, AuthZone closestZone, AuthZone forwarderZone, bool isRecursionAllowed)
        {
            IReadOnlyList<DnsResourceRecord> authority = null;

            if (zone is not null)
                authority = zone.QueryRecords(DnsResourceRecordType.FWD);

            if (((authority is null) || (authority.Count == 0)) && (closestZone is not null))
                authority = closestZone.QueryRecords(DnsResourceRecordType.FWD);

            if ((authority is null) || (authority.Count == 0))
                authority = forwarderZone.QueryRecords(DnsResourceRecordType.FWD);

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, null, authority);
        }

        internal void Flush()
        {
            _root.Clear();
        }

        private static IReadOnlyList<DnsResourceRecord> CondenseIncrementalZoneTransferRecords(string domain, DnsResourceRecord currentSoaRecord, IReadOnlyList<DnsResourceRecord> xfrRecords)
        {
            DnsResourceRecord firstSoaRecord = xfrRecords[0];
            DnsResourceRecord lastSoaRecord = xfrRecords[xfrRecords.Count - 1];

            DnsResourceRecord firstDeletedSoaRecord = null;
            DnsResourceRecord lastAddedSoaRecord = null;

            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedGlueRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> addedGlueRecords = new List<DnsResourceRecord>();

            //read and apply difference sequences
            int index = 1;
            int count = xfrRecords.Count - 1;
            DnsSOARecord currentSoa = (DnsSOARecord)currentSoaRecord.RDATA;

            while (index < count)
            {
                //read deleted records
                DnsResourceRecord deletedSoaRecord = xfrRecords[index];
                if ((deletedSoaRecord.Type != DnsResourceRecordType.SOA) || !deletedSoaRecord.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                if (firstDeletedSoaRecord is null)
                    firstDeletedSoaRecord = deletedSoaRecord;

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = xfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (domain.Length == 0)
                    {
                        //root zone case
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                if (addedGlueRecords.Contains(record))
                                    addedGlueRecords.Remove(record);
                                else
                                    deletedGlueRecords.Add(record);

                                break;

                            default:
                                if (addedRecords.Contains(record))
                                    addedRecords.Remove(record);
                                else
                                    deletedRecords.Add(record);

                                break;
                        }
                    }
                    else
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                        {
                            if (addedRecords.Contains(record))
                                addedRecords.Remove(record);
                            else
                                deletedRecords.Add(record);
                        }
                        else
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                case DnsResourceRecordType.AAAA:
                                    if (addedGlueRecords.Contains(record))
                                        addedGlueRecords.Remove(record);
                                    else
                                        deletedGlueRecords.Add(record);

                                    break;
                            }
                        }
                    }

                    index++;
                }

                //read added records
                DnsResourceRecord addedSoaRecord = xfrRecords[index];
                if (!addedSoaRecord.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                lastAddedSoaRecord = addedSoaRecord;

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = xfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (domain.Length == 0)
                    {
                        //root zone case
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                if (deletedGlueRecords.Contains(record))
                                    deletedGlueRecords.Remove(record);
                                else
                                    addedGlueRecords.Add(record);

                                break;

                            default:
                                if (deletedRecords.Contains(record))
                                    deletedRecords.Remove(record);
                                else
                                    addedRecords.Add(record);

                                break;
                        }
                    }
                    else
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                        {
                            if (deletedRecords.Contains(record))
                                deletedRecords.Remove(record);
                            else
                                addedRecords.Add(record);
                        }
                        else
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                case DnsResourceRecordType.AAAA:
                                    if (deletedGlueRecords.Contains(record))
                                        deletedGlueRecords.Remove(record);
                                    else
                                        addedGlueRecords.Add(record);

                                    break;
                            }
                        }
                    }

                    index++;
                }

                //check sequence soa serial
                DnsSOARecord deletedSoa = deletedSoaRecord.RDATA as DnsSOARecord;

                if (currentSoa.Serial != deletedSoa.Serial)
                    throw new InvalidOperationException("Current SOA serial does not match with the IXFR difference sequence deleted SOA.");

                //check next difference sequence
                currentSoa = addedSoaRecord.RDATA as DnsSOARecord;
            }

            //create condensed records
            List<DnsResourceRecord> condensedRecords = new List<DnsResourceRecord>(2 + 2 + deletedRecords.Count + deletedGlueRecords.Count + addedRecords.Count + addedGlueRecords.Count);

            condensedRecords.Add(firstSoaRecord);

            condensedRecords.Add(firstDeletedSoaRecord);
            condensedRecords.AddRange(deletedRecords);
            condensedRecords.AddRange(deletedGlueRecords);

            condensedRecords.Add(lastAddedSoaRecord);
            condensedRecords.AddRange(addedRecords);
            condensedRecords.AddRange(addedGlueRecords);

            condensedRecords.Add(lastSoaRecord);

            return condensedRecords;
        }

        #endregion

        #region public

        public void LoadAllZoneFiles()
        {
            _root.Clear();

            string zonesFolder = Path.Combine(_dnsServer.ConfigFolder, "zones");
            if (!Directory.Exists(zonesFolder))
                Directory.CreateDirectory(zonesFolder);

            //move zone files to new folder
            {
                string[] oldZoneFiles = Directory.GetFiles(_dnsServer.ConfigFolder, "*.zone");

                foreach (string oldZoneFile in oldZoneFiles)
                    File.Move(oldZoneFile, Path.Combine(zonesFolder, Path.GetFileName(oldZoneFile)));
            }

            //remove old internal zones
            {
                string[] oldZoneFiles = new string[] { "localhost.zone", "1.0.0.127.in-addr.arpa.zone", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.zone" };

                foreach (string oldZoneFile in oldZoneFiles)
                {
                    string filePath = Path.Combine(zonesFolder, oldZoneFile);

                    if (File.Exists(filePath))
                    {
                        try
                        {
                            File.Delete(filePath);
                        }
                        catch
                        { }
                    }
                }
            }

            //load system zones
            {
                {
                    CreatePrimaryZone("localhost", _dnsServer.ServerDomain, true);
                    SetRecords("localhost", DnsResourceRecordType.A, 3600, new DnsResourceRecordData[] { new DnsARecord(IPAddress.Loopback) });
                    SetRecords("localhost", DnsResourceRecordType.AAAA, 3600, new DnsResourceRecordData[] { new DnsAAAARecord(IPAddress.IPv6Loopback) });
                }

                {
                    string prtDomain = "0.in-addr.arpa";

                    CreatePrimaryZone(prtDomain, _dnsServer.ServerDomain, true);
                }

                {
                    string prtDomain = "255.in-addr.arpa";

                    CreatePrimaryZone(prtDomain, _dnsServer.ServerDomain, true);
                }

                {
                    string prtDomain = "127.in-addr.arpa";

                    CreatePrimaryZone(prtDomain, _dnsServer.ServerDomain, true);
                    SetRecords("1.0.0.127.in-addr.arpa", DnsResourceRecordType.PTR, 3600, new DnsResourceRecordData[] { new DnsPTRRecord("localhost") });
                }

                {
                    string prtDomain = new DnsQuestionRecord(IPAddress.IPv6Loopback, DnsClass.IN).Name;

                    CreatePrimaryZone(prtDomain, _dnsServer.ServerDomain, true);
                    SetRecords(prtDomain, DnsResourceRecordType.PTR, 3600, new DnsResourceRecordData[] { new DnsPTRRecord("localhost") });
                }
            }

            //load zone files
            string[] zoneFiles = Directory.GetFiles(zonesFolder, "*.zone");

            foreach (string zoneFile in zoneFiles)
            {
                try
                {
                    using (FileStream fS = new FileStream(zoneFile, FileMode.Open, FileAccess.Read))
                    {
                        LoadZoneFrom(fS);
                    }

                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server successfully loaded zone file: " + zoneFile);
                }
                catch (Exception ex)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server failed to load zone file: " + zoneFile + "\r\n" + ex.ToString());
                }
            }
        }

        internal AuthZoneInfo CreateSpecialPrimaryZone(string domain, DnsSOARecord soaRecord, DnsNSRecord ns)
        {
            AuthZone authZone = new PrimaryZone(_dnsServer, domain, soaRecord, ns);

            if (_root.TryAdd(authZone))
            {
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            return null;
        }

        public AuthZoneInfo CreatePrimaryZone(string domain, string primaryNameServer, bool @internal)
        {
            PrimaryZone authZone = new PrimaryZone(_dnsServer, domain, primaryNameServer, @internal);

            if (_root.TryAdd(authZone))
            {
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            if (_root.TryGet(domain, out AuthZone existingZone) && (existingZone is SubDomainZone))
            {
                _root[domain] = authZone;
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            return null;
        }

        public async Task<AuthZoneInfo> CreateSecondaryZoneAsync(string domain, string primaryNameServerAddresses = null, DnsTransportProtocol zoneTransferProtocol = DnsTransportProtocol.Tcp, string tsigKeyName = null)
        {
            SecondaryZone authZone = await SecondaryZone.CreateAsync(_dnsServer, domain, primaryNameServerAddresses, zoneTransferProtocol, tsigKeyName);

            if (_root.TryAdd(authZone))
            {
                authZone.TriggerRefresh(0);
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            if (_root.TryGet(domain, out AuthZone existingZone) && (existingZone is SubDomainZone))
            {
                _root[domain] = authZone;
                authZone.TriggerRefresh(0);
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            return null;
        }

        public async Task<AuthZoneInfo> CreateStubZoneAsync(string domain, string primaryNameServerAddresses = null)
        {
            StubZone authZone = await StubZone.CreateAsync(_dnsServer, domain, primaryNameServerAddresses);

            if (_root.TryAdd(authZone))
            {
                authZone.TriggerRefresh(0);
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            if (_root.TryGet(domain, out AuthZone existingZone) && (existingZone is SubDomainZone))
            {
                _root[domain] = authZone;
                authZone.TriggerRefresh(0);
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            return null;
        }

        public AuthZoneInfo CreateForwarderZone(string domain, DnsTransportProtocol forwarderProtocol, string forwarder)
        {
            ForwarderZone authZone = new ForwarderZone(domain, forwarderProtocol, forwarder);

            if (_root.TryAdd(authZone))
            {
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            if (_root.TryGet(domain, out AuthZone existingZone) && (existingZone is SubDomainZone))
            {
                _root[domain] = authZone;
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            return null;
        }

        public bool DeleteZone(string domain)
        {
            if (_root.TryRemove(domain, out AuthZone authZone))
            {
                authZone.Dispose();

                if (!(authZone is SubDomainZone))
                    _totalZones--;

                return true;
            }

            return false;
        }

        public AuthZoneInfo GetAuthZoneInfo(string domain, bool loadHistory = false)
        {
            _ = _root.FindZone(domain, out _, out _, out AuthZone authority, out _);
            if (authority == null)
                return null;

            return new AuthZoneInfo(authority, loadHistory);
        }

        public void ListAllRecords(string domain, List<DnsResourceRecord> records)
        {
            foreach (AuthZone zone in _root.GetZoneWithSubDomainZones(domain))
                zone.ListAllRecords(records);
        }

        public IReadOnlyList<DnsResourceRecord> GetRecords(string domain, DnsResourceRecordType type)
        {
            if (_root.TryGet(domain, out AuthZone zone))
                return zone.GetRecords(type);

            return Array.Empty<DnsResourceRecord>();
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecords(string domain, DnsResourceRecordType type)
        {
            if (_root.TryGet(domain, out AuthZone zone))
                return zone.QueryRecords(type);

            return Array.Empty<DnsResourceRecord>();
        }

        public IReadOnlyList<DnsResourceRecord> QueryZoneTransferRecords(string domain)
        {
            AuthZoneInfo authZone = GetAuthZoneInfo(domain, false);
            if (authZone is null)
                throw new InvalidOperationException("Zone was not found: " + domain);

            //only primary and secondary zones support zone transfer
            IReadOnlyList<DnsResourceRecord> soaRecords = authZone.GetRecords(DnsResourceRecordType.SOA);
            if (soaRecords.Count != 1)
                throw new InvalidOperationException("Zone must be a primary or secondary zone.");

            DnsResourceRecord soaRecord = soaRecords[0];

            List<DnsResourceRecord> records = new List<DnsResourceRecord>();
            ListAllRecords(domain, records);

            List<DnsResourceRecord> xfrRecords = new List<DnsResourceRecord>(records.Count + 1);

            //start message
            xfrRecords.Add(soaRecord);

            foreach (DnsResourceRecord record in records)
            {
                if (record.IsDisabled())
                    continue;

                switch (record.Type)
                {
                    case DnsResourceRecordType.SOA:
                        break; //skip record

                    case DnsResourceRecordType.NS:
                        xfrRecords.Add(record);

                        foreach (DnsResourceRecord glueRecord in record.GetGlueRecords())
                            xfrRecords.Add(glueRecord);

                        break;

                    default:
                        xfrRecords.Add(record);
                        break;
                }
            }

            //end message
            xfrRecords.Add(soaRecord);

            return xfrRecords;
        }

        public IReadOnlyList<DnsResourceRecord> QueryIncrementalZoneTransferRecords(string domain, DnsResourceRecord clientSoaRecord)
        {
            AuthZoneInfo authZone = GetAuthZoneInfo(domain, true);
            if (authZone is null)
                throw new InvalidOperationException("Zone was not found: " + domain);

            //only primary and secondary zones support zone transfer
            IReadOnlyList<DnsResourceRecord> soaRecords = authZone.GetRecords(DnsResourceRecordType.SOA);
            if (soaRecords.Count != 1)
                throw new InvalidOperationException("Zone must be a primary or secondary zone.");

            DnsResourceRecord currentSoaRecord = soaRecords[0];
            uint clientSerial = (clientSoaRecord.RDATA as DnsSOARecord).Serial;

            if (clientSerial == (currentSoaRecord.RDATA as DnsSOARecord).Serial)
            {
                //zone not modified
                return new DnsResourceRecord[] { currentSoaRecord };
            }

            //find history record start from client serial
            IReadOnlyList<DnsResourceRecord> zoneHistory = authZone.ZoneHistory;

            int index = 0;
            while (index < zoneHistory.Count)
            {
                //check difference sequence
                if ((zoneHistory[index].RDATA as DnsSOARecord).Serial == clientSerial)
                    break; //found history for client's serial

                //skip to next difference sequence
                index++;
                int soaCount = 1;

                while (index < zoneHistory.Count)
                {
                    if (zoneHistory[index].Type == DnsResourceRecordType.SOA)
                    {
                        soaCount++;

                        if (soaCount == 3)
                            break;
                    }

                    index++;
                }
            }

            if (index == zoneHistory.Count)
            {
                //client's serial was not found in zone history
                //do full zone transfer
                return QueryZoneTransferRecords(domain);
            }

            List<DnsResourceRecord> xfrRecords = new List<DnsResourceRecord>();

            //start incremental message
            xfrRecords.Add(currentSoaRecord);

            //write history
            for (int i = index; i < zoneHistory.Count; i++)
                xfrRecords.Add(zoneHistory[i]);

            //end incremental message
            xfrRecords.Add(currentSoaRecord);

            //condense
            return CondenseIncrementalZoneTransferRecords(domain, clientSoaRecord, xfrRecords);
        }

        public void SyncZoneTransferRecords(string domain, IReadOnlyList<DnsResourceRecord> xfrRecords)
        {
            if ((xfrRecords.Count < 2) || (xfrRecords[0].Type != DnsResourceRecordType.SOA) || !xfrRecords[0].Name.Equals(domain, StringComparison.OrdinalIgnoreCase) || !xfrRecords[xfrRecords.Count - 1].Equals(xfrRecords[0]))
                throw new DnsServerException("Invalid AXFR response was received.");

            List<DnsResourceRecord> latestRecords = new List<DnsResourceRecord>(xfrRecords.Count);
            List<DnsResourceRecord> allGlueRecords = new List<DnsResourceRecord>(4);

            if (domain.Length == 0)
            {
                //root zone case
                for (int i = 1; i < xfrRecords.Count; i++)
                {
                    DnsResourceRecord record = xfrRecords[i];

                    switch (record.Type)
                    {
                        case DnsResourceRecordType.A:
                        case DnsResourceRecordType.AAAA:
                            if (!allGlueRecords.Contains(record))
                                allGlueRecords.Add(record);

                            break;

                        default:
                            if (!latestRecords.Contains(record))
                                latestRecords.Add(record);

                            break;
                    }
                }
            }
            else
            {
                for (int i = 1; i < xfrRecords.Count; i++)
                {
                    DnsResourceRecord record = xfrRecords[i];

                    if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!latestRecords.Contains(record))
                            latestRecords.Add(record);
                    }
                    else if (!allGlueRecords.Contains(record))
                    {
                        allGlueRecords.Add(record);
                    }
                }
            }

            if (allGlueRecords.Count > 0)
            {
                foreach (DnsResourceRecord record in latestRecords)
                {
                    if (record.Type == DnsResourceRecordType.NS)
                        record.SyncGlueRecords(allGlueRecords);
                }
            }

            //sync records
            List<DnsResourceRecord> currentRecords = new List<DnsResourceRecord>();
            ListAllRecords(domain, currentRecords);

            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> currentRecordsGroupedByDomain = DnsResourceRecord.GroupRecords(currentRecords);
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> latestRecordsGroupedByDomain = DnsResourceRecord.GroupRecords(latestRecords);

            //remove domains that do not exists in new records
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> currentDomain in currentRecordsGroupedByDomain)
            {
                if (!latestRecordsGroupedByDomain.ContainsKey(currentDomain.Key))
                    _root.TryRemove(currentDomain.Key, out _);
            }

            //sync new records
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> latestEntries in latestRecordsGroupedByDomain)
            {
                AuthZone zone = GetOrAddSubDomainZone(latestEntries.Key);

                if (zone.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    zone.SyncRecords(latestEntries.Value);
                else if ((zone is SubDomainZone subDomainZone) && subDomainZone.AuthoritativeZone.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    zone.SyncRecords(latestEntries.Value);
            }
        }

        public IReadOnlyList<DnsResourceRecord> SyncIncrementalZoneTransferRecords(string domain, IReadOnlyList<DnsResourceRecord> xfrRecords)
        {
            if ((xfrRecords.Count < 2) || (xfrRecords[0].Type != DnsResourceRecordType.SOA) || !xfrRecords[0].Name.Equals(domain, StringComparison.OrdinalIgnoreCase) || !xfrRecords[xfrRecords.Count - 1].Equals(xfrRecords[0]))
                throw new DnsServerException("Invalid IXFR/AXFR response was received.");

            if ((xfrRecords.Count < 4) || (xfrRecords[1].Type != DnsResourceRecordType.SOA))
            {
                //received AXFR response
                SyncZoneTransferRecords(domain, xfrRecords);
                return Array.Empty<DnsResourceRecord>();
            }

            IReadOnlyList<DnsResourceRecord> soaRecords = GetRecords(domain, DnsResourceRecordType.SOA);
            if (soaRecords.Count != 1)
                throw new InvalidOperationException("No authoritative zone was found for the domain.");

            //process IXFR response
            DnsResourceRecord currentSoaRecord = soaRecords[0];
            DnsSOARecord currentSoa = currentSoaRecord.RDATA as DnsSOARecord;

            IReadOnlyList<DnsResourceRecord> condensedXfrRecords = CondenseIncrementalZoneTransferRecords(domain, currentSoaRecord, xfrRecords);

            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedGlueRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> addedGlueRecords = new List<DnsResourceRecord>();

            //read and apply difference sequences
            int index = 1;
            int count = condensedXfrRecords.Count - 1;

            while (index < count)
            {
                //read deleted records
                DnsResourceRecord deletedSoaRecord = condensedXfrRecords[index];
                if ((deletedSoaRecord.Type != DnsResourceRecordType.SOA) || !deletedSoaRecord.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = condensedXfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (domain.Length == 0)
                    {
                        //root zone case
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                deletedGlueRecords.Add(record);
                                break;

                            default:
                                deletedRecords.Add(record);
                                break;
                        }
                    }
                    else
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                        {
                            deletedRecords.Add(record);
                        }
                        else
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                case DnsResourceRecordType.AAAA:
                                    deletedGlueRecords.Add(record);
                                    break;
                            }
                        }
                    }

                    index++;
                }

                //read added records
                DnsResourceRecord addedSoaRecord = condensedXfrRecords[index];
                if (!addedSoaRecord.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = condensedXfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (domain.Length == 0)
                    {
                        //root zone case
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                addedGlueRecords.Add(record);
                                break;

                            default:
                                addedRecords.Add(record);
                                break;
                        }
                    }
                    else
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                        {
                            addedRecords.Add(record);
                        }
                        else
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                case DnsResourceRecordType.AAAA:
                                    addedGlueRecords.Add(record);
                                    break;
                            }
                        }
                    }

                    index++;
                }

                //check sequence soa serial
                DnsSOARecord deletedSoa = deletedSoaRecord.RDATA as DnsSOARecord;

                if (currentSoa.Serial != deletedSoa.Serial)
                    throw new InvalidOperationException("Current SOA serial does not match with the IXFR difference sequence deleted SOA.");

                //sync difference sequence
                if (deletedRecords.Count > 0)
                {
                    foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> deletedEntry in DnsResourceRecord.GroupRecords(deletedRecords))
                    {
                        AuthZone zone = GetOrAddSubDomainZone(deletedEntry.Key);

                        if (zone.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                            zone.SyncRecords(deletedEntry.Value, null);
                        else if ((zone is SubDomainZone subDomainZone) && subDomainZone.AuthoritativeZone.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                            zone.SyncRecords(deletedEntry.Value, null);
                    }
                }

                if (addedRecords.Count > 0)
                {
                    foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> addedEntry in DnsResourceRecord.GroupRecords(addedRecords))
                    {
                        AuthZone zone = GetOrAddSubDomainZone(addedEntry.Key);

                        if (zone.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                            zone.SyncRecords(null, addedEntry.Value);
                        else if ((zone is SubDomainZone subDomainZone) && subDomainZone.AuthoritativeZone.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                            zone.SyncRecords(null, addedEntry.Value);
                    }
                }

                if ((deletedGlueRecords.Count > 0) || (addedGlueRecords.Count > 0))
                {
                    foreach (AuthZone zone in _root.GetZoneWithSubDomainZones(domain))
                        zone.SyncGlueRecords(deletedGlueRecords, addedGlueRecords);
                }

                {
                    AuthZone zone = GetOrAddSubDomainZone(domain);

                    addedSoaRecord.CopyRecordInfoFrom(currentSoaRecord);

                    zone.LoadRecords(DnsResourceRecordType.SOA, new DnsResourceRecord[] { addedSoaRecord });
                }

                //check next difference sequence
                currentSoa = addedSoaRecord.RDATA as DnsSOARecord;

                deletedRecords.Clear();
                deletedGlueRecords.Clear();
                addedRecords.Clear();
                addedGlueRecords.Clear();
            }

            //return history
            List<DnsResourceRecord> historyRecords = new List<DnsResourceRecord>(xfrRecords.Count - 2);

            for (int i = 1; i < xfrRecords.Count - 1; i++)
                historyRecords.Add(xfrRecords[i]);

            return historyRecords;
        }

        public void LoadRecords(IReadOnlyCollection<DnsResourceRecord> records)
        {
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> zoneEntry in DnsResourceRecord.GroupRecords(records))
            {
                AuthZone zone = GetOrAddSubDomainZone(zoneEntry.Key);

                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                    zone.LoadRecords(rrsetEntry.Key, rrsetEntry.Value);
            }
        }

        public void SetRecords(string domain, DnsResourceRecordType type, uint ttl, DnsResourceRecordData[] records)
        {
            DnsResourceRecord[] resourceRecords = new DnsResourceRecord[records.Length];

            for (int i = 0; i < records.Length; i++)
                resourceRecords[i] = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, records[i]);

            AuthZone zone = GetOrAddSubDomainZone(domain);

            zone.SetRecords(type, resourceRecords);

            if (zone is SubDomainZone subDomainZone)
                subDomainZone.AutoUpdateState();
        }

        public void SetRecord(DnsResourceRecord record)
        {
            AuthZone zone = GetOrAddSubDomainZone(record.Name);

            zone.SetRecords(record.Type, new DnsResourceRecord[] { record });

            if (zone is SubDomainZone subDomainZone)
                subDomainZone.AutoUpdateState();
        }

        public void AddRecord(string domain, DnsResourceRecordType type, uint ttl, DnsResourceRecordData record)
        {
            AuthZone zone = GetOrAddSubDomainZone(domain);

            zone.AddRecord(new DnsResourceRecord(zone.Name, type, DnsClass.IN, ttl, record));

            if (zone is SubDomainZone subDomainZone)
                subDomainZone.AutoUpdateState();
        }

        public void AddRecord(DnsResourceRecord record)
        {
            AuthZone zone = GetOrAddSubDomainZone(record.Name);

            zone.AddRecord(record);

            if (zone is SubDomainZone subDomainZone)
                subDomainZone.AutoUpdateState();
        }

        public void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            if (oldRecord.Type != newRecord.Type)
                throw new DnsServerException("Cannot update record: new record must be of same type.");

            if (oldRecord.Type == DnsResourceRecordType.SOA)
                throw new DnsServerException("Cannot update record: use SetRecords() for updating SOA record.");

            if (!_root.TryGet(oldRecord.Name, out AuthZone zone))
                throw new DnsServerException("Cannot update record: zone does not exists.");

            switch (oldRecord.Type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.DNAME:
                case DnsResourceRecordType.PTR:
                case DnsResourceRecordType.APP:
                    if (oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        zone.SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });

                        if (zone is SubDomainZone subDomainZone)
                            subDomainZone.AutoUpdateState();
                    }
                    else
                    {
                        zone.DeleteRecords(oldRecord.Type);

                        if (zone is SubDomainZone subDomainZone)
                        {
                            if (zone.IsEmpty)
                                _root.TryRemove(oldRecord.Name, out _); //remove empty sub zone
                            else
                                subDomainZone.AutoUpdateState();
                        }

                        AuthZone newZone = GetOrAddSubDomainZone(newRecord.Name);

                        newZone.SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });

                        if (newZone is SubDomainZone subDomainZone1)
                            subDomainZone1.AutoUpdateState();
                    }
                    break;

                default:
                    if (oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        zone.UpdateRecord(oldRecord, newRecord);

                        if (zone is SubDomainZone subDomainZone)
                            subDomainZone.AutoUpdateState();
                    }
                    else
                    {
                        zone.DeleteRecord(oldRecord.Type, oldRecord.RDATA);

                        if (zone is SubDomainZone subDomainZone)
                        {
                            if (zone.IsEmpty)
                                _root.TryRemove(oldRecord.Name, out _); //remove empty sub zone
                            else
                                subDomainZone.AutoUpdateState();
                        }

                        AuthZone newZone = GetOrAddSubDomainZone(newRecord.Name);

                        newZone.AddRecord(newRecord);

                        if (newZone is SubDomainZone subDomainZone1)
                            subDomainZone1.AutoUpdateState();
                    }
                    break;
            }
        }

        public void DeleteRecord(string domain, DnsResourceRecordType type, DnsResourceRecordData record)
        {
            if (_root.TryGet(domain, out AuthZone zone))
            {
                zone.DeleteRecord(type, record);

                if (zone is SubDomainZone subDomainZone)
                {
                    if (zone.IsEmpty)
                        _root.TryRemove(domain, out _); //remove empty sub zone
                    else
                        subDomainZone.AutoUpdateState();
                }
            }
        }

        public void DeleteRecords(string domain, DnsResourceRecordType type)
        {
            if (_root.TryGet(domain, out AuthZone zone))
            {
                zone.DeleteRecords(type);

                if (zone is SubDomainZone subDomainZone)
                {
                    if (zone.IsEmpty)
                        _root.TryRemove(domain, out _); //remove empty sub zone
                    else
                        subDomainZone.AutoUpdateState();
                }
            }
        }

        public List<AuthZoneInfo> ListZones()
        {
            List<AuthZoneInfo> zones = new List<AuthZoneInfo>();

            foreach (AuthZone zone in _root)
            {
                AuthZoneInfo zoneInfo = new AuthZoneInfo(zone);
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Stub:
                    case AuthZoneType.Forwarder:
                        zones.Add(zoneInfo);
                        break;
                }
            }

            _totalZones = zones.Count;

            return zones;
        }

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            _root.ListSubDomains(domain, subDomains);
        }

        public DnsDatagram QueryClosestDelegation(DnsDatagram request)
        {
            _ = _root.FindZone(request.Question[0].Name, out _, out AuthZone delegation, out _, out _);
            if (delegation != null)
            {
                //return closest name servers in delegation
                IReadOnlyList<DnsResourceRecord> closestAuthority = delegation.QueryRecords(DnsResourceRecordType.NS);
                if ((closestAuthority.Count > 0) && (closestAuthority[0].Type == DnsResourceRecordType.NS))
                {
                    IReadOnlyList<DnsResourceRecord> additional = GetAdditionalRecords(closestAuthority);

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, closestAuthority, additional);
                }
            }

            //no delegation found
            return null;
        }

        public DnsDatagram Query(DnsDatagram request, bool isRecursionAllowed)
        {
            DnsQuestionRecord question = request.Question[0];

            AuthZone zone = _root.FindZone(question.Name, out AuthZone closest, out AuthZone delegation, out AuthZone authZone, out bool hasSubDomains);

            if ((authZone == null) || !authZone.IsActive) //no authority for requested zone
                return null;

            if ((delegation != null) && delegation.IsActive)
                return GetReferralResponse(request, delegation, isRecursionAllowed);

            if ((zone == null) || !zone.IsActive)
            {
                //zone not found                
                if (authZone is StubZone)
                    return GetReferralResponse(request, authZone, isRecursionAllowed);
                else if (authZone is ForwarderZone)
                    return GetForwarderResponse(request, null, closest, authZone, isRecursionAllowed);

                DnsResponseCode rCode = DnsResponseCode.NoError;
                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;

                if (closest is not null)
                {
                    answer = closest.QueryRecords(DnsResourceRecordType.DNAME);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                    else
                    {
                        answer = null;
                        authority = closest.QueryRecords(DnsResourceRecordType.APP);
                    }
                }

                if (((answer is null) || (answer.Count == 0)) && ((authority is null) || (authority.Count == 0)))
                {
                    answer = authZone.QueryRecords(DnsResourceRecordType.DNAME);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                    else
                    {
                        answer = null;
                        authority = authZone.QueryRecords(DnsResourceRecordType.APP);
                        if (authority.Count == 0)
                        {
                            if (!hasSubDomains)
                                rCode = DnsResponseCode.NxDomain;

                            authority = authZone.GetRecords(DnsResourceRecordType.SOA);
                        }
                    }
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, rCode, request.Question, answer, authority);
            }
            else
            {
                //zone found
                IReadOnlyList<DnsResourceRecord> authority;
                IReadOnlyList<DnsResourceRecord> additional;

                IReadOnlyList<DnsResourceRecord> answers = zone.QueryRecords(question.Type);
                if (answers.Count == 0)
                {
                    //record type not found
                    if (authZone is StubZone)
                        return GetReferralResponse(request, authZone, isRecursionAllowed);
                    else if (authZone is ForwarderZone)
                        return GetForwarderResponse(request, zone, closest, authZone, isRecursionAllowed);

                    authority = zone.QueryRecords(DnsResourceRecordType.APP);
                    if (authority.Count == 0)
                    {
                        if (closest is not null)
                            authority = closest.QueryRecords(DnsResourceRecordType.APP);

                        if (authority.Count == 0)
                        {
                            authority = authZone.QueryRecords(DnsResourceRecordType.APP);
                            if (authority.Count == 0)
                                authority = authZone.GetRecords(DnsResourceRecordType.SOA);
                        }
                    }

                    additional = null;
                }
                else
                {
                    //record type found
                    if (zone.Name.Contains("*"))
                    {
                        //wildcard zone; generate new answer records
                        DnsResourceRecord[] wildcardAnswers = new DnsResourceRecord[answers.Count];

                        for (int i = 0; i < answers.Count; i++)
                            wildcardAnswers[i] = new DnsResourceRecord(question.Name, answers[i].Type, answers[i].Class, answers[i].TtlValue, answers[i].RDATA) { Tag = answers[i].Tag };

                        answers = wildcardAnswers;
                    }

                    DnsResourceRecord lastRR = answers[answers.Count - 1];
                    if ((lastRR.Type != question.Type) && (lastRR.Type == DnsResourceRecordType.CNAME) && (question.Type != DnsResourceRecordType.ANY))
                    {
                        List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(answers);

                        ResolveCNAME(question, lastRR, newAnswers);

                        answers = newAnswers;
                    }

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.NS:
                        case DnsResourceRecordType.MX:
                        case DnsResourceRecordType.SRV:
                            authority = null;
                            additional = GetAdditionalRecords(answers);
                            break;

                        default:
                            authority = null;
                            additional = null;
                            break;
                    }
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers, authority, additional);
            }
        }

        public void LoadZoneFrom(Stream s)
        {
            BinaryReader bR = new BinaryReader(s);

            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DZ")
                throw new InvalidDataException("DnsServer zone file format is invalid.");

            switch (bR.ReadByte())
            {
                case 2:
                    {
                        DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                        if (records.Length > 0)
                        {
                            DnsResourceRecord soaRecord = null;

                            for (int i = 0; i < records.Length; i++)
                            {
                                records[i] = new DnsResourceRecord(s);

                                if (records[i].Type == DnsResourceRecordType.SOA)
                                    soaRecord = records[i];
                            }

                            if (soaRecord == null)
                                throw new InvalidDataException("Zone does not contain SOA record.");

                            //make zone info
                            AuthZoneType zoneType;
                            if (_dnsServer.ServerDomain.Equals((soaRecord.RDATA as DnsSOARecord).PrimaryNameServer, StringComparison.OrdinalIgnoreCase))
                                zoneType = AuthZoneType.Primary;
                            else
                                zoneType = AuthZoneType.Stub;

                            AuthZoneInfo zoneInfo = new AuthZoneInfo(records[0].Name, zoneType, false);

                            //create zone
                            AuthZone authZone = CreateEmptyZone(zoneInfo);

                            try
                            {
                                //load records
                                LoadRecords(authZone, records);
                            }
                            catch
                            {
                                DeleteZone(zoneInfo.Name);
                                throw;
                            }

                            //init zone
                            switch (zoneInfo.Type)
                            {
                                case AuthZoneType.Primary:
                                    (authZone as PrimaryZone).TriggerNotify();
                                    break;
                            }
                        }
                    }
                    break;

                case 3:
                    {
                        bool zoneDisabled = bR.ReadBoolean();
                        DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                        if (records.Length > 0)
                        {
                            DnsResourceRecord soaRecord = null;

                            for (int i = 0; i < records.Length; i++)
                            {
                                records[i] = new DnsResourceRecord(s);
                                records[i].Tag = new DnsResourceRecordInfo(bR, records[i].Type == DnsResourceRecordType.SOA);

                                if (records[i].Type == DnsResourceRecordType.SOA)
                                    soaRecord = records[i];
                            }

                            if (soaRecord == null)
                                throw new InvalidDataException("Zone does not contain SOA record.");

                            //make zone info
                            AuthZoneType zoneType;
                            if (_dnsServer.ServerDomain.Equals((soaRecord.RDATA as DnsSOARecord).PrimaryNameServer, StringComparison.OrdinalIgnoreCase))
                                zoneType = AuthZoneType.Primary;
                            else
                                zoneType = AuthZoneType.Stub;

                            AuthZoneInfo zoneInfo = new AuthZoneInfo(records[0].Name, zoneType, zoneDisabled);

                            //create zone
                            AuthZone authZone = CreateEmptyZone(zoneInfo);

                            try
                            {
                                //load records
                                LoadRecords(authZone, records);
                            }
                            catch
                            {
                                DeleteZone(zoneInfo.Name);
                                throw;
                            }

                            //init zone
                            switch (zoneInfo.Type)
                            {
                                case AuthZoneType.Primary:
                                    (authZone as PrimaryZone).TriggerNotify();
                                    break;
                            }
                        }
                    }
                    break;

                case 4:
                    {
                        //read zone info
                        AuthZoneInfo zoneInfo = new AuthZoneInfo(bR);

                        //create zone
                        AuthZone authZone = CreateEmptyZone(zoneInfo);

                        //read all zone records
                        DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                        if (records.Length > 0)
                        {
                            for (int i = 0; i < records.Length; i++)
                            {
                                records[i] = new DnsResourceRecord(s);
                                records[i].Tag = new DnsResourceRecordInfo(bR, records[i].Type == DnsResourceRecordType.SOA);
                            }

                            try
                            {
                                //load records
                                LoadRecords(authZone, records);
                            }
                            catch
                            {
                                DeleteZone(zoneInfo.Name);
                                throw;
                            }

                            //init zone
                            switch (zoneInfo.Type)
                            {
                                case AuthZoneType.Primary:
                                    (authZone as PrimaryZone).TriggerNotify();
                                    break;

                                case AuthZoneType.Secondary:
                                    SecondaryZone secondary = authZone as SecondaryZone;

                                    secondary.TriggerNotify();
                                    secondary.TriggerRefresh();
                                    break;

                                case AuthZoneType.Stub:
                                    (authZone as StubZone).TriggerRefresh();
                                    break;
                            }
                        }
                    }
                    break;

                default:
                    throw new InvalidDataException("DNS Zone file version not supported.");
            }
        }

        public void WriteZoneTo(string domain, Stream s)
        {
            AuthZoneInfo zoneInfo = GetAuthZoneInfo(domain, true);
            if (zoneInfo is null)
                throw new InvalidOperationException("Zone was not found: " + domain);

            //serialize zone
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("DZ")); //format
            bW.Write((byte)4); //version

            //write zone info
            if (zoneInfo.Internal)
                throw new InvalidOperationException("Cannot save zones marked as internal.");

            zoneInfo.WriteTo(bW);

            //write all zone records
            List<DnsResourceRecord> records = new List<DnsResourceRecord>();
            ListAllRecords(domain, records);

            bW.Write(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                record.WriteTo(s);

                if (record.Tag is not DnsResourceRecordInfo rrInfo)
                    rrInfo = new DnsResourceRecordInfo(); //default info

                rrInfo.WriteTo(bW);
            }
        }

        public void SaveZoneFile(string domain)
        {
            domain = domain.ToLower();

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize zone
                WriteZoneTo(domain, mS);

                //write to zone file
                mS.Position = 0;

                using (FileStream fS = new FileStream(Path.Combine(_dnsServer.ConfigFolder, "zones", domain + ".zone"), FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            LogManager log = _dnsServer.LogManager;
            if (log != null)
                log.Write("Saved zone file for domain: " + (domain == "" ? "<root>" : domain));
        }

        public void DeleteZoneFile(string domain)
        {
            domain = domain.ToLower();

            File.Delete(Path.Combine(_dnsServer.ConfigFolder, "zones", domain + ".zone"));

            LogManager log = _dnsServer.LogManager;
            if (log != null)
                log.Write("Deleted zone file for domain: " + domain);
        }

        #endregion

        #region properties

        public string ServerDomain
        {
            get { return _serverDomain; }
            set { UpdateServerDomain(value); }
        }

        public int TotalZones
        { get { return _totalZones; } }

        #endregion
    }
}
