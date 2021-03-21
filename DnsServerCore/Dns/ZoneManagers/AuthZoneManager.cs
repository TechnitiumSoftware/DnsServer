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
                    if (zone is SubDomainZone)
                    {
                        foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                            zone.LoadRecords(groupedRecords.Key, groupedRecords.Value);

                        (zone as SubDomainZone).AutoUpdateState();
                    }
                }
            }
        }

        private AuthZone GetOrAddSubDomainZone(string domain)
        {
            return _root.GetOrAdd(domain, delegate (string key)
            {
                _ = _root.FindZone(domain, out _, out AuthZone authZone, out _);
                if (authZone == null)
                    throw new DnsServerException("Zone was not found for domain: " + domain);

                if (authZone is PrimaryZone)
                    return new PrimarySubDomainZone(authZone as PrimaryZone, domain);
                else if (authZone is SecondaryZone)
                    return new SecondarySubDomainZone(domain);
                else if (authZone is ForwarderZone)
                    return new ForwarderSubDomainZone(domain);

                throw new DnsServerException("Zone cannot have sub domains.");
            });
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
            AuthZone authZone = _root.FindZone(domain, out _, out _, out _);
            if ((authZone != null) && authZone.IsActive)
            {
                {
                    IReadOnlyList<DnsResourceRecord> records = authZone.QueryRecords(DnsResourceRecordType.A);
                    if ((records.Count > 0) && (records[0].RDATA is DnsARecord))
                        additionalRecords.AddRange(records);
                }

                {
                    IReadOnlyList<DnsResourceRecord> records = authZone.QueryRecords(DnsResourceRecordType.AAAA);
                    if ((records.Count > 0) && (records[0].RDATA is DnsAAAARecord))
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

        private static DnsDatagram GetForwarderResponse(DnsDatagram request, AuthZone zone, AuthZone forwarderZone, bool isRecursionAllowed)
        {
            IReadOnlyList<DnsResourceRecord> authority = null;

            if (zone != null)
                authority = zone.QueryRecords(DnsResourceRecordType.FWD);

            if ((authority == null) || (authority.Count == 0))
                authority = forwarderZone.QueryRecords(DnsResourceRecordType.FWD);

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, null, authority);
        }

        internal void Flush()
        {
            _root.Clear();
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

        internal AuthZoneInfo CreateInternalPrimaryZone(string domain, DnsSOARecord soaRecord, DnsNSRecord ns)
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
            AuthZone authZone = new PrimaryZone(_dnsServer, domain, primaryNameServer, @internal);

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

        public async Task<AuthZoneInfo> CreateSecondaryZoneAsync(string domain, string primaryNameServerAddresses = null)
        {
            AuthZone authZone = await SecondaryZone.CreateAsync(_dnsServer, domain, primaryNameServerAddresses);

            if (_root.TryAdd(authZone))
            {
                (authZone as SecondaryZone).RefreshZone();
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            if (_root.TryGet(domain, out AuthZone existingZone) && (existingZone is SubDomainZone))
            {
                _root[domain] = authZone;
                (authZone as SecondaryZone).RefreshZone();
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            return null;
        }

        public async Task<AuthZoneInfo> CreateStubZoneAsync(string domain, string primaryNameServerAddresses = null)
        {
            AuthZone authZone = await StubZone.CreateAsync(_dnsServer, domain, primaryNameServerAddresses);

            if (_root.TryAdd(authZone))
            {
                (authZone as StubZone).RefreshZone();
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            if (_root.TryGet(domain, out AuthZone existingZone) && (existingZone is SubDomainZone))
            {
                _root[domain] = authZone;
                (authZone as StubZone).RefreshZone();
                _totalZones++;
                return new AuthZoneInfo(authZone);
            }

            return null;
        }

        public AuthZoneInfo CreateForwarderZone(string domain, DnsTransportProtocol forwarderProtocol, string forwarder)
        {
            AuthZone authZone = new ForwarderZone(domain, forwarderProtocol, forwarder);

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

        public AuthZoneInfo GetAuthZoneInfo(string domain)
        {
            _ = _root.FindZone(domain, out _, out AuthZone authority, out _);
            if (authority == null)
                return null;

            return new AuthZoneInfo(authority);
        }

        public List<DnsResourceRecord> ListAllRecords(string domain)
        {
            List<DnsResourceRecord> records = new List<DnsResourceRecord>();

            foreach (AuthZone zone in _root.GetZoneWithSubDomainZones(domain))
                records.AddRange(zone.ListAllRecords());

            return records;
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecords(string domain, DnsResourceRecordType type)
        {
            if (_root.TryGet(domain, out AuthZone zone))
                return zone.QueryRecords(type);

            return Array.Empty<DnsResourceRecord>();
        }

        public IReadOnlyList<DnsResourceRecord> QueryZoneTransferRecords(string domain)
        {
            List<DnsResourceRecord> axfrRecords = new List<DnsResourceRecord>();

            List<AuthZone> zones = _root.GetZoneWithSubDomainZones(domain);

            if ((zones.Count > 0) && zones[0].IsActive)
            {
                //only primary zones support zone transfer
                DnsResourceRecord soaRecord = zones[0].GetRecords(DnsResourceRecordType.SOA)[0];

                axfrRecords.Add(soaRecord);

                foreach (Zone zone in zones)
                {
                    foreach (DnsResourceRecord record in zone.ListAllRecords())
                    {
                        if (record.IsDisabled())
                            continue;

                        switch (record.Type)
                        {
                            case DnsResourceRecordType.SOA:
                                break; //skip record

                            case DnsResourceRecordType.NS:
                                axfrRecords.Add(record);

                                foreach (DnsResourceRecord glueRecord in record.GetGlueRecords())
                                {
                                    if (!axfrRecords.Contains(glueRecord))
                                        axfrRecords.Add(glueRecord);
                                }
                                break;

                            default:
                                axfrRecords.Add(record);
                                break;
                        }
                    }
                }

                axfrRecords.Add(soaRecord);
            }

            return axfrRecords;
        }

        public void SyncRecords(string domain, IReadOnlyList<DnsResourceRecord> syncRecords, IReadOnlyList<DnsResourceRecord> additionalRecords = null, bool dontRemoveRecords = false)
        {
            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(syncRecords.Count);
            List<DnsResourceRecord> allGlueRecords = new List<DnsResourceRecord>();

            if (additionalRecords != null)
            {
                foreach (DnsResourceRecord additionalRecord in additionalRecords)
                {
                    if (!allGlueRecords.Contains(additionalRecord))
                        allGlueRecords.Add(additionalRecord);
                }
            }

            int i = 0;

            if ((syncRecords.Count > 1) && (syncRecords[0].Type == DnsResourceRecordType.SOA) && (syncRecords[syncRecords.Count - 1].Type == DnsResourceRecordType.SOA))
                i = 1; //skip first SOA in AXFR

            if (domain.Length == 0)
            {
                //root zone case
                for (; i < syncRecords.Count; i++)
                {
                    DnsResourceRecord record = syncRecords[i];

                    switch (record.Type)
                    {
                        case DnsResourceRecordType.A:
                        case DnsResourceRecordType.AAAA:
                            if (!allGlueRecords.Contains(record))
                                allGlueRecords.Add(record);

                            break;

                        default:
                            newRecords.Add(record);
                            break;
                    }
                }
            }
            else
            {
                for (; i < syncRecords.Count; i++)
                {
                    DnsResourceRecord record = syncRecords[i];

                    if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                        newRecords.Add(record);
                    else if (!allGlueRecords.Contains(record))
                        allGlueRecords.Add(record);
                }
            }

            if (allGlueRecords.Count > 0)
            {
                foreach (DnsResourceRecord record in newRecords)
                {
                    switch (record.Type)
                    {
                        case DnsResourceRecordType.NS:
                            record.SyncGlueRecords(allGlueRecords);
                            break;
                    }
                }
            }

            List<DnsResourceRecord> oldRecords = ListAllRecords(domain);

            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> newRecordsGroupedByDomain = DnsResourceRecord.GroupRecords(newRecords);
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> oldRecordsGroupedByDomain = DnsResourceRecord.GroupRecords(oldRecords);

            if (!dontRemoveRecords)
            {
                //remove domains that do not exists in new records
                foreach (string oldDomain in oldRecordsGroupedByDomain.Keys)
                {
                    if (!newRecordsGroupedByDomain.ContainsKey(oldDomain))
                        _root.TryRemove(oldDomain, out _);
                }
            }

            //sync new records
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> newEntries in newRecordsGroupedByDomain)
            {
                AuthZone zone = GetOrAddSubDomainZone(newEntries.Key);

                if (zone.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    zone.SyncRecords(newEntries.Value, dontRemoveRecords);
                else if (zone is SubDomainZone)
                    zone.SyncRecords(newEntries.Value, dontRemoveRecords);
            }
        }

        public void SetRecords(string domain, DnsResourceRecordType type, uint ttl, DnsResourceRecordData[] records)
        {
            DnsResourceRecord[] resourceRecords = new DnsResourceRecord[records.Length];

            for (int i = 0; i < records.Length; i++)
                resourceRecords[i] = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, records[i]);

            AuthZone zone = GetOrAddSubDomainZone(domain);

            zone.SetRecords(type, resourceRecords);

            if (zone is SubDomainZone)
                (zone as SubDomainZone).AutoUpdateState();
        }

        public void SetRecord(DnsResourceRecord record)
        {
            AuthZone zone = GetOrAddSubDomainZone(record.Name);

            zone.SetRecords(record.Type, new DnsResourceRecord[] { record });

            if (zone is SubDomainZone)
                (zone as SubDomainZone).AutoUpdateState();
        }

        public void AddRecord(string domain, DnsResourceRecordType type, uint ttl, DnsResourceRecordData record)
        {
            AuthZone zone = GetOrAddSubDomainZone(domain);

            zone.AddRecord(new DnsResourceRecord(zone.Name, type, DnsClass.IN, ttl, record));

            if (zone is SubDomainZone)
                (zone as SubDomainZone).AutoUpdateState();
        }

        public void AddRecord(DnsResourceRecord record)
        {
            AuthZone zone = GetOrAddSubDomainZone(record.Name);

            zone.AddRecord(record);

            if (zone is SubDomainZone)
                (zone as SubDomainZone).AutoUpdateState();
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
                case DnsResourceRecordType.ANAME:
                case DnsResourceRecordType.PTR:
                case DnsResourceRecordType.APP:
                    if (oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        zone.SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });

                        if (zone is SubDomainZone)
                            (zone as SubDomainZone).AutoUpdateState();
                    }
                    else
                    {
                        zone.DeleteRecords(oldRecord.Type);

                        if (zone is SubDomainZone)
                        {
                            if (zone.IsEmpty)
                                _root.TryRemove(oldRecord.Name, out _); //remove empty sub zone
                            else
                                (zone as SubDomainZone).AutoUpdateState();
                        }

                        AuthZone newZone = GetOrAddSubDomainZone(newRecord.Name);

                        newZone.SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });

                        if (newZone is SubDomainZone)
                            (newZone as SubDomainZone).AutoUpdateState();
                    }
                    break;

                default:
                    if (oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        zone.DeleteRecord(oldRecord.Type, oldRecord.RDATA);
                        zone.AddRecord(newRecord);

                        if (zone is SubDomainZone)
                            (zone as SubDomainZone).AutoUpdateState();
                    }
                    else
                    {
                        zone.DeleteRecord(oldRecord.Type, oldRecord.RDATA);

                        if (zone is SubDomainZone)
                        {
                            if (zone.IsEmpty)
                                _root.TryRemove(oldRecord.Name, out _); //remove empty sub zone
                            else
                                (zone as SubDomainZone).AutoUpdateState();
                        }

                        AuthZone newZone = GetOrAddSubDomainZone(newRecord.Name);

                        newZone.AddRecord(newRecord);

                        if (newZone is SubDomainZone)
                            (newZone as SubDomainZone).AutoUpdateState();
                    }
                    break;
            }
        }

        public void DeleteRecord(string domain, DnsResourceRecordType type, DnsResourceRecordData record)
        {
            if (_root.TryGet(domain, out AuthZone zone))
            {
                zone.DeleteRecord(type, record);

                if (zone is SubDomainZone)
                {
                    if (zone.IsEmpty)
                        _root.TryRemove(domain, out _); //remove empty sub zone
                    else
                        (zone as SubDomainZone).AutoUpdateState();
                }
            }
        }

        public void DeleteRecords(string domain, DnsResourceRecordType type)
        {
            if (_root.TryGet(domain, out AuthZone zone))
            {
                zone.DeleteRecords(type);

                if (zone is SubDomainZone)
                {
                    if (zone.IsEmpty)
                        _root.TryRemove(domain, out _); //remove empty sub zone
                    else
                        (zone as SubDomainZone).AutoUpdateState();
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

        public List<string> ListSubDomains(string domain)
        {
            return _root.ListSubDomains(domain);
        }

        public DnsDatagram Query(DnsDatagram request, bool isRecursionAllowed)
        {
            AuthZone zone = _root.FindZone(request.Question[0].Name, out AuthZone delegation, out AuthZone authZone, out bool hasSubDomains);

            if ((authZone == null) || !authZone.IsActive) //no authority for requested zone
                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Question);

            if ((delegation != null) && delegation.IsActive)
                return GetReferralResponse(request, delegation, isRecursionAllowed);

            if ((zone == null) || !zone.IsActive)
            {
                //zone not found                
                if (authZone is StubZone)
                    return GetReferralResponse(request, authZone, isRecursionAllowed);
                else if (authZone is ForwarderZone)
                    return GetForwarderResponse(request, null, authZone, isRecursionAllowed);

                DnsResponseCode rCode = DnsResponseCode.NoError;
                IReadOnlyList<DnsResourceRecord> authority = authZone.QueryRecords(DnsResourceRecordType.APP);
                if (authority.Count == 0)
                {
                    if (!hasSubDomains)
                        rCode = DnsResponseCode.NameError;

                    authority = authZone.GetRecords(DnsResourceRecordType.SOA);
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, rCode, request.Question, null, authority);
            }
            else
            {
                //zone found
                IReadOnlyList<DnsResourceRecord> authority;
                IReadOnlyList<DnsResourceRecord> additional;

                IReadOnlyList<DnsResourceRecord> answers = zone.QueryRecords(request.Question[0].Type);
                if (answers.Count == 0)
                {
                    //record type not found
                    if (authZone is StubZone)
                        return GetReferralResponse(request, authZone, isRecursionAllowed);
                    else if (authZone is ForwarderZone)
                        return GetForwarderResponse(request, zone, authZone, isRecursionAllowed);

                    authority = zone.QueryRecords(DnsResourceRecordType.APP);
                    if (authority.Count == 0)
                    {
                        authority = authZone.QueryRecords(DnsResourceRecordType.APP);
                        if (authority.Count == 0)
                            authority = authZone.GetRecords(DnsResourceRecordType.SOA);
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
                            wildcardAnswers[i] = new DnsResourceRecord(request.Question[0].Name, answers[i].Type, answers[i].Class, answers[i].TtlValue, answers[i].RDATA) { Tag = answers[i].Tag };

                        answers = wildcardAnswers;
                    }

                    switch (request.Question[0].Type)
                    {
                        case DnsResourceRecordType.NS:
                        case DnsResourceRecordType.MX:
                        case DnsResourceRecordType.SRV:
                            authority = null;
                            additional = GetAdditionalRecords(answers);
                            break;

                        case DnsResourceRecordType.ANY:
                            authority = null;
                            additional = null;
                            break;

                        default:
                            authority = authZone.QueryRecords(DnsResourceRecordType.NS);
                            additional = GetAdditionalRecords(authority);
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
                                    (authZone as PrimaryZone).NotifyNameServers();
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
                                records[i].Tag = new DnsResourceRecordInfo(bR);

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
                                    (authZone as PrimaryZone).NotifyNameServers();
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
                                records[i].Tag = new DnsResourceRecordInfo(bR);
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
                                    (authZone as PrimaryZone).NotifyNameServers();
                                    break;

                                case AuthZoneType.Secondary:
                                    (authZone as SecondaryZone).RefreshZone();
                                    break;

                                case AuthZoneType.Stub:
                                    (authZone as StubZone).RefreshZone();
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
            List<AuthZone> zones = _root.GetZoneWithSubDomainZones(domain);
            if (zones.Count == 0)
                throw new DnsServerException("Zone was not found: " + domain);

            //serialize zone
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("DZ")); //format
            bW.Write((byte)4); //version

            //write zone info
            AuthZoneInfo zoneInfo = new AuthZoneInfo(zones[0]);

            if (zoneInfo.Internal)
                throw new InvalidOperationException("Cannot save zones marked as internal.");

            zoneInfo.WriteTo(bW);

            //write all zone records
            List<DnsResourceRecord> records = new List<DnsResourceRecord>();

            foreach (AuthZone zone in zones)
                records.AddRange(zone.ListAllRecords());

            bW.Write(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                record.WriteTo(s);

                DnsResourceRecordInfo rrInfo = record.Tag as DnsResourceRecordInfo;
                if (rrInfo == null)
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
                log.Write("Saved zone file for domain: " + domain);
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
