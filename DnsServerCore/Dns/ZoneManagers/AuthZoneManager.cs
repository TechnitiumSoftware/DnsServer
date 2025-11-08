/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Trees;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class AuthZoneManager : IDisposable
    {
        #region events

        public event EventHandler<SecondaryCatalogEventArgs> SecondaryCatalogZoneAdded;
        public event EventHandler<SecondaryCatalogEventArgs> SecondaryCatalogZoneRemoved;

        #endregion

        #region variables

        readonly DnsServer _dnsServer;

        string _serverDomain;
        uint _defaultRecordTtl = 3600;
        bool _useSoaSerialDateScheme;
        uint _minSoaRefresh = 300;
        uint _minSoaRetry = 300;

        readonly AuthZoneTree _root = new AuthZoneTree();

        readonly List<AuthZoneInfo> _zoneIndex = new List<AuthZoneInfo>(10);
        readonly List<AuthZoneInfo> _catalogZoneIndex = new List<AuthZoneInfo>(2);
        readonly ReaderWriterLockSlim _zoneIndexLock = new ReaderWriterLockSlim();

        readonly object _saveLock = new object();
        readonly Dictionary<string, object> _pendingSaveZones = new Dictionary<string, object>();
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        volatile int _updateServerDomainId;

        #endregion

        #region constructor

        public AuthZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _serverDomain = _dnsServer.ServerDomain;

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    List<string> failedZones = new List<string>();

                    foreach (KeyValuePair<string, object> pendingSaveZone in _pendingSaveZones)
                    {
                        try
                        {
                            SaveZoneFileInternal(pendingSaveZone.Key);
                        }
                        catch (Exception ex)
                        {
                            _dnsServer.LogManager.Write(ex);

                            failedZones.Add(pendingSaveZone.Key);
                        }
                    }

                    _pendingSaveZones.Clear();

                    foreach (string zoneName in failedZones)
                        _pendingSaveZones.TryAdd(zoneName, null);

                    if (_pendingSaveZones.Count > 0)
                        _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                }
            });
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
                lock (_saveLock)
                {
                    _saveTimer?.Dispose();

                    try
                    {
                        foreach (KeyValuePair<string, object> pendingSaveZone in _pendingSaveZones)
                        {
                            try
                            {
                                SaveZoneFileInternal(pendingSaveZone.Key);
                            }
                            catch (Exception ex)
                            {
                                _dnsServer.LogManager.Write(ex);
                            }
                        }
                    }
                    finally
                    {
                        _pendingSaveZones.Clear();
                    }
                }

                foreach (AuthZoneNode zoneNode in _root)
                    zoneNode.Dispose();

                _zoneIndexLock.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region zone file serialization and loading

        public void LoadAllZoneFiles()
        {
            string zonesFolder = Path.Combine(_dnsServer.ConfigFolder, "zones");
            if (!Directory.Exists(zonesFolder))
                Directory.CreateDirectory(zonesFolder);

            //move zone files to new folder
            {
                string[] oldZoneFiles = Directory.GetFiles(_dnsServer.ConfigFolder, "*.zone");

                foreach (string oldZoneFile in oldZoneFiles)
                    File.Move(oldZoneFile, Path.Combine(zonesFolder, Path.GetFileName(oldZoneFile)));
            }

            //remove old internal zones files
            {
                string[] oldZoneFiles = ["localhost.zone", "1.0.0.127.in-addr.arpa.zone", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.zone"];

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

            //flush existing zones
            Flush();

            //load all internal zones
            LoadAllInternalZones();

            //load zone files
            _zoneIndexLock.EnterWriteLock();
            try
            {
                string[] zoneFiles = Directory.GetFiles(zonesFolder, "*.zone");

                foreach (string zoneFile in zoneFiles)
                {
                    try
                    {
                        using (FileStream fS = new FileStream(zoneFile, FileMode.Open, FileAccess.Read))
                        {
                            AuthZoneInfo zoneInfo = LoadZoneFrom(fS, File.GetLastWriteTimeUtc(fS.SafeFileHandle));
                            _zoneIndex.Add(zoneInfo);

                            if (zoneInfo.Type == AuthZoneType.Catalog)
                                _catalogZoneIndex.Add(zoneInfo);
                        }

                        _dnsServer.LogManager.Write("DNS Server successfully loaded zone file: " + zoneFile);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write("DNS Server failed to load zone file: " + zoneFile + "\r\n" + ex.ToString());
                    }
                }

                _zoneIndex.Sort();
                _catalogZoneIndex.Sort();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        private void LoadAllInternalZones()
        {
            {
                CreateInternalPrimaryZone("localhost");
                SetRecord("localhost", new DnsResourceRecord("localhost", DnsResourceRecordType.A, DnsClass.IN, 3600, new DnsARecordData(IPAddress.Loopback)));
                SetRecord("localhost", new DnsResourceRecord("localhost", DnsResourceRecordType.AAAA, DnsClass.IN, 3600, new DnsAAAARecordData(IPAddress.IPv6Loopback)));
            }

            {
                string ptrDomain = "0.in-addr.arpa";

                CreateInternalPrimaryZone(ptrDomain);
            }

            {
                string ptrDomain = "255.in-addr.arpa";

                CreateInternalPrimaryZone(ptrDomain);
            }

            {
                string ptrZoneName = "127.in-addr.arpa";

                CreateInternalPrimaryZone(ptrZoneName);
                SetRecord(ptrZoneName, new DnsResourceRecord("1.0.0.127.in-addr.arpa", DnsResourceRecordType.PTR, DnsClass.IN, 3600, new DnsPTRRecordData("localhost")));
            }

            {
                string ptrZoneName = IPAddress.IPv6Loopback.GetReverseDomain();

                CreateInternalPrimaryZone(ptrZoneName);
                SetRecord(ptrZoneName, new DnsResourceRecord(ptrZoneName, DnsResourceRecordType.PTR, DnsClass.IN, 3600, new DnsPTRRecordData("localhost")));
            }
        }

        private void SaveZoneFileInternal(string zoneName)
        {
            zoneName = zoneName.ToLowerInvariant();

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize zone
                WriteZoneTo(zoneName, mS);

                if (mS.Position == 0)
                    return; //zone was not found

                //write to zone file
                mS.Position = 0;

                using (FileStream fS = new FileStream(Path.Combine(_dnsServer.ConfigFolder, "zones", zoneName + ".zone"), FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _dnsServer.LogManager.Write("Saved zone file for domain: " + (zoneName == "" ? "<root>" : zoneName));
        }

        public void SaveZoneFile(string zoneName)
        {
            zoneName = zoneName.ToLowerInvariant();

            lock (_saveLock)
            {
                if (!_pendingSaveZones.TryAdd(zoneName, null))
                    return;

                if (_pendingSaveZones.Count == 1)
                    _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private static uint GetMinExpiryTtlFor(IReadOnlyList<DnsResourceRecord> records)
        {
            uint minExpiryTtl = 0u;

            foreach (DnsResourceRecord record in records)
            {
                GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();
                if (recordInfo.ExpiryTtl > 0u)
                {
                    uint pendingExpiryTtl = recordInfo.GetPendingExpiryTtl();
                    if (pendingExpiryTtl == 0)
                    {
                        //expired record found; set 10 sec ttl for timer to delete it
                        minExpiryTtl = 10;
                    }
                    else
                    {
                        if (minExpiryTtl == 0u)
                            minExpiryTtl = pendingExpiryTtl;
                        else
                            minExpiryTtl = Math.Min(minExpiryTtl, pendingExpiryTtl);
                    }
                }
            }

            return minExpiryTtl;
        }

        private void LoadAndInitZone(AuthZoneInfo zoneInfo, IReadOnlyList<DnsResourceRecord> records)
        {
            ApexZone apexZone = zoneInfo.ApexZone;

            //load records
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> zoneEntry in DnsResourceRecord.GroupRecords(records))
            {
                if (apexZone.Name.Equals(zoneEntry.Key, StringComparison.OrdinalIgnoreCase))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                        apexZone.LoadRecords(rrsetEntry.Key, rrsetEntry.Value);
                }
                else
                {
                    ValidateIfDomainBelongsToZone(apexZone.Name, zoneEntry.Key);

                    AuthZone authZone = GetOrAddSubDomainZone(apexZone.Name, zoneEntry.Key);

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                        authZone.LoadRecords(rrsetEntry.Key, rrsetEntry.Value);

                    if (authZone is SubDomainZone subDomainZone)
                        subDomainZone.AutoUpdateState();
                }
            }

            //update dnssec status
            apexZone.UpdateDnssecStatus();

            //init zone
            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    {
                        apexZone.TriggerNotify();

                        uint minExpiryTtl = GetMinExpiryTtlFor(records);
                        if (minExpiryTtl > 0u)
                            apexZone.StartRecordExpiryTimer(minExpiryTtl);
                    }
                    break;

                case AuthZoneType.Secondary:
                    {
                        SecondaryZone secondary = apexZone as SecondaryZone;

                        DnsResourceRecord soaRecord = secondary.GetRecords(DnsResourceRecordType.SOA)[0];
                        SOARecordInfo soaInfo = soaRecord.GetAuthSOARecordInfo();
                        if (soaInfo.Version == 1)
                        {
                            secondary.PrimaryNameServerAddresses = soaInfo.PrimaryNameServers;
                            secondary.PrimaryZoneTransferProtocol = soaInfo.ZoneTransferProtocol;
                            secondary.PrimaryZoneTransferTsigKeyName = soaInfo.TsigKeyName;
                        }

                        secondary.TriggerNotify();
                        secondary.TriggerRefresh();
                    }
                    break;

                case AuthZoneType.Stub:
                    {
                        StubZone stub = apexZone as StubZone;

                        DnsResourceRecord soaRecord = stub.GetRecords(DnsResourceRecordType.SOA)[0];
                        SOARecordInfo soaInfo = soaRecord.GetAuthSOARecordInfo();
                        if (soaInfo.Version == 1)
                            stub.PrimaryNameServerAddresses = soaInfo.PrimaryNameServers;

                        stub.TriggerRefresh();
                    }
                    break;

                case AuthZoneType.Forwarder:
                    {
                        IReadOnlyList<DnsResourceRecord> soaRecords = apexZone.GetRecords(DnsResourceRecordType.SOA);
                        if (soaRecords.Count == 0)
                            (apexZone as ForwarderZone).InitZone();

                        apexZone.TriggerNotify();

                        uint minExpiryTtl = GetMinExpiryTtlFor(records);
                        if (minExpiryTtl > 0u)
                            apexZone.StartRecordExpiryTimer(minExpiryTtl);
                    }
                    break;

                case AuthZoneType.SecondaryForwarder:
                    {
                        (apexZone as SecondaryZone).TriggerRefresh();
                    }
                    break;

                case AuthZoneType.Catalog:
                    {
                        (apexZone as CatalogZone).BuildMembersIndex();
                        apexZone.TriggerNotify();

                        uint minExpiryTtl = GetMinExpiryTtlFor(records);
                        if (minExpiryTtl > 0u)
                            apexZone.StartRecordExpiryTimer(minExpiryTtl);
                    }
                    break;

                case AuthZoneType.SecondaryCatalog:
                    {
                        (apexZone as SecondaryZone).TriggerRefresh();
                        (apexZone as SecondaryCatalogZone).BuildMembersIndex();
                    }
                    break;
            }
        }

        public AuthZoneInfo LoadZoneFrom(Stream s, DateTime lastModified)
        {
            BinaryReader bR = new BinaryReader(s);

            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DZ")
                throw new InvalidDataException("DnsServer zone file format is invalid.");

            switch (bR.ReadByte())
            {
                case 2:
                    {
                        DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                        if (records.Length == 0)
                            throw new InvalidDataException("Zone does not contain SOA record.");

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
                        if (_dnsServer.ServerDomain.Equals((soaRecord.RDATA as DnsSOARecordData).PrimaryNameServer, StringComparison.OrdinalIgnoreCase))
                            zoneType = AuthZoneType.Primary;
                        else
                            zoneType = AuthZoneType.Stub;

                        AuthZoneInfo zoneInfo = new AuthZoneInfo(records[0].Name, zoneType, false);

                        //create zone
                        ApexZone apexZone = CreateEmptyApexZone(zoneInfo);
                        zoneInfo = new AuthZoneInfo(apexZone);

                        try
                        {
                            //load and init zone
                            LoadAndInitZone(zoneInfo, records);
                        }
                        catch
                        {
                            DeleteZone(zoneInfo);
                            throw;
                        }

                        return zoneInfo;
                    }

                case 3:
                    {
                        bool zoneDisabled = bR.ReadBoolean();
                        DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                        if (records.Length == 0)
                            throw new InvalidDataException("Zone does not contain SOA record.");

                        DnsResourceRecord soaRecord = null;

                        for (int i = 0; i < records.Length; i++)
                        {
                            records[i] = new DnsResourceRecord(s);
                            records[i].Tag = AuthRecordInfo.ReadGenericRecordInfoFrom(bR, records[i].Type);

                            if (records[i].Type == DnsResourceRecordType.SOA)
                                soaRecord = records[i];
                        }

                        if (soaRecord == null)
                            throw new InvalidDataException("Zone does not contain SOA record.");

                        //make zone info
                        AuthZoneType zoneType;
                        if (_dnsServer.ServerDomain.Equals((soaRecord.RDATA as DnsSOARecordData).PrimaryNameServer, StringComparison.OrdinalIgnoreCase))
                            zoneType = AuthZoneType.Primary;
                        else
                            zoneType = AuthZoneType.Stub;

                        AuthZoneInfo zoneInfo = new AuthZoneInfo(records[0].Name, zoneType, zoneDisabled);

                        //create zone
                        ApexZone apexZone = CreateEmptyApexZone(zoneInfo);
                        zoneInfo = new AuthZoneInfo(apexZone);

                        try
                        {
                            //load and init zone
                            LoadAndInitZone(zoneInfo, records);
                        }
                        catch
                        {
                            DeleteZone(zoneInfo);
                            throw;
                        }

                        return zoneInfo;
                    }

                case 4:
                    {
                        //read zone info
                        AuthZoneInfo zoneInfo = new AuthZoneInfo(bR, lastModified);

                        //create zone
                        ApexZone apexZone = CreateEmptyApexZone(zoneInfo);
                        zoneInfo = new AuthZoneInfo(apexZone);

                        try
                        {
                            //read all zone records
                            DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                            if (records.Length < 1)
                                throw new InvalidDataException("Failed to load DNS zone file: the zone file does not contain any records.");

                            for (int i = 0; i < records.Length; i++)
                            {
                                records[i] = new DnsResourceRecord(s);
                                records[i].Tag = AuthRecordInfo.ReadGenericRecordInfoFrom(bR, records[i].Type);
                            }

                            //load and init zone
                            LoadAndInitZone(zoneInfo, records);
                        }
                        catch
                        {
                            DeleteZone(zoneInfo);
                            throw;
                        }

                        return zoneInfo;
                    }

                default:
                    throw new InvalidDataException("DNS Zone file version not supported.");
            }
        }

        public void WriteZoneTo(string zoneName, Stream s)
        {
            AuthZoneInfo zoneInfo = GetAuthZoneInfo(zoneName, true);
            if (zoneInfo is null)
                return;

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
            ListAllZoneRecords(zoneInfo.Name, records);

            bW.Write(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                record.WriteTo(s);
                record.GetAuthGenericRecordInfo().WriteTo(bW);
            }
        }

        #endregion

        #region internal

        internal void TriggerUpdateServerDomain(bool useBlockingAnswerTtl = false)
        {
            int id = RandomNumberGenerator.GetInt32(int.MaxValue);
            _updateServerDomainId = id;

            ThreadPool.QueueUserWorkItem(delegate (object state)
            {
                string serverDomain = _dnsServer.ServerDomain;

                //update authoritative zone SOA and NS records
                try
                {
                    IReadOnlyList<AuthZoneInfo> zones = GetAllZones();

                    foreach (AuthZoneInfo zone in zones)
                    {
                        if (_updateServerDomainId != id)
                            return; //stop current update since another update has been triggerred

                        if (zone.Type != AuthZoneType.Primary)
                            continue;

                        DnsResourceRecord record = zone.ApexZone.GetRecords(DnsResourceRecordType.SOA)[0];
                        DnsSOARecordData soa = record.RDATA as DnsSOARecordData;

                        uint ttl;
                        uint minimum;

                        if (useBlockingAnswerTtl)
                        {
                            ttl = _dnsServer.BlockingAnswerTtl;
                            minimum = ttl;
                        }
                        else
                        {
                            ttl = record.TTL;
                            minimum = soa.Minimum;
                        }

                        if (soa.PrimaryNameServer.Equals(_serverDomain, StringComparison.OrdinalIgnoreCase))
                        {
                            SetRecord(zone.Name, new DnsResourceRecord(record.Name, record.Type, DnsClass.IN, ttl, new DnsSOARecordData(serverDomain, soa.ResponsiblePerson, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, minimum)));

                            //update NS records
                            IReadOnlyList<DnsResourceRecord> nsResourceRecords = zone.ApexZone.GetRecords(DnsResourceRecordType.NS);

                            foreach (DnsResourceRecord nsResourceRecord in nsResourceRecords)
                            {
                                if ((nsResourceRecord.RDATA as DnsNSRecordData).NameServer.Equals(_serverDomain, StringComparison.OrdinalIgnoreCase))
                                {
                                    UpdateRecord(zone.Name, nsResourceRecord, new DnsResourceRecord(nsResourceRecord.Name, nsResourceRecord.Type, nsResourceRecord.Class, nsResourceRecord.TTL, new DnsNSRecordData(serverDomain)) { Tag = nsResourceRecord.Tag });
                                    break;
                                }
                            }

                            if (zone.Internal)
                                continue; //dont save internal zones to disk

                            //save zone file
                            SaveZoneFile(zone.Name);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }

                //update server domain
                _serverDomain = serverDomain;
            });
        }

        internal static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

        internal static bool DomainBelongsToZone(string zoneName, string domain)
        {
            return domain.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase) || (zoneName.Length == 0);
        }

        internal static void ValidateIfDomainBelongsToZone(string zoneName, string domain)
        {
            if (!DomainBelongsToZone(zoneName, domain))
                throw new DnsServerException("The domain name '" + domain + "' does not belong to the zone: " + zoneName);
        }

        #endregion

        #region auth zone tree methods

        private ApexZone CreateEmptyApexZone(AuthZoneInfo zoneInfo)
        {
            ApexZone apexZone;

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    apexZone = new PrimaryZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.Secondary:
                    apexZone = new SecondaryZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.Stub:
                    apexZone = new StubZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.Forwarder:
                    apexZone = new ForwarderZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.SecondaryForwarder:
                    apexZone = new SecondaryForwarderZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.Catalog:
                    apexZone = new CatalogZone(_dnsServer, zoneInfo);
                    break;

                case AuthZoneType.SecondaryCatalog:
                    SecondaryCatalogZone secondaryCatalogZone = new SecondaryCatalogZone(_dnsServer, zoneInfo);
                    secondaryCatalogZone.ZoneAdded += SecondaryCatalogZoneAdded;
                    secondaryCatalogZone.ZoneRemoved += SecondaryCatalogZoneRemoved;

                    apexZone = secondaryCatalogZone;
                    break;

                default:
                    throw new InvalidDataException("DNS zone type not supported.");
            }

            if (_root.TryAdd(apexZone))
                return apexZone;

            throw new DnsServerException("Zone already exists: " + zoneInfo.DisplayName);
        }

        internal AuthZone GetOrAddSubDomainZone(string zoneName, string domain)
        {
            return _root.GetOrAddSubDomainZone(zoneName, domain, delegate ()
            {
                if (!_root.TryGet(zoneName, out ApexZone apexZone))
                    throw new DnsServerException("Zone was not found for domain: " + domain);

                if (apexZone is PrimaryZone primaryZone)
                    return new PrimarySubDomainZone(primaryZone, domain);
                else if (apexZone is SecondaryCatalogZone secondaryCatalogZone)
                    return new SecondaryCatalogSubDomainZone(secondaryCatalogZone, domain);
                else if (apexZone is SecondaryZone secondaryZone)
                    return new SecondarySubDomainZone(secondaryZone, domain);
                else if (apexZone is CatalogZone catalogZone)
                    return new CatalogSubDomainZone(catalogZone, domain);
                else if (apexZone is ForwarderZone forwarderZone)
                    return new ForwarderSubDomainZone(forwarderZone, domain);

                throw new DnsServerException("Zone cannot have sub domains.");
            });
        }

        internal IReadOnlyList<AuthZone> GetApexZoneWithSubDomainZones(string zoneName)
        {
            return _root.GetApexZoneWithSubDomainZones(zoneName);
        }

        public AuthZoneInfo GetAuthZoneInfo(string zoneName, bool loadHistory = false)
        {
            if (_root.TryGet(zoneName, out AuthZoneNode authZoneNode) && (authZoneNode.ApexZone is not null))
                return new AuthZoneInfo(authZoneNode.ApexZone, loadHistory);

            return null;
        }

        public AuthZoneInfo FindAuthZoneInfo(string domain, bool loadHistory = false)
        {
            _ = _root.FindZone(domain, out _, out _, out ApexZone apexZone, out _);
            if (apexZone is null)
                return null;

            return new AuthZoneInfo(apexZone, loadHistory);
        }

        internal AuthZone GetAuthZone(string zoneName, string domain)
        {
            return _root.GetAuthZone(zoneName, domain);
        }

        internal ApexZone GetApexZone(string zoneName)
        {
            return _root.GetApexZone(zoneName);
        }

        public bool NameExists(string zoneName, string domain)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            return _root.TryGet(zoneName, domain, out _);
        }

        internal AuthZone FindPreviousSubDomainZone(string zoneName, string domain)
        {
            return _root.FindPreviousSubDomainZone(zoneName, domain);
        }

        internal AuthZone FindNextSubDomainZone(string zoneName, string domain)
        {
            return _root.FindNextSubDomainZone(zoneName, domain);
        }

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            _root.ListSubDomains(domain, subDomains);
        }

        internal bool SubDomainExistsFor(string zoneName, string domain)
        {
            return _root.SubDomainExistsFor(zoneName, domain);
        }

        internal void RemoveSubDomainZone(string domain, bool removeAllSubDomains = false)
        {
            _root.TryRemove(domain, out SubDomainZone _, removeAllSubDomains);
        }

        internal void Flush()
        {
            _zoneIndexLock.EnterWriteLock();
            try
            {
                foreach (AuthZoneNode zoneNode in _root)
                    zoneNode.Dispose();

                _root.Clear();
                _zoneIndex.Clear();
                _catalogZoneIndex.Clear();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        #endregion

        #region zone create / delete / convert / clone

        internal AuthZoneInfo CreateSpecialPrimaryZone(string zoneName, DnsSOARecordData soaRecord, DnsNSRecordData ns)
        {
            PrimaryZone apexZone = new PrimaryZone(_dnsServer, zoneName, soaRecord, ns);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        internal void LoadSpecialPrimaryZones(IReadOnlyList<string> zoneNames, DnsSOARecordData soaRecord, DnsNSRecordData ns)
        {
            _zoneIndexLock.EnterWriteLock();
            try
            {
                foreach (string zoneName in zoneNames)
                {
                    PrimaryZone apexZone = new PrimaryZone(_dnsServer, zoneName, soaRecord, ns);

                    if (_root.TryAdd(apexZone))
                    {
                        AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                        _zoneIndex.Add(zoneInfo);
                    }
                }

                _zoneIndex.Sort();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        internal void LoadSpecialPrimaryZones(Func<string> getZoneName, DnsSOARecordData soaRecord, DnsNSRecordData ns)
        {
            _zoneIndexLock.EnterWriteLock();
            try
            {
                string zoneName;

                while (true)
                {
                    zoneName = getZoneName();
                    if (zoneName is null)
                        break;

                    PrimaryZone apexZone = new PrimaryZone(_dnsServer, zoneName, soaRecord, ns);

                    if (_root.TryAdd(apexZone))
                    {
                        AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                        _zoneIndex.Add(zoneInfo);
                    }
                }

                _zoneIndex.Sort();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        internal AuthZoneInfo CreateInternalPrimaryZone(string zoneName)
        {
            return CreatePrimaryZone(zoneName, true, _useSoaSerialDateScheme);
        }

        public AuthZoneInfo CreatePrimaryZone(string zoneName)
        {
            return CreatePrimaryZone(zoneName, false, _useSoaSerialDateScheme);
        }

        public AuthZoneInfo CreatePrimaryZone(string zoneName, bool useSoaSerialDateScheme)
        {
            return CreatePrimaryZone(zoneName, false, useSoaSerialDateScheme);
        }

        private AuthZoneInfo CreatePrimaryZone(string zoneName, bool @internal, bool useSoaSerialDateScheme)
        {
            PrimaryZone apexZone = new PrimaryZone(_dnsServer, zoneName, @internal, useSoaSerialDateScheme);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    if (!@internal)
                        SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public Task<AuthZoneInfo> CreateSecondaryZoneAsync(string zoneName, string primaryNameServerAddresses = null, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null, bool validateZone = false, bool ignoreSoaFailure = false)
        {
            NameServerAddress[] primaryNameServers;

            if (string.IsNullOrEmpty(primaryNameServerAddresses))
                primaryNameServers = null;
            else
                primaryNameServers = primaryNameServerAddresses.Split(NameServerAddress.Parse, ',');

            return CreateSecondaryZoneAsync(zoneName, primaryNameServers, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName, validateZone, ignoreSoaFailure);
        }

        public async Task<AuthZoneInfo> CreateSecondaryZoneAsync(string zoneName, IReadOnlyList<NameServerAddress> primaryNameServerAddresses = null, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null, bool validateZone = false, bool ignoreSoaFailure = false)
        {
            SecondaryZone apexZone = await SecondaryZone.CreateAsync(_dnsServer, zoneName, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName, validateZone, ignoreSoaFailure);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    apexZone.TriggerRefresh(0);

                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public Task<AuthZoneInfo> CreateStubZoneAsync(string zoneName, string primaryNameServerAddresses = null, bool ignoreSoaFailure = false)
        {
            NameServerAddress[] primaryNameServers;

            if (string.IsNullOrEmpty(primaryNameServerAddresses))
                primaryNameServers = null;
            else
                primaryNameServers = primaryNameServerAddresses.Split(NameServerAddress.Parse, ',');

            return CreateStubZoneAsync(zoneName, primaryNameServers, ignoreSoaFailure);
        }

        public async Task<AuthZoneInfo> CreateStubZoneAsync(string zoneName, IReadOnlyList<NameServerAddress> primaryNameServerAddresses = null, bool ignoreSoaFailure = false)
        {
            StubZone apexZone = await StubZone.CreateAsync(_dnsServer, zoneName, primaryNameServerAddresses, ignoreSoaFailure);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    apexZone.TriggerRefresh(0);

                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public AuthZoneInfo CreateForwarderZone(string zoneName)
        {
            ForwarderZone apexZone = new ForwarderZone(_dnsServer, zoneName);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public AuthZoneInfo CreateForwarderZone(string zoneName, DnsTransportProtocol forwarderProtocol, string forwarder, bool dnssecValidation, DnsForwarderRecordProxyType proxyType, string proxyAddress, ushort proxyPort, string proxyUsername, string proxyPassword, string fwdRecordComments)
        {
            ForwarderZone apexZone = new ForwarderZone(_dnsServer, zoneName, forwarderProtocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, fwdRecordComments);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public AuthZoneInfo CreateSecondaryForwarderZone(string zoneName, string primaryNameServerAddresses = null, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null)
        {
            NameServerAddress[] primaryNameServers;

            if (string.IsNullOrEmpty(primaryNameServerAddresses))
                primaryNameServers = null;
            else
                primaryNameServers = primaryNameServerAddresses.Split(NameServerAddress.Parse, ',');

            return CreateSecondaryForwarderZone(zoneName, primaryNameServers, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName);
        }

        public AuthZoneInfo CreateSecondaryForwarderZone(string zoneName, IReadOnlyList<NameServerAddress> primaryNameServerAddresses = null, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null)
        {
            SecondaryForwarderZone apexZone = new SecondaryForwarderZone(_dnsServer, zoneName, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    apexZone.TriggerRefresh(0);

                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public AuthZoneInfo CreateCatalogZone(string zoneName)
        {
            CatalogZone apexZone = new CatalogZone(_dnsServer, zoneName);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    _catalogZoneIndex.Add(zoneInfo);
                    _catalogZoneIndex.Sort();

                    apexZone.InitZoneProperties();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public AuthZoneInfo CreateSecondaryCatalogZone(string zoneName, string primaryNameServerAddresses, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null)
        {
            NameServerAddress[] primaryNameServers;

            if (string.IsNullOrEmpty(primaryNameServerAddresses))
                primaryNameServers = null;
            else
                primaryNameServers = primaryNameServerAddresses.Split(NameServerAddress.Parse, ',');

            return CreateSecondaryCatalogZone(zoneName, primaryNameServers, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName);
        }

        public AuthZoneInfo CreateSecondaryCatalogZone(string zoneName, IReadOnlyList<NameServerAddress> primaryNameServerAddresses, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null)
        {
            SecondaryCatalogZone apexZone = new SecondaryCatalogZone(_dnsServer, zoneName, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName);

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    apexZone.ZoneAdded += SecondaryCatalogZoneAdded;
                    apexZone.ZoneRemoved += SecondaryCatalogZoneRemoved;
                    apexZone.TriggerRefresh(0);

                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return null;
        }

        public bool DeleteZone(string zoneName, bool deleteZoneFile = false)
        {
            AuthZoneInfo zoneInfo = GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                return false;

            return DeleteZone(zoneInfo, deleteZoneFile);
        }

        public bool DeleteZone(AuthZoneInfo zoneInfo, bool deleteZoneFile = false)
        {
            return DeleteZone(zoneInfo, deleteZoneFile, false);
        }

        private bool DeleteZone(AuthZoneInfo zoneInfo, bool deleteZoneFile, bool skipCatalogMemberZoneProcessing)
        {
            if (!skipCatalogMemberZoneProcessing)
            {
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Catalog:
                        //update all zone memberships for catalog zone to be deleted
                        foreach (string memberZoneName in (zoneInfo.ApexZone as CatalogZone).GetAllMemberZoneNames())
                        {
                            AuthZoneInfo memberZoneInfo = GetAuthZoneInfo(memberZoneName);
                            if (memberZoneInfo is null)
                                continue;

                            if (zoneInfo.Name.Equals(memberZoneInfo.CatalogZoneName, StringComparison.OrdinalIgnoreCase))
                            {
                                memberZoneInfo.ApexZone.CatalogZoneName = null;
                                SaveZoneFile(memberZoneInfo.Name);
                            }
                        }
                        break;

                    case AuthZoneType.SecondaryCatalog:
                        //delete all member zones for secondary catalog zone to be deleted
                        foreach (string memberZoneName in (zoneInfo.ApexZone as SecondaryCatalogZone).GetAllMemberZoneNames())
                        {
                            AuthZoneInfo memberZoneInfo = GetAuthZoneInfo(memberZoneName);
                            if (memberZoneInfo is null)
                                continue;

                            if (zoneInfo.Name.Equals(memberZoneInfo.CatalogZoneName, StringComparison.OrdinalIgnoreCase))
                                DeleteZone(memberZoneInfo, true);
                        }
                        break;
                }
            }

            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryRemove(zoneInfo.Name, out ApexZone removedApexZone))
                {
                    removedApexZone.Dispose();

                    _zoneIndex.Remove(zoneInfo);

                    if (zoneInfo.Type == AuthZoneType.Catalog)
                        _catalogZoneIndex.Remove(zoneInfo);

                    if (zoneInfo.CatalogZoneName is not null)
                        RemoveCatalogMemberZone(zoneInfo); //remove catalog zone membership

                    if (deleteZoneFile)
                    {
                        File.Delete(Path.Combine(_dnsServer.ConfigFolder, "zones", zoneInfo.Name + ".zone"));

                        _dnsServer.LogManager.Write("Deleted zone file for domain: " + zoneInfo.DisplayName);
                    }

                    return true;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return false;
        }

        public AuthZoneInfo CloneZone(string zoneName, string sourceZoneName)
        {
            AuthZoneInfo sourceZoneInfo = GetAuthZoneInfo(sourceZoneName);
            if (sourceZoneInfo is null)
                throw new DnsServerException("No such zone was found: " + (sourceZoneName.Length == 0 ? "." : sourceZoneName));

            AuthZoneInfo zoneInfo;

            switch (sourceZoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    zoneInfo = CreatePrimaryZone(zoneName);
                    break;

                case AuthZoneType.Forwarder:
                    zoneInfo = CreateForwarderZone(zoneName);
                    break;

                default:
                    throw new DnsServerException("Cannot clone the zone: source zone must be a Primary or Conditional Forwarder zone.");
            }

            if (zoneInfo is null)
                throw new DnsServerException("Failed to clone the zone: zone already exists.");

            //copy zone options
            zoneInfo.Disabled = sourceZoneInfo.Disabled;

            if (zoneInfo.Type == AuthZoneType.Primary)
            {
                zoneInfo.ZoneTransfer = sourceZoneInfo.ZoneTransfer;
                zoneInfo.ZoneTransferNetworkACL = sourceZoneInfo.ZoneTransferNetworkACL;
                zoneInfo.ZoneTransferTsigKeyNames = sourceZoneInfo.ZoneTransferTsigKeyNames;

                zoneInfo.Notify = sourceZoneInfo.Notify;
                zoneInfo.NotifyNameServers = sourceZoneInfo.NotifyNameServers;

                zoneInfo.Update = sourceZoneInfo.Update;
                zoneInfo.UpdateNetworkACL = sourceZoneInfo.UpdateNetworkACL;

                if (sourceZoneInfo.UpdateSecurityPolicies is not null)
                {
                    Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicies = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(sourceZoneInfo.UpdateSecurityPolicies.Count);

                    foreach (KeyValuePair<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> sourceSecurityPolicy in sourceZoneInfo.UpdateSecurityPolicies)
                    {
                        Dictionary<string, IReadOnlyList<DnsResourceRecordType>> policyMap = new Dictionary<string, IReadOnlyList<DnsResourceRecordType>>();

                        foreach (KeyValuePair<string, IReadOnlyList<DnsResourceRecordType>> sourcePolicyMap in sourceSecurityPolicy.Value)
                            policyMap.Add(string.Concat(sourcePolicyMap.Key.AsSpan(0, sourcePolicyMap.Key.Length - sourceZoneName.Length), zoneName), sourcePolicyMap.Value);

                        updateSecurityPolicies.Add(sourceSecurityPolicy.Key, policyMap);
                    }

                    zoneInfo.UpdateSecurityPolicies = updateSecurityPolicies;
                }
            }

            //copy records
            List<DnsResourceRecord> sourceRecords = new List<DnsResourceRecord>();
            ListAllZoneRecords(sourceZoneName, sourceRecords);

            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(sourceRecords.Count);

            foreach (DnsResourceRecord sourceRecord in sourceRecords)
            {
                switch (sourceRecord.Type)
                {
                    case DnsResourceRecordType.DNSKEY:
                    case DnsResourceRecordType.RRSIG:
                    case DnsResourceRecordType.NSEC:
                    case DnsResourceRecordType.NSEC3:
                    case DnsResourceRecordType.NSEC3PARAM:
                    case DnsResourceRecordType.DS:
                        continue; //skip DNSSEC records

                    default:
                        DnsResourceRecord newRecord = new DnsResourceRecord(string.Concat(sourceRecord.Name.AsSpan(0, sourceRecord.Name.Length - sourceZoneName.Length), zoneName), sourceRecord.Type, sourceRecord.Class, sourceRecord.TTL, sourceRecord.RDATA);

                        if (sourceRecord.Tag is NSRecordInfo nsInfo)
                        {
                            NSRecordInfo nrInfo = new NSRecordInfo();

                            nrInfo.Disabled = nsInfo.Disabled;
                            nrInfo.Comments = nsInfo.Comments;
                            nrInfo.GlueRecords = nsInfo.GlueRecords;

                            newRecord.Tag = nrInfo;
                        }
                        else if (sourceRecord.Tag is SOARecordInfo soaInfo)
                        {
                            SOARecordInfo nrInfo = new SOARecordInfo();

                            nrInfo.Disabled = soaInfo.Disabled;
                            nrInfo.Comments = soaInfo.Comments;
                            nrInfo.UseSoaSerialDateScheme = soaInfo.UseSoaSerialDateScheme;

                            newRecord.Tag = nrInfo;
                        }
                        else if (sourceRecord.Tag is SVCBRecordInfo svcbInfo)
                        {
                            SVCBRecordInfo nrInfo = new SVCBRecordInfo();

                            nrInfo.Disabled = svcbInfo.Disabled;
                            nrInfo.Comments = svcbInfo.Comments;
                            nrInfo.AutoIpv4Hint = svcbInfo.AutoIpv4Hint;
                            nrInfo.AutoIpv6Hint = svcbInfo.AutoIpv6Hint;

                            newRecord.Tag = nrInfo;
                        }
                        else if (sourceRecord.Tag is GenericRecordInfo srInfo)
                        {
                            GenericRecordInfo nrInfo = new GenericRecordInfo();

                            nrInfo.Disabled = srInfo.Disabled;
                            nrInfo.Comments = srInfo.Comments;

                            newRecord.Tag = nrInfo;
                        }

                        newRecords.Add(newRecord);
                        break;
                }
            }

            //load and init zone
            LoadAndInitZone(zoneInfo, newRecords);

            //save zone file
            SaveZoneFile(zoneInfo.Name);

            return zoneInfo;
        }

        public AuthZoneInfo ConvertZoneTypeTo(string zoneName, AuthZoneType newType)
        {
            AuthZoneInfo currentZoneInfo = GetAuthZoneInfo(zoneName);
            if (currentZoneInfo is null)
                throw new DnsServerException("No such zone was found: " + (zoneName.Length == 0 ? "." : zoneName));

            //validate conversion type
            if (currentZoneInfo.Type == newType)
                throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: the zone is already of the same type.");

            switch (currentZoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    switch (newType)
                    {
                        case AuthZoneType.Forwarder:
                            if (currentZoneInfo.ApexZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned)
                                throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: converting the zone will cause lose of DNSSEC private keys.");

                            break;

                        default:
                            throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: not supported.");
                    }

                    break;

                case AuthZoneType.Secondary:
                case AuthZoneType.SecondaryForwarder:
                case AuthZoneType.SecondaryCatalog:
                    switch (newType)
                    {
                        case AuthZoneType.Primary:
                        case AuthZoneType.Forwarder:
                        case AuthZoneType.Catalog:
                            break;

                        default:
                            throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: not supported.");
                    }

                    break;

                case AuthZoneType.Forwarder:
                    switch (newType)
                    {
                        case AuthZoneType.Primary:
                            break;

                        default:
                            throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: not supported.");
                    }

                    break;

                default:
                    throw new DnsServerException("Cannot convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone: not supported.");
            }

            return ConvertZoneTypeTo(currentZoneInfo, newType);
        }

        private AuthZoneInfo ConvertZoneTypeTo(AuthZoneInfo currentZoneInfo, AuthZoneType newType)
        {
            //read all current records
            List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();
            ListAllZoneRecords(currentZoneInfo.Name, allRecords);

            try
            {
                //delete current zone from auth tree
                DeleteZone(currentZoneInfo, false, true);

                //create new zone
                AuthZoneInfo newZoneInfo;

                switch (newType)
                {
                    case AuthZoneType.Primary:
                        switch (currentZoneInfo.Type)
                        {
                            case AuthZoneType.Secondary:
                                {
                                    //reset SOA metadata and remove DNSSEC records
                                    List<DnsResourceRecord> updateRecords = new List<DnsResourceRecord>(allRecords.Count);

                                    foreach (DnsResourceRecord record in allRecords)
                                    {
                                        switch (record.Type)
                                        {
                                            case DnsResourceRecordType.SOA:
                                                {
                                                    GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();
                                                    record.Tag = null;

                                                    GenericRecordInfo newRecordInfo = record.GetAuthGenericRecordInfo();
                                                    newRecordInfo.Comments = recordInfo.Comments;
                                                }
                                                break;

                                            case DnsResourceRecordType.DNSKEY:
                                            case DnsResourceRecordType.RRSIG:
                                            case DnsResourceRecordType.NSEC:
                                            case DnsResourceRecordType.NSEC3:
                                            case DnsResourceRecordType.NSEC3PARAM:
                                                continue;
                                        }

                                        updateRecords.Add(record);
                                    }

                                    allRecords = updateRecords;
                                }
                                break;

                            case AuthZoneType.Forwarder:
                            case AuthZoneType.SecondaryForwarder:
                                {
                                    //remove all FWD records
                                    List<DnsResourceRecord> updateRecords = new List<DnsResourceRecord>(allRecords.Count);

                                    foreach (DnsResourceRecord record in allRecords)
                                    {
                                        if (record.Type == DnsResourceRecordType.FWD)
                                            continue;

                                        updateRecords.Add(record);
                                    }

                                    allRecords = updateRecords;
                                }
                                break;
                        }

                        newZoneInfo = CreatePrimaryZone(currentZoneInfo.Name);
                        break;

                    case AuthZoneType.Forwarder:
                        switch (currentZoneInfo.Type)
                        {
                            case AuthZoneType.Primary:
                            case AuthZoneType.SecondaryForwarder:
                                {
                                    //remove SOA and NS records
                                    List<DnsResourceRecord> updateRecords = new List<DnsResourceRecord>(allRecords.Count);

                                    foreach (DnsResourceRecord record in allRecords)
                                    {
                                        switch (record.Type)
                                        {
                                            case DnsResourceRecordType.SOA:
                                            case DnsResourceRecordType.NS:
                                                continue;
                                        }

                                        updateRecords.Add(record);
                                    }

                                    allRecords = updateRecords;
                                }
                                break;

                            case AuthZoneType.Secondary:
                                {
                                    //remove SOA, NS and DNSSEC records
                                    List<DnsResourceRecord> updateRecords = new List<DnsResourceRecord>(allRecords.Count);

                                    foreach (DnsResourceRecord record in allRecords)
                                    {
                                        switch (record.Type)
                                        {
                                            case DnsResourceRecordType.SOA:
                                            case DnsResourceRecordType.NS:
                                            case DnsResourceRecordType.DNSKEY:
                                            case DnsResourceRecordType.RRSIG:
                                            case DnsResourceRecordType.NSEC:
                                            case DnsResourceRecordType.NSEC3:
                                            case DnsResourceRecordType.NSEC3PARAM:
                                            case DnsResourceRecordType.DS:
                                                continue;
                                        }

                                        updateRecords.Add(record);
                                    }

                                    allRecords = updateRecords;
                                }
                                break;
                        }

                        newZoneInfo = CreateForwarderZone(currentZoneInfo.Name);
                        break;

                    case AuthZoneType.Catalog:
                        newZoneInfo = CreateCatalogZone(currentZoneInfo.Name);
                        break;

                    default:
                        throw new InvalidOperationException();
                }

                //load and init zone
                LoadAndInitZone(newZoneInfo, allRecords);

                //save zone file
                SaveZoneFile(newZoneInfo.Name);

                //post processing for catalog zones
                if (newType == AuthZoneType.Catalog)
                {
                    //convert all member zones too
                    CatalogZone newCatalogZone = newZoneInfo.ApexZone as CatalogZone;

                    foreach (string memberZoneName in newCatalogZone.GetAllMemberZoneNames())
                    {
                        AuthZoneInfo memberZoneInfo = GetAuthZoneInfo(memberZoneName);
                        if (memberZoneInfo is null)
                            continue;

                        switch (memberZoneInfo.Type)
                        {
                            case AuthZoneType.Secondary:
                                try
                                {
                                    AuthZoneInfo newMemberZoneInfo = ConvertZoneTypeTo(memberZoneInfo, AuthZoneType.Primary);
                                    newMemberZoneInfo.ApexZone.CatalogZoneName = newZoneInfo.Name;

                                    AuthZoneDnssecStatus dnssecStatus = memberZoneInfo.ApexZone.DnssecStatus;
                                    if (dnssecStatus != AuthZoneDnssecStatus.Unsigned)
                                    {
                                        //sign the new primary zone if the secondary zone was signed
                                        SecondaryZone secondaryZone = memberZoneInfo.ApexZone as SecondaryZone;

                                        IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys = secondaryZone.DnssecPrivateKeys;
                                        if (dnssecPrivateKeys is not null)
                                        {
                                            try
                                            {
                                                IReadOnlyList<DnsResourceRecord> existingDnsKeyRecords = secondaryZone.GetRecords(DnsResourceRecordType.DNSKEY);

                                                uint dnsKeyTtl = existingDnsKeyRecords[0].OriginalTtlValue;
                                                bool useNSec3 = dnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3;
                                                ushort iterations = 0;
                                                byte[] salt = [];

                                                if (useNSec3)
                                                {
                                                    IReadOnlyList<DnsResourceRecord> existingNsec3ParamRecord = secondaryZone.GetRecords(DnsResourceRecordType.NSEC3PARAM);
                                                    DnsNSEC3PARAMRecordData nsec3Param = existingNsec3ParamRecord[0].RDATA as DnsNSEC3PARAMRecordData;

                                                    iterations = nsec3Param.Iterations;
                                                    salt = nsec3Param.Salt;
                                                }

                                                PrimaryZone newPrimaryZone = newMemberZoneInfo.ApexZone as PrimaryZone;
                                                newPrimaryZone.SignZone(dnssecPrivateKeys, dnsKeyTtl, useNSec3, iterations, salt);
                                            }
                                            catch (Exception ex)
                                            {
                                                _dnsServer.LogManager.Write(ex);
                                            }
                                        }
                                    }

                                    SaveZoneFile(newMemberZoneInfo.Name);
                                }
                                catch
                                {
                                    //ignore errors since they were already logged
                                }
                                break;

                            case AuthZoneType.SecondaryForwarder:
                                try
                                {
                                    AuthZoneInfo newMemberZoneInfo = ConvertZoneTypeTo(memberZoneInfo, AuthZoneType.Forwarder);
                                    newMemberZoneInfo.ApexZone.CatalogZoneName = newZoneInfo.Name;

                                    SaveZoneFile(newMemberZoneInfo.Name);
                                }
                                catch
                                {
                                    //ignore errors since they were already logged
                                }
                                break;
                        }
                    }
                }

                return newZoneInfo;
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server failed to convert the zone '" + currentZoneInfo.DisplayName + "' from " + currentZoneInfo.TypeName + " to " + AuthZoneInfo.GetZoneTypeName(newType) + " zone.\r\n" + ex.ToString());

                //delete the zone if it was created
                DeleteZone(currentZoneInfo);

                //reload old zone file
                string zoneFile = Path.Combine(_dnsServer.ConfigFolder, "zones", currentZoneInfo.Name + ".zone");

                _zoneIndexLock.EnterWriteLock();
                try
                {
                    using (FileStream fS = new FileStream(zoneFile, FileMode.Open, FileAccess.Read))
                    {
                        AuthZoneInfo zoneInfo = LoadZoneFrom(fS, File.GetLastWriteTimeUtc(fS.SafeFileHandle));
                        _zoneIndex.Add(zoneInfo);
                        _zoneIndex.Sort();
                    }

                    _dnsServer.LogManager.Write("DNS Server successfully loaded zone file: " + zoneFile);
                }
                catch (Exception ex2)
                {
                    _dnsServer.LogManager.Write("DNS Server failed to load zone file: " + zoneFile + "\r\n" + ex2.ToString());
                }
                finally
                {
                    _zoneIndexLock.ExitWriteLock();
                }

                throw;
            }
        }

        #endregion

        #region catalog member zones

        public void AddCatalogMemberZone(string catalogZoneName, AuthZoneInfo memberZoneInfo, bool ignoreValidationErrors = false)
        {
            switch (memberZoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Stub:
                case AuthZoneType.Forwarder:
                    if (!ignoreValidationErrors)
                    {
                        string currentCatalogZoneName = memberZoneInfo.ApexZone.CatalogZoneName;
                        if (currentCatalogZoneName is not null)
                            throw new DnsServerException("The zone '" + memberZoneInfo.DisplayName + "' is already a member of Catalog zone '" + currentCatalogZoneName + "'.");
                    }

                    ApexZone apexZone = _root.GetApexZone(catalogZoneName);
                    if (apexZone is not CatalogZone catalogZone)
                    {
                        if (ignoreValidationErrors)
                            return;

                        throw new DnsServerException("No such Catalog zone was found: " + catalogZoneName);
                    }

                    catalogZone.AddMemberZone(memberZoneInfo.Name, memberZoneInfo.Type);
                    memberZoneInfo.ApexZone.CatalogZoneName = catalogZone.Name;

                    //update properties in catalog zone by settings member zone property values again
                    switch (memberZoneInfo.Type)
                    {
                        case AuthZoneType.Primary:
                            memberZoneInfo.QueryAccess = memberZoneInfo.QueryAccess;
                            memberZoneInfo.ZoneTransfer = memberZoneInfo.ZoneTransfer;
                            memberZoneInfo.ZoneTransferTsigKeyNames = memberZoneInfo.ZoneTransferTsigKeyNames;
                            break;

                        case AuthZoneType.Stub:
                            memberZoneInfo.PrimaryNameServerAddresses = memberZoneInfo.PrimaryNameServerAddresses;
                            memberZoneInfo.QueryAccess = memberZoneInfo.QueryAccess;
                            break;

                        case AuthZoneType.Forwarder:
                            memberZoneInfo.QueryAccess = memberZoneInfo.QueryAccess;
                            break;
                    }

                    SaveZoneFile(catalogZoneName);
                    break;

                default:
                    throw new NotSupportedException();
            }
        }

        public void RemoveCatalogMemberZone(AuthZoneInfo memberZoneInfo)
        {
            switch (memberZoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Stub:
                case AuthZoneType.Forwarder:
                case AuthZoneType.Secondary:
                case AuthZoneType.SecondaryForwarder:
                    string catalogZoneName = memberZoneInfo.ApexZone.CatalogZoneName;
                    if (catalogZoneName is null)
                        return;

                    memberZoneInfo.ApexZone.CatalogZone?.RemoveMemberZone(memberZoneInfo.Name);

                    memberZoneInfo.ApexZone.CatalogZoneName = null;
                    SaveZoneFile(catalogZoneName);
                    break;

                default:
                    throw new NotSupportedException();
            }
        }

        public void ChangeCatalogMemberZoneOwnership(AuthZoneInfo memberZoneInfo, string newCatalogZoneName)
        {
            switch (memberZoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Stub:
                case AuthZoneType.Forwarder:
                    string currentCatalogZoneName = memberZoneInfo.ApexZone.CatalogZoneName;
                    if (currentCatalogZoneName is null)
                        throw new DnsServerException("The zone '" + memberZoneInfo.DisplayName + "' is not a member of any Catalog zone.");

                    AddCatalogMemberZone(newCatalogZoneName, memberZoneInfo, true);

                    ApexZone apexZone = _root.GetApexZone(currentCatalogZoneName);
                    if (apexZone is CatalogZone currentCatalogZone)
                        currentCatalogZone.ChangeMemberZoneOwnership(memberZoneInfo.Name, newCatalogZoneName);

                    SaveZoneFile(currentCatalogZoneName);
                    break;

                default:
                    throw new NotSupportedException();
            }
        }

        #endregion

        #region DNSSEC

        public void SignPrimaryZone(string zoneName, DnssecPrivateKey kskPrivateKey, DnssecPrivateKey zskPrivateKey, uint dnsKeyTtl, bool useNSec3, ushort iterations = 0, byte saltLength = 0)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.SignZone(kskPrivateKey, zskPrivateKey, dnsKeyTtl, useNSec3, iterations, saltLength);

            SaveZoneFile(primaryZone.Name);
        }

        public void UnsignPrimaryZone(string zoneName)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.UnsignZone();

            SaveZoneFile(primaryZone.Name);
        }

        public void ConvertPrimaryZoneToNSEC(string zoneName)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.ConvertToNSec();

            SaveZoneFile(primaryZone.Name);
        }

        public void ConvertPrimaryZoneToNSEC3(string zoneName, ushort iterations, byte saltLength)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.ConvertToNSec3(iterations, saltLength);

            SaveZoneFile(primaryZone.Name);
        }

        public void UpdatePrimaryZoneNSEC3Parameters(string zoneName, ushort iterations, byte saltLength)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.UpdateNSec3Parameters(iterations, saltLength);

            SaveZoneFile(primaryZone.Name);
        }

        public void UpdatePrimaryZoneDnsKeyTtl(string zoneName, uint dnsKeyTtl)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.UpdateDnsKeyTtl(dnsKeyTtl);

            SaveZoneFile(primaryZone.Name);
        }

        public DnssecPrivateKey GenerateAndAddPrimaryZoneDnssecPrivateKey(string zoneName, DnssecPrivateKeyType keyType, DnssecAlgorithm algorithm, ushort rolloverDays, int keySize = -1)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            DnssecPrivateKey privateKey = primaryZone.GenerateAndAddPrivateKey(keyType, algorithm, rolloverDays, keySize);

            SaveZoneFile(primaryZone.Name);

            return privateKey;
        }

        public void AddPrimaryZoneDnssecPrivateKey(string zoneName, DnssecPrivateKey privateKey)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.AddPrivateKey(privateKey);

            SaveZoneFile(primaryZone.Name);
        }

        public DnssecPrivateKey UpdatePrimaryZoneDnssecPrivateKey(string zoneName, ushort keyTag, ushort rolloverDays)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            DnssecPrivateKey privateKey = primaryZone.UpdatePrivateKey(keyTag, rolloverDays);

            SaveZoneFile(primaryZone.Name);

            return privateKey;
        }

        public void DeletePrimaryZoneDnssecPrivateKey(string zoneName, ushort keyTag)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.DeletePrivateKey(keyTag);

            SaveZoneFile(primaryZone.Name);
        }

        public void PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(string zoneName)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.PublishAllGeneratedKeys();

            SaveZoneFile(primaryZone.Name);
        }

        public void RolloverPrimaryZoneDnsKey(string zoneName, ushort keyTag)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            primaryZone.RolloverDnsKey(keyTag);

            SaveZoneFile(primaryZone.Name);
        }

        public async Task RetirePrimaryZoneDnsKeyAsync(string zoneName, ushort keyTag)
        {
            if (!_root.TryGet(zoneName, out ApexZone apexZone) || (apexZone is not PrimaryZone primaryZone) || primaryZone.Internal)
                throw new DnsServerException("No such primary zone was found: " + zoneName);

            await primaryZone.RetireDnsKeyAsync(keyTag);

            SaveZoneFile(primaryZone.Name);
        }

        public void LoadTrustAnchorsTo(DnsClient dnsClient, string domain, DnsResourceRecordType type)
        {
            if (type == DnsResourceRecordType.DS)
            {
                domain = GetParentZone(domain);
                if (domain is null)
                    domain = "";
            }

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.FindAuthZoneInfo(domain, false);
            if ((zoneInfo is not null) && (zoneInfo.ApexZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned))
            {
                IReadOnlyList<DnsResourceRecord> dnsKeyRecords = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.DNSKEY);
                List<DnsResourceRecord> dsRecords = new List<DnsResourceRecord>(dnsKeyRecords.Count);

                foreach (DnsResourceRecord dnsKeyRecord in dnsKeyRecords)
                {
                    DnsDNSKEYRecordData dnsKey = dnsKeyRecord.RDATA as DnsDNSKEYRecordData;

                    if (dnsKey.Flags.HasFlag(DnsDnsKeyFlag.SecureEntryPoint) && !dnsKey.Flags.HasFlag(DnsDnsKeyFlag.Revoke))
                        dsRecords.Add(new DnsResourceRecord(dnsKeyRecord.Name, DnsResourceRecordType.DS, DnsClass.IN, 0, dnsKey.CreateDS(dnsKeyRecord.Name, DnssecDigestType.SHA256)));
                }

                //set trust anchor
                dnsClient.TrustAnchors[zoneInfo.Name] = dsRecords;
            }
        }

        #endregion

        #region zone listing

        public IEnumerable<AuthZoneInfo> EnumerateAllZones()
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                foreach (AuthZoneInfo zoneInfo in _zoneIndex)
                    yield return zoneInfo;
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        public IReadOnlyList<AuthZoneInfo> GetAllZones()
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                return _zoneIndex.ToArray();
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        public IReadOnlyList<AuthZoneInfo> GetZones(Func<AuthZoneInfo, bool> predicate)
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                List<AuthZoneInfo> zoneInfoList = new List<AuthZoneInfo>();

                foreach (AuthZoneInfo zoneInfo in _zoneIndex)
                {
                    if (predicate(zoneInfo))
                        zoneInfoList.Add(zoneInfo);
                }

                return zoneInfoList;
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        public IReadOnlyList<AuthZoneInfo> GetAllCatalogZones()
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                return _catalogZoneIndex.ToArray();
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        public IReadOnlyList<AuthZoneInfo> GetCatalogZones(Func<AuthZoneInfo, bool> predicate)
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                List<AuthZoneInfo> catalogZoneInfoList = new List<AuthZoneInfo>();

                foreach (AuthZoneInfo zone in _catalogZoneIndex)
                {
                    if (predicate(zone))
                        catalogZoneInfoList.Add(zone);
                }

                return catalogZoneInfoList;
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        #endregion

        #region zone record management

        public void ListAllZoneRecords(string zoneName, List<DnsResourceRecord> records)
        {
            foreach (AuthZone authZone in _root.GetApexZoneWithSubDomainZones(zoneName))
                authZone.ListAllRecords(records);
        }

        public void ListAllZoneRecords(string zoneName, DnsResourceRecordType[] types, List<DnsResourceRecord> records)
        {
            foreach (AuthZone authZone in _root.GetApexZoneWithSubDomainZones(zoneName))
            {
                foreach (DnsResourceRecordType type in types)
                    records.AddRange(authZone.GetRecords(type));
            }
        }

        public void ListAllRecords(string zoneName, string domain, List<DnsResourceRecord> records)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (_root.TryGet(zoneName, domain, out AuthZone authZone))
                authZone.ListAllRecords(records);
        }

        public IEnumerable<DnsResourceRecord> EnumerateAllRecords(string zoneName, string domain, bool includeAllSubDomainNames = false)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (includeAllSubDomainNames)
            {
                foreach (AuthZone authZone in _root.GetSubDomainZoneWithSubDomainZones(domain))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in authZone.Entries)
                    {
                        foreach (DnsResourceRecord record in entry.Value)
                            yield return record;
                    }
                }
            }
            else
            {
                if (_root.TryGet(zoneName, domain, out AuthZone authZone))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in authZone.Entries)
                    {
                        foreach (DnsResourceRecord record in entry.Value)
                            yield return record;
                    }
                }
            }
        }

        public IReadOnlyList<DnsResourceRecord> GetRecords(string zoneName, string domain, DnsResourceRecordType type)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (_root.TryGet(zoneName, domain, out AuthZone authZone))
                return authZone.GetRecords(type);

            return Array.Empty<DnsResourceRecord>();
        }

        public IReadOnlyDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> GetEntriesFor(string zoneName, string domain)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (_root.TryGet(zoneName, domain, out AuthZone authZone))
                return authZone.Entries;

            return new Dictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(1);
        }

        public void SetRecords(string zoneName, IReadOnlyList<DnsResourceRecord> records)
        {
            for (int i = 1; i < records.Count; i++)
            {
                if (!records[i].Name.Equals(records[0].Name, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                if (records[i].Type != records[0].Type)
                    throw new InvalidOperationException();

                if (records[i].Class != records[0].Class)
                    throw new InvalidOperationException();
            }

            AuthZone authZone = GetOrAddSubDomainZone(zoneName, records[0].Name);

            authZone.SetRecords(records[0].Type, records);

            if (authZone is SubDomainZone subDomainZone)
                subDomainZone.AutoUpdateState();
        }

        public void SetRecord(string zoneName, DnsResourceRecord record)
        {
            ValidateIfDomainBelongsToZone(zoneName, record.Name);

            AuthZone authZone = GetOrAddSubDomainZone(zoneName, record.Name);

            authZone.SetRecords(record.Type, new DnsResourceRecord[] { record });

            if (authZone is SubDomainZone subDomainZone)
                subDomainZone.AutoUpdateState();
        }

        public bool AddRecord(string zoneName, DnsResourceRecord record)
        {
            ValidateIfDomainBelongsToZone(zoneName, record.Name);

            AuthZone authZone = GetOrAddSubDomainZone(zoneName, record.Name);

            if (authZone.AddRecord(record))
            {
                if (authZone is SubDomainZone subDomainZone)
                    subDomainZone.AutoUpdateState();

                return true;
            }

            return false;
        }

        public void UpdateRecord(string zoneName, DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            ValidateIfDomainBelongsToZone(zoneName, oldRecord.Name);
            ValidateIfDomainBelongsToZone(zoneName, newRecord.Name);

            if (oldRecord.Type != newRecord.Type)
                throw new DnsServerException("Cannot update record: new record must be of same type.");

            if (oldRecord.Type == DnsResourceRecordType.SOA)
                throw new DnsServerException("Cannot update record: use SetRecords() for updating SOA record.");

            if (!_root.TryGet(zoneName, oldRecord.Name, out AuthZone authZone))
                throw new DnsServerException("Cannot update record: zone '" + zoneName + "' does not exists.");

            switch (oldRecord.Type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.DNAME:
                case DnsResourceRecordType.APP:
                    if (oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        authZone.SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });

                        if (authZone is SubDomainZone subDomainZone)
                            subDomainZone.AutoUpdateState();
                    }
                    else
                    {
                        authZone.DeleteRecords(oldRecord.Type);

                        if (authZone is SubDomainZone subDomainZone)
                        {
                            if (authZone.IsEmpty)
                                _root.TryRemove(oldRecord.Name, out SubDomainZone _); //remove empty sub zone
                            else
                                subDomainZone.AutoUpdateState();
                        }

                        AuthZone newZone = GetOrAddSubDomainZone(zoneName, newRecord.Name);

                        newZone.SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });

                        if (newZone is SubDomainZone subDomainZone1)
                            subDomainZone1.AutoUpdateState();
                    }
                    break;

                default:
                    if (oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        authZone.UpdateRecord(oldRecord, newRecord);

                        if (authZone is SubDomainZone subDomainZone)
                            subDomainZone.AutoUpdateState();
                    }
                    else
                    {
                        if (!authZone.DeleteRecord(oldRecord.Type, oldRecord.RDATA))
                            throw new DnsWebServiceException("Cannot update record: the old record does not exists.");

                        if (authZone is SubDomainZone subDomainZone)
                        {
                            if (authZone.IsEmpty)
                                _root.TryRemove(oldRecord.Name, out SubDomainZone _); //remove empty sub zone
                            else
                                subDomainZone.AutoUpdateState();
                        }

                        AuthZone newZone = GetOrAddSubDomainZone(zoneName, newRecord.Name);

                        newZone.AddRecord(newRecord);

                        if (newZone is SubDomainZone subDomainZone1)
                            subDomainZone1.AutoUpdateState();
                    }
                    break;
            }
        }

        public bool DeleteRecord(string zoneName, DnsResourceRecord record)
        {
            return DeleteRecord(zoneName, record.Name, record.Type, record.RDATA);
        }

        public bool DeleteRecord(string zoneName, string domain, DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (_root.TryGet(zoneName, domain, out AuthZone authZone))
            {
                if (authZone.DeleteRecord(type, rdata))
                {
                    if (authZone is SubDomainZone subDomainZone)
                    {
                        if (authZone.IsEmpty)
                            _root.TryRemove(domain, out SubDomainZone _); //remove empty sub zone
                        else
                            subDomainZone.AutoUpdateState();
                    }

                    return true;
                }
            }

            return false;
        }

        public bool DeleteRecords(string zoneName, string domain, DnsResourceRecordType type)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (_root.TryGet(zoneName, domain, out AuthZone authZone))
            {
                if (authZone.DeleteRecords(type))
                {
                    if (authZone is SubDomainZone subDomainZone)
                    {
                        if (authZone.IsEmpty)
                            _root.TryRemove(domain, out SubDomainZone _); //remove empty sub zone
                        else
                            subDomainZone.AutoUpdateState();
                    }

                    return true;
                }
            }

            return false;
        }

        #endregion

        #region zone transfer / import

        public IReadOnlyList<DnsResourceRecord> QueryZoneTransferRecords(string zoneName)
        {
            AuthZoneInfo zoneInfo = GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new InvalidOperationException("Zone was not found: " + zoneName);

            //primary, secondary, and forwarder zones support zone transfer
            IReadOnlyList<DnsResourceRecord> soaRecords = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.SOA);
            if (soaRecords.Count != 1)
                throw new InvalidOperationException("Zone must be a primary, secondary, or forwarder zone.");

            DnsResourceRecord soaRecord = soaRecords[0];

            List<DnsResourceRecord> records = new List<DnsResourceRecord>();
            ListAllZoneRecords(zoneName, records);

            List<DnsResourceRecord> xfrRecords = new List<DnsResourceRecord>(records.Count + 1);

            //start message
            xfrRecords.Add(soaRecord);

            foreach (DnsResourceRecord record in records)
            {
                GenericRecordInfo authRecordInfo = record.GetAuthGenericRecordInfo();
                if (authRecordInfo.Disabled)
                    continue;

                switch (record.Type)
                {
                    case DnsResourceRecordType.SOA:
                        break; //skip record

                    case DnsResourceRecordType.NS:
                        xfrRecords.Add(record);

                        IReadOnlyList<DnsResourceRecord> glueRecords = (authRecordInfo as NSRecordInfo).GlueRecords;
                        if (glueRecords is not null)
                        {
                            foreach (DnsResourceRecord glueRecord in glueRecords)
                                xfrRecords.Add(glueRecord);
                        }
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

        public IReadOnlyList<DnsResourceRecord> QueryIncrementalZoneTransferRecords(string zoneName, DnsResourceRecord clientSoaRecord)
        {
            AuthZoneInfo authZone = GetAuthZoneInfo(zoneName, true);
            if (authZone is null)
                throw new InvalidOperationException("Zone was not found: " + zoneName);

            //primary, secondary, forwarder, and catalog zones support zone transfer
            IReadOnlyList<DnsResourceRecord> soaRecords = authZone.ApexZone.GetRecords(DnsResourceRecordType.SOA);
            if (soaRecords.Count != 1)
                throw new InvalidOperationException("No SOA record was found for IXFR.");

            DnsResourceRecord currentSoaRecord = soaRecords[0];
            uint clientSerial = (clientSoaRecord.RDATA as DnsSOARecordData).Serial;

            if (clientSerial == (currentSoaRecord.RDATA as DnsSOARecordData).Serial)
            {
                //zone not modified
                return [currentSoaRecord];
            }

            //find history record start from client serial
            IReadOnlyList<DnsResourceRecord> zoneHistory = authZone.ZoneHistory;

            int index = 0;
            while (index < zoneHistory.Count)
            {
                //check difference sequence
                if ((zoneHistory[index].RDATA as DnsSOARecordData).Serial == clientSerial)
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
                return QueryZoneTransferRecords(zoneName);
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
            return CondenseIncrementalZoneTransferRecords(zoneName, clientSoaRecord, xfrRecords);
        }

        public void SyncZoneTransferRecords(string zoneName, IReadOnlyList<DnsResourceRecord> xfrRecords)
        {
            if ((xfrRecords.Count < 2) || (xfrRecords[0].Type != DnsResourceRecordType.SOA) || !xfrRecords[0].Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || !xfrRecords[xfrRecords.Count - 1].Equals(xfrRecords[0]))
                throw new DnsServerException("Invalid AXFR response was received.");

            List<DnsResourceRecord> latestRecords = new List<DnsResourceRecord>(xfrRecords.Count);
            List<DnsResourceRecord> allGlueRecords = new List<DnsResourceRecord>(4);

            if (zoneName.Length == 0)
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

                    if (record.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase))
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
            ListAllZoneRecords(zoneName, currentRecords);

            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> currentRecordsGroupedByDomain = DnsResourceRecord.GroupRecords(currentRecords);
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> latestRecordsGroupedByDomain = DnsResourceRecord.GroupRecords(latestRecords);

            //remove domains that do not exists in new records
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> currentDomain in currentRecordsGroupedByDomain)
            {
                if (!latestRecordsGroupedByDomain.ContainsKey(currentDomain.Key))
                    _root.TryRemove(currentDomain.Key, out SubDomainZone _);
            }

            //sync new records
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> latestEntries in latestRecordsGroupedByDomain)
            {
                AuthZone zone = GetOrAddSubDomainZone(zoneName, latestEntries.Key);

                if (zone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    zone.SyncRecords(latestEntries.Value);
                else if ((zone is SubDomainZone subDomainZone) && subDomainZone.AuthoritativeZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    zone.SyncRecords(latestEntries.Value);
            }

            if (!_root.TryGet(zoneName, out ApexZone apexZone))
                throw new InvalidOperationException();

            apexZone.UpdateDnssecStatus();

            SaveZoneFile(apexZone.Name);
        }

        public IReadOnlyList<DnsResourceRecord> SyncIncrementalZoneTransferRecords(string zoneName, IReadOnlyList<DnsResourceRecord> xfrRecords)
        {
            if ((xfrRecords.Count < 2) || (xfrRecords[0].Type != DnsResourceRecordType.SOA) || !xfrRecords[0].Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || !xfrRecords[xfrRecords.Count - 1].Equals(xfrRecords[0]))
                throw new DnsServerException("Invalid IXFR/AXFR response was received.");

            if ((xfrRecords.Count < 4) || (xfrRecords[1].Type != DnsResourceRecordType.SOA))
            {
                //received AXFR response
                SyncZoneTransferRecords(zoneName, xfrRecords);
                return Array.Empty<DnsResourceRecord>();
            }

            if (!_root.TryGet(zoneName, out ApexZone apexZone))
                throw new InvalidOperationException("No such zone was found: " + zoneName);

            IReadOnlyList<DnsResourceRecord> soaRecords = apexZone.GetRecords(DnsResourceRecordType.SOA);
            if (soaRecords.Count != 1)
                throw new InvalidOperationException("No authoritative zone was found: " + zoneName);

            //process IXFR response
            DnsResourceRecord currentSoaRecord = soaRecords[0];
            DnsSOARecordData currentSoa = currentSoaRecord.RDATA as DnsSOARecordData;

            List<DnsResourceRecord> condensedXfrRecords = CondenseIncrementalZoneTransferRecords(zoneName, currentSoaRecord, xfrRecords);

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
                if ((deletedSoaRecord.Type != DnsResourceRecordType.SOA) || !deletedSoaRecord.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = condensedXfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (zoneName.Length == 0)
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
                        if (record.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase))
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
                if (!addedSoaRecord.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = condensedXfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (zoneName.Length == 0)
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
                        if (record.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase))
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
                DnsSOARecordData deletedSoa = deletedSoaRecord.RDATA as DnsSOARecordData;

                if (currentSoa.Serial != deletedSoa.Serial)
                    throw new InvalidOperationException("Current SOA serial does not match with the IXFR difference sequence deleted SOA.");

                //sync difference sequence
                if (deletedRecords.Count > 0)
                {
                    foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> deletedEntry in DnsResourceRecord.GroupRecords(deletedRecords))
                    {
                        AuthZone zone = GetOrAddSubDomainZone(zoneName, deletedEntry.Key);

                        if (zone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                        {
                            zone.SyncRecords(deletedEntry.Value, null);
                        }
                        else if ((zone is SubDomainZone subDomainZone) && subDomainZone.AuthoritativeZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                        {
                            zone.SyncRecords(deletedEntry.Value, null);

                            if (zone.IsEmpty)
                                _root.TryRemove(deletedEntry.Key, out SubDomainZone _); //remove empty sub zone
                        }
                    }
                }

                if (addedRecords.Count > 0)
                {
                    foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> addedEntry in DnsResourceRecord.GroupRecords(addedRecords))
                    {
                        AuthZone zone = GetOrAddSubDomainZone(zoneName, addedEntry.Key);

                        if (zone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                            zone.SyncRecords(null, addedEntry.Value);
                        else if ((zone is SubDomainZone subDomainZone) && subDomainZone.AuthoritativeZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                            zone.SyncRecords(null, addedEntry.Value);
                    }
                }

                if ((deletedGlueRecords.Count > 0) || (addedGlueRecords.Count > 0))
                {
                    foreach (AuthZone zone in _root.GetApexZoneWithSubDomainZones(zoneName))
                        zone.SyncGlueRecords(deletedGlueRecords, addedGlueRecords);
                }

                {
                    AuthZone zone = GetOrAddSubDomainZone(zoneName, zoneName);

                    addedSoaRecord.CopyRecordInfoFrom(currentSoaRecord);

                    zone.LoadRecords(DnsResourceRecordType.SOA, new DnsResourceRecord[] { addedSoaRecord });
                }

                //check next difference sequence
                currentSoa = addedSoaRecord.RDATA as DnsSOARecordData;

                deletedRecords.Clear();
                deletedGlueRecords.Clear();
                addedRecords.Clear();
                addedGlueRecords.Clear();
            }

            apexZone.UpdateDnssecStatus();

            SaveZoneFile(apexZone.Name);

            //return history
            List<DnsResourceRecord> historyRecords = new List<DnsResourceRecord>(xfrRecords.Count - 2);

            for (int i = 1; i < xfrRecords.Count - 1; i++)
                historyRecords.Add(xfrRecords[i]);

            return historyRecords;
        }

        private static List<DnsResourceRecord> CondenseIncrementalZoneTransferRecords(string zoneName, DnsResourceRecord currentSoaRecord, IReadOnlyList<DnsResourceRecord> xfrRecords)
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
            DnsSOARecordData currentSoa = (DnsSOARecordData)currentSoaRecord.RDATA;

            while (index < count)
            {
                //read deleted records
                DnsResourceRecord deletedSoaRecord = xfrRecords[index];
                if ((deletedSoaRecord.Type != DnsResourceRecordType.SOA) || !deletedSoaRecord.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                if (firstDeletedSoaRecord is null)
                    firstDeletedSoaRecord = deletedSoaRecord;

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = xfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (zoneName.Length == 0)
                    {
                        //root zone case
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                if (!addedGlueRecords.Remove(record))
                                    deletedGlueRecords.Add(record);

                                break;

                            default:
                                if (!addedRecords.Remove(record))
                                    deletedRecords.Add(record);

                                break;
                        }
                    }
                    else
                    {
                        if (record.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase))
                        {
                            if (!addedRecords.Remove(record))
                                deletedRecords.Add(record);
                        }
                        else
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                case DnsResourceRecordType.AAAA:
                                    if (!addedGlueRecords.Remove(record))
                                        deletedGlueRecords.Add(record);

                                    break;
                            }
                        }
                    }

                    index++;
                }

                //read added records
                DnsResourceRecord addedSoaRecord = xfrRecords[index];
                if (!addedSoaRecord.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                lastAddedSoaRecord = addedSoaRecord;

                index++;

                while (index < count)
                {
                    DnsResourceRecord record = xfrRecords[index];
                    if (record.Type == DnsResourceRecordType.SOA)
                        break;

                    if (zoneName.Length == 0)
                    {
                        //root zone case
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                if (!deletedGlueRecords.Remove(record))
                                    addedGlueRecords.Add(record);

                                break;

                            default:
                                if (!deletedRecords.Remove(record))
                                    addedRecords.Add(record);

                                break;
                        }
                    }
                    else
                    {
                        if (record.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase))
                        {
                            if (!deletedRecords.Remove(record))
                                addedRecords.Add(record);
                        }
                        else
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                case DnsResourceRecordType.AAAA:
                                    if (!deletedGlueRecords.Remove(record))
                                        addedGlueRecords.Add(record);

                                    break;
                            }
                        }
                    }

                    index++;
                }

                //check sequence soa serial
                DnsSOARecordData deletedSoa = deletedSoaRecord.RDATA as DnsSOARecordData;

                if (currentSoa.Serial != deletedSoa.Serial)
                    throw new InvalidOperationException("Current SOA serial does not match with the IXFR difference sequence deleted SOA.");

                //check next difference sequence
                currentSoa = addedSoaRecord.RDATA as DnsSOARecordData;
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

        internal void ImportRecords(string zoneName, IReadOnlyList<DnsResourceRecord> records, bool overwrite, bool overwriteSoaSerial)
        {
            _ = _root.FindZone(zoneName, out _, out _, out ApexZone apexZone, out _);
            if ((apexZone is null) || !apexZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                throw new DnsServerException("No such zone was found: " + zoneName);

            if ((apexZone is not PrimaryZone) && (apexZone is not ForwarderZone))
                throw new DnsServerException("Zone must be a primary or forwarder type: " + apexZone.ToString());

            List<DnsResourceRecord> soaRRSet = null;

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> zoneEntry in DnsResourceRecord.GroupRecords(records))
            {
                if (zoneName.Equals(zoneEntry.Key, StringComparison.OrdinalIgnoreCase))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                    {
                        switch (rrsetEntry.Key)
                        {
                            case DnsResourceRecordType.CNAME:
                            case DnsResourceRecordType.DNAME:
                                apexZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                                break;

                            case DnsResourceRecordType.SOA:
                                if (!overwriteSoaSerial)
                                    rrsetEntry.Value[0].GetAuthSOARecordInfo().UseSoaSerialDateScheme = apexZone.GetRecords(DnsResourceRecordType.SOA)[0].GetAuthSOARecordInfo().UseSoaSerialDateScheme;

                                apexZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                                soaRRSet = rrsetEntry.Value;
                                break;

                            default:
                                if (overwrite)
                                {
                                    apexZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                                }
                                else
                                {
                                    foreach (DnsResourceRecord record in rrsetEntry.Value)
                                        apexZone.AddRecord(record);
                                }
                                break;
                        }
                    }
                }
                else
                {
                    ValidateIfDomainBelongsToZone(zoneName, zoneEntry.Key);

                    AuthZone authZone = GetOrAddSubDomainZone(zoneName, zoneEntry.Key);

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                    {
                        switch (rrsetEntry.Key)
                        {
                            case DnsResourceRecordType.CNAME:
                            case DnsResourceRecordType.DNAME:
                            case DnsResourceRecordType.SOA:
                                authZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                                break;

                            default:
                                if (overwrite)
                                {
                                    authZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                                }
                                else
                                {
                                    foreach (DnsResourceRecord record in rrsetEntry.Value)
                                        authZone.AddRecord(record);
                                }
                                break;
                        }
                    }

                    if (authZone is SubDomainZone subDomainZone)
                        subDomainZone.AutoUpdateState();
                }
            }

            if (overwriteSoaSerial && (soaRRSet is not null) && ((apexZone is PrimaryZone) || (apexZone is ForwarderZone)))
                apexZone.SetSoaSerial((soaRRSet[0].RDATA as DnsSOARecordData).Serial);

            SaveZoneFile(apexZone.Name);
        }

        #endregion

        #region query processing

        public DnsDatagram QueryClosestDelegation(DnsDatagram request)
        {
            _ = _root.FindZone(request.Question[0].Name, out _, out SubDomainZone delegation, out ApexZone apexZone, out _);
            if (delegation is not null)
            {
                bool dnssecOk = request.DnssecOk && (apexZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned);

                return GetReferralResponse(request, dnssecOk, delegation, apexZone);
            }

            if (apexZone is StubZone)
                return GetReferralResponse(request, false, apexZone, apexZone);

            //no delegation found
            return null;
        }

        public async Task<DnsDatagram> QueryAsync(DnsDatagram request, IPAddress remoteIP, bool isRecursionAllowed)
        {
            AuthZone zone = _root.FindZone(request.Question[0].Name, out SubDomainZone closest, out SubDomainZone delegation, out ApexZone apexZone, out bool hasSubDomains);

            if ((apexZone is null) || !apexZone.IsActive)
                return null; //no authority for requested zone

            if (!await IsQueryAllowedAsync(apexZone, remoteIP))
                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Question);

            return InternalQuery(request, isRecursionAllowed, zone, closest, delegation, apexZone, hasSubDomains);
        }

        public DnsDatagram Query(DnsDatagram request, bool isRecursionAllowed)
        {
            AuthZone zone = _root.FindZone(request.Question[0].Name, out SubDomainZone closest, out SubDomainZone delegation, out ApexZone apexZone, out bool hasSubDomains);

            if ((apexZone is null) || !apexZone.IsActive)
                return null; //no authority for requested zone

            return InternalQuery(request, isRecursionAllowed, zone, closest, delegation, apexZone, hasSubDomains);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private DnsDatagram InternalQuery(DnsDatagram request, bool isRecursionAllowed, AuthZone zone, SubDomainZone closest, SubDomainZone delegation, ApexZone apexZone, bool hasSubDomains)
        {
            DnsQuestionRecord question = request.Question[0];
            bool dnssecOk = request.DnssecOk && (apexZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned);

            if ((zone is null) || !zone.IsActive)
            {
                //zone not found
                if ((delegation is not null) && delegation.IsActive && (delegation.Name.Length > apexZone.Name.Length))
                    return GetReferralResponse(request, dnssecOk, delegation, apexZone);

                if (apexZone is StubZone)
                    return GetReferralResponse(request, false, apexZone, apexZone);

                DnsResponseCode rCode = DnsResponseCode.NoError;
                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;

                if (closest is not null)
                {
                    answer = closest.QueryRecords(DnsResourceRecordType.DNAME, dnssecOk);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, dnssecOk, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                    else
                    {
                        answer = null;
                        authority = closest.QueryRecords(DnsResourceRecordType.APP, false);
                    }
                }

                if (((answer is null) || (answer.Count == 0)) && ((authority is null) || (authority.Count == 0)))
                {
                    answer = apexZone.QueryRecords(DnsResourceRecordType.DNAME, dnssecOk);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, dnssecOk, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                    else
                    {
                        answer = null;
                        authority = apexZone.QueryRecords(DnsResourceRecordType.APP, false);
                        if (authority.Count == 0)
                        {
                            if ((apexZone is ForwarderZone) || (apexZone is SecondaryForwarderZone))
                                return GetForwarderResponse(request, null, closest, apexZone); //no DNAME or APP record available so process FWD response

                            if (!hasSubDomains)
                                rCode = DnsResponseCode.NxDomain;

                            authority = apexZone.QueryRecords(DnsResourceRecordType.SOA, dnssecOk);

                            if (dnssecOk)
                            {
                                //add proof of non existence (NXDOMAIN) to prove the qname does not exists
                                IReadOnlyList<DnsResourceRecord> nsecRecords;

                                if (apexZone.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3)
                                    nsecRecords = _root.FindNSec3ProofOfNonExistenceNxDomain(question.Name, false);
                                else
                                    nsecRecords = _root.FindNSecProofOfNonExistenceNxDomain(question.Name, false);

                                if (nsecRecords.Count > 0)
                                {
                                    List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(authority.Count + nsecRecords.Count);

                                    newAuthority.AddRange(authority);
                                    newAuthority.AddRange(nsecRecords);

                                    authority = newAuthority;
                                }
                            }
                        }
                    }
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, rCode, request.Question, answer, authority);
            }
            else
            {
                //zone found
                if (question.Type == DnsResourceRecordType.DS)
                {
                    if (zone is ApexZone)
                    {
                        if ((delegation is null) || !delegation.IsActive || !delegation.AuthoritativeZone.IsActive || (delegation.Name.Length > apexZone.Name.Length))
                            return null; //no authoritative parent side delegation zone available to answer for DS

                        zone = delegation; //switch zone to parent side sub domain delegation zone for DS record

                        if (request.DnssecOk)
                            dnssecOk = delegation.AuthoritativeZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned;
                    }
                }
                else if ((delegation is not null) && delegation.IsActive && (delegation.Name.Length > apexZone.Name.Length))
                {
                    //zone is delegation
                    return GetReferralResponse(request, dnssecOk, delegation, apexZone);
                }

                DnsResponseCode rCode = DnsResponseCode.NoError;
                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;
                IReadOnlyList<DnsResourceRecord> additional = null;

                if (closest is not null)
                {
                    answer = closest.QueryRecords(DnsResourceRecordType.DNAME, dnssecOk);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, dnssecOk, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                }

                if (((answer is null) || (answer.Count == 0)) && (question.Name.Length > apexZone.Name.Length))
                {
                    //query for DNAME only for subdomain names
                    answer = apexZone.QueryRecords(DnsResourceRecordType.DNAME, dnssecOk);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, dnssecOk, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                }

                if ((answer is null) || (answer.Count == 0))
                {
                    answer = zone.QueryRecords(question.Type, dnssecOk);
                    if (answer.Count == 0)
                    {
                        //record type not found
                        if (question.Type == DnsResourceRecordType.DS)
                        {
                            //check for correct auth zone
                            if (apexZone.Name.Equals(question.Name, StringComparison.OrdinalIgnoreCase))
                            {
                                //current auth zone is child side; find parent side auth zone for DS
                                string parentZone = GetParentZone(question.Name);
                                if (parentZone is null)
                                    parentZone = string.Empty;

                                _ = _root.FindZone(parentZone, out _, out _, out apexZone, out _);

                                if ((apexZone is null) || !apexZone.IsActive)
                                    return null; //no authority for requested zone
                            }
                        }
                        else
                        {
                            //check for delegation, stub & forwarder
                            if ((delegation is not null) && delegation.IsActive && (delegation.Name.Length > apexZone.Name.Length))
                                return GetReferralResponse(request, dnssecOk, delegation, apexZone);

                            if (apexZone is StubZone)
                                return GetReferralResponse(request, false, apexZone, apexZone);
                        }

                        authority = zone.QueryRecords(DnsResourceRecordType.APP, false);
                        if (authority.Count == 0)
                        {
                            if ((apexZone is ForwarderZone) || (apexZone is SecondaryForwarderZone))
                                return GetForwarderResponse(request, zone, closest, apexZone); //no APP record available so process FWD response

                            authority = apexZone.QueryRecords(DnsResourceRecordType.SOA, dnssecOk);

                            if (dnssecOk)
                            {
                                //add proof of non existence (NODATA) to prove that no such type or record exists
                                IReadOnlyList<DnsResourceRecord> nsecRecords;

                                if (apexZone.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3)
                                    nsecRecords = _root.FindNSec3ProofOfNonExistenceNoData(question.Name, zone, apexZone);
                                else
                                    nsecRecords = _root.FindNSecProofOfNonExistenceNoData(question.Name, zone);

                                if (nsecRecords.Count > 0)
                                {
                                    List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(authority.Count + nsecRecords.Count);

                                    newAuthority.AddRange(authority);
                                    newAuthority.AddRange(nsecRecords);

                                    authority = newAuthority;
                                }
                            }
                        }

                        additional = null;
                    }
                    else
                    {
                        //record type found
                        if (zone.Name.StartsWith('*') && !zone.Name.Equals(question.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            //wildcard zone; generate new answer records
                            DnsResourceRecord[] wildcardAnswers = new DnsResourceRecord[answer.Count];

                            for (int i = 0; i < answer.Count; i++)
                                wildcardAnswers[i] = new DnsResourceRecord(question.Name, answer[i].Type, answer[i].Class, answer[i].TTL, answer[i].RDATA) { Tag = answer[i].Tag };

                            answer = wildcardAnswers;

                            //add proof of non existence (WILDCARD) to prove that the wildcard expansion was legit and the qname actually does not exists
                            if (dnssecOk)
                            {
                                IReadOnlyList<DnsResourceRecord> nsecRecords;

                                if (apexZone.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3)
                                    nsecRecords = _root.FindNSec3ProofOfNonExistenceNxDomain(question.Name, true);
                                else
                                    nsecRecords = _root.FindNSecProofOfNonExistenceNxDomain(question.Name, true);

                                if (nsecRecords.Count > 0)
                                    authority = nsecRecords;
                            }
                        }

                        DnsResourceRecord lastRR = answer[answer.Count - 1];
                        if ((lastRR.Type != question.Type) && (question.Type != DnsResourceRecordType.ANY))
                        {
                            switch (lastRR.Type)
                            {
                                case DnsResourceRecordType.CNAME:
                                    List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(answer.Count + 1);
                                    newAnswers.AddRange(answer);

                                    ResolveCNAME(question, dnssecOk, lastRR, newAnswers);

                                    answer = newAnswers;
                                    break;

                                case DnsResourceRecordType.ANAME:
                                case DnsResourceRecordType.ALIAS:
                                    authority = apexZone.GetRecords(DnsResourceRecordType.SOA); //adding SOA for use with NO DATA response
                                    break;
                            }
                        }

                        switch (question.Type)
                        {
                            case DnsResourceRecordType.NS:
                            case DnsResourceRecordType.MX:
                            case DnsResourceRecordType.SRV:
                            case DnsResourceRecordType.SVCB:
                            case DnsResourceRecordType.HTTPS:
                                additional = GetAdditionalRecords(answer, dnssecOk);
                                break;

                            default:
                                additional = null;
                                break;
                        }
                    }
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, rCode, request.Question, answer, authority, additional);
            }
        }

        private static async Task<bool> IsQueryAllowedAsync(ApexZone apexZone, IPAddress remoteIP)
        {
            async Task<bool> IsZoneNameServerAllowedAsync()
            {
                IReadOnlyList<NameServerAddress> zoneNameServers = await apexZone.GetAllResolvedNameServerAddressesAsync();

                foreach (NameServerAddress nameServer in zoneNameServers)
                {
                    if (nameServer.IPEndPoint.Address.Equals(remoteIP))
                        return true;
                }

                return false;
            }

            CatalogZone catalogZone = apexZone.CatalogZone;
            if (catalogZone is not null)
            {
                if (!apexZone.OverrideCatalogQueryAccess)
                    apexZone = catalogZone; //use catalog query access options
            }
            else
            {
                SecondaryCatalogZone secondaryCatalogZone = apexZone.SecondaryCatalogZone;
                if (secondaryCatalogZone is not null)
                {
                    if (!apexZone.OverrideCatalogQueryAccess)
                        apexZone = secondaryCatalogZone; //use secondary query access options
                }
            }

            switch (apexZone.QueryAccess)
            {
                case AuthZoneQueryAccess.Allow:
                    return true;

                case AuthZoneQueryAccess.AllowOnlyPrivateNetworks:
                    if (IPAddress.IsLoopback(remoteIP) || IPAddress.Any.Equals(remoteIP))
                        return true;

                    switch (remoteIP.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                        case AddressFamily.InterNetworkV6:
                            return NetUtilities.IsPrivateIP(remoteIP);

                        default:
                            return false;
                    }

                case AuthZoneQueryAccess.AllowOnlyZoneNameServers:
                    if (IPAddress.IsLoopback(remoteIP) || IPAddress.Any.Equals(remoteIP))
                        return true;

                    return await IsZoneNameServerAllowedAsync();

                case AuthZoneQueryAccess.UseSpecifiedNetworkACL:
                    if (IPAddress.IsLoopback(remoteIP) || IPAddress.Any.Equals(remoteIP))
                        return true;

                    return NetworkAccessControl.IsAddressAllowed(remoteIP, apexZone.QueryAccessNetworkACL);

                case AuthZoneQueryAccess.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                    if (IPAddress.IsLoopback(remoteIP) || IPAddress.Any.Equals(remoteIP))
                        return true;

                    return NetworkAccessControl.IsAddressAllowed(remoteIP, apexZone.QueryAccessNetworkACL) || await IsZoneNameServerAllowedAsync();

                default:
                    if (IPAddress.IsLoopback(remoteIP) || IPAddress.Any.Equals(remoteIP))
                        return true;

                    return false;
            }
        }

        private void ResolveCNAME(DnsQuestionRecord question, bool dnssecOk, DnsResourceRecord lastCNAME, List<DnsResourceRecord> answerRecords)
        {
            int queryCount = 0;

            do
            {
                string cnameDomain = (lastCNAME.RDATA as DnsCNAMERecordData).Domain;
                if (lastCNAME.Name.Equals(cnameDomain, StringComparison.OrdinalIgnoreCase))
                    break; //loop detected

                if (!_root.TryGet(cnameDomain, out AuthZoneNode zoneNode))
                    break;

                IReadOnlyList<DnsResourceRecord> records = zoneNode.QueryRecords(question.Type, dnssecOk);
                if (records.Count < 1)
                    break;

                DnsResourceRecord lastRR = records[records.Count - 1];
                if (lastRR.Type != DnsResourceRecordType.CNAME)
                {
                    answerRecords.AddRange(records);
                    break;
                }

                foreach (DnsResourceRecord answerRecord in answerRecords)
                {
                    if (answerRecord.Type != DnsResourceRecordType.CNAME)
                        continue;

                    if (answerRecord.RDATA.Equals(lastRR.RDATA))
                        return; //loop detected
                }

                answerRecords.AddRange(records);

                lastCNAME = lastRR;
            }
            while (++queryCount < DnsServer.MAX_CNAME_HOPS);
        }

        private bool DoDNAMESubstitution(DnsQuestionRecord question, bool dnssecOk, IReadOnlyList<DnsResourceRecord> answer, out IReadOnlyList<DnsResourceRecord> newAnswer)
        {
            DnsResourceRecord dnameRR = answer[0];

            string result = (dnameRR.RDATA as DnsDNAMERecordData).Substitute(question.Name, dnameRR.Name);

            if (DnsClient.IsDomainNameValid(result))
            {
                DnsResourceRecord cnameRR = new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, question.Class, dnameRR.TTL, new DnsCNAMERecordData(result));

                List<DnsResourceRecord> list = new List<DnsResourceRecord>(5);

                list.AddRange(answer);
                list.Add(cnameRR);

                ResolveCNAME(question, dnssecOk, cnameRR, list);

                newAnswer = list;
                return true;
            }
            else
            {
                newAnswer = answer;
                return false;
            }
        }

        private List<DnsResourceRecord> GetAdditionalRecords(IReadOnlyList<DnsResourceRecord> refRecords, bool dnssecOk)
        {
            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>(refRecords.Count);

            foreach (DnsResourceRecord refRecord in refRecords)
            {
                switch (refRecord.Type)
                {
                    case DnsResourceRecordType.NS:
                        IReadOnlyList<DnsResourceRecord> glueRecords = refRecord.GetAuthNSRecordInfo().GlueRecords;
                        if (glueRecords is not null)
                        {
                            additionalRecords.AddRange(glueRecords);
                        }
                        else
                        {
                            ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsNSRecordData).NameServer, dnssecOk, additionalRecords);
                        }
                        break;

                    case DnsResourceRecordType.MX:
                        ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsMXRecordData).Exchange, dnssecOk, additionalRecords);
                        break;

                    case DnsResourceRecordType.SRV:
                        ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsSRVRecordData).Target, dnssecOk, additionalRecords);
                        break;

                    case DnsResourceRecordType.SVCB:
                    case DnsResourceRecordType.HTTPS:
                        DnsSVCBRecordData svcb = refRecord.RDATA as DnsSVCBRecordData;
                        string targetName = svcb.TargetName;

                        if (svcb.SvcPriority == 0)
                        {
                            //For AliasMode SVCB RRs, a TargetName of "." indicates that the service is not available or does not exist [draft-ietf-dnsop-svcb-https-12]
                            if ((targetName.Length == 0) || targetName.Equals(refRecord.Name, StringComparison.OrdinalIgnoreCase))
                                break;
                        }
                        else
                        {
                            //For ServiceMode SVCB RRs, if TargetName has the value ".", then the owner name of this record MUST be used as the effective TargetName [draft-ietf-dnsop-svcb-https-12]
                            if (targetName.Length == 0)
                                targetName = refRecord.Name;
                        }

                        ResolveAdditionalRecords(refRecord, targetName, dnssecOk, additionalRecords);
                        break;
                }
            }

            return additionalRecords;
        }

        private void ResolveAdditionalRecords(DnsResourceRecord refRecord, string domain, bool dnssecOk, List<DnsResourceRecord> additionalRecords)
        {
            int count = 0;

            while (count++ < DnsServer.MAX_CNAME_HOPS)
            {
                AuthZone zone = _root.FindZone(domain, out _, out _, out _, out _);
                if ((zone is null) || !zone.IsActive)
                    break;

                if (((refRecord.Type == DnsResourceRecordType.SVCB) || (refRecord.Type == DnsResourceRecordType.HTTPS)) && ((refRecord.RDATA as DnsSVCBRecordData).SvcPriority == 0))
                {
                    //resolve SVCB/HTTPS for Alias mode refRecord
                    IReadOnlyList<DnsResourceRecord> records = zone.QueryRecordsWildcard(refRecord.Type, dnssecOk, domain);
                    if ((records.Count > 0) && (records[0].Type == refRecord.Type) && (records[0].RDATA is DnsSVCBRecordData svcb))
                    {
                        additionalRecords.AddRange(records);

                        string targetName = svcb.TargetName;

                        if (svcb.SvcPriority == 0)
                        {
                            //Alias mode
                            if ((targetName.Length == 0) || targetName.Equals(records[0].Name, StringComparison.OrdinalIgnoreCase))
                                break; //For AliasMode SVCB RRs, a TargetName of "." indicates that the service is not available or does not exist [draft-ietf-dnsop-svcb-https-12]

                            foreach (DnsResourceRecord additionalRecord in additionalRecords)
                            {
                                if (additionalRecord.Name.Equals(targetName, StringComparison.OrdinalIgnoreCase))
                                    return; //loop detected
                            }

                            //continue to resolve SVCB/HTTPS further
                            domain = targetName;
                            refRecord = records[0];
                            continue;
                        }
                        else
                        {
                            //Service mode
                            if (targetName.Length > 0)
                            {
                                //continue to resolve A/AAAA for target name
                                domain = targetName;
                                refRecord = records[0];
                                continue;
                            }

                            //resolve A/AAAA below
                        }
                    }
                }

                bool hasA = false;
                bool hasAAAA = false;

                if ((refRecord.Type == DnsResourceRecordType.SRV) || (refRecord.Type == DnsResourceRecordType.SVCB) || (refRecord.Type == DnsResourceRecordType.HTTPS))
                {
                    foreach (DnsResourceRecord additionalRecord in additionalRecords)
                    {
                        if (additionalRecord.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (additionalRecord.Type)
                            {
                                case DnsResourceRecordType.A:
                                    hasA = true;
                                    break;

                                case DnsResourceRecordType.AAAA:
                                    hasAAAA = true;
                                    break;
                            }
                        }

                        if (hasA && hasAAAA)
                            break;
                    }
                }

                if (!hasA)
                {
                    IReadOnlyList<DnsResourceRecord> records = zone.QueryRecordsWildcard(DnsResourceRecordType.A, dnssecOk, domain);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.A))
                        additionalRecords.AddRange(records);
                }

                if (!hasAAAA)
                {
                    IReadOnlyList<DnsResourceRecord> records = zone.QueryRecordsWildcard(DnsResourceRecordType.AAAA, dnssecOk, domain);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.AAAA))
                        additionalRecords.AddRange(records);
                }

                break;
            }
        }

        private DnsDatagram GetReferralResponse(DnsDatagram request, bool dnssecOk, AuthZone delegationZone, ApexZone apexZone)
        {
            IReadOnlyList<DnsResourceRecord> authority;

            if (delegationZone is StubZone)
            {
                authority = delegationZone.GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant query

                //update last used on
                DateTime utcNow = DateTime.UtcNow;

                foreach (DnsResourceRecord record in authority)
                    record.GetAuthGenericRecordInfo().LastUsedOn = utcNow;
            }
            else
            {
                authority = delegationZone.QueryRecords(DnsResourceRecordType.NS, false);

                if (dnssecOk)
                {
                    IReadOnlyList<DnsResourceRecord> dsRecords = delegationZone.QueryRecords(DnsResourceRecordType.DS, true);
                    if (dsRecords.Count > 0)
                    {
                        List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(authority.Count + dsRecords.Count);

                        newAuthority.AddRange(authority);
                        newAuthority.AddRange(dsRecords);

                        authority = newAuthority;
                    }
                    else
                    {
                        //add proof of non existence (NODATA) to prove DS record does not exists
                        IReadOnlyList<DnsResourceRecord> nsecRecords;

                        if (apexZone.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3)
                            nsecRecords = _root.FindNSec3ProofOfNonExistenceNoData(request.Question[0].Name, delegationZone, apexZone);
                        else
                            nsecRecords = _root.FindNSecProofOfNonExistenceNoData(request.Question[0].Name, delegationZone);

                        if (nsecRecords.Count > 0)
                        {
                            List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(authority.Count + nsecRecords.Count);

                            newAuthority.AddRange(authority);
                            newAuthority.AddRange(nsecRecords);

                            authority = newAuthority;
                        }
                    }
                }
            }

            IReadOnlyList<DnsResourceRecord> additional = GetAdditionalRecords(authority, dnssecOk);

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, null, authority, additional);
        }

        private DnsDatagram GetForwarderResponse(DnsDatagram request, AuthZone zone, SubDomainZone closestZone, ApexZone forwarderZone)
        {
            IReadOnlyList<DnsResourceRecord> authority = null;

            if (zone is not null)
            {
                if (zone.ContainsNameServerRecords())
                    return GetReferralResponse(request, false, zone, forwarderZone);

                authority = zone.QueryRecords(DnsResourceRecordType.FWD, false);
            }

            if (((authority is null) || (authority.Count == 0)) && (closestZone is not null))
            {
                if (closestZone.ContainsNameServerRecords())
                    return GetReferralResponse(request, false, closestZone, forwarderZone);

                authority = closestZone.QueryRecords(DnsResourceRecordType.FWD, false);
            }

            if ((authority is null) || (authority.Count == 0))
            {
                if (forwarderZone.ContainsNameServerRecords())
                    return GetReferralResponse(request, false, forwarderZone, forwarderZone);

                authority = forwarderZone.QueryRecords(DnsResourceRecordType.FWD, false);
            }

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, null, authority);
        }

        #endregion

        #region properties

        public uint DefaultRecordTtl
        {
            get { return _defaultRecordTtl; }
            set { _defaultRecordTtl = value; }
        }

        public bool UseSoaSerialDateScheme
        {
            get { return _useSoaSerialDateScheme; }
            set { _useSoaSerialDateScheme = value; }
        }

        public uint MinSoaRefresh
        {
            get { return _minSoaRefresh; }
            set { _minSoaRefresh = value; }
        }

        public uint MinSoaRetry
        {
            get { return _minSoaRetry; }
            set { _minSoaRetry = value; }
        }

        public int TotalZones
        { get { return _zoneIndex.Count; } }

        #endregion
    }
}
