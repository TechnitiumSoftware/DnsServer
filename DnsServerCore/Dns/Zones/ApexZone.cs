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

using DnsServerCore.Dns.ResourceRecords;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    public enum AuthZoneQueryAccess : byte
    {
        Deny = 0,
        Allow = 1,
        AllowOnlyPrivateNetworks = 2,
        AllowOnlyZoneNameServers = 3,
        UseSpecifiedNetworkACL = 4,
        AllowZoneNameServersAndUseSpecifiedNetworkACL = 5
    }

    public enum AuthZoneTransfer : byte
    {
        Deny = 0,
        Allow = 1,
        AllowOnlyZoneNameServers = 2,
        UseSpecifiedNetworkACL = 3,
        AllowZoneNameServersAndUseSpecifiedNetworkACL = 4
    }

    public enum AuthZoneNotify : byte
    {
        None = 0,
        ZoneNameServers = 1,
        SpecifiedNameServers = 2,
        BothZoneAndSpecifiedNameServers = 3,
        SeparateNameServersForCatalogAndMemberZones = 4
    }

    public enum AuthZoneUpdate : byte
    {
        Deny = 0,
        Allow = 1,
        AllowOnlyZoneNameServers = 2,
        UseSpecifiedNetworkACL = 3,
        AllowZoneNameServersAndUseSpecifiedNetworkACL = 4
    }

    abstract class ApexZone : AuthZone, IDisposable
    {
        #region variables

        protected readonly DnsServer _dnsServer;
        protected DateTime _lastModified;

        string _catalogZoneName;
        bool _overrideCatalogQueryAccess;
        bool _overrideCatalogZoneTransfer;
        bool _overrideCatalogNotify;

        protected AuthZoneQueryAccess _queryAccess;
        IReadOnlyCollection<NetworkAccessControl> _queryAccessNetworkACL;

        protected AuthZoneTransfer _zoneTransfer;
        IReadOnlyCollection<NetworkAccessControl> _zoneTransferNetworkACL;
        IReadOnlySet<string> _zoneTransferTsigKeyNames;
        readonly List<DnsResourceRecord> _zoneHistory; //for IXFR support

        AuthZoneNotify _notify;
        IReadOnlyCollection<IPAddress> _notifyNameServers;
        IReadOnlyCollection<IPAddress> _notifySecondaryCatalogNameServers;

        AuthZoneUpdate _update;
        IReadOnlyCollection<NetworkAccessControl> _updateNetworkACL;
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> _updateSecurityPolicies;

        protected AuthZoneDnssecStatus _dnssecStatus;

        Timer _notifyTimer;
        bool _notifyTimerTriggered;
        const int NOTIFY_TIMER_INTERVAL = 5000;
        List<string> _notifyList;
        List<string> _notifyFailed;
        const int NOTIFY_TIMEOUT = 10000;
        const int NOTIFY_RETRIES = 5;

        protected bool _syncFailed;

        Timer _recordExpiryTimer;
        readonly object _recordExpiryTimerLock = new object();
        DateTime _recordExpiryTimerStartedOn;
        uint _recordExpiryTimerTtl;
        bool _recordExpiryTimerRunning;

        CatalogZone _catalogZone;
        SecondaryCatalogZone _secondaryCatalogZone;

        #endregion

        #region constructor

        protected ApexZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(zoneInfo)
        {
            _dnsServer = dnsServer;

            _catalogZoneName = zoneInfo.CatalogZoneName;
            _overrideCatalogQueryAccess = zoneInfo.OverrideCatalogQueryAccess;
            _overrideCatalogZoneTransfer = zoneInfo.OverrideCatalogZoneTransfer;
            _overrideCatalogNotify = zoneInfo.OverrideCatalogNotify;

            _queryAccess = zoneInfo.QueryAccess;
            _queryAccessNetworkACL = zoneInfo.QueryAccessNetworkACL;

            _zoneTransfer = zoneInfo.ZoneTransfer;
            _zoneTransferNetworkACL = zoneInfo.ZoneTransferNetworkACL;
            _zoneTransferTsigKeyNames = zoneInfo.ZoneTransferTsigKeyNames;

            if (zoneInfo.ZoneHistory is null)
                _zoneHistory = new List<DnsResourceRecord>();
            else
                _zoneHistory = new List<DnsResourceRecord>(zoneInfo.ZoneHistory);

            _notify = zoneInfo.Notify;
            _notifyNameServers = zoneInfo.NotifyNameServers;
            _notifySecondaryCatalogNameServers = zoneInfo.NotifySecondaryCatalogNameServers;

            _update = zoneInfo.Update;
            _updateNetworkACL = zoneInfo.UpdateNetworkACL;
            _updateSecurityPolicies = zoneInfo.UpdateSecurityPolicies;

            _lastModified = zoneInfo.LastModified;
        }

        protected ApexZone(DnsServer dnsServer, string name)
            : base(name)
        {
            _dnsServer = dnsServer;

            _queryAccess = AuthZoneQueryAccess.Allow;
            _zoneHistory = new List<DnsResourceRecord>();

            _lastModified = DateTime.UtcNow;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                _notifyTimer?.Dispose();

                lock (_recordExpiryTimerLock)
                {
                    if (_recordExpiryTimer is not null)
                    {
                        _recordExpiryTimer.Dispose();
                        _recordExpiryTimer = null;
                    }
                }
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region notify

        protected void InitNotify()
        {
            _notifyTimer = new Timer(NotifyTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
            _notifyList = new List<string>();
            _notifyFailed = new List<string>();
        }

        protected void DisableNotifyTimer()
        {
            if (_notifyTimer is not null)
                _notifyTimer.Change(Timeout.Infinite, Timeout.Infinite);
        }

        private void NotifyTimerCallback(object state)
        {
            ApexZone apexZone = this;

            if ((apexZone.CatalogZone is not null) && !apexZone.OverrideCatalogNotify)
                apexZone = apexZone.CatalogZone;

            List<string> notifiedNameServers = new List<string>();

            async Task NotifyZoneNameServersAsync(bool onlyFailedNameServers)
            {
                string primaryNameServer = (_entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData).PrimaryNameServer;
                IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

                //notify all secondary name servers
                List<Task> tasks = new List<Task>();

                foreach (DnsResourceRecord nsRecord in nsRecords)
                {
                    if (nsRecord.GetAuthGenericRecordInfo().Disabled)
                        continue;

                    string nameServerHost = (nsRecord.RDATA as DnsNSRecordData).NameServer;

                    if (primaryNameServer.Equals(nameServerHost, StringComparison.OrdinalIgnoreCase))
                        continue; //skip primary name server

                    if (onlyFailedNameServers)
                    {
                        lock (_notifyFailed)
                        {
                            if (!_notifyFailed.Contains(nameServerHost))
                                continue;
                        }
                    }

                    notifiedNameServers.Add(nameServerHost);

                    List<NameServerAddress> nameServers = new List<NameServerAddress>(2);
                    await ResolveNameServerAddressesAsync(nsRecord, nameServers);

                    if (nameServers.Count > 0)
                    {
                        tasks.Add(NotifyNameServerAsync(nameServerHost, nameServers));
                    }
                    else
                    {
                        lock (_notifyFailed)
                        {
                            if (!_notifyFailed.Contains(nameServerHost))
                                _notifyFailed.Add(nameServerHost);
                        }

                        _dnsServer.LogManager.Write("DNS Server failed to notify name server '" + nameServerHost + "' due to failure in resolving its IP address for zone: " + ToString());
                    }
                }

                await Task.WhenAll(tasks);
            }

            Task NotifySpecifiedNameServersAsync(bool onlyFailedNameServers)
            {
                IReadOnlyCollection<IPAddress> specifiedNameServers = apexZone._notifyNameServers;
                if (specifiedNameServers is not null)
                    return NotifyNameServersAsync(specifiedNameServers, onlyFailedNameServers);

                return Task.CompletedTask;
            }

            Task NotifySecondaryCatalogNameServersAsync(bool onlyFailedNameServers)
            {
                IReadOnlyCollection<IPAddress> secondaryCatalogNameServers = apexZone._notifySecondaryCatalogNameServers;
                if (secondaryCatalogNameServers is not null)
                    return NotifyNameServersAsync(secondaryCatalogNameServers, onlyFailedNameServers);

                return Task.CompletedTask;
            }

            async Task NotifyNameServersAsync(IReadOnlyCollection<IPAddress> nameServerIpAddresses, bool onlyFailedNameServers)
            {
                List<Task> tasks = new List<Task>();

                foreach (IPAddress nameServerIpAddress in nameServerIpAddresses)
                {
                    string nameServerHost = nameServerIpAddress.ToString();

                    if (onlyFailedNameServers)
                    {
                        lock (_notifyFailed)
                        {
                            if (!_notifyFailed.Contains(nameServerHost))
                                continue;
                        }
                    }

                    notifiedNameServers.Add(nameServerHost);

                    tasks.Add(NotifyNameServerAsync(nameServerHost, [new NameServerAddress(nameServerIpAddress)]));
                }

                await Task.WhenAll(tasks);
            }

            //notify in DNS server's resolver thread pool
            if (!_dnsServer.TryQueueResolverTask(async delegate (object state)
                {
                    try
                    {
                        switch (apexZone._notify)
                        {
                            case AuthZoneNotify.ZoneNameServers:
                                await NotifyZoneNameServersAsync(!_notifyTimerTriggered);
                                break;

                            case AuthZoneNotify.SpecifiedNameServers:
                                await NotifySpecifiedNameServersAsync(!_notifyTimerTriggered);
                                break;

                            case AuthZoneNotify.BothZoneAndSpecifiedNameServers:
                                Task t1 = NotifyZoneNameServersAsync(!_notifyTimerTriggered);
                                Task t2 = NotifySpecifiedNameServersAsync(!_notifyTimerTriggered);

                                await Task.WhenAll(t1, t2);
                                break;

                            case AuthZoneNotify.SeparateNameServersForCatalogAndMemberZones:
                                if (this is CatalogZone)
                                    await NotifySecondaryCatalogNameServersAsync(!_notifyTimerTriggered);
                                else
                                    await NotifySpecifiedNameServersAsync(!_notifyTimerTriggered);

                                break;
                        }

                        //remove non-existent name servers from notify failed list
                        lock (_notifyFailed)
                        {
                            if (_notifyFailed.Count > 0)
                            {
                                List<string> toRemove = new List<string>();

                                foreach (string failedNameServer in _notifyFailed)
                                {
                                    if (!notifiedNameServers.Contains(failedNameServer))
                                        toRemove.Add(failedNameServer);
                                }

                                foreach (string failedNameServer in toRemove)
                                    _notifyFailed.Remove(failedNameServer);

                                if (_notifyFailed.Count > 0)
                                {
                                    //set timer to notify failed name servers again
                                    _notifyTimer.Change(Math.Max(GetZoneSoaRetry(), _dnsServer.AuthZoneManager.MinSoaRetry) * 1000, Timeout.Infinite);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                    finally
                    {
                        _notifyTimerTriggered = false;
                    }
                })
            )
            {
                //failed to queue notify task; try again in some time
                _notifyTimer?.Change(NOTIFY_TIMER_INTERVAL, Timeout.Infinite);
            }
        }

        private async Task NotifyNameServerAsync(string nameServerHost, IReadOnlyList<NameServerAddress> nameServers)
        {
            //use notify list to prevent multiple threads from notifying the same name server
            lock (_notifyList)
            {
                if (_notifyList.Contains(nameServerHost))
                    return; //already notifying the name server in another thread

                _notifyList.Add(nameServerHost);
            }

            try
            {
                DnsClient client = new DnsClient(nameServers);

                client.Proxy = _dnsServer.Proxy;
                client.Timeout = NOTIFY_TIMEOUT;
                client.Retries = NOTIFY_RETRIES;

                DnsDatagram notifyRequest = new DnsDatagram(0, false, DnsOpcode.Notify, true, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN) }, _entries[DnsResourceRecordType.SOA]);
                DnsDatagram response = await client.RawResolveAsync(notifyRequest);

                switch (response.RCODE)
                {
                    case DnsResponseCode.NoError:
                    case DnsResponseCode.NotImplemented:
                        {
                            //transaction complete
                            lock (_notifyFailed)
                            {
                                _notifyFailed.Remove(nameServerHost);
                            }

                            _dnsServer.LogManager.Write("DNS Server successfully notified name server '" + nameServerHost + "' for zone: " + ToString());
                        }
                        break;

                    default:
                        {
                            //transaction failed
                            lock (_notifyFailed)
                            {
                                if (!_notifyFailed.Contains(nameServerHost))
                                    _notifyFailed.Add(nameServerHost);
                            }

                            _dnsServer.LogManager.Write("DNS Server failed to notify name server '" + nameServerHost + "' (RCODE=" + response.RCODE.ToString() + ") for zone: " + ToString());
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                lock (_notifyFailed)
                {
                    if (!_notifyFailed.Contains(nameServerHost))
                        _notifyFailed.Add(nameServerHost);
                }

                _dnsServer.LogManager.Write("DNS Server failed to notify name server '" + nameServerHost + "' for zone: " + ToString() + "\r\n" + ex.ToString());
            }
            finally
            {
                lock (_notifyList)
                {
                    _notifyList.Remove(nameServerHost);
                }
            }
        }

        internal void RemoveFromNotifyFailedList(NameServerAddress allowedZoneNameServer, IPAddress allowedIPAddress)
        {
            if (_notifyFailed is null)
                return;

            lock (_notifyFailed)
            {
                if (_notifyFailed.Count == 0)
                    return;

                if ((allowedZoneNameServer is not null) && (allowedZoneNameServer.DomainEndPoint is not null))
                    _notifyFailed.Remove(allowedZoneNameServer.DomainEndPoint.Address);

                _notifyFailed.Remove(allowedIPAddress.ToString());
            }
        }

        public void TriggerNotify()
        {
            if (Disabled)
                return;

            ApexZone apexZone = this;

            if ((apexZone.CatalogZone is not null) && !apexZone.OverrideCatalogNotify)
                apexZone = apexZone.CatalogZone;

            if (apexZone._notify == AuthZoneNotify.None)
            {
                if (_notifyFailed is not null)
                {
                    lock (_notifyFailed)
                    {
                        _notifyFailed.Clear();
                    }
                }

                return;
            }

            if (_notifyTimerTriggered)
                return;

            if (_disposed)
                return;

            if (_notifyTimer is null)
                return;

            _notifyTimer.Change(NOTIFY_TIMER_INTERVAL, Timeout.Infinite);
            _notifyTimerTriggered = true;
        }

        #endregion

        #region record expiry

        protected void InitRecordExpiry()
        {
            _recordExpiryTimer = new Timer(RecordExpiryTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
        }

        private uint GetMinRecordExpiryTtl(uint minExpiryTtl)
        {
            if (!_recordExpiryTimerRunning)
                return Math.Min(minExpiryTtl, uint.MaxValue / 1000);

            uint elapsedSeconds = Convert.ToUInt32((DateTime.UtcNow - _recordExpiryTimerStartedOn).TotalSeconds);
            if (elapsedSeconds >= _recordExpiryTimerTtl)
                return 0u;

            uint pendingExpiryTtl = _recordExpiryTimerTtl - elapsedSeconds;

            return Math.Min(Math.Min(pendingExpiryTtl, minExpiryTtl), uint.MaxValue / 1000);
        }

        public void StartRecordExpiryTimer(uint minExpiryTtl)
        {
            lock (_recordExpiryTimerLock)
            {
                if (_recordExpiryTimer is not null)
                {
                    uint minTtl = GetMinRecordExpiryTtl(minExpiryTtl);

                    _recordExpiryTimer.Change(minTtl * 1000, Timeout.Infinite);
                    _recordExpiryTimerStartedOn = DateTime.UtcNow;
                    _recordExpiryTimerTtl = minTtl;
                    _recordExpiryTimerRunning = true;
                }
            }
        }

        private void RecordExpiryTimerCallback(object state)
        {
            _recordExpiryTimerRunning = false;
            uint minExpiryTtl = 0u;

            try
            {
                IReadOnlyList<AuthZone> authZones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);
                bool recordsDeleted = false;

                foreach (AuthZone authZone in authZones)
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in authZone.Entries)
                    {
                        foreach (DnsResourceRecord record in entry.Value)
                        {
                            GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();
                            if (recordInfo.ExpiryTtl > 0u)
                            {
                                uint pendingExpiryTtl = recordInfo.GetPendingExpiryTtl();
                                if (pendingExpiryTtl == 0u)
                                {
                                    if (_dnsServer.AuthZoneManager.DeleteRecord(_name, record))
                                        recordsDeleted = true;
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
                    }
                }

                if (recordsDeleted)
                    _dnsServer.AuthZoneManager.SaveZoneFile(_name);
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }
            finally
            {
                if (minExpiryTtl > 0u)
                    StartRecordExpiryTimer(minExpiryTtl);
            }
        }

        #endregion

        #region internal

        internal virtual void UpdateDnssecStatus()
        {
            if (!_entries.ContainsKey(DnsResourceRecordType.DNSKEY))
                _dnssecStatus = AuthZoneDnssecStatus.Unsigned;
            else if (_entries.ContainsKey(DnsResourceRecordType.NSEC3PARAM))
                _dnssecStatus = AuthZoneDnssecStatus.SignedWithNSEC3;
            else
                _dnssecStatus = AuthZoneDnssecStatus.SignedWithNSEC;
        }

        #endregion

        #region versioning

        internal virtual void CommitAndIncrementSerial(IReadOnlyList<DnsResourceRecord> deletedRecords = null, IReadOnlyList<DnsResourceRecord> addedRecords = null)
        {
            _lastModified = DateTime.UtcNow;

            if (addedRecords is not null)
            {
                uint minExpiryTtl = 0u;

                foreach (DnsResourceRecord addedRecord in addedRecords)
                {
                    uint expiryTtl = addedRecord.GetAuthGenericRecordInfo().ExpiryTtl;
                    if (expiryTtl > 0u)
                    {
                        if (minExpiryTtl == 0u)
                            minExpiryTtl = expiryTtl;
                        else
                            minExpiryTtl = Math.Min(minExpiryTtl, expiryTtl);
                    }
                }

                if (minExpiryTtl > 0u)
                    StartRecordExpiryTimer(minExpiryTtl);
            }

            lock (_zoneHistory)
            {
                DnsResourceRecord oldSoaRecord = _entries[DnsResourceRecordType.SOA][0];
                DnsResourceRecord newSoaRecord;
                {
                    DnsSOARecordData oldSoa = oldSoaRecord.RDATA as DnsSOARecordData;

                    if ((addedRecords is not null) && (addedRecords.Count == 1) && (addedRecords[0].Type == DnsResourceRecordType.SOA))
                    {
                        DnsResourceRecord addSoaRecord = addedRecords[0];
                        DnsSOARecordData addSoa = addSoaRecord.RDATA as DnsSOARecordData;

                        uint serial = GetNewSerial(oldSoa.Serial, addSoa.Serial, addSoaRecord.GetAuthSOARecordInfo().UseSoaSerialDateScheme);

                        newSoaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, addSoaRecord.TTL, new DnsSOARecordData(addSoa.PrimaryNameServer, addSoa.ResponsiblePerson, serial, addSoa.Refresh, addSoa.Retry, addSoa.Expire, addSoa.Minimum)) { Tag = addSoaRecord.Tag };
                        addedRecords = null;
                    }
                    else
                    {
                        uint serial = GetNewSerial(oldSoa.Serial, 0, oldSoaRecord.GetAuthSOARecordInfo().UseSoaSerialDateScheme);

                        newSoaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, oldSoaRecord.TTL, new DnsSOARecordData(oldSoa.PrimaryNameServer, oldSoa.ResponsiblePerson, serial, oldSoa.Refresh, oldSoa.Retry, oldSoa.Expire, oldSoa.Minimum)) { Tag = oldSoaRecord.Tag };
                    }
                }

                DnsResourceRecord[] newSoaRecords = [newSoaRecord];

                //update SOA
                _entries[DnsResourceRecordType.SOA] = newSoaRecords;

                IReadOnlyList<DnsResourceRecord> newRRSigRecords = null;
                IReadOnlyList<DnsResourceRecord> deletedRRSigRecords = null;

                if (_dnssecStatus != AuthZoneDnssecStatus.Unsigned)
                {
                    //sign SOA and update RRSig
                    newRRSigRecords = SignRRSet(newSoaRecords);
                    AddOrUpdateRRSigRecords(newRRSigRecords, out deletedRRSigRecords);
                }

                //remove RR info from old SOA to allow creating new history RR info for setting DeletedOn
                oldSoaRecord.Tag = null;

                //start commit
                oldSoaRecord.GetAuthHistoryRecordInfo().DeletedOn = DateTime.UtcNow;

                //write removed
                _zoneHistory.Add(oldSoaRecord);

                if (deletedRecords is not null)
                {
                    foreach (DnsResourceRecord deletedRecord in deletedRecords)
                    {
                        if (deletedRecord.GetAuthGenericRecordInfo().Disabled)
                            continue;

                        _zoneHistory.Add(deletedRecord);

                        if (deletedRecord.Type == DnsResourceRecordType.NS)
                        {
                            IReadOnlyList<DnsResourceRecord> glueRecords = deletedRecord.GetAuthNSRecordInfo().GlueRecords;
                            if (glueRecords is not null)
                                _zoneHistory.AddRange(glueRecords);
                        }
                    }
                }

                if (deletedRRSigRecords is not null)
                    _zoneHistory.AddRange(deletedRRSigRecords);

                //write added
                _zoneHistory.Add(newSoaRecord);

                if (addedRecords is not null)
                {
                    foreach (DnsResourceRecord addedRecord in addedRecords)
                    {
                        if (addedRecord.GetAuthGenericRecordInfo().Disabled)
                            continue;

                        _zoneHistory.Add(addedRecord);

                        if (addedRecord.Type == DnsResourceRecordType.NS)
                        {
                            IReadOnlyList<DnsResourceRecord> glueRecords = addedRecord.GetAuthNSRecordInfo().GlueRecords;
                            if (glueRecords is not null)
                                _zoneHistory.AddRange(glueRecords);
                        }
                    }
                }

                if (newRRSigRecords is not null)
                    _zoneHistory.AddRange(newRRSigRecords);

                //end commit

                CleanupHistory();
            }
        }

        protected static uint GetNewSerial(uint oldSerial, uint updateSerial, bool useSoaSerialDateScheme)
        {
            if (useSoaSerialDateScheme)
            {
                string strOldSerial = oldSerial.ToString();
                string strOldSerialDate = null;
                byte counter = 0;

                if (strOldSerial.Length == 10)
                {
                    //parse old serial
                    strOldSerialDate = strOldSerial.Substring(0, 8);
                    counter = byte.Parse(strOldSerial.Substring(8));
                }

                string strSerialDate = DateTime.UtcNow.ToString("yyyyMMdd");

                if (strOldSerialDate is null)
                {
                    //transitioning to date scheme
                    return uint.Parse(strSerialDate + counter.ToString().PadLeft(2, '0'));
                }
                else if (strSerialDate.Equals(strOldSerialDate))
                {
                    //same date
                    if (counter < 99)
                    {
                        counter++;
                        return uint.Parse(strSerialDate + counter.ToString().PadLeft(2, '0'));
                    }
                    else
                    {
                        //more than 100 increments
                        return uint.Parse(strSerialDate + counter.ToString().PadLeft(2, '0')) + 1;
                    }
                }
                else if (uint.Parse(strSerialDate) > uint.Parse(strOldSerialDate))
                {
                    //later date
                    return uint.Parse(strSerialDate + "00");
                }
            }

            //default
            uint serial = oldSerial;

            if (updateSerial > serial)
                serial = updateSerial;
            else if (serial < uint.MaxValue)
                serial++;
            else
                serial = 1;

            return serial;
        }

        internal void SetSoaSerial(uint newSerial)
        {
            lock (_zoneHistory)
            {
                DnsResourceRecord oldSoaRecord = _entries[DnsResourceRecordType.SOA][0];
                DnsSOARecordData oldSoa = oldSoaRecord.RDATA as DnsSOARecordData;

                DnsResourceRecord newSoaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, oldSoaRecord.TTL, new DnsSOARecordData(oldSoa.PrimaryNameServer, oldSoa.ResponsiblePerson, newSerial, oldSoa.Refresh, oldSoa.Retry, oldSoa.Expire, oldSoa.Minimum)) { Tag = oldSoaRecord.Tag };
                DnsResourceRecord[] newSoaRecords = [newSoaRecord];

                //update SOA
                _entries[DnsResourceRecordType.SOA] = newSoaRecords;

                //clear history
                _zoneHistory.Clear();
            }
        }

        public IReadOnlyList<DnsResourceRecord> GetZoneHistory()
        {
            lock (_zoneHistory)
            {
                return _zoneHistory.ToArray();
            }
        }

        protected void CleanupHistory()
        {
            DnsSOARecordData soa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData;
            DateTime expiry = DateTime.UtcNow.AddSeconds(-soa.Expire);
            int index = 0;

            while (index < _zoneHistory.Count)
            {
                //check difference sequence
                if (_zoneHistory[index].GetAuthHistoryRecordInfo().DeletedOn > expiry)
                    break; //found record to keep

                //skip to next difference sequence
                index++;
                int soaCount = 1;

                while (index < _zoneHistory.Count)
                {
                    if (_zoneHistory[index].Type == DnsResourceRecordType.SOA)
                    {
                        soaCount++;

                        if (soaCount == 3)
                            break;
                    }

                    index++;
                }
            }

            if (index == _zoneHistory.Count)
            {
                //delete entire history
                _zoneHistory.Clear();
                return;
            }

            //remove expired records
            _zoneHistory.RemoveRange(0, index);
        }

        protected void CommitZoneHistory(IReadOnlyList<DnsResourceRecord> historyRecords)
        {
            lock (_zoneHistory)
            {
                historyRecords[0].GetAuthHistoryRecordInfo().DeletedOn = DateTime.UtcNow;

                //write history
                _zoneHistory.AddRange(historyRecords);

                CleanupHistory();
            }
        }

        protected void ClearZoneHistory()
        {
            lock (_zoneHistory)
            {
                _zoneHistory.Clear();
            }
        }

        #endregion

        #region catalog zone

        private IReadOnlyCollection<NetworkAccessControl> GetQueryAccessACL()
        {
            switch (_queryAccess)
            {
                case AuthZoneQueryAccess.Allow:
                    return [
                                new NetworkAccessControl(IPAddress.Any, 0),
                                new NetworkAccessControl(IPAddress.IPv6Any, 0)
                           ];

                case AuthZoneQueryAccess.AllowOnlyPrivateNetworks:
                    return [
                                new NetworkAccessControl(IPAddress.Parse("127.0.0.0"), 8),
                                new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8),
                                new NetworkAccessControl(IPAddress.Parse("100.64.0.0"), 10),
                                new NetworkAccessControl(IPAddress.Parse("169.254.0.0"), 16),
                                new NetworkAccessControl(IPAddress.Parse("172.16.0.0"), 12),
                                new NetworkAccessControl(IPAddress.Parse("192.168.0.0"), 16),
                                new NetworkAccessControl(IPAddress.Parse("2000::"), 3, true),
                                new NetworkAccessControl(IPAddress.IPv6Any, 0)
                           ];

                case AuthZoneQueryAccess.AllowOnlyZoneNameServers:
                    return [
                                new NetworkAccessControl(IPAddress.Parse("224.0.0.0"), 32)
                           ];

                case AuthZoneQueryAccess.UseSpecifiedNetworkACL:
                    return _queryAccessNetworkACL;

                case AuthZoneQueryAccess.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                    if (_queryAccessNetworkACL is null)
                    {
                        return [
                                    new NetworkAccessControl(IPAddress.Parse("224.0.0.0"), 32)
                                ];
                    }

                    return [
                                new NetworkAccessControl(IPAddress.Parse("224.0.0.0"), 32),
                                .._queryAccessNetworkACL
                           ];

                case AuthZoneQueryAccess.Deny:
                default:
                    return [
                                new NetworkAccessControl(IPAddress.Parse("127.0.0.0"), 8),
                                new NetworkAccessControl(IPAddress.Parse("::1"), 128)
                           ];
            }
        }

        private IReadOnlyCollection<NetworkAccessControl> GetZoneTranferACL()
        {
            switch (_zoneTransfer)
            {
                case AuthZoneTransfer.Allow:
                    return [
                                new NetworkAccessControl(IPAddress.Any, 0),
                                new NetworkAccessControl(IPAddress.IPv6Any, 0)
                           ];

                case AuthZoneTransfer.AllowOnlyZoneNameServers:
                    return [
                                new NetworkAccessControl(IPAddress.Parse("224.0.0.0"), 32)
                           ];

                case AuthZoneTransfer.UseSpecifiedNetworkACL:
                    return _zoneTransferNetworkACL;

                case AuthZoneTransfer.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                    if (_zoneTransferNetworkACL is null)
                    {
                        return [
                                    new NetworkAccessControl(IPAddress.Parse("224.0.0.0"), 32)
                                ];
                    }

                    return [
                                new NetworkAccessControl(IPAddress.Parse("224.0.0.0"), 32),
                                .._zoneTransferNetworkACL
                           ];

                case AuthZoneTransfer.Deny:
                default:
                    return [
                                new NetworkAccessControl(IPAddress.Any, 0, true),
                                new NetworkAccessControl(IPAddress.IPv6Any, 0, true)
                           ];
            }
        }

        #endregion

        #region public

        public uint GetZoneSoaSerial()
        {
            return (_entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData).Serial;
        }

        public uint GetZoneSoaRetry()
        {
            return (_entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData).Retry;
        }

        public uint GetZoneSoaExpire()
        {
            return (_entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData).Expire;
        }

        public uint GetZoneSoaMinimum()
        {
            return (_entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData).Minimum;
        }

        public abstract string GetZoneTypeName();

        public override string ToString()
        {
            return _name.Length == 0 ? "<root>" : _name;
        }

        #endregion

        #region name server address resolution

        public async Task<IReadOnlyList<NameServerAddress>> GetResolvedPrimaryNameServerAddressesAsync()
        {
            IReadOnlyList<NameServerAddress> primaryNameServers;

            if (this is SecondaryZone secondary)
                primaryNameServers = secondary.PrimaryNameServerAddresses;
            else if (this is StubZone stub)
                primaryNameServers = stub.PrimaryNameServerAddresses;
            else
                primaryNameServers = null;

            if (primaryNameServers is not null)
                return await GetResolvedNameServerAddressesAsync(primaryNameServers);

            DnsResourceRecord soaRecord = _entries[DnsResourceRecordType.SOA][0];
            string primaryNameServer = (soaRecord.RDATA as DnsSOARecordData).PrimaryNameServer;
            IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

            List<NameServerAddress> nameServers = new List<NameServerAddress>(nsRecords.Count * 2);

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.GetAuthGenericRecordInfo().Disabled)
                    continue;

                if (primaryNameServer.Equals((nsRecord.RDATA as DnsNSRecordData).NameServer, StringComparison.OrdinalIgnoreCase))
                {
                    //found primary NS
                    await ResolveNameServerAddressesAsync(nsRecord, nameServers);
                    break;
                }
            }

            if (nameServers.Count < 1)
                await ResolveNameServerAddressesAsync(primaryNameServer, 53, DnsTransportProtocol.Udp, nameServers);

            return nameServers;
        }

        public async Task<IReadOnlyList<NameServerAddress>> GetResolvedSecondaryNameServerAddressesAsync()
        {
            string primaryNameServer = (_entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData).PrimaryNameServer;
            IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

            List<NameServerAddress> nameServers = new List<NameServerAddress>(nsRecords.Count * 2);

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.GetAuthGenericRecordInfo().Disabled)
                    continue;

                if (primaryNameServer.Equals((nsRecord.RDATA as DnsNSRecordData).NameServer, StringComparison.OrdinalIgnoreCase))
                    continue; //skip primary name server

                await ResolveNameServerAddressesAsync(nsRecord, nameServers);
            }

            return nameServers;
        }

        public async Task<IReadOnlyList<NameServerAddress>> GetAllResolvedNameServerAddressesAsync()
        {
            IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

            List<NameServerAddress> nameServers = new List<NameServerAddress>(nsRecords.Count * 2);

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.GetAuthGenericRecordInfo().Disabled)
                    continue;

                await ResolveNameServerAddressesAsync(nsRecord, nameServers);
            }

            return nameServers;
        }

        public async Task<IReadOnlyList<NameServerAddress>> GetResolvedNameServerAddressesAsync(IReadOnlyList<NameServerAddress> nameServers)
        {
            List<NameServerAddress> resolvedNameServers = new List<NameServerAddress>(nameServers.Count * 2);
            List<Task> resolverTasks = new List<Task>(nameServers.Count);

            foreach (NameServerAddress nameServer in nameServers)
            {
                if (nameServer.IsIPEndPointStale)
                    resolverTasks.Add(ResolveNameServerAddressesAsync(nameServer.Host, nameServer.Port, nameServer.Protocol, resolvedNameServers));
                else
                    resolvedNameServers.Add(nameServer);
            }

            await Task.WhenAll(resolverTasks);

            return resolvedNameServers;
        }

        private async Task ResolveNameServerAddressesAsync(string nsDomain, int port, DnsTransportProtocol protocol, List<NameServerAddress> outNameServers, CancellationToken cancellationToken = default)
        {
            try
            {
                DnsDatagram response = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.A, DnsClass.IN), cancellationToken: cancellationToken);
                if (response.Answer.Count > 0)
                {
                    IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseA(response);
                    foreach (IPAddress address in addresses)
                        outNameServers.Add(new NameServerAddress(nsDomain, new IPEndPoint(address, port), protocol));
                }
            }
            catch (Exception ex)
            {
                _dnsServer.ResolverLogManager?.Write(ex);
            }

            if (_dnsServer.PreferIPv6)
            {
                try
                {
                    DnsDatagram response = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.AAAA, DnsClass.IN), cancellationToken: cancellationToken);
                    if (response.Answer.Count > 0)
                    {
                        IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseAAAA(response);
                        foreach (IPAddress address in addresses)
                            outNameServers.Add(new NameServerAddress(nsDomain, new IPEndPoint(address, port), protocol));
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.ResolverLogManager?.Write(ex);
                }
            }
        }

        private Task ResolveNameServerAddressesAsync(DnsResourceRecord nsRecord, List<NameServerAddress> outNameServers)
        {
            string nsDomain = (nsRecord.RDATA as DnsNSRecordData).NameServer;

            IReadOnlyList<DnsResourceRecord> glueRecords = nsRecord.GetAuthNSRecordInfo().GlueRecords;
            if (glueRecords is not null)
            {
                foreach (DnsResourceRecord glueRecord in glueRecords)
                {
                    switch (glueRecord.Type)
                    {
                        case DnsResourceRecordType.A:
                            outNameServers.Add(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsARecordData).Address));
                            break;

                        case DnsResourceRecordType.AAAA:
                            if (_dnsServer.PreferIPv6)
                                outNameServers.Add(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsAAAARecordData).Address));

                            break;
                    }
                }

                return Task.CompletedTask;
            }
            else
            {
                return ResolveNameServerAddressesAsync(nsDomain, 53, DnsTransportProtocol.Udp, outNameServers);
            }
        }

        #endregion

        #region properties

        public override bool Disabled
        {
            get { return base.Disabled; }
            set
            {
                if (base.Disabled == value)
                    return;

                base.Disabled = value; //set value early to be able to use it for setting catalog properties

                CatalogZone catalogZone = CatalogZone;
                if (catalogZone is not null)
                {
                    if (value)
                    {
                        //remove catalog zone membership without removing it from zone's options
                        catalogZone.RemoveMemberZone(_name);
                        _dnsServer.AuthZoneManager.SaveZoneFile(catalogZone._name);
                    }
                    else
                    {
                        //add catalog zone membership
                        _dnsServer.AuthZoneManager.AddCatalogMemberZone(_catalogZoneName, new AuthZoneInfo(this), true);
                    }
                }
            }
        }

        public DateTime LastModified
        { get { return _lastModified; } }

        public virtual string CatalogZoneName
        {
            get { return _catalogZoneName; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    _catalogZoneName = null;
                else
                    _catalogZoneName = value;

                //reset
                _catalogZone = null;
                _secondaryCatalogZone = null;
            }
        }

        public virtual bool OverrideCatalogQueryAccess
        {
            get { return _overrideCatalogQueryAccess; }
            set { _overrideCatalogQueryAccess = value; }
        }

        public virtual bool OverrideCatalogZoneTransfer
        {
            get { return _overrideCatalogZoneTransfer; }
            set { _overrideCatalogZoneTransfer = value; }
        }

        public virtual bool OverrideCatalogNotify
        {
            get { return _overrideCatalogNotify; }
            set { _overrideCatalogNotify = value; }
        }

        public virtual AuthZoneQueryAccess QueryAccess
        {
            get { return _queryAccess; }
            set
            {
                _queryAccess = value;

                //update catalog zone property
                if (this is CatalogZone thisCatalogZone)
                {
                    //update global custom property
                    thisCatalogZone.SetAllowQueryProperty(GetQueryAccessACL());
                }
                else if (!Disabled && ((this is PrimaryZone) || (this is StubZone) || (this is ForwarderZone)))
                {
                    CatalogZone catalogZone = CatalogZone;
                    if (catalogZone is not null)
                    {
                        if (_overrideCatalogQueryAccess)
                            catalogZone.SetAllowQueryProperty(GetQueryAccessACL(), _name); //update member zone custom property
                        else
                            catalogZone.SetAllowQueryProperty(null, _name); //remove member zone custom property
                    }
                }
            }
        }

        public IReadOnlyCollection<NetworkAccessControl> QueryAccessNetworkACL
        {
            get { return _queryAccessNetworkACL; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _queryAccessNetworkACL = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(QueryAccessNetworkACL), "Network ACL cannot have more than 255 entries.");
                else
                    _queryAccessNetworkACL = value;
            }
        }

        public virtual AuthZoneTransfer ZoneTransfer
        {
            get { return _zoneTransfer; }
            set
            {
                _zoneTransfer = value;

                //update catalog zone property
                if (this is CatalogZone thisCatalogZone)
                {
                    //update global custom property
                    thisCatalogZone.SetAllowTransferProperty(GetZoneTranferACL());
                }
                else if (!Disabled && (this is PrimaryZone))
                {
                    CatalogZone catalogZone = CatalogZone;
                    if (catalogZone is not null)
                    {
                        if (_overrideCatalogZoneTransfer)
                            catalogZone.SetAllowTransferProperty(GetZoneTranferACL(), _name); //update member zone custom property
                        else
                            catalogZone.SetAllowTransferProperty(null, _name); //remove member zone custom property
                    }
                }
            }
        }

        public IReadOnlyCollection<NetworkAccessControl> ZoneTransferNetworkACL
        {
            get { return _zoneTransferNetworkACL; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _zoneTransferNetworkACL = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(ZoneTransferNetworkACL), "Network ACL cannot have more than 255 entries.");
                else
                    _zoneTransferNetworkACL = value;
            }
        }

        public IReadOnlySet<string> ZoneTransferTsigKeyNames
        {
            get { return _zoneTransferTsigKeyNames; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _zoneTransferTsigKeyNames = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(ZoneTransferTsigKeyNames), "Zone transfer TSIG key names cannot have more than 255 entries.");
                else
                    _zoneTransferTsigKeyNames = value;

                //update catalog zone property
                if (this is CatalogZone thisCatalogZone)
                {
                    //update global custom property
                    thisCatalogZone.SetZoneTransferTsigKeyNamesProperty(_zoneTransferTsigKeyNames);
                }
                else if (!Disabled && (this is PrimaryZone))
                {
                    CatalogZone catalogZone = CatalogZone;
                    if (catalogZone is not null)
                    {
                        if (_overrideCatalogZoneTransfer)
                            catalogZone.SetZoneTransferTsigKeyNamesProperty(_zoneTransferTsigKeyNames, _name); //update member zone custom property
                        else
                            catalogZone.SetZoneTransferTsigKeyNamesProperty(null, _name); //remove member zone custom property
                    }
                }
            }
        }

        public virtual AuthZoneNotify Notify
        {
            get { return _notify; }
            set
            {
                _notify = value;

                lock (_notifyFailed)
                {
                    _notifyFailed.Clear();
                }
            }
        }

        public IReadOnlyCollection<IPAddress> NotifyNameServers
        {
            get { return _notifyNameServers; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _notifyNameServers = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(NotifyNameServers), "Name server addresses cannot have more than 255 entries.");
                else
                    _notifyNameServers = value;

                lock (_notifyFailed)
                {
                    _notifyFailed.Clear();
                }
            }
        }

        public IReadOnlyCollection<IPAddress> NotifySecondaryCatalogNameServers
        {
            get { return _notifySecondaryCatalogNameServers; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _notifySecondaryCatalogNameServers = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(NotifySecondaryCatalogNameServers), "Secondary Catalog name server addresses cannot have more than 255 entries.");
                else
                    _notifySecondaryCatalogNameServers = value;

                lock (_notifyFailed)
                {
                    _notifyFailed.Clear();
                }
            }
        }

        public virtual AuthZoneUpdate Update
        {
            get { return _update; }
            set { _update = value; }
        }

        public IReadOnlyCollection<NetworkAccessControl> UpdateNetworkACL
        {
            get { return _updateNetworkACL; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _updateNetworkACL = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(UpdateNetworkACL), "Network ACL cannot have more than 255 entries.");
                else
                    _updateNetworkACL = value;
            }
        }

        public IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> UpdateSecurityPolicies
        {
            get { return _updateSecurityPolicies; }
            set { _updateSecurityPolicies = value; }
        }

        public AuthZoneDnssecStatus DnssecStatus
        { get { return _dnssecStatus; } }

        public string[] NotifyFailed
        {
            get
            {
                if (_notifyFailed is null)
                    return Array.Empty<string>();

                lock (_notifyFailed)
                {
                    if (_notifyFailed.Count > 0)
                        return _notifyFailed.ToArray();

                    return Array.Empty<string>();
                }
            }
        }

        public bool SyncFailed
        { get { return _syncFailed; } }

        public CatalogZone CatalogZone
        {
            get
            {
                if (_catalogZoneName is null)
                    return null;

                if (_secondaryCatalogZone is not null)
                    return null;

                if (_catalogZone is null)
                {
                    if ((this is PrimaryZone) || (this is ForwarderZone))
                    {
                        ApexZone apexZone = _dnsServer.AuthZoneManager.GetApexZone(_catalogZoneName);
                        if (apexZone is CatalogZone catalogZone)
                            _catalogZone = catalogZone;
                    }
                    else if (this is StubZone)
                    {
                        ApexZone apexZone = _dnsServer.AuthZoneManager.GetApexZone(_catalogZoneName);
                        if (apexZone is CatalogZone catalogZone)
                            _catalogZone = catalogZone;
                        else if (apexZone is SecondaryCatalogZone secondaryCatalogZone)
                            _secondaryCatalogZone = secondaryCatalogZone;
                    }
                }

                return _catalogZone;
            }
        }

        public SecondaryCatalogZone SecondaryCatalogZone
        {
            get
            {
                if (_catalogZoneName is null)
                    return null;

                if (_catalogZone is not null)
                    return null;

                if (_secondaryCatalogZone is null)
                {
                    if (this is SecondaryZone)
                    {
                        ApexZone apexZone = _dnsServer.AuthZoneManager.GetApexZone(_catalogZoneName);
                        if (apexZone is SecondaryCatalogZone secondaryCatalogZone)
                            _secondaryCatalogZone = secondaryCatalogZone;
                    }
                    else if (this is StubZone)
                    {
                        ApexZone apexZone = _dnsServer.AuthZoneManager.GetApexZone(_catalogZoneName);
                        if (apexZone is SecondaryCatalogZone secondaryCatalogZone)
                            _secondaryCatalogZone = secondaryCatalogZone;
                        else if (apexZone is CatalogZone catalogZone)
                            _catalogZone = catalogZone;
                    }
                }

                return _secondaryCatalogZone;
            }
        }

        #endregion
    }
}
