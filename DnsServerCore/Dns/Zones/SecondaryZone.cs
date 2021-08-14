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
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class SecondaryZone : AuthZone
    {
        #region variables

        readonly DnsServer _dnsServer;

        readonly List<DnsResourceRecord> _history; //for IXFR support
        IReadOnlyDictionary<string, object> _tsigKeyNames;

        readonly Timer _notifyTimer;
        bool _notifyTimerTriggered;
        const int NOTIFY_TIMER_INTERVAL = 10000;
        readonly List<NameServerAddress> _notifyList;

        const int NOTIFY_TIMEOUT = 10000;
        const int NOTIFY_RETRIES = 5;

        readonly object _refreshTimerLock = new object();
        Timer _refreshTimer;
        bool _refreshTimerTriggered;
        const int REFRESH_TIMER_INTERVAL = 5000;

        const int REFRESH_SOA_TIMEOUT = 10000;
        const int REFRESH_XFR_TIMEOUT = 120000;
        const int REFRESH_RETRIES = 5;

        const int REFRESH_TSIG_FUDGE = 300;

        DateTime _expiry;
        bool _isExpired;

        bool _resync;

        #endregion

        #region constructor

        public SecondaryZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(zoneInfo)
        {
            _dnsServer = dnsServer;

            if (zoneInfo.ZoneHistory is null)
                _history = new List<DnsResourceRecord>();
            else
                _history = new List<DnsResourceRecord>(zoneInfo.ZoneHistory);

            _tsigKeyNames = zoneInfo.TsigKeyNames;

            _expiry = zoneInfo.Expiry;

            _isExpired = DateTime.UtcNow > _expiry;
            _refreshTimer = new Timer(RefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);

            _notifyTimer = new Timer(NotifyTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
            _notifyList = new List<NameServerAddress>();
        }

        private SecondaryZone(DnsServer dnsServer, string name)
            : base(name)
        {
            _dnsServer = dnsServer;

            _history = new List<DnsResourceRecord>();

            _zoneTransfer = AuthZoneTransfer.Deny;
            _notify = AuthZoneNotify.None;

            _notifyTimer = new Timer(NotifyTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
            _notifyList = new List<NameServerAddress>();
        }

        #endregion

        #region static

        public static async Task<SecondaryZone> CreateAsync(DnsServer dnsServer, string name, string primaryNameServerAddresses = null, DnsTransportProtocol zoneTransferProtocol = DnsTransportProtocol.Tcp, string tsigKeyName = null)
        {
            switch (zoneTransferProtocol)
            {
                case DnsTransportProtocol.Tcp:
                case DnsTransportProtocol.Tls:
                    break;

                default:
                    throw new NotSupportedException("Zone transfer protocol is not supported: XFR-over-" + zoneTransferProtocol.ToString().ToUpper());
            }

            SecondaryZone secondaryZone = new SecondaryZone(dnsServer, name);

            DnsQuestionRecord soaQuestion = new DnsQuestionRecord(name, DnsResourceRecordType.SOA, DnsClass.IN);
            DnsDatagram soaResponse;

            if (primaryNameServerAddresses == null)
            {
                soaResponse = await secondaryZone._dnsServer.DirectQueryAsync(soaQuestion).WithTimeout(2000);
            }
            else
            {
                DnsClient dnsClient = new DnsClient(primaryNameServerAddresses);

                dnsClient.Proxy = secondaryZone._dnsServer.Proxy;
                dnsClient.PreferIPv6 = secondaryZone._dnsServer.PreferIPv6;

                if (string.IsNullOrEmpty(tsigKeyName))
                    soaResponse = await dnsClient.ResolveAsync(soaQuestion);
                else if ((dnsServer.TsigKeys is not null) && dnsServer.TsigKeys.TryGetValue(tsigKeyName, out TsigKey key))
                    soaResponse = await dnsClient.ResolveAsync(soaQuestion, key, REFRESH_TSIG_FUDGE);
                else
                    throw new DnsServerException("No such TSIG key was found configured: " + tsigKeyName);
            }

            if ((soaResponse.Answer.Count == 0) || (soaResponse.Answer[0].Type != DnsResourceRecordType.SOA))
                throw new DnsServerException("DNS Server failed to find SOA record for: " + name);

            DnsSOARecord receivedSoa = soaResponse.Answer[0].RDATA as DnsSOARecord;

            DnsSOARecord soa = new DnsSOARecord(receivedSoa.PrimaryNameServer, receivedSoa.ResponsiblePerson, 0u, receivedSoa.Refresh, receivedSoa.Retry, receivedSoa.Expire, receivedSoa.Minimum);
            DnsResourceRecord[] soaRR = new DnsResourceRecord[] { new DnsResourceRecord(secondaryZone._name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Refresh, soa) };

            if (!string.IsNullOrEmpty(primaryNameServerAddresses))
                soaRR[0].SetPrimaryNameServers(primaryNameServerAddresses);

            DnsResourceRecordInfo recordInfo = soaRR[0].GetRecordInfo();

            recordInfo.ZoneTransferProtocol = zoneTransferProtocol;
            recordInfo.TsigKeyName = tsigKeyName;

            secondaryZone._entries[DnsResourceRecordType.SOA] = soaRR;

            secondaryZone._isExpired = true; //new secondary zone is considered expired till it refreshes
            secondaryZone._refreshTimer = new Timer(secondaryZone.RefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);

            return secondaryZone;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_notifyTimer is not null)
                    _notifyTimer.Dispose();

                lock (_refreshTimerLock)
                {
                    if (_refreshTimer != null)
                    {
                        _refreshTimer.Dispose();
                        _refreshTimer = null;
                    }
                }
            }

            _disposed = true;
        }

        #endregion

        #region private

        private async void NotifyTimerCallback(object state)
        {
            try
            {
                switch (_notify)
                {
                    case AuthZoneNotify.ZoneNameServers:
                        IReadOnlyList<NameServerAddress> secondaryNameServers = await GetSecondaryNameServerAddressesAsync(_dnsServer);

                        foreach (NameServerAddress secondaryNameServer in secondaryNameServers)
                            _ = NotifyNameServerAsync(secondaryNameServer);

                        break;

                    case AuthZoneNotify.SpecifiedNameServers:
                        IReadOnlyCollection<IPAddress> specifiedNameServers = _notifyNameServers;
                        if (specifiedNameServers is not null)
                        {
                            foreach (IPAddress specifiedNameServer in specifiedNameServers)
                                _ = NotifyNameServerAsync(new NameServerAddress(specifiedNameServer));
                        }

                        break;

                    default:
                        return;
                }
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write(ex);
            }
            finally
            {
                _notifyTimerTriggered = false;
            }
        }

        private async Task NotifyNameServerAsync(NameServerAddress nameServer)
        {
            //use notify list to prevent multiple threads from notifying the same name server
            lock (_notifyList)
            {
                if (_notifyList.Contains(nameServer))
                    return; //already notifying the name server in another thread

                _notifyList.Add(nameServer);
            }

            try
            {
                DnsClient client = new DnsClient(nameServer);

                client.Proxy = _dnsServer.Proxy;
                client.Timeout = NOTIFY_TIMEOUT;
                client.Retries = NOTIFY_RETRIES;

                DnsDatagram notifyRequest = new DnsDatagram(0, false, DnsOpcode.Notify, true, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN) }, _entries[DnsResourceRecordType.SOA]);
                DnsDatagram response = await client.ResolveAsync(notifyRequest);

                switch (response.RCODE)
                {
                    case DnsResponseCode.NoError:
                    case DnsResponseCode.NotImplemented:
                        {
                            //transaction complete
                            LogManager log = _dnsServer.LogManager;
                            if (log != null)
                                log.Write("DNS Server successfully notified name server for '" + (_name == "" ? "<root>" : _name) + "' zone changes: " + nameServer.ToString());
                        }
                        break;

                    default:
                        {
                            //transaction failed
                            LogManager log = _dnsServer.LogManager;
                            if (log != null)
                                log.Write("DNS Server received RCODE=" + response.RCODE.ToString() + " from name server for '" + (_name == "" ? "<root>" : _name) + "' zone notification: " + nameServer.ToString());
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                {
                    log.Write("DNS Server failed to notify name server for '" + (_name == "" ? "<root>" : _name) + "' zone changes: " + nameServer.ToString());
                    log.Write(ex);
                }
            }
            finally
            {
                lock (_notifyList)
                {
                    _notifyList.Remove(nameServer);
                }
            }
        }

        private async void RefreshTimerCallback(object state)
        {
            try
            {
                if (_disabled && !_resync)
                    return;

                _isExpired = DateTime.UtcNow > _expiry;

                //get primary name server addresses
                IReadOnlyList<NameServerAddress> primaryNameServers = await GetPrimaryNameServerAddressesAsync(_dnsServer);

                DnsResourceRecord currentSoaRecord = _entries[DnsResourceRecordType.SOA][0];
                DnsSOARecord currentSoa = currentSoaRecord.RDATA as DnsSOARecord;

                if (primaryNameServers.Count == 0)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server could not find primary name server IP addresses for secondary zone: " + (_name == "" ? "<root>" : _name));

                    //set timer for retry
                    ResetRefreshTimer(currentSoa.Retry * 1000);
                    return;
                }

                DnsResourceRecordInfo recordInfo = currentSoaRecord.GetRecordInfo();
                TsigKey key = null;

                if (!string.IsNullOrEmpty(recordInfo.TsigKeyName) && ((_dnsServer.TsigKeys is null) || !_dnsServer.TsigKeys.TryGetValue(recordInfo.TsigKeyName, out key)))
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server does not have TSIG key '" + recordInfo.TsigKeyName + "' configured for refreshing secondary zone: " + (_name == "" ? "<root>" : _name));

                    //set timer for retry
                    ResetRefreshTimer(currentSoa.Retry * 1000);
                    return;
                }

                //refresh zone
                if (await RefreshZoneAsync(primaryNameServers, recordInfo.ZoneTransferProtocol, key))
                {
                    //zone refreshed; set timer for refresh
                    DnsSOARecord latestSoa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                    ResetRefreshTimer(latestSoa.Refresh * 1000);

                    _expiry = DateTime.UtcNow.AddSeconds(latestSoa.Expire);
                    _isExpired = false;
                    _resync = false;
                    _dnsServer.AuthZoneManager.SaveZoneFile(_name);
                    return;
                }

                //no response from any of the name servers; set timer for retry
                DnsSOARecord soa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                ResetRefreshTimer(soa.Retry * 1000);
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write(ex);

                //set timer for retry
                DnsSOARecord soa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                ResetRefreshTimer(soa.Retry * 1000);
            }
            finally
            {
                _refreshTimerTriggered = false;
            }
        }

        private void ResetRefreshTimer(long dueTime)
        {
            lock (_refreshTimerLock)
            {
                if (_refreshTimer != null)
                    _refreshTimer.Change(dueTime, Timeout.Infinite);
            }
        }

        private async Task<bool> RefreshZoneAsync(IReadOnlyList<NameServerAddress> primaryNameServers, DnsTransportProtocol zoneTransferProtocol, TsigKey key)
        {
            try
            {
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server has started zone refresh for secondary zone: " + (_name == "" ? "<root>" : _name));
                }

                DnsResourceRecord currentSoaRecord = _entries[DnsResourceRecordType.SOA][0];
                DnsSOARecord currentSoa = currentSoaRecord.RDATA as DnsSOARecord;

                if (!_resync)
                {
                    DnsClient client = new DnsClient(primaryNameServers);

                    client.Proxy = _dnsServer.Proxy;
                    client.PreferIPv6 = _dnsServer.PreferIPv6;
                    client.Timeout = REFRESH_SOA_TIMEOUT;
                    client.Retries = REFRESH_RETRIES;
                    client.Concurrency = 1;

                    DnsDatagram soaRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN) });
                    DnsDatagram soaResponse;

                    if (key is null)
                        soaResponse = await client.ResolveAsync(soaRequest);
                    else
                        soaResponse = await client.ResolveAsync(soaRequest, key, REFRESH_TSIG_FUDGE);

                    if (soaResponse.RCODE != DnsResponseCode.NoError)
                    {
                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write("DNS Server received RCODE=" + soaResponse.RCODE.ToString() + " for '" + (_name == "" ? "<root>" : _name) + "' secondary zone refresh from: " + soaResponse.Metadata.NameServerAddress.ToString());

                        return false;
                    }

                    if ((soaResponse.Answer.Count < 1) || (soaResponse.Answer[0].Type != DnsResourceRecordType.SOA) || !_name.Equals(soaResponse.Answer[0].Name, StringComparison.OrdinalIgnoreCase))
                    {
                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write("DNS Server received an empty response for SOA query for '" + (_name == "" ? "<root>" : _name) + "' secondary zone refresh from: " + soaResponse.Metadata.NameServerAddress.ToString());

                        return false;
                    }

                    DnsResourceRecord receivedSoaRecord = soaResponse.Answer[0];
                    DnsSOARecord receivedSoa = receivedSoaRecord.RDATA as DnsSOARecord;

                    //compare using sequence space arithmetic
                    if (!currentSoa.IsZoneUpdateAvailable(receivedSoa))
                    {
                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write("DNS Server successfully checked for '" + (_name == "" ? "<root>" : _name) + "' secondary zone update from: " + soaResponse.Metadata.NameServerAddress.ToString());

                        return true;
                    }
                }

                //update available; do zone transfer with TLS or TCP transport

                if (zoneTransferProtocol == DnsTransportProtocol.Tls)
                {
                    //change name server protocol to TLS
                    List<NameServerAddress> tlsNameServers = new List<NameServerAddress>(primaryNameServers.Count);

                    foreach (NameServerAddress primaryNameServer in primaryNameServers)
                    {
                        if (primaryNameServer.Protocol == DnsTransportProtocol.Tls)
                            tlsNameServers.Add(primaryNameServer);
                        else
                            tlsNameServers.Add(primaryNameServer.ChangeProtocol(DnsTransportProtocol.Tls));
                    }

                    primaryNameServers = tlsNameServers;
                }
                else
                {
                    //change name server protocol to TCP
                    List<NameServerAddress> tcpNameServers = new List<NameServerAddress>(primaryNameServers.Count);

                    foreach (NameServerAddress primaryNameServer in primaryNameServers)
                    {
                        if (primaryNameServer.Protocol == DnsTransportProtocol.Tcp)
                            tcpNameServers.Add(primaryNameServer);
                        else
                            tcpNameServers.Add(primaryNameServer.ChangeProtocol(DnsTransportProtocol.Tcp));
                    }

                    primaryNameServers = tcpNameServers;
                }

                DnsClient xfrClient = new DnsClient(primaryNameServers);

                xfrClient.Proxy = _dnsServer.Proxy;
                xfrClient.PreferIPv6 = _dnsServer.PreferIPv6;
                xfrClient.Timeout = REFRESH_XFR_TIMEOUT;
                xfrClient.Retries = REFRESH_RETRIES;
                xfrClient.Concurrency = 1;

                bool doIXFR = !_isExpired && !_resync;

                while (true)
                {
                    DnsQuestionRecord xfrQuestion;
                    IReadOnlyList<DnsResourceRecord> xfrAuthority;

                    if (doIXFR)
                    {
                        xfrQuestion = new DnsQuestionRecord(_name, DnsResourceRecordType.IXFR, DnsClass.IN);
                        xfrAuthority = new DnsResourceRecord[] { currentSoaRecord };
                    }
                    else
                    {
                        xfrQuestion = new DnsQuestionRecord(_name, DnsResourceRecordType.AXFR, DnsClass.IN);
                        xfrAuthority = null;
                    }

                    DnsDatagram xfrRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { xfrQuestion }, null, xfrAuthority);

                    DnsDatagram xfrResponse;

                    if (key is null)
                        xfrResponse = await xfrClient.ResolveAsync(xfrRequest);
                    else
                        xfrResponse = await xfrClient.ResolveAsync(xfrRequest, key, REFRESH_TSIG_FUDGE);

                    if (doIXFR && (xfrResponse.RCODE == DnsResponseCode.NotImplemented))
                    {
                        doIXFR = false;
                        continue;
                    }

                    if (xfrResponse.RCODE != DnsResponseCode.NoError)
                    {
                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write("DNS Server received a zone transfer response (RCODE=" + xfrResponse.RCODE.ToString() + ") for '" + (_name == "" ? "<root>" : _name) + "' secondary zone from: " + xfrResponse.Metadata.NameServerAddress.ToString());

                        return false;
                    }

                    if (xfrResponse.Answer.Count < 1)
                    {
                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write("DNS Server received an empty response for zone transfer query for '" + (_name == "" ? "<root>" : _name) + "' secondary zone from: " + xfrResponse.Metadata.NameServerAddress.ToString());

                        return false;
                    }

                    if (!_name.Equals(xfrResponse.Answer[0].Name, StringComparison.OrdinalIgnoreCase) || (xfrResponse.Answer[0].Type != DnsResourceRecordType.SOA) || (xfrResponse.Answer[0].RDATA is not DnsSOARecord xfrSoa))
                    {
                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write("DNS Server received invalid response for zone transfer query for '" + (_name == "" ? "<root>" : _name) + "' secondary zone from: " + xfrResponse.Metadata.NameServerAddress.ToString());

                        return false;
                    }

                    if (_resync || currentSoa.IsZoneUpdateAvailable(xfrSoa))
                    {
                        xfrResponse = xfrResponse.Join(); //join multi message response

                        if (doIXFR)
                        {
                            IReadOnlyList<DnsResourceRecord> historyRecords = _dnsServer.AuthZoneManager.SyncIncrementalZoneTransferRecords(_name, xfrResponse.Answer);
                            if (historyRecords.Count > 0)
                                CommitHistory(historyRecords);
                            else
                                ClearHistory(); //AXFR response was received
                        }
                        else
                        {
                            _dnsServer.AuthZoneManager.SyncZoneTransferRecords(_name, xfrResponse.Answer);
                            ClearHistory();
                        }

                        //trigger notify
                        TriggerNotify();

                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write("DNS Server successfully refreshed '" + (_name == "" ? "<root>" : _name) + "' secondary zone from: " + xfrResponse.Metadata.NameServerAddress.ToString());
                    }
                    else
                    {
                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write("DNS Server successfully checked for '" + (_name == "" ? "<root>" : _name) + "' secondary zone update from: " + xfrResponse.Metadata.NameServerAddress.ToString());
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                {
                    string strNameServers = null;

                    foreach (NameServerAddress nameServer in primaryNameServers)
                    {
                        if (strNameServers == null)
                            strNameServers = nameServer.ToString();
                        else
                            strNameServers += ", " + nameServer.ToString();
                    }

                    log.Write("DNS Server failed to refresh '" + (_name == "" ? "<root>" : _name) + "' secondary zone from: " + strNameServers);
                    log.Write(ex);
                }

                return false;
            }
        }

        private void CommitHistory(IReadOnlyList<DnsResourceRecord> historyRecords)
        {
            lock (_history)
            {
                historyRecords[0].SetDeletedOn(DateTime.UtcNow);

                //write history
                _history.AddRange(historyRecords);

                CleanupHistory(_history);
            }
        }

        private void ClearHistory()
        {
            lock (_history)
            {
                _history.Clear();
            }
        }

        #endregion

        #region public

        public void TriggerNotify()
        {
            if (_disabled)
                return;

            if (_notify == AuthZoneNotify.None)
                return;

            if (_notifyTimerTriggered)
                return;

            _notifyTimer.Change(NOTIFY_TIMER_INTERVAL, Timeout.Infinite);
            _notifyTimerTriggered = true;
        }

        public void TriggerRefresh(int refreshInterval = REFRESH_TIMER_INTERVAL)
        {
            if (_disabled)
                return;

            if (_refreshTimerTriggered)
                return;

            _refreshTimerTriggered = true;
            ResetRefreshTimer(refreshInterval);
        }

        public void TriggerResync()
        {
            if (_refreshTimerTriggered)
                return;

            _resync = true;

            _refreshTimerTriggered = true;
            ResetRefreshTimer(0);
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.SOA:
                    if ((records.Count != 1) || !records[0].Name.Equals(_name, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Invalid SOA record.");

                    DnsResourceRecord existingSoaRecord = _entries[DnsResourceRecordType.SOA][0];
                    DnsResourceRecord newSoaRecord = records[0];

                    existingSoaRecord.CopyRecordInfoFrom(newSoaRecord);
                    break;

                default:
                    throw new InvalidOperationException("Cannot set records in secondary zone.");
            }
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            throw new InvalidOperationException("Cannot add record in secondary zone.");
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            throw new InvalidOperationException("Cannot delete record in secondary zone.");
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            throw new InvalidOperationException("Cannot delete records in secondary zone.");
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            throw new InvalidOperationException("Cannot update record in secondary zone.");
        }

        public IReadOnlyList<DnsResourceRecord> GetHistory()
        {
            lock (_history)
            {
                return _history.ToArray();
            }
        }

        #endregion

        #region properties

        public DateTime Expiry
        { get { return _expiry; } }

        public bool IsExpired
        { get { return _isExpired; } }

        public override bool Disabled
        {
            get { return _disabled; }
            set
            {
                if (_disabled != value)
                {
                    _disabled = value;

                    if (_disabled)
                        ResetRefreshTimer(Timeout.Infinite);
                    else
                        TriggerRefresh();
                }
            }
        }

        public override bool IsActive
        {
            get { return !_disabled && !_isExpired; }
        }

        public IReadOnlyDictionary<string, object> TsigKeyNames
        {
            get { return _tsigKeyNames; }
            set { _tsigKeyNames = value; }
        }

        #endregion
    }
}
