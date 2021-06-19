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

        DnsServer _dnsServer;

        readonly Timer _notifyTimer;
        const int NOTIFY_TIMER_INTERVAL = 10000;
        readonly List<NameServerAddress> _notifyList;

        const int NOTIFY_TIMEOUT = 10000;
        const int NOTIFY_RETRIES = 5;

        readonly object _refreshTimerLock = new object();
        Timer _refreshTimer;
        const int REFRESH_TIMER_INTERVAL = 5000;

        const int REFRESH_SOA_TIMEOUT = 10000;
        const int REFRESH_AXFR_TIMEOUT = 120000;
        const int REFRESH_RETRIES = 5;

        DateTime _expiry;
        bool _isExpired;

        #endregion

        #region constructor

        public SecondaryZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(zoneInfo)
        {
            _dnsServer = dnsServer;

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

            _zoneTransfer = AuthZoneTransfer.Deny;
            _notify = AuthZoneNotify.None;

            _notifyTimer = new Timer(NotifyTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
            _notifyList = new List<NameServerAddress>();
        }

        #endregion

        #region static

        public static async Task<SecondaryZone> CreateAsync(DnsServer dnsServer, string name, string primaryNameServerAddresses = null)
        {
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

                soaResponse = await dnsClient.ResolveAsync(soaQuestion);
            }

            if ((soaResponse.Answer.Count == 0) || (soaResponse.Answer[0].Type != DnsResourceRecordType.SOA))
                throw new DnsServerException("DNS Server failed to find SOA record for: " + name);

            DnsSOARecord receivedSoa = soaResponse.Answer[0].RDATA as DnsSOARecord;

            DnsSOARecord soa = new DnsSOARecord(receivedSoa.PrimaryNameServer, receivedSoa.ResponsiblePerson, receivedSoa.Serial - 1, receivedSoa.Refresh, receivedSoa.Retry, receivedSoa.Expire, receivedSoa.Minimum);
            DnsResourceRecord[] soaRR = new DnsResourceRecord[] { new DnsResourceRecord(secondaryZone._name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Refresh, soa) };

            if (!string.IsNullOrEmpty(primaryNameServerAddresses))
                soaRR[0].SetGlueRecords(primaryNameServerAddresses);

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
                                log.Write("DNS Server successfully notified name server for '" + _name + "' zone changes: " + nameServer.ToString());
                        }
                        break;

                    default:
                        {
                            //transaction failed
                            LogManager log = _dnsServer.LogManager;
                            if (log != null)
                                log.Write("DNS Server received RCODE=" + response.RCODE.ToString() + " from name server for '" + _name + "' zone notification: " + nameServer.ToString());
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                {
                    log.Write("DNS Server failed to notify name server for '" + _name + "' zone changes: " + nameServer.ToString());
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
            if (_disabled)
                return;

            try
            {
                _isExpired = DateTime.UtcNow > _expiry;

                //get primary name server addresses
                IReadOnlyList<NameServerAddress> primaryNameServers = await GetPrimaryNameServerAddressesAsync(_dnsServer);

                if (primaryNameServers.Count == 0)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server could not find primary name server IP addresses for secondary zone: " + _name);

                    //set timer for retry
                    DnsSOARecord soa1 = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                    _refreshTimer.Change(soa1.Retry * 1000, Timeout.Infinite);
                    return;
                }

                //refresh zone
                if (await RefreshZoneAsync(primaryNameServers))
                {
                    //zone refreshed; set timer for refresh
                    DnsSOARecord latestSoa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                    _refreshTimer.Change(latestSoa.Refresh * 1000, Timeout.Infinite);

                    _expiry = DateTime.UtcNow.AddSeconds(latestSoa.Expire);
                    _isExpired = false;
                    _dnsServer.AuthZoneManager.SaveZoneFile(_name);
                    return;
                }

                //no response from any of the name servers; set timer for retry
                DnsSOARecord soa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                _refreshTimer.Change(soa.Retry * 1000, Timeout.Infinite);
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write(ex);

                //set timer for retry
                lock (_refreshTimerLock)
                {
                    if (_refreshTimer != null)
                    {
                        DnsSOARecord soa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                        _refreshTimer.Change(soa.Retry * 1000, Timeout.Infinite);
                    }
                }
            }
        }

        private async Task<bool> RefreshZoneAsync(IReadOnlyList<NameServerAddress> primaryNameServers)
        {
            try
            {
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server has started zone refresh for secondary zone: " + _name);
                }

                DnsClient client = new DnsClient(primaryNameServers);

                client.Proxy = _dnsServer.Proxy;
                client.PreferIPv6 = _dnsServer.PreferIPv6;
                client.Timeout = REFRESH_SOA_TIMEOUT;
                client.Retries = REFRESH_RETRIES;

                DnsDatagram soaRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN) });
                DnsDatagram soaResponse = await client.ResolveAsync(soaRequest);

                if (soaResponse.RCODE != DnsResponseCode.NoError)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received RCODE=" + soaResponse.RCODE.ToString() + " for '" + _name + "' secondary zone refresh from: " + soaResponse.Metadata.NameServerAddress.ToString());

                    return false;
                }

                if (soaResponse.Answer.Count < 1)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received an empty response for SOA query for '" + _name + "' secondary zone refresh from: " + soaResponse.Metadata.NameServerAddress.ToString());

                    return false;
                }

                DnsSOARecord currentSoaRecord = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                DnsSOARecord receivedSoaRecord = soaResponse.Answer[0].RDATA as DnsSOARecord;

                //compare using sequence space arithmetic
                if (!currentSoaRecord.IsZoneUpdateAvailable(receivedSoaRecord))
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server successfully checked for update to '" + _name + "' secondary zone from: " + soaResponse.Metadata.NameServerAddress.ToString());

                    return true;
                }

                //update available; do zone transfer with TCP transport
                List<NameServerAddress> tcpNameServers = new List<NameServerAddress>();

                foreach (NameServerAddress nameServer in primaryNameServers)
                    tcpNameServers.Add(new NameServerAddress(nameServer, DnsTransportProtocol.Tcp));

                primaryNameServers = tcpNameServers;
                client = new DnsClient(primaryNameServers);

                client.Proxy = _dnsServer.Proxy;
                client.PreferIPv6 = _dnsServer.PreferIPv6;
                client.Timeout = REFRESH_AXFR_TIMEOUT;
                client.Retries = REFRESH_RETRIES;

                DnsDatagram axfrRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.AXFR, DnsClass.IN) });
                DnsDatagram axfrResponse = await client.ResolveAsync(axfrRequest);

                if (axfrResponse.RCODE != DnsResponseCode.NoError)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received RCODE=" + axfrResponse.RCODE.ToString() + " for '" + _name + "' secondary zone transfer from: " + axfrResponse.Metadata.NameServerAddress.ToString());

                    return false;
                }

                if (axfrResponse.Answer.Count < 1)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received an empty response for AXFR query for '" + _name + "' secondary zone from: " + axfrResponse.Metadata.NameServerAddress.ToString());

                    return false;
                }

                DnsSOARecord axfrSoaRecord = axfrResponse.Answer[0].RDATA as DnsSOARecord;
                if (axfrSoaRecord == null)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received invalid response for AXFR query for '" + _name + "' secondary zone from: " + axfrResponse.Metadata.NameServerAddress.ToString());

                    return false;
                }

                if (currentSoaRecord.IsZoneUpdateAvailable(axfrSoaRecord))
                {
                    _dnsServer.AuthZoneManager.SyncRecords(_name, axfrResponse.Answer);

                    //trigger notify
                    TriggerNotify();

                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server successfully refreshed '" + _name + "' secondary zone from: " + axfrResponse.Metadata.NameServerAddress.ToString());
                }
                else
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server successfully checked for update to '" + _name + "' secondary zone from: " + soaResponse.Metadata.NameServerAddress.ToString());
                }

                return true;
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

                    log.Write("DNS Server failed to refresh '" + _name + "' secondary zone from: " + strNameServers);
                    log.Write(ex);
                }

                return false;
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

            _notifyTimer.Change(NOTIFY_TIMER_INTERVAL, Timeout.Infinite);
        }

        public void TriggerRefresh()
        {
            if (_disabled)
                return;

            _refreshTimer.Change(REFRESH_TIMER_INTERVAL, Timeout.Infinite);
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.SOA:
                    if ((records.Count != 1) || !records[0].Name.Equals(_name, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Invalid SOA record.");

                    DnsResourceRecord existingSoaRR = _entries[DnsResourceRecordType.SOA][0];

                    existingSoaRR.SetGlueRecords(records.GetGlueRecords());
                    existingSoaRR.SetComments(records[0].GetComments());
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
                        _refreshTimer.Change(Timeout.Infinite, Timeout.Infinite);
                    else
                        TriggerRefresh();
                }
            }
        }

        public override bool IsActive
        {
            get { return !_disabled && !_isExpired; }
        }

        #endregion
    }
}
