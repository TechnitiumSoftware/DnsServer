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
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class StubZone : ApexZone
    {
        #region variables

        readonly object _refreshTimerLock = new object();
        Timer _refreshTimer;
        bool _refreshTimerTriggered;
        const int REFRESH_TIMER_INTERVAL = 5000;

        const int REFRESH_TIMEOUT = 10000;
        const int REFRESH_RETRIES = 5;

        IReadOnlyList<NameServerAddress> _primaryNameServerAddresses;

        DateTime _expiry;
        bool _isExpired;

        bool _resync;

        #endregion

        #region constructor

        public StubZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(dnsServer, zoneInfo)
        {
            _primaryNameServerAddresses = zoneInfo.PrimaryNameServerAddresses;

            _expiry = zoneInfo.Expiry;
            _isExpired = DateTime.UtcNow > _expiry;

            _refreshTimer = new Timer(RefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
        }

        private StubZone(DnsServer dnsServer, string name, IReadOnlyList<NameServerAddress> primaryNameServerAddresses)
            : base(dnsServer, name)
        {
            PrimaryNameServerAddresses = primaryNameServerAddresses?.Convert(delegate (NameServerAddress nameServer)
            {
                if (nameServer.Protocol != DnsTransportProtocol.Udp)
                    nameServer = nameServer.ChangeProtocol(DnsTransportProtocol.Udp);

                return nameServer;
            });

            _isExpired = true; //new stub zone is considered expired till it refreshes

            _refreshTimer = new Timer(RefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
        }

        #endregion

        #region static

        public static async Task<StubZone> CreateAsync(DnsServer dnsServer, string name, IReadOnlyList<NameServerAddress> primaryNameServerAddresses = null, bool ignoreSoaFailure = false)
        {
            StubZone stubZone = new StubZone(dnsServer, name, primaryNameServerAddresses);

            try
            {
                DnsDatagram soaResponse;

                DnsQuestionRecord soaQuestion = new DnsQuestionRecord(name, DnsResourceRecordType.SOA, DnsClass.IN);

                if (stubZone.PrimaryNameServerAddresses is null)
                {
                    soaResponse = await stubZone._dnsServer.DirectQueryAsync(soaQuestion);
                }
                else
                {
                    DnsClient dnsClient = new DnsClient(stubZone.PrimaryNameServerAddresses);
                    List<Task> tasks = new List<Task>(dnsClient.Servers.Count);

                    foreach (NameServerAddress nameServerAddress in dnsClient.Servers)
                    {
                        if (nameServerAddress.IsIPEndPointStale)
                            tasks.Add(nameServerAddress.ResolveIPAddressAsync(stubZone._dnsServer, stubZone._dnsServer.PreferIPv6));
                    }

                    await Task.WhenAll(tasks);

                    dnsClient.Proxy = stubZone._dnsServer.Proxy;
                    dnsClient.PreferIPv6 = stubZone._dnsServer.PreferIPv6;

                    DnsDatagram soaRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [soaQuestion], null, null, null, dnsServer.UdpPayloadSize);

                    soaResponse = await dnsClient.RawResolveAsync(soaRequest);
                }

                if ((soaResponse.Answer.Count == 0) || (soaResponse.Answer[0].Type != DnsResourceRecordType.SOA))
                    throw new DnsServerException("DNS Server did not receive SOA record in response from any of the primary name servers for: " + name);

                DnsResourceRecord receivedSoaRecord = soaResponse.Answer[0];
                DnsSOARecordData receivedSoa = receivedSoaRecord.RDATA as DnsSOARecordData;

                DnsSOARecordData soa = new DnsSOARecordData(receivedSoa.PrimaryNameServer, receivedSoa.ResponsiblePerson, 0u, receivedSoa.Refresh, receivedSoa.Retry, receivedSoa.Expire, receivedSoa.Minimum);
                DnsResourceRecord soaRecord = new DnsResourceRecord(stubZone._name, DnsResourceRecordType.SOA, DnsClass.IN, receivedSoaRecord.TTL, soa);

                stubZone._entries[DnsResourceRecordType.SOA] = [soaRecord];
            }
            catch
            {
                if (!ignoreSoaFailure)
                    throw;

                //continue with dummy SOA
                DnsSOARecordData soa = new DnsSOARecordData(stubZone._dnsServer.ServerDomain, "invalid", 0, 300, 60, 604800, 900);
                DnsResourceRecord soaRecord = new DnsResourceRecord(stubZone._name, DnsResourceRecordType.SOA, DnsClass.IN, 0, soa);
                soaRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

                stubZone._entries[DnsResourceRecordType.SOA] = [soaRecord];
            }

            return stubZone;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        protected override void Dispose(bool disposing)
        {
            try
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
            finally
            {
                base.Dispose(disposing);
            }
        }

        #endregion

        #region private

        private void RefreshTimerCallback(object state)
        {
            //refresh zone in DNS server's resolver thread pool
            if (!_dnsServer.TryQueueResolverTask(async delegate (object state)
            {
                try
                {
                    if (Disabled && !_resync)
                        return;

                    _isExpired = DateTime.UtcNow > _expiry;

                    //get primary name server addresses
                    IReadOnlyList<NameServerAddress> primaryNameServers = await GetResolvedPrimaryNameServerAddressesAsync();

                    if (primaryNameServers.Count == 0)
                    {
                        _dnsServer.LogManager.Write("DNS Server could not find primary name server IP addresses for Stub zone: " + ToString());

                        //set timer for retry
                        ResetRefreshTimer(Math.Max(GetZoneSoaRetry(), _dnsServer.AuthZoneManager.MinSoaRetry) * 1000);
                        _syncFailed = true;
                        return;
                    }

                    //refresh zone
                    if (await RefreshZoneAsync(primaryNameServers))
                    {
                        //zone refreshed; set timer for refresh
                        DnsSOARecordData latestSoa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData;
                        ResetRefreshTimer(Math.Max(latestSoa.Refresh, _dnsServer.AuthZoneManager.MinSoaRefresh) * 1000);
                        _syncFailed = false;
                        _expiry = DateTime.UtcNow.AddSeconds(latestSoa.Expire);
                        _isExpired = false;
                        _resync = false;
                        _dnsServer.AuthZoneManager.SaveZoneFile(_name);
                        return;
                    }

                    //no response from any of the name servers; set timer for retry
                    ResetRefreshTimer(Math.Max(GetZoneSoaRetry(), _dnsServer.AuthZoneManager.MinSoaRetry) * 1000);
                    _syncFailed = true;
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);

                    //set timer for retry
                    ResetRefreshTimer(Math.Max(GetZoneSoaRetry(), _dnsServer.AuthZoneManager.MinSoaRetry) * 1000);
                    _syncFailed = true;
                }
                finally
                {
                    _refreshTimerTriggered = false;
                }
            })
            )
            {
                //failed to queue refresh zone task; try again in some time
                _refreshTimer?.Change(REFRESH_TIMER_INTERVAL, Timeout.Infinite);
            }
        }

        private void ResetRefreshTimer(long dueTime)
        {
            lock (_refreshTimerLock)
            {
                _refreshTimer?.Change(dueTime, Timeout.Infinite);
            }
        }

        private async Task<bool> RefreshZoneAsync(IReadOnlyList<NameServerAddress> nameServers)
        {
            try
            {
                _dnsServer.LogManager.Write("DNS Server has started zone refresh for Stub zone: " + ToString());

                DnsClient client = new DnsClient(nameServers);

                client.Proxy = _dnsServer.Proxy;
                client.PreferIPv6 = _dnsServer.PreferIPv6;
                client.Timeout = REFRESH_TIMEOUT;
                client.Retries = REFRESH_RETRIES;
                client.Concurrency = 1;

                DnsDatagram soaRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN)], null, null, null, _dnsServer.UdpPayloadSize);
                DnsDatagram soaResponse = await client.RawResolveAsync(soaRequest);

                if (soaResponse.RCODE != DnsResponseCode.NoError)
                {
                    _dnsServer.LogManager.Write("DNS Server received RCODE=" + soaResponse.RCODE.ToString() + " for '" + ToString() + "' Stub zone refresh from: " + soaResponse.Metadata.NameServer.ToString());

                    return false;
                }

                if ((soaResponse.Answer.Count < 1) || (soaResponse.Answer[0].Type != DnsResourceRecordType.SOA) || !_name.Equals(soaResponse.Answer[0].Name, StringComparison.OrdinalIgnoreCase))
                {
                    _dnsServer.LogManager.Write("DNS Server received an empty response for SOA query for '" + ToString() + "' Stub zone refresh from: " + soaResponse.Metadata.NameServer.ToString());

                    return false;
                }

                DnsResourceRecord currentSoaRecord = _entries[DnsResourceRecordType.SOA][0];
                DnsResourceRecord receivedSoaRecord = soaResponse.Answer[0];

                DnsSOARecordData currentSoa = currentSoaRecord.RDATA as DnsSOARecordData;
                DnsSOARecordData receivedSoa = receivedSoaRecord.RDATA as DnsSOARecordData;

                //compare using sequence space arithmetic
                if (!_resync && !currentSoa.IsZoneUpdateAvailable(receivedSoa))
                {
                    _dnsServer.LogManager.Write("DNS Server successfully checked for '" + ToString() + "' Stub zone update from: " + soaResponse.Metadata.NameServer.ToString());

                    return true;
                }

                //update available; do zone sync with TCP transport
                List<NameServerAddress> tcpNameServers = new List<NameServerAddress>();

                foreach (NameServerAddress nameServer in nameServers)
                    tcpNameServers.Add(nameServer.ChangeProtocol(DnsTransportProtocol.Tcp));

                client = new DnsClient(tcpNameServers);

                client.Proxy = _dnsServer.Proxy;
                client.PreferIPv6 = _dnsServer.PreferIPv6;
                client.Timeout = REFRESH_TIMEOUT;
                client.Retries = REFRESH_RETRIES;
                client.Concurrency = 1;

                DnsDatagram nsRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.NS, DnsClass.IN) });
                DnsDatagram nsResponse = await client.RawResolveAsync(nsRequest);

                if (nsResponse.RCODE != DnsResponseCode.NoError)
                {
                    _dnsServer.LogManager.Write("DNS Server received RCODE=" + nsResponse.RCODE.ToString() + " for '" + ToString() + "' Stub zone refresh from: " + nsResponse.Metadata.NameServer.ToString());

                    return false;
                }

                if (nsResponse.Answer.Count < 1)
                {
                    _dnsServer.LogManager.Write("DNS Server received an empty response for NS query for '" + ToString() + "' Stub zone from: " + nsResponse.Metadata.NameServer.ToString());

                    return false;
                }

                //prepare sync records
                List<DnsResourceRecord> nsRecords = new List<DnsResourceRecord>(nsResponse.Answer.Count);

                foreach (DnsResourceRecord record in nsResponse.Answer)
                {
                    if ((record.Type == DnsResourceRecordType.NS) && record.Name.Equals(_name, StringComparison.OrdinalIgnoreCase))
                    {
                        record.SyncGlueRecords(nsResponse.Additional);
                        nsRecords.Add(record);
                    }
                }

                receivedSoaRecord.CopyRecordInfoFrom(currentSoaRecord);

                //sync records
                _entries[DnsResourceRecordType.NS] = nsRecords;
                _entries[DnsResourceRecordType.SOA] = [receivedSoaRecord];

                _lastModified = DateTime.UtcNow;

                _dnsServer.LogManager.Write("DNS Server successfully refreshed '" + ToString() + "' Stub zone from: " + nsResponse.Metadata.NameServer.ToString());

                return true;
            }
            catch (Exception ex)
            {
                string strNameServers = null;

                foreach (NameServerAddress nameServer in nameServers)
                {
                    if (strNameServers == null)
                        strNameServers = nameServer.ToString();
                    else
                        strNameServers += ", " + nameServer.ToString();
                }

                _dnsServer.LogManager.Write("DNS Server failed to refresh '" + ToString() + "' Stub zone from: " + strNameServers + "\r\n" + ex.ToString());

                return false;
            }
        }

        #endregion

        #region public

        public override string GetZoneTypeName()
        {
            return "Stub";
        }

        public void TriggerRefresh(int refreshInterval = REFRESH_TIMER_INTERVAL)
        {
            if (Disabled)
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
            throw new InvalidOperationException("Cannot set records in Stub zone.");
        }

        public override bool AddRecord(DnsResourceRecord record)
        {
            throw new InvalidOperationException("Cannot add record in Stub zone.");
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            throw new InvalidOperationException("Cannot delete record in Stub zone.");
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            throw new InvalidOperationException("Cannot delete records in Stub zone.");
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            throw new InvalidOperationException("Cannot update record in Stub zone.");
        }

        public override IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool dnssecOk)
        {
            return []; //stub zone has no authority so cant return any records as query response to allow generating referral response
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

                base.Disabled = value; //set value early to be able to use it for refresh

                if (value)
                    ResetRefreshTimer(Timeout.Infinite);
                else
                    TriggerRefresh();
            }
        }

        public override bool OverrideCatalogZoneTransfer
        {
            get { throw new InvalidOperationException(); }
            set { throw new InvalidOperationException(); }
        }

        public override bool OverrideCatalogNotify
        {
            get { throw new InvalidOperationException(); }
            set { throw new InvalidOperationException(); }
        }

        public override AuthZoneQueryAccess QueryAccess
        {
            get { return base.QueryAccess; }
            set
            {
                switch (value)
                {
                    case AuthZoneQueryAccess.AllowOnlyZoneNameServers:
                    case AuthZoneQueryAccess.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                        throw new ArgumentException("The Query Access option is invalid for Stub zones: " + value.ToString(), nameof(QueryAccess));
                }

                base.QueryAccess = value;
            }
        }

        public override AuthZoneTransfer ZoneTransfer
        {
            get { return base.ZoneTransfer; }
            set { throw new InvalidOperationException(); }
        }

        public override AuthZoneNotify Notify
        {
            get { return base.Notify; }
            set { throw new InvalidOperationException(); }
        }

        public override AuthZoneUpdate Update
        {
            get { return base.Update; }
            set { throw new InvalidOperationException(); }
        }

        public IReadOnlyList<NameServerAddress> PrimaryNameServerAddresses
        {
            get { return _primaryNameServerAddresses; }
            set
            {
                if ((value is null) || (value.Count == 0))
                {
                    _primaryNameServerAddresses = null;
                }
                else if (value.Count > byte.MaxValue)
                {
                    throw new ArgumentOutOfRangeException(nameof(PrimaryNameServerAddresses), "Name server addresses cannot have more than 255 entries.");
                }
                else
                {
                    foreach (NameServerAddress nameServer in value)
                    {
                        if (nameServer.Port != 53)
                            throw new ArgumentException("Name server address must use port 53 for Stub zones.", nameof(PrimaryNameServerAddresses));
                    }

                    _primaryNameServerAddresses = value;
                }

                //update catalog zone property
                CatalogZone?.SetPrimaryAddressesProperty(_primaryNameServerAddresses, _name);
            }
        }

        public DateTime Expiry
        { get { return _expiry; } }

        public bool IsExpired
        { get { return _isExpired; } }

        public override bool IsActive
        {
            get { return !Disabled && !_isExpired; }
        }

        #endregion
    }
}
