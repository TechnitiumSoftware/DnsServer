/*
Technitium DNS Server
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class StubZone : AuthZone
    {
        #region variables

        readonly DnsServer _dnsServer;

        readonly object _refreshTimerLock = new object();
        Timer _refreshTimer;
        const int REFRESH_TIMER_INTERVAL = 10000;

        const int REFRESH_TIMEOUT = 10000;
        const int REFRESH_RETRIES = 5;

        DateTime _expiry;
        bool _isExpired;

        #endregion

        #region constructor

        public StubZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(zoneInfo.Name)
        {
            _dnsServer = dnsServer;

            _disabled = zoneInfo.Disabled;
            _expiry = zoneInfo.Expiry;

            _isExpired = DateTime.UtcNow > _expiry;
            _refreshTimer = new Timer(RefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
        }

        public StubZone(DnsServer dnsServer, string name, string primaryNameServerAddresses = null)
            : base(name)
        {
            _dnsServer = dnsServer;

            DnsQuestionRecord soaQuestion = new DnsQuestionRecord(name, DnsResourceRecordType.SOA, DnsClass.IN);
            DnsDatagram soaResponse = null;

            if (primaryNameServerAddresses == null)
            {
                soaResponse = _dnsServer.DirectQuery(soaQuestion);
            }
            else
            {
                DnsClient dnsClient = new DnsClient(primaryNameServerAddresses);

                dnsClient.Proxy = _dnsServer.Proxy;
                dnsClient.PreferIPv6 = _dnsServer.PreferIPv6;
                dnsClient.Retries = _dnsServer.Retries;
                dnsClient.Timeout = _dnsServer.Timeout;

                soaResponse = dnsClient.Resolve(soaQuestion);
            }

            if ((soaResponse == null) || (soaResponse.Answer.Count == 0) || (soaResponse.Answer[0].Type != DnsResourceRecordType.SOA))
                throw new DnsServerException("DNS Server failed to find SOA record for: " + name);

            DnsSOARecord receivedSoa = soaResponse.Answer[0].RDATA as DnsSOARecord;

            DnsSOARecord soa = new DnsSOARecord(receivedSoa.PrimaryNameServer, receivedSoa.ResponsiblePerson, receivedSoa.Serial - 1, receivedSoa.Refresh, receivedSoa.Retry, receivedSoa.Expire, receivedSoa.Minimum);
            DnsResourceRecord[] soaRR = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Refresh, soa) };

            if (!string.IsNullOrEmpty(primaryNameServerAddresses))
                soaRR[0].SetGlueRecords(primaryNameServerAddresses);

            _entries[DnsResourceRecordType.SOA] = soaRR;

            _isExpired = true; //new stub zone is considered expired till it refreshes
            _refreshTimer = new Timer(RefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
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

        private void RefreshTimerCallback(object state)
        {
            if (_disabled)
                return;

            try
            {
                _isExpired = DateTime.UtcNow > _expiry;

                //get primary name server addresses
                IReadOnlyList<NameServerAddress> primaryNameServers = GetPrimaryNameServerAddresses(_dnsServer);

                if (primaryNameServers.Count == 0)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server could not find primary name server IP addresses for stub zone: " + _name);

                    //set timer for retry
                    DnsSOARecord soa1 = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                    _refreshTimer.Change(soa1.Retry * 1000, Timeout.Infinite);
                    return;
                }

                //refresh zone
                if (RefreshZone(primaryNameServers))
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

        private bool RefreshZone(IReadOnlyList<NameServerAddress> primaryNameServers)
        {
            try
            {
                DnsClient client = new DnsClient(primaryNameServers);

                client.Timeout = REFRESH_TIMEOUT;
                client.Retries = REFRESH_RETRIES;

                DnsDatagram soaRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN) });
                DnsDatagram soaResponse = client.Resolve(soaRequest);

                if (soaResponse.RCODE != DnsResponseCode.NoError)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received RCODE=" + soaResponse.RCODE.ToString() + " for '" + _name + "' stub zone refresh from: " + soaResponse.Metadata.NameServerAddress.ToString());

                    return false;
                }

                if (soaResponse.Answer.Count < 1)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received an empty response for SOA query for '" + _name + "' stub zone refresh from: " + soaResponse.Metadata.NameServerAddress.ToString());

                    return false;
                }

                DnsSOARecord currentSoaRecord = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                DnsSOARecord receivedSoaRecord = soaResponse.Answer[0].RDATA as DnsSOARecord;

                //compare using sequence space arithmetic
                if (!currentSoaRecord.IsZoneUpdateAvailable(receivedSoaRecord))
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server successfully checked for update to '" + _name + "' stub zone from: " + soaResponse.Metadata.NameServerAddress.ToString());

                    return true;
                }

                //update available; do zone sync
                DnsDatagram nsRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.NS, DnsClass.IN) });
                DnsDatagram nsResponse = client.Resolve(nsRequest);

                if (nsResponse.RCODE != DnsResponseCode.NoError)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received RCODE=" + nsResponse.RCODE.ToString() + " for '" + _name + "' stub zone refresh from: " + nsResponse.Metadata.NameServerAddress.ToString());

                    return false;
                }

                if (nsResponse.Answer.Count < 1)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received an empty response for NS query for '" + _name + "' stub zone from: " + nsResponse.Metadata.NameServerAddress.ToString());

                    return false;
                }

                List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();

                allRecords.AddRange(nsResponse.Answer);
                allRecords.AddRange(soaResponse.Answer); //to sync latest SOA record

                _dnsServer.AuthZoneManager.SyncRecords(_name, allRecords, nsResponse.Additional, true);

                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server successfully refreshed '" + _name + "' stub zone from: " + nsResponse.Metadata.NameServerAddress.ToString());
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

                    log.Write("DNS Server failed to refresh '" + _name + "' stub zone from: " + strNameServers);
                    log.Write(ex);
                }

                return false;
            }
        }

        #endregion

        #region public

        public void RefreshZone()
        {
            if (_disabled)
                return;

            _refreshTimer.Change(REFRESH_TIMER_INTERVAL, Timeout.Infinite);
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                    throw new InvalidOperationException("Cannot set CNAME record to zone root.");

                case DnsResourceRecordType.NS:
                    throw new InvalidOperationException("Cannot set NS records at stub zone root.");

                case DnsResourceRecordType.SOA:
                    if ((records.Count != 1) || !records[0].Name.Equals(_name, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Invalid SOA record.");

                    _entries[DnsResourceRecordType.SOA][0].SetGlueRecords(records.GetGlueRecords());
                    break;

                default:
                    base.SetRecords(type, records);
                    break;
            }
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.NS:
                    throw new InvalidOperationException("Cannot add NS record at stub zone root.");

                default:
                    base.AddRecord(record);
                    break;
            }
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            switch (type)
            {
                case DnsResourceRecordType.NS:
                    throw new InvalidOperationException("Cannot delete NS records in stub zone root.");

                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot delete SOA record.");

                default:
                    return base.DeleteRecords(type);
            }
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            switch (type)
            {
                case DnsResourceRecordType.NS:
                    throw new InvalidOperationException("Cannot delete NS record in stub zone root.");

                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot delete SOA record.");

                default:
                    return base.DeleteRecord(type, record);
            }
        }

        public override IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type)
        {
            switch (type)
            {
                case DnsResourceRecordType.SOA:
                case DnsResourceRecordType.NS:
                    return Array.Empty<DnsResourceRecord>(); //stub zone has no authority so cant return NS or SOA records as query response

                default:
                    return base.QueryRecords(type);
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
                        _refreshTimer.Change(Timeout.Infinite, Timeout.Infinite);
                    else
                        RefreshZone();
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
