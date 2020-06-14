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
using System.Net;
using System.Threading;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    public sealed class SecondaryZone : AuthZone
    {
        #region variables

        readonly DnsServer _dnsServer;

        readonly Timer _refreshTimer;
        const int REFRESH_TIMER_INTERVAL = 10000;

        const int REFRESH_TIMEOUT = 60000;
        const int REFRESH_RETRIES = 5;

        DateTime _expiry;
        bool _isExpired;

        #endregion

        #region constructor

        public SecondaryZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(zoneInfo.Name)
        {
            _dnsServer = dnsServer;

            _disabled = zoneInfo.Disabled;
            _expiry = zoneInfo.Expiry;

            _isExpired = DateTime.UtcNow > _expiry;
            _refreshTimer = new Timer(RefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
        }

        public SecondaryZone(DnsServer dnsServer, string name, string primaryNameServer = null, string glueAddresses = null)
            : base(name)
        {
            _dnsServer = dnsServer;

            if (primaryNameServer == null)
            {
                DnsDatagram soaResponse = _dnsServer.DirectQuery(new DnsQuestionRecord(name, DnsResourceRecordType.SOA, DnsClass.IN));
                if ((soaResponse == null) || (soaResponse.Answer.Count == 0) || (soaResponse.Answer[0].Type != DnsResourceRecordType.SOA))
                    throw new DnsServerException("DNS Server failed to find SOA record for: " + name);

                DnsDatagram nsResponse = _dnsServer.DirectQuery(new DnsQuestionRecord(name, DnsResourceRecordType.NS, DnsClass.IN));
                if ((nsResponse == null) || (nsResponse.Answer.Count == 0) || (nsResponse.Answer[0].Type != DnsResourceRecordType.NS))
                    throw new DnsServerException("DNS Server failed to find NS records for: " + name);

                foreach (DnsResourceRecord record in soaResponse.Answer)
                    record.RemoveExpiry();

                foreach (DnsResourceRecord record in nsResponse.Answer)
                    record.RemoveExpiry();

                if (nsResponse.Additional.Count > 0)
                {
                    foreach (DnsResourceRecord record in nsResponse.Answer)
                    {
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.NS:
                            case DnsResourceRecordType.SOA:
                                record.SetGlueRecords(nsResponse.Additional);
                                break;
                        }
                    }
                }

                _entries[DnsResourceRecordType.SOA] = soaResponse.Answer;
                _entries[DnsResourceRecordType.NS] = nsResponse.Answer;
            }
            else
            {
                DnsSOARecord soa = new DnsSOARecord(primaryNameServer, "hostadmin." + primaryNameServer, 1, 14400, 3600, 604800, 900);

                DnsResourceRecord[] soaRR = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Refresh, soa) };
                DnsResourceRecord[] nsRR = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, soa.Refresh, new DnsNSRecord(soa.PrimaryNameServer)) }; ;

                if (glueAddresses != null)
                {
                    soaRR[0].SetGlueRecords(glueAddresses);
                    nsRR[0].SetGlueRecords(glueAddresses);
                }

                _entries[DnsResourceRecordType.SOA] = soaRR;
                _entries[DnsResourceRecordType.NS] = nsRR;
            }

            _isExpired = true; //new secondary zone is considered expired till it refreshes
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
                if (_refreshTimer != null)
                    _refreshTimer.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region private

        private void RefreshTimerCallback(object state)
        {
            if (_disabled)
                return;

            DnsResourceRecord soaRecord = _entries[DnsResourceRecordType.SOA][0];
            DnsSOARecord soa = soaRecord.RDATA as DnsSOARecord;

            try
            {
                _isExpired = DateTime.UtcNow > _expiry;

                //get primary name server addresses
                string primaryNameServer = soa.PrimaryNameServer;
                List<NameServerAddress> primaryNameServers = new List<NameServerAddress>();

                IReadOnlyList<DnsResourceRecord> glueRecords = soaRecord.GetGlueRecords();
                if (glueRecords.Count > 0)
                {
                    foreach (DnsResourceRecord glueRecord in glueRecords)
                    {
                        switch (glueRecord.Type)
                        {
                            case DnsResourceRecordType.A:
                                primaryNameServers.Add(new NameServerAddress(primaryNameServer, (glueRecord.RDATA as DnsARecord).Address));
                                break;

                            case DnsResourceRecordType.AAAA:
                                if (_dnsServer.PreferIPv6)
                                    primaryNameServers.Add(new NameServerAddress(primaryNameServer, (glueRecord.RDATA as DnsAAAARecord).Address));

                                break;
                        }
                    }
                }
                else
                {
                    //resolve addresses
                    DnsDatagram response = _dnsServer.DirectQuery(new DnsQuestionRecord(primaryNameServer, DnsResourceRecordType.A, DnsClass.IN));
                    if (response != null)
                    {
                        IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseA(response);
                        foreach (IPAddress address in addresses)
                            primaryNameServers.Add(new NameServerAddress(primaryNameServer, address));
                    }

                    if (_dnsServer.PreferIPv6)
                    {
                        response = _dnsServer.DirectQuery(new DnsQuestionRecord(primaryNameServer, DnsResourceRecordType.AAAA, DnsClass.IN));
                        if (response != null)
                        {
                            IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseAAAA(response);
                            foreach (IPAddress address in addresses)
                                primaryNameServers.Add(new NameServerAddress(primaryNameServer, address));
                        }
                    }
                }

                if (primaryNameServers.Count == 0)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server could not find primary name server IP addresses for secondary zone: " + _name);

                    //set timer for retry
                    _refreshTimer.Change(soa.Retry * 1000, Timeout.Infinite);
                    return;
                }

                //refresh zone
                if (RefreshZone(primaryNameServers))
                {
                    //zone refreshed; set timer for refresh
                    DnsSOARecord latestSoaRecord = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                    _refreshTimer.Change(latestSoaRecord.Refresh * 1000, Timeout.Infinite);

                    _expiry = DateTime.UtcNow.AddSeconds(latestSoaRecord.Expire);
                    _isExpired = false;
                    _dnsServer.AuthZoneManager.SaveZoneFile(_name);
                    return;
                }

                //no response from any of the name servers; set timer for retry
                _refreshTimer.Change(soa.Retry * 1000, Timeout.Infinite);
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write(ex);

                //set timer for retry
                _refreshTimer.Change(soa.Retry * 1000, Timeout.Infinite);
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
                        log.Write("DNS Server successfully refreshed '" + _name + "' secondary zone from: " + soaResponse.Metadata.NameServerAddress.ToString());

                    return true;
                }

                //update available; do zone transfer with TCP transport
                primaryNameServers = new NameServerAddress[] { new NameServerAddress(soaResponse.Metadata.NameServerAddress, DnsTransportProtocol.Tcp) };
                client = new DnsClient(primaryNameServers);
                client.Timeout = REFRESH_TIMEOUT;
                client.Retries = REFRESH_RETRIES;

                DnsDatagram axfrRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.AXFR, DnsClass.IN) });
                DnsDatagram axfrResponse = client.Resolve(axfrRequest);

                if (axfrResponse.RCODE != DnsResponseCode.NoError)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received RCODE=" + axfrResponse.RCODE.ToString() + " for '" + _name + "' secondary zone refresh from: " + axfrResponse.Metadata.NameServerAddress.ToString());

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
                    _dnsServer.AuthZoneManager.SyncRecords(_name, axfrResponse.Answer);

                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server successfully refreshed '" + _name + "' secondary zone from: " + axfrResponse.Metadata.NameServerAddress.ToString());
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

        public void RefreshZone()
        {
            if (_disabled)
                return;

            _refreshTimer.Change(REFRESH_TIMER_INTERVAL, Timeout.Infinite);
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            throw new InvalidOperationException("Cannot set records in secondary zone.");
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
