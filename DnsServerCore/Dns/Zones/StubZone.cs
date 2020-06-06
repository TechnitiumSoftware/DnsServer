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
    public sealed class StubZone : AuthZone
    {
        #region variables

        readonly DnsServer _dnsServer;

        readonly Timer _refreshTimer;
        const int REFRESH_TIMER_INITIAL_INTERVAL = 30000;

        const int REFRESH_TIMEOUT = 60000;
        const int REFRESH_RETRIES = 5;

        #endregion

        #region constructor

        public StubZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(zoneInfo.Name)
        {
            _dnsServer = dnsServer;

            _disabled = zoneInfo.Disabled;

            _refreshTimer = new Timer(RefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
        }

        public StubZone(DnsServer dnsServer, string name, DnsSOARecord soa)
            : base(name, soa)
        {
            _dnsServer = dnsServer;

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

            DnsResourceRecord record = _entries[DnsResourceRecordType.SOA][0];
            DnsSOARecord soaRecord = record.RDATA as DnsSOARecord;

            try
            {
                string nsDomain = soaRecord.MasterNameServer;
                List<NameServerAddress> nameServers = new List<NameServerAddress>();

                IReadOnlyList<DnsResourceRecord> glueRecords = record.GetGlueRecords();
                if (glueRecords.Count > 0)
                {
                    foreach (DnsResourceRecord glueRecord in glueRecords)
                    {
                        switch (glueRecord.Type)
                        {
                            case DnsResourceRecordType.A:
                                nameServers.Add(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsARecord).Address));
                                break;

                            case DnsResourceRecordType.AAAA:
                                if (_dnsServer.PreferIPv6)
                                    nameServers.Add(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsAAAARecord).Address));

                                break;
                        }
                    }
                }
                else
                {
                    //resolve addresses
                    DnsDatagram response = _dnsServer.DirectQuery(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.A, DnsClass.IN));
                    if (response != null)
                    {
                        IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseA(response);
                        foreach (IPAddress address in addresses)
                            nameServers.Add(new NameServerAddress(nsDomain, address));
                    }

                    if (_dnsServer.PreferIPv6)
                    {
                        response = _dnsServer.DirectQuery(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.AAAA, DnsClass.IN));
                        if (response != null)
                        {
                            IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseAAAA(response);
                            foreach (IPAddress address in addresses)
                                nameServers.Add(new NameServerAddress(nsDomain, address));
                        }
                    }
                }

                //refresh zone
                foreach (NameServerAddress nameServer in nameServers)
                {
                    if (RefreshZone(nameServer))
                    {
                        //zone refreshed; set timer for refresh
                        DnsSOARecord latestSoaRecord = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                        _refreshTimer.Change(latestSoaRecord.Refresh * 1000, Timeout.Infinite);

                        _dnsServer.AuthZoneManager.SaveZoneFile(_name);
                        return;
                    }
                }

                //no response from any of the name servers; set timer for retry
                _refreshTimer.Change(soaRecord.Retry * 1000, Timeout.Infinite);
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write(ex);

                //set timer for retry
                _refreshTimer.Change(soaRecord.Retry * 1000, Timeout.Infinite);
            }
        }

        private bool RefreshZone(NameServerAddress nameServer)
        {
            try
            {
                DnsClient client = new DnsClient(nameServer);

                client.Timeout = REFRESH_TIMEOUT;
                client.Retries = REFRESH_RETRIES;

                DnsDatagram soaRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN) });
                DnsDatagram soaResponse = client.Resolve(soaRequest);

                if (soaResponse.RCODE != DnsResponseCode.NoError)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received RCODE=" + soaResponse.RCODE.ToString() + " for '" + _name + "' stub zone refresh from: " + nameServer.ToString());

                    return false;
                }

                if (soaResponse.Answer.Count < 1)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received an empty response for SOA query for '" + _name + "' stub zone refresh from: " + nameServer.ToString());

                    return false;
                }

                DnsSOARecord currentSoaRecord = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                DnsSOARecord receivedSoaRecord = soaResponse.Answer[0].RDATA as DnsSOARecord;

                //compare using sequence space arithmetic
                if (!currentSoaRecord.IsZoneUpdateAvailable(receivedSoaRecord))
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server successfully refreshed '" + _name + "' stub zone from: " + nameServer.ToString());

                    return true;
                }

                //update available; do zone sync
                nameServer = new NameServerAddress(nameServer, DnsTransportProtocol.Tcp);
                client = new DnsClient(nameServer);
                client.Timeout = REFRESH_TIMEOUT;
                client.Retries = REFRESH_RETRIES;

                DnsDatagram nsRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.NS, DnsClass.IN) });
                DnsDatagram nsResponse = client.Resolve(nsRequest);

                if (nsResponse.RCODE != DnsResponseCode.NoError)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received RCODE=" + nsResponse.RCODE.ToString() + " for '" + _name + "' stub zone refresh from: " + nameServer.ToString());

                    return false;
                }

                if (nsResponse.Answer.Count < 1)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server received an empty response for NS query for '" + _name + "' stub zone from: " + nameServer.ToString());

                    return false;
                }

                List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();

                allRecords.AddRange(nsResponse.Answer);
                allRecords.AddRange(soaResponse.Answer); //to sync latest SOA record

                _dnsServer.AuthZoneManager.SyncRecords(_name, allRecords, nsResponse.Additional, true);

                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server successfully refreshed '" + _name + "' stub zone from: " + nameServer.ToString());
                }

                return true;
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                {
                    log.Write("DNS Server failed to refresh '" + _name + "' stub zone from: " + nameServer.ToString());
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

            _refreshTimer.Change(REFRESH_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
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
                    throw new InvalidOperationException("Cannot set SOA record in stub zone.");

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

        #endregion
    }
}
