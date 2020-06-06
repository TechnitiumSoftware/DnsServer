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
    public sealed class PrimaryZone : AuthZone
    {
        #region variables

        readonly DnsServer _dnsServer;
        readonly bool _internal;

        readonly Timer _notifyTimer;
        const int NOTIFY_TIMER_INTERVAL = 30000;
        readonly List<NameServerAddress> _notifyList = new List<NameServerAddress>();

        const int NOTIFY_TIMEOUT = 60000;
        const int NOTIFY_RETRIES = 5;

        #endregion

        #region constructor

        public PrimaryZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(zoneInfo.Name)
        {
            _dnsServer = dnsServer;

            _disabled = zoneInfo.Disabled;

            _notifyTimer = new Timer(NotifyTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
        }

        public PrimaryZone(DnsServer dnsServer, string name, DnsSOARecord soa, bool @internal)
            : base(name, soa)
        {
            _dnsServer = dnsServer;
            _internal = @internal;

            _notifyTimer = new Timer(NotifyTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
        }

        public PrimaryZone(DnsServer dnsServer, string name, DnsSOARecord soa, DnsNSRecord ns, bool @internal)
            : base(name, soa, ns)
        {
            _dnsServer = dnsServer;
            _internal = @internal;

            _notifyTimer = new Timer(NotifyTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
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
                if (_notifyTimer != null)
                    _notifyTimer.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region private

        private void NotifyTimerCallback(object state)
        {
            try
            {
                DnsSOARecord soa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
                IReadOnlyList<DnsResourceRecord> nsRecords = QueryRecords(DnsResourceRecordType.NS);

                foreach (DnsResourceRecord nsRecord in nsRecords)
                {
                    string nsDomain = (nsRecord.RDATA as DnsNSRecord).NSDomainName;

                    if (soa.MasterNameServer.Equals(nsDomain, StringComparison.OrdinalIgnoreCase))
                        continue; //dont notify self

                    IReadOnlyList<DnsResourceRecord> glueRecords = nsRecord.GetGlueRecords();
                    if (glueRecords.Count > 0)
                    {
                        foreach (DnsResourceRecord glueRecord in glueRecords)
                        {
                            switch (glueRecord.Type)
                            {
                                case DnsResourceRecordType.A:
                                    NotifyNameServer(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsARecord).Address));
                                    break;

                                case DnsResourceRecordType.AAAA:
                                    NotifyNameServer(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsAAAARecord).Address));
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
                                NotifyNameServer(new NameServerAddress(nsDomain, address));
                        }

                        response = _dnsServer.DirectQuery(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.AAAA, DnsClass.IN));
                        if (response != null)
                        {
                            IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseAAAA(response);
                            foreach (IPAddress address in addresses)
                                NotifyNameServer(new NameServerAddress(nsDomain, address));
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
        }

        private void NotifyNameServer(NameServerAddress nameServer)
        {
            //use notify list to prevent multiple threads from notifying the same name server
            lock (_notifyList)
            {
                if (_notifyList.Contains(nameServer))
                    return; //already notifying the name server in another thread

                _notifyList.Add(nameServer);
            }

            ThreadPool.QueueUserWorkItem(delegate (object state)
            {
                try
                {
                    DnsClient client = new DnsClient(nameServer);

                    client.Timeout = NOTIFY_TIMEOUT;
                    client.Retries = NOTIFY_RETRIES;

                    DnsDatagram notifyRequest = new DnsDatagram(0, false, DnsOpcode.Notify, true, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN) });
                    DnsDatagram response = client.Resolve(notifyRequest);

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
            });
        }

        #endregion

        #region public

        public void IncrementSoaSerial()
        {
            DnsResourceRecord record = _entries[DnsResourceRecordType.SOA][0];
            DnsSOARecord soa = record.RDATA as DnsSOARecord;

            uint serial = soa.Serial;
            if (serial < uint.MaxValue)
                serial++;
            else
                serial = 0;

            DnsResourceRecord newRecord = new DnsResourceRecord(record.Name, record.Type, record.Class, record.TtlValue, new DnsSOARecord(soa.MasterNameServer, soa.ResponsiblePerson, serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum));
            _entries[DnsResourceRecordType.SOA] = new DnsResourceRecord[] { newRecord };
        }

        public void NotifyNameServers()
        {
            _notifyTimer.Change(NOTIFY_TIMER_INTERVAL, Timeout.Infinite);
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (type == DnsResourceRecordType.CNAME)
                throw new InvalidOperationException("Cannot set CNAME record to zone root.");

            base.SetRecords(type, records);

            IncrementSoaSerial();
            NotifyNameServers();
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            base.AddRecord(record);

            IncrementSoaSerial();
            NotifyNameServers();
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            if (type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot delete SOA record.");

            if (base.DeleteRecords(type))
            {
                IncrementSoaSerial();
                NotifyNameServers();

                return true;
            }

            return false;
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            if (type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot delete SOA record.");

            if (base.DeleteRecord(type, record))
            {
                IncrementSoaSerial();
                NotifyNameServers();

                return true;
            }

            return false;
        }

        #endregion

        #region properties

        public bool Internal
        { get { return _internal; } }

        #endregion
    }
}
