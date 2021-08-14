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
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class PrimaryZone : AuthZone
    {
        #region variables

        readonly DnsServer _dnsServer;
        readonly bool _internal;

        readonly List<DnsResourceRecord> _history; //for IXFR support
        IReadOnlyDictionary<string, object> _tsigKeyNames;

        readonly Timer _notifyTimer;
        bool _notifyTimerTriggered;
        const int NOTIFY_TIMER_INTERVAL = 10000;
        readonly List<NameServerAddress> _notifyList;

        const int NOTIFY_TIMEOUT = 10000;
        const int NOTIFY_RETRIES = 5;

        #endregion

        #region constructor

        public PrimaryZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(zoneInfo)
        {
            _dnsServer = dnsServer;

            if (zoneInfo.ZoneHistory is null)
                _history = new List<DnsResourceRecord>();
            else
                _history = new List<DnsResourceRecord>(zoneInfo.ZoneHistory);

            _tsigKeyNames = zoneInfo.TsigKeyNames;

            _notifyTimer = new Timer(NotifyTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
            _notifyList = new List<NameServerAddress>();
        }

        public PrimaryZone(DnsServer dnsServer, string name, string primaryNameServer, bool @internal)
            : base(name)
        {
            _dnsServer = dnsServer;
            _internal = @internal;

            if (_internal)
            {
                _zoneTransfer = AuthZoneTransfer.Deny;
                _notify = AuthZoneNotify.None;
            }
            else
            {
                _zoneTransfer = AuthZoneTransfer.AllowOnlyZoneNameServers;
                _notify = AuthZoneNotify.ZoneNameServers;

                _history = new List<DnsResourceRecord>();

                _notifyTimer = new Timer(NotifyTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
                _notifyList = new List<NameServerAddress>();
            }

            DnsSOARecord soa = new DnsSOARecord(primaryNameServer, _name.Length == 0 ? "hostadmin" : "hostadmin." + _name, 1, 900, 300, 604800, 900);

            _entries[DnsResourceRecordType.SOA] = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Refresh, soa) };
            _entries[DnsResourceRecordType.NS] = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, soa.Refresh, new DnsNSRecord(soa.PrimaryNameServer)) };
        }

        internal PrimaryZone(DnsServer dnsServer, string name, DnsSOARecord soa, DnsNSRecord ns)
            : base(name)
        {
            _dnsServer = dnsServer;
            _internal = true;

            _zoneTransfer = AuthZoneTransfer.Deny;
            _notify = AuthZoneNotify.None;

            _entries[DnsResourceRecordType.SOA] = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Refresh, soa) };
            _entries[DnsResourceRecordType.NS] = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, soa.Refresh, ns) };
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

        #endregion

        #region internal

        internal void CommitAndIncrementSerial(IReadOnlyList<DnsResourceRecord> deletedRecords = null, IReadOnlyList<DnsResourceRecord> addedRecords = null)
        {
            if (_internal)
                return;

            lock (_history)
            {
                DnsResourceRecord oldSoaRecord = _entries[DnsResourceRecordType.SOA][0];
                DnsResourceRecord newSoaRecord;
                {
                    DnsSOARecord soa = oldSoaRecord.RDATA as DnsSOARecord;

                    uint serial = soa.Serial;
                    if (serial < uint.MaxValue)
                        serial++;
                    else
                        serial = 1;

                    newSoaRecord = new DnsResourceRecord(oldSoaRecord.Name, oldSoaRecord.Type, oldSoaRecord.Class, oldSoaRecord.TtlValue, new DnsSOARecord(soa.PrimaryNameServer, soa.ResponsiblePerson, serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum)) { Tag = oldSoaRecord.Tag };
                    oldSoaRecord.Tag = null; //remove RR info from old SOA to allow creating new RR info for it during SetDeletedOn()
                }

                //update SOA
                _entries[DnsResourceRecordType.SOA] = new DnsResourceRecord[] { newSoaRecord };

                //start commit
                oldSoaRecord.SetDeletedOn(DateTime.UtcNow);

                //write removed
                _history.Add(oldSoaRecord);

                if (deletedRecords is not null)
                {
                    foreach (DnsResourceRecord deletedRecord in deletedRecords)
                    {
                        if (deletedRecord.IsDisabled())
                            continue;

                        _history.Add(deletedRecord);

                        if (deletedRecord.Type == DnsResourceRecordType.NS)
                            _history.AddRange(deletedRecord.GetGlueRecords());
                    }
                }

                //write added
                _history.Add(newSoaRecord);

                if (addedRecords is not null)
                {
                    foreach (DnsResourceRecord addedRecord in addedRecords)
                    {
                        if (addedRecord.IsDisabled())
                            continue;

                        _history.Add(addedRecord);

                        if (addedRecord.Type == DnsResourceRecordType.NS)
                            _history.AddRange(addedRecord.GetGlueRecords());
                    }
                }

                //end commit

                CleanupHistory(_history);
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

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                    throw new InvalidOperationException("Cannot set CNAME record to zone root.");

                case DnsResourceRecordType.SOA:
                    if ((records.Count != 1) || !records[0].Name.Equals(_name, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Invalid SOA record.");

                    //remove any resource record info except comments
                    string comments = records[0].GetComments();
                    records[0].Tag = null;
                    records[0].SetComments(comments);

                    base.SetRecords(type, records);

                    CommitAndIncrementSerial();
                    TriggerNotify();
                    break;

                default:
                    if (!SetRecords(type, records, out IReadOnlyList<DnsResourceRecord> deletedRecords))
                        throw new DnsServerException("Failed to set records. Please try again.");

                    CommitAndIncrementSerial(deletedRecords, records);
                    TriggerNotify();
                    break;
            }
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            if (record.Type == DnsResourceRecordType.APP)
                throw new InvalidOperationException("Cannot add record: use SetRecords() for " + record.Type.ToString() + " record");

            base.AddRecord(record);

            CommitAndIncrementSerial(null, new DnsResourceRecord[] { record });
            TriggerNotify();
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            if (type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot delete SOA record.");

            if (_entries.TryRemove(type, out IReadOnlyList<DnsResourceRecord> removedRecords))
            {
                CommitAndIncrementSerial(removedRecords);
                TriggerNotify();

                return true;
            }

            return false;
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            if (type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot delete SOA record.");

            if (DeleteRecord(type, record, out DnsResourceRecord deletedRecord))
            {
                CommitAndIncrementSerial(new DnsResourceRecord[] { deletedRecord });
                TriggerNotify();

                return true;
            }

            return false;
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            if (oldRecord.Type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot update record: use SetRecords() for " + oldRecord.Type.ToString() + " record");

            if (oldRecord.Type != newRecord.Type)
                throw new InvalidOperationException("Old and new record types do not match.");

            DeleteRecord(oldRecord.Type, oldRecord.RDATA, out DnsResourceRecord deletedRecord);
            base.AddRecord(newRecord);

            CommitAndIncrementSerial(new DnsResourceRecord[] { deletedRecord }, new DnsResourceRecord[] { newRecord });
            TriggerNotify();
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

        public bool Internal
        { get { return _internal; } }

        public override bool Disabled
        {
            get { return _disabled; }
            set
            {
                if (_disabled != value)
                {
                    _disabled = value;

                    if (_disabled)
                        _notifyTimer.Change(Timeout.Infinite, Timeout.Infinite);
                    else
                        TriggerNotify();
                }
            }
        }

        public override AuthZoneTransfer ZoneTransfer
        {
            get { return _zoneTransfer; }
            set
            {
                if (_internal)
                    throw new InvalidOperationException();

                _zoneTransfer = value;
            }
        }

        public override AuthZoneNotify Notify
        {
            get { return _notify; }
            set
            {
                if (_internal)
                    throw new InvalidOperationException();

                _notify = value;
            }
        }

        public IReadOnlyDictionary<string, object> TsigKeyNames
        {
            get { return _tsigKeyNames; }
            set { _tsigKeyNames = value; }
        }

        #endregion
    }
}
