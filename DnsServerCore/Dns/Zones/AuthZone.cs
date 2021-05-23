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
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    public enum AuthZoneTransfer : byte
    {
        Deny = 0,
        Allow = 1,
        AllowOnlyZoneNameServers = 2,
        AllowOnlySpecifiedNameServers = 3
    }

    public enum AuthZoneNotify : byte
    {
        None = 0,
        ZoneNameServers = 1,
        SpecifiedNameServers = 2
    }

    abstract class AuthZone : Zone, IDisposable
    {
        #region variables

        protected bool _disabled;
        protected AuthZoneTransfer _zoneTransfer;
        protected IReadOnlyCollection<IPAddress> _zoneTransferNameServers;
        protected AuthZoneNotify _notify;
        protected IReadOnlyCollection<IPAddress> _notifyNameServers;

        #endregion

        #region constructor

        protected AuthZone(AuthZoneInfo zoneInfo)
            : base(zoneInfo.Name)
        {
            _disabled = zoneInfo.Disabled;
            _zoneTransfer = zoneInfo.ZoneTransfer;
            _zoneTransferNameServers = zoneInfo.ZoneTransferNameServers;
            _notify = zoneInfo.Notify;
            _notifyNameServers = zoneInfo.NotifyNameServers;
        }

        protected AuthZone(string name)
            : base(name)
        { }

        #endregion

        #region IDisposable

        protected virtual void Dispose(bool disposing)
        { }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private IReadOnlyList<DnsResourceRecord> FilterDisabledRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (_disabled)
                return Array.Empty<DnsResourceRecord>();

            if (records.Count == 1)
            {
                if (records[0].IsDisabled())
                    return Array.Empty<DnsResourceRecord>(); //record disabled

                return records;
            }

            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                if (record.IsDisabled())
                    continue; //record disabled

                newRecords.Add(record);
            }

            if (newRecords.Count > 1)
            {
                switch (type)
                {
                    case DnsResourceRecordType.A:
                    case DnsResourceRecordType.AAAA:
                    case DnsResourceRecordType.NS:
                        newRecords.Shuffle(); //shuffle records to allow load balancing
                        break;
                }
            }

            return newRecords;
        }

        private static async Task<IReadOnlyList<NameServerAddress>> GetNameServerAddressesAsync(DnsServer dnsServer, DnsResourceRecord record)
        {
            string nsDomain;

            switch (record.Type)
            {
                case DnsResourceRecordType.NS:
                    nsDomain = (record.RDATA as DnsNSRecord).NameServer;
                    break;

                case DnsResourceRecordType.SOA:
                    nsDomain = (record.RDATA as DnsSOARecord).PrimaryNameServer;
                    break;

                default:
                    throw new InvalidOperationException();
            }

            List<NameServerAddress> nameServers = new List<NameServerAddress>(2);

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
                            if (dnsServer.PreferIPv6)
                                nameServers.Add(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsAAAARecord).Address));

                            break;
                    }
                }
            }
            else
            {
                //resolve addresses
                try
                {
                    DnsDatagram response = await dnsServer.DirectQueryAsync(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.A, DnsClass.IN));
                    if ((response != null) && (response.Answer.Count > 0))
                    {
                        IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseA(response);
                        foreach (IPAddress address in addresses)
                            nameServers.Add(new NameServerAddress(nsDomain, address));
                    }
                }
                catch
                { }

                if (dnsServer.PreferIPv6)
                {
                    try
                    {
                        DnsDatagram response = await dnsServer.DirectQueryAsync(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.AAAA, DnsClass.IN));
                        if ((response != null) && (response.Answer.Count > 0))
                        {
                            IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseAAAA(response);
                            foreach (IPAddress address in addresses)
                                nameServers.Add(new NameServerAddress(nsDomain, address));
                        }
                    }
                    catch
                    { }
                }
            }

            return nameServers;
        }

        #endregion

        #region public

        public async Task<IReadOnlyList<NameServerAddress>> GetPrimaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            List<NameServerAddress> nameServers = new List<NameServerAddress>();

            DnsResourceRecord soaRecord = _entries[DnsResourceRecordType.SOA][0];
            DnsSOARecord soa = soaRecord.RDATA as DnsSOARecord;
            IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.IsDisabled())
                    continue;

                string nsDomain = (nsRecord.RDATA as DnsNSRecord).NameServer;

                if (soa.PrimaryNameServer.Equals(nsDomain, StringComparison.OrdinalIgnoreCase))
                {
                    //found primary NS
                    nameServers.AddRange(await GetNameServerAddressesAsync(dnsServer, nsRecord));
                    break;
                }
            }

            foreach (NameServerAddress nameServer in await GetNameServerAddressesAsync(dnsServer, soaRecord))
            {
                if (!nameServers.Contains(nameServer))
                    nameServers.Add(nameServer);
            }

            return nameServers;
        }

        public async Task<IReadOnlyList<NameServerAddress>> GetSecondaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            List<NameServerAddress> nameServers = new List<NameServerAddress>();

            DnsSOARecord soa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
            IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.IsDisabled())
                    continue;

                string nsDomain = (nsRecord.RDATA as DnsNSRecord).NameServer;

                if (soa.PrimaryNameServer.Equals(nsDomain, StringComparison.OrdinalIgnoreCase))
                    continue; //skip primary name server

                nameServers.AddRange(await GetNameServerAddressesAsync(dnsServer, nsRecord));
            }

            return nameServers;
        }

        public void SyncRecords(Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> newEntries, bool dontRemoveRecords)
        {
            if (!dontRemoveRecords)
            {
                //remove entires of type that do not exists in new entries
                foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                {
                    if (!newEntries.ContainsKey(entry.Key))
                        _entries.TryRemove(entry.Key, out _);
                }
            }

            //set new entries into zone
            if (this is ForwarderZone)
            {
                //skip NS and SOA records from being added to ForwarderZone
                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> newEntry in newEntries)
                {
                    switch (newEntry.Key)
                    {
                        case DnsResourceRecordType.NS:
                        case DnsResourceRecordType.SOA:
                            break;

                        default:
                            _entries[newEntry.Key] = newEntry.Value;
                            break;
                    }
                }
            }
            else
            {
                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> newEntry in newEntries)
                {
                    if (newEntry.Key == DnsResourceRecordType.SOA)
                    {
                        if (newEntry.Value.Count != 1)
                            continue; //skip invalid SOA record

                        if ((this is SecondaryZone) || (this is StubZone))
                        {
                            //copy existing SOA record's glue addresses to new SOA record
                            newEntry.Value[0].SetGlueRecords(_entries[DnsResourceRecordType.SOA][0].GetGlueRecords());
                        }
                    }

                    _entries[newEntry.Key] = newEntry.Value;
                }
            }
        }

        public void LoadRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            _entries[type] = records;
        }

        public virtual void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            _entries[type] = records;
        }

        public virtual void AddRecord(DnsResourceRecord record)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.PTR:
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot add record: use SetRecords() for " + record.Type.ToString() + " record");
            }

            _entries.AddOrUpdate(record.Type, delegate (DnsResourceRecordType key)
            {
                return new DnsResourceRecord[] { record };
            },
            delegate (DnsResourceRecordType key, IReadOnlyList<DnsResourceRecord> existingRecords)
            {
                foreach (DnsResourceRecord existingRecord in existingRecords)
                {
                    if (record.Equals(existingRecord.RDATA))
                        return existingRecords;
                }

                List<DnsResourceRecord> updateRecords = new List<DnsResourceRecord>(existingRecords.Count + 1);

                updateRecords.AddRange(existingRecords);
                updateRecords.Add(record);

                return updateRecords;
            });
        }

        public virtual bool DeleteRecords(DnsResourceRecordType type)
        {
            return _entries.TryRemove(type, out _);
        }

        public virtual bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
            {
                if (existingRecords.Count == 1)
                {
                    if (record.Equals(existingRecords[0].RDATA))
                        return _entries.TryRemove(type, out _);
                }
                else
                {
                    List<DnsResourceRecord> updateRecords = new List<DnsResourceRecord>(existingRecords.Count);

                    for (int i = 0; i < existingRecords.Count; i++)
                    {
                        if (!record.Equals(existingRecords[i].RDATA))
                            updateRecords.Add(existingRecords[i]);
                    }

                    return _entries.TryUpdate(type, updateRecords, existingRecords);
                }
            }

            return false;
        }

        public virtual IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type)
        {
            //check for CNAME
            if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
            {
                IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingCNAMERecords);
                if (filteredRecords.Count > 0)
                    return filteredRecords;
            }

            if (type == DnsResourceRecordType.ANY)
            {
                List<DnsResourceRecord> records = new List<DnsResourceRecord>(_entries.Count * 2);

                foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                {
                    switch (entry.Key)
                    {
                        case DnsResourceRecordType.FWD:
                        case DnsResourceRecordType.APP:
                            //skip records
                            continue;

                        default:
                            records.AddRange(entry.Value);
                            break;
                    }
                }

                return FilterDisabledRecords(type, records);
            }

            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
            {
                IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingRecords);
                if (filteredRecords.Count > 0)
                    return filteredRecords;
            }

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    if (_entries.TryGetValue(DnsResourceRecordType.ANAME, out IReadOnlyList<DnsResourceRecord> anameRecords))
                        return FilterDisabledRecords(type, anameRecords);

                    break;
            }

            return Array.Empty<DnsResourceRecord>();
        }

        public IReadOnlyList<DnsResourceRecord> GetRecords(DnsResourceRecordType type)
        {
            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> records))
                return records;

            return Array.Empty<DnsResourceRecord>();
        }

        public override bool ContainsNameServerRecords()
        {
            if (!_entries.TryGetValue(DnsResourceRecordType.NS, out IReadOnlyList<DnsResourceRecord> records))
                return false;

            foreach (DnsResourceRecord record in records)
            {
                if (record.IsDisabled())
                    continue;

                return true;
            }

            return false;
        }

        #endregion

        #region properties

        public virtual bool Disabled
        {
            get { return _disabled; }
            set { _disabled = value; }
        }

        public virtual AuthZoneTransfer ZoneTransfer
        {
            get { return _zoneTransfer; }
            set { _zoneTransfer = value; }
        }

        public IReadOnlyCollection<IPAddress> ZoneTransferNameServers
        {
            get { return _zoneTransferNameServers; }
            set
            {
                if ((value is not null) && (value.Count > byte.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(ZoneTransferNameServers), "Name server addresses cannot be more than 255.");

                _zoneTransferNameServers = value;
            }
        }

        public virtual AuthZoneNotify Notify
        {
            get { return _notify; }
            set { _notify = value; }
        }

        public IReadOnlyCollection<IPAddress> NotifyNameServers
        {
            get { return _notifyNameServers; }
            set
            {
                if ((value is not null) && (value.Count > byte.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(NotifyNameServers), "Name server addresses cannot be more than 255.");

                _notifyNameServers = value;
            }
        }

        public virtual bool IsActive
        {
            get { return !_disabled; }
        }

        #endregion
    }
}
