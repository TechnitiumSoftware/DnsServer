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

        private static async Task ResolveNameServerAddressesAsync(DnsServer dnsServer, string nsDomain, int port, DnsTransportProtocol protocol, List<NameServerAddress> outNameServers)
        {
            try
            {
                DnsDatagram response = await dnsServer.DirectQueryAsync(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.A, DnsClass.IN)).WithTimeout(2000);
                if (response.Answer.Count > 0)
                {
                    IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseA(response);
                    foreach (IPAddress address in addresses)
                        outNameServers.Add(new NameServerAddress(nsDomain, new IPEndPoint(address, port), protocol));
                }
            }
            catch
            { }

            if (dnsServer.PreferIPv6)
            {
                try
                {
                    DnsDatagram response = await dnsServer.DirectQueryAsync(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.AAAA, DnsClass.IN)).WithTimeout(2000);
                    if (response.Answer.Count > 0)
                    {
                        IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseAAAA(response);
                        foreach (IPAddress address in addresses)
                            outNameServers.Add(new NameServerAddress(nsDomain, new IPEndPoint(address, port), protocol));
                    }
                }
                catch
                { }
            }
        }

        private static Task ResolveNameServerAddressesAsync(DnsServer dnsServer, DnsResourceRecord nsRecord, List<NameServerAddress> outNameServers)
        {
            switch (nsRecord.Type)
            {
                case DnsResourceRecordType.NS:
                    {
                        string nsDomain = (nsRecord.RDATA as DnsNSRecord).NameServer;

                        IReadOnlyList<DnsResourceRecord> glueRecords = nsRecord.GetGlueRecords();
                        if (glueRecords.Count > 0)
                        {
                            foreach (DnsResourceRecord glueRecord in glueRecords)
                            {
                                switch (glueRecord.Type)
                                {
                                    case DnsResourceRecordType.A:
                                        outNameServers.Add(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsARecord).Address));
                                        break;

                                    case DnsResourceRecordType.AAAA:
                                        if (dnsServer.PreferIPv6)
                                            outNameServers.Add(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsAAAARecord).Address));

                                        break;
                                }
                            }

                            return Task.CompletedTask;
                        }
                        else
                        {
                            return ResolveNameServerAddressesAsync(dnsServer, nsDomain, 53, DnsTransportProtocol.Udp, outNameServers);
                        }
                    }

                default:
                    throw new InvalidOperationException();
            }
        }

        #endregion

        #region protected

        protected void CleanupHistory(List<DnsResourceRecord> history)
        {
            DnsSOARecord soa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
            DateTime expiry = DateTime.UtcNow.AddSeconds(-soa.Expire);
            int index = 0;

            while (index < history.Count)
            {
                //check difference sequence
                if (history[index].GetDeletedOn() > expiry)
                    break; //found record to keep

                //skip to next difference sequence
                index++;
                int soaCount = 1;

                while (index < history.Count)
                {
                    if (history[index].Type == DnsResourceRecordType.SOA)
                    {
                        soaCount++;

                        if (soaCount == 3)
                            break;
                    }

                    index++;
                }
            }

            if (index == history.Count)
            {
                //delete entire history
                history.Clear();
                return;
            }

            //remove expired records
            history.RemoveRange(0, index);
        }

        protected bool SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, out IReadOnlyList<DnsResourceRecord> deletedRecords)
        {
            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
            {
                deletedRecords = existingRecords;
                return _entries.TryUpdate(type, records, existingRecords);
            }
            else
            {
                deletedRecords = null;
                return _entries.TryAdd(type, records);
            }
        }

        protected bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata, out DnsResourceRecord deletedRecord)
        {
            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
            {
                if (existingRecords.Count == 1)
                {
                    if (rdata.Equals(existingRecords[0].RDATA))
                    {
                        if (_entries.TryRemove(type, out IReadOnlyList<DnsResourceRecord> removedRecords))
                        {
                            deletedRecord = removedRecords[0];
                            return true;
                        }
                    }
                }
                else
                {
                    deletedRecord = null;
                    List<DnsResourceRecord> updatedRecords = new List<DnsResourceRecord>(existingRecords.Count);

                    foreach (DnsResourceRecord existingRecord in existingRecords)
                    {
                        if ((deletedRecord is null) && rdata.Equals(existingRecord.RDATA))
                            deletedRecord = existingRecord;
                        else
                            updatedRecords.Add(existingRecord);
                    }

                    return _entries.TryUpdate(type, updatedRecords, existingRecords);
                }
            }

            deletedRecord = null;
            return false;
        }

        #endregion

        #region public

        public async Task<IReadOnlyList<NameServerAddress>> GetPrimaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            DnsResourceRecord soaRecord = _entries[DnsResourceRecordType.SOA][0];

            IReadOnlyList<NameServerAddress> primaryNameServers = soaRecord.GetPrimaryNameServers();
            if (primaryNameServers.Count > 0)
            {
                List<NameServerAddress> resolvedNameServers = new List<NameServerAddress>(primaryNameServers.Count * 2);

                foreach (NameServerAddress nameServer in primaryNameServers)
                {
                    if (nameServer.IPEndPoint is null)
                    {
                        await ResolveNameServerAddressesAsync(dnsServer, nameServer.Host, nameServer.Port, nameServer.Protocol, resolvedNameServers);
                    }
                    else
                    {
                        resolvedNameServers.Add(nameServer);
                    }
                }

                return resolvedNameServers;
            }

            string primaryNameServer = (soaRecord.RDATA as DnsSOARecord).PrimaryNameServer;
            IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

            List<NameServerAddress> nameServers = new List<NameServerAddress>(nsRecords.Count * 2);

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.IsDisabled())
                    continue;

                if (primaryNameServer.Equals((nsRecord.RDATA as DnsNSRecord).NameServer, StringComparison.OrdinalIgnoreCase))
                {
                    //found primary NS
                    await ResolveNameServerAddressesAsync(dnsServer, nsRecord, nameServers);
                    break;
                }
            }

            if (nameServers.Count < 1)
                await ResolveNameServerAddressesAsync(dnsServer, primaryNameServer, 53, DnsTransportProtocol.Udp, nameServers);

            return nameServers;
        }

        public async Task<IReadOnlyList<NameServerAddress>> GetSecondaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            string primaryNameServer = (_entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord).PrimaryNameServer;
            IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

            List<NameServerAddress> nameServers = new List<NameServerAddress>(nsRecords.Count * 2);

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.IsDisabled())
                    continue;

                if (primaryNameServer.Equals((nsRecord.RDATA as DnsNSRecord).NameServer, StringComparison.OrdinalIgnoreCase))
                    continue; //skip primary name server

                await ResolveNameServerAddressesAsync(dnsServer, nsRecord, nameServers);
            }

            return nameServers;
        }

        public async Task<IReadOnlyList<NameServerAddress>> GetAllNameServerAddressesAsync(DnsServer dnsServer)
        {
            IReadOnlyList<NameServerAddress> primaryNameServers = await GetPrimaryNameServerAddressesAsync(dnsServer);
            IReadOnlyList<NameServerAddress> secondaryNameServers = await GetSecondaryNameServerAddressesAsync(dnsServer);

            if (secondaryNameServers.Count < 1)
                return primaryNameServers;

            List<NameServerAddress> allNameServers = new List<NameServerAddress>(primaryNameServers.Count + secondaryNameServers.Count);

            allNameServers.AddRange(primaryNameServers);
            allNameServers.AddRange(secondaryNameServers);

            return allNameServers;
        }

        public void SyncRecords(Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> newEntries)
        {
            //remove entires of type that do not exists in new entries
            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                if (!newEntries.ContainsKey(entry.Key))
                    _entries.TryRemove(entry.Key, out _);
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

                        if (this is SecondaryZone)
                        {
                            //copy existing SOA record's info to new SOA record
                            DnsResourceRecord existingSoaRecord = _entries[DnsResourceRecordType.SOA][0];
                            DnsResourceRecord newSoaRecord = newEntry.Value[0];

                            newSoaRecord.CopyRecordInfoFrom(existingSoaRecord);
                        }
                    }

                    _entries[newEntry.Key] = newEntry.Value;
                }
            }
        }

        public void SyncRecords(Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> deletedEntries, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> addedEntries)
        {
            if (deletedEntries is not null)
            {
                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> deletedEntry in deletedEntries)
                {
                    if (_entries.TryGetValue(deletedEntry.Key, out IReadOnlyList<DnsResourceRecord> existingRecords))
                    {
                        List<DnsResourceRecord> updatedRecords = new List<DnsResourceRecord>(Math.Max(0, existingRecords.Count - deletedEntry.Value.Count));

                        foreach (DnsResourceRecord existingRecord in existingRecords)
                        {
                            bool deleted = false;

                            foreach (DnsResourceRecord deletedRecord in deletedEntry.Value)
                            {
                                if (existingRecord.RDATA.Equals(deletedRecord.RDATA))
                                {
                                    deleted = true;
                                    break;
                                }
                            }

                            if (!deleted)
                                updatedRecords.Add(existingRecord);
                        }

                        if (existingRecords.Count > updatedRecords.Count)
                        {
                            if (updatedRecords.Count > 0)
                                _entries[deletedEntry.Key] = updatedRecords;
                            else
                                _entries.TryRemove(deletedEntry.Key, out _);
                        }
                    }
                }
            }

            if (addedEntries is not null)
            {
                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> addedEntry in addedEntries)
                {
                    _entries.AddOrUpdate(addedEntry.Key, addedEntry.Value, delegate (DnsResourceRecordType key, IReadOnlyList<DnsResourceRecord> existingRecords)
                    {
                        List<DnsResourceRecord> updatedRecords = new List<DnsResourceRecord>(existingRecords.Count + addedEntry.Value.Count);

                        updatedRecords.AddRange(existingRecords);

                        foreach (DnsResourceRecord addedRecord in addedEntry.Value)
                        {
                            bool exists = false;

                            foreach (DnsResourceRecord existingRecord in existingRecords)
                            {
                                if (addedRecord.RDATA.Equals(existingRecord.RDATA))
                                {
                                    exists = true;
                                    break;
                                }
                            }

                            if (!exists)
                                updatedRecords.Add(addedRecord);
                        }

                        if (updatedRecords.Count > existingRecords.Count)
                            return updatedRecords;
                        else
                            return existingRecords;
                    });
                }
            }
        }

        public void SyncGlueRecords(IReadOnlyCollection<DnsResourceRecord> deletedGlueRecords, IReadOnlyCollection<DnsResourceRecord> addedGlueRecords)
        {
            if (_entries.TryGetValue(DnsResourceRecordType.NS, out IReadOnlyList<DnsResourceRecord> nsRecords))
            {
                foreach (DnsResourceRecord nsRecord in nsRecords)
                    nsRecord.SyncGlueRecords(deletedGlueRecords, addedGlueRecords);
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
                case DnsResourceRecordType.DNAME:
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
                    if (record.RDATA.Equals(existingRecord.RDATA))
                        return existingRecords;
                }

                List<DnsResourceRecord> updatedRecords = new List<DnsResourceRecord>(existingRecords.Count + 1);

                updatedRecords.AddRange(existingRecords);
                updatedRecords.Add(record);

                return updatedRecords;
            });
        }

        public virtual bool DeleteRecords(DnsResourceRecordType type)
        {
            return _entries.TryRemove(type, out _);
        }

        public virtual bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            return DeleteRecord(type, rdata, out _);
        }

        public virtual void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            if (oldRecord.Type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot update record: use SetRecords() for " + oldRecord.Type.ToString() + " record");

            if (oldRecord.Type != newRecord.Type)
                throw new InvalidOperationException("Old and new record types do not match.");

            DeleteRecord(oldRecord.Type, oldRecord.RDATA);
            AddRecord(newRecord);
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
