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
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns.Zones
{
    public abstract class AuthZone : Zone, IDisposable
    {
        #region variables

        protected bool _disabled;

        #endregion

        #region constructor

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
                        newRecords.Shuffle(); //shuffle records to allow load balancing
                        break;
                }
            }

            return newRecords;
        }

        #endregion

        #region public

        public void SyncRecords(Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> newEntries, bool dontRemoveRecords)
        {
            if (!dontRemoveRecords)
            {
                //remove entires of type that do not exists in new entries
                foreach (DnsResourceRecordType type in _entries.Keys)
                {
                    if (!newEntries.ContainsKey(type))
                        _entries.TryRemove(type, out _);
                }
            }

            //set new entries into zone
            foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> newEntry in newEntries)
                _entries[newEntry.Key] = newEntry.Value;
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
                    return existingCNAMERecords;
            }

            if (type == DnsResourceRecordType.ANY)
            {
                List<DnsResourceRecord> records = new List<DnsResourceRecord>(_entries.Count * 2);

                foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                {
                    if (entry.Key != DnsResourceRecordType.ANY)
                        records.AddRange(entry.Value);
                }

                return FilterDisabledRecords(type, records);
            }

            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
            {
                IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingRecords);
                if (filteredRecords.Count > 0)
                    return existingRecords;
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
            return _entries[type];
        }

        public override bool ContainsNameServerRecords()
        {
            IReadOnlyList<DnsResourceRecord> records = QueryRecords(DnsResourceRecordType.NS);
            return (records.Count > 0) && (records[0].Type == DnsResourceRecordType.NS);
        }

        #endregion

        #region properties

        public virtual bool Disabled
        {
            get { return _disabled; }
            set { _disabled = value; }
        }

        public virtual bool IsActive
        {
            get { return !_disabled; }
        }

        #endregion
    }
}
