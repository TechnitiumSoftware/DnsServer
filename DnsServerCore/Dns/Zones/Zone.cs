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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns.Zones
{
    public abstract class Zone
    {
        #region variables

        protected readonly string _name;
        protected readonly ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> _entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>();

        #endregion

        #region constructor

        protected Zone(string name)
        {
            _name = name;
        }

        #endregion

        #region public

        public List<DnsResourceRecord> ListAllRecords()
        {
            List<DnsResourceRecord> records = new List<DnsResourceRecord>(_entries.Count * 2);

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                records.AddRange(entry.Value);

            return records;
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

        public abstract bool ContainsNameServerRecords();

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public bool IsEmpty
        { get { return _entries.IsEmpty; } }

        #endregion
    }
}
