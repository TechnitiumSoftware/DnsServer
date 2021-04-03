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

using System;
using System.Collections.Generic;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class CacheZone : Zone
    {
        #region constructor

        public CacheZone(string name)
            : base(name)
        { }

        #endregion

        #region private

        private static IReadOnlyList<DnsResourceRecord> FilterExpiredRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, bool serveStale, bool filterSpecialCacheRecords)
        {
            if (records.Count == 1)
            {
                DnsResourceRecord record = records[0];

                if (!serveStale && record.IsStale)
                    return Array.Empty<DnsResourceRecord>(); //record is stale

                if (record.TtlValue < 1u)
                    return Array.Empty<DnsResourceRecord>(); //ttl expired

                if (filterSpecialCacheRecords)
                {
                    if ((record.RDATA is DnsCache.DnsNXRecord) || (record.RDATA is DnsCache.DnsEmptyRecord) || (record.RDATA is DnsCache.DnsFailureRecord))
                        return Array.Empty<DnsResourceRecord>(); //special cache record
                }

                return records;
            }

            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                if (!serveStale && record.IsStale)
                    continue; //record is stale

                if (record.TtlValue < 1u)
                    continue; //ttl expired

                if (filterSpecialCacheRecords)
                {
                    if ((record.RDATA is DnsCache.DnsNXRecord) || (record.RDATA is DnsCache.DnsEmptyRecord) || (record.RDATA is DnsCache.DnsFailureRecord))
                        continue; //special cache record
                }

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

        public void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, bool serveStale)
        {
            if ((records.Count > 0) && (records[0].RDATA is DnsCache.DnsFailureRecord))
            {
                //call trying to cache failure record
                if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                {
                    if ((existingRecords.Count > 0) && !(existingRecords[0].RDATA is DnsCache.DnsFailureRecord) && (serveStale || !existingRecords[0].IsStale))
                        return; //skip to avoid overwriting a useful record with a failure record
                }
            }

            //set records
            _entries[type] = records;

            if (serveStale && (records.Count > 0) && !(records[0].RDATA is DnsCache.DnsFailureRecord))
            {
                //remove stale CNAME entry only when serve stale is enabled
                //making sure current record is not a failure record causing removal of useful stale CNAME record
                switch (type)
                {
                    case DnsResourceRecordType.CNAME:
                    case DnsResourceRecordType.SOA:
                    case DnsResourceRecordType.NS:
                        //do nothing
                        break;

                    default:
                        //remove stale CNAME entry since current new entry type overlaps any existing CNAME entry in cache
                        //keeping both entries will create issue with serve stale implementation since stale CNAME entry will be always returned

                        if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                        {
                            if ((existingCNAMERecords.Count > 0) && (existingCNAMERecords[0].RDATA is DnsCNAMERecord) && existingCNAMERecords[0].IsStale)
                            {
                                //delete CNAME entry only when it contains stale DnsCNAMERecord RDATA and not special cache records
                                _entries.TryRemove(DnsResourceRecordType.CNAME, out _);
                            }
                        }
                        break;
                }
            }
        }

        public void RemoveExpiredRecords(bool serveStale)
        {
            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                bool isExpired = false;

                foreach (DnsResourceRecord record in entry.Value)
                {
                    if ((record.TtlValue < 1u) || (!serveStale && record.IsStale))
                    {
                        //record expired
                        isExpired = true;
                        break;
                    }
                }

                if (isExpired)
                {
                    List<DnsResourceRecord> newRecords = null;

                    foreach (DnsResourceRecord record in entry.Value)
                    {
                        if ((record.TtlValue < 1u) || (!serveStale && record.IsStale))
                            continue; //record expired, skip it

                        if (newRecords == null)
                            newRecords = new List<DnsResourceRecord>(entry.Value.Count);

                        newRecords.Add(record);
                    }

                    if (newRecords == null)
                    {
                        //all records expired; remove entry
                        _entries.TryRemove(entry.Key, out _);
                    }
                    else
                    {
                        //try update entry with non-expired records
                        _entries.TryUpdate(entry.Key, newRecords, entry.Value);
                    }
                }
            }
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool serveStale, bool filterSpecialCacheRecords)
        {
            //check for CNAME
            if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
            {
                IReadOnlyList<DnsResourceRecord> filteredRecords = FilterExpiredRecords(type, existingCNAMERecords, serveStale, filterSpecialCacheRecords);
                if (filteredRecords.Count > 0)
                {
                    if ((type == DnsResourceRecordType.CNAME) || (filteredRecords[0].RDATA is DnsCNAMERecord))
                        return filteredRecords;
                }
            }

            if (type == DnsResourceRecordType.ANY)
            {
                List<DnsResourceRecord> anyRecords = new List<DnsResourceRecord>();

                foreach (IReadOnlyList<DnsResourceRecord> entryRecords in _entries.Values)
                    anyRecords.AddRange(FilterExpiredRecords(type, entryRecords, serveStale, true));

                return anyRecords;
            }

            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                return FilterExpiredRecords(type, existingRecords, serveStale, filterSpecialCacheRecords);

            return Array.Empty<DnsResourceRecord>();
        }

        public override bool ContainsNameServerRecords()
        {
            if (!_entries.TryGetValue(DnsResourceRecordType.NS, out IReadOnlyList<DnsResourceRecord> records))
                return false;

            foreach (DnsResourceRecord record in records)
            {
                if (record.IsStale)
                    continue;

                if (record.TtlValue < 1u)
                    continue;

                return true;
            }

            return false;
        }

        #endregion
    }
}
