/*
Technitium DNS Server
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class CacheZone : Zone
    {
        #region constructor

        public CacheZone(string name, int capacity)
            : base(name, capacity)
        { }

        #endregion

        #region private

        private static IReadOnlyList<DnsResourceRecord> ValidateRRSet(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, bool serveStale, bool skipSpecialCacheRecord)
        {
            foreach (DnsResourceRecord record in records)
            {
                if (record.IsExpired(serveStale))
                    return Array.Empty<DnsResourceRecord>(); //RR Set is expired

                if (skipSpecialCacheRecord && (record.RDATA is DnsCache.DnsSpecialCacheRecord))
                    return Array.Empty<DnsResourceRecord>(); //RR Set is special cache record
            }

            if (records.Count > 1)
            {
                switch (type)
                {
                    case DnsResourceRecordType.A:
                    case DnsResourceRecordType.AAAA:
                        List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records);
                        newRecords.Shuffle(); //shuffle records to allow load balancing
                        return newRecords;
                }
            }

            return records;
        }

        #endregion

        #region public

        public void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, bool serveStale)
        {
            bool isFailureRecord = (records.Count > 0) && (records[0].RDATA is DnsCache.DnsSpecialCacheRecord splRecord) && (splRecord.Type == DnsCache.DnsSpecialCacheRecordType.FailureCache);
            if (isFailureRecord)
            {
                //call trying to cache failure record
                if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                {
                    if ((existingRecords.Count > 0) && !(existingRecords[0].RDATA is DnsCache.DnsSpecialCacheRecord existingSplRecord && (existingSplRecord.Type == DnsCache.DnsSpecialCacheRecordType.FailureCache)) && !DnsResourceRecord.IsRRSetExpired(existingRecords, serveStale))
                        return; //skip to avoid overwriting a useful record with a failure record
                }
            }

            //set records
            _entries[type] = records;

            if (serveStale && !isFailureRecord)
            {
                //remove stale CNAME entry only when serve stale is enabled
                //making sure current record is not a failure record causing removal of useful stale CNAME record
                switch (type)
                {
                    case DnsResourceRecordType.CNAME:
                    case DnsResourceRecordType.SOA:
                    case DnsResourceRecordType.NS:
                    case DnsResourceRecordType.DS:
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
                if (DnsResourceRecord.IsRRSetExpired(entry.Value, serveStale))
                    _entries.TryRemove(entry.Key, out _); //RR Set is expired; remove entry
            }
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool serveStale, bool skipSpecialCacheRecord)
        {
            switch (type)
            {
                case DnsResourceRecordType.DS:
                    {
                        //since some zones have CNAME at apex so no CNAME lookup for DS queries!
                        if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                            return ValidateRRSet(type, existingRecords, serveStale, skipSpecialCacheRecord);
                    }
                    break;

                case DnsResourceRecordType.SOA:
                case DnsResourceRecordType.DNSKEY:
                    {
                        //since some zones have CNAME at apex!
                        if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                            return ValidateRRSet(type, existingRecords, serveStale, skipSpecialCacheRecord);

                        if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                        {
                            IReadOnlyList<DnsResourceRecord> rrset = ValidateRRSet(type, existingCNAMERecords, serveStale, skipSpecialCacheRecord);
                            if (rrset.Count > 0)
                            {
                                if ((type == DnsResourceRecordType.CNAME) || (rrset[0].RDATA is DnsCNAMERecord))
                                    return rrset;
                            }
                        }
                    }
                    break;

                case DnsResourceRecordType.ANY:
                    List<DnsResourceRecord> anyRecords = new List<DnsResourceRecord>();

                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                        anyRecords.AddRange(ValidateRRSet(type, entry.Value, serveStale, true));

                    return anyRecords;

                default:
                    {
                        if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                        {
                            IReadOnlyList<DnsResourceRecord> rrset = ValidateRRSet(type, existingCNAMERecords, serveStale, skipSpecialCacheRecord);
                            if (rrset.Count > 0)
                            {
                                if ((type == DnsResourceRecordType.CNAME) || (rrset[0].RDATA is DnsCNAMERecord))
                                    return rrset;
                            }
                        }

                        if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                            return ValidateRRSet(type, existingRecords, serveStale, skipSpecialCacheRecord);
                    }
                    break;
            }

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

                if (record.RDATA is DnsNSRecord)
                    return true;
            }

            return false;
        }

        #endregion
    }
}
