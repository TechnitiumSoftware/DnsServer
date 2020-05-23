using System;
using System.Collections.Generic;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns.Zones
{
    public sealed class CacheZone : Zone
    {
        #region constructor

        public CacheZone(string name)
            : base(name)
        { }

        #endregion

        #region private

        private static IReadOnlyList<DnsResourceRecord> FilterExpiredRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, bool serveStale)
        {
            if (records.Count == 1)
            {
                if (!serveStale && records[0].IsStale)
                    return Array.Empty<DnsResourceRecord>(); //record is stale

                if (records[0].TtlValue < 1u)
                    return Array.Empty<DnsResourceRecord>(); //ttl expired

                return records;
            }

            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                if (!serveStale && record.IsStale)
                    continue; //record is stale

                if (record.TtlValue < 1u)
                    continue; //ttl expired

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

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if ((records.Count > 0) && (records[0].RDATA is DnsCache.DnsFailureRecord))
            {
                //call trying to cache failure record
                if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                {
                    if ((existingRecords.Count > 0) && !(existingRecords[0].RDATA is DnsCache.DnsFailureRecord))
                        return; //skip to avoid overwriting a useful stale record with a failure record to allow serve-stale to work as intended
                }
            }

            //set records
            base.SetRecords(type, records);

            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.SOA:
                case DnsResourceRecordType.NS:
                    //do nothing
                    break;

                default:
                    //remove old CNAME entry since current new entry type overlaps any existing CNAME entry in cache
                    //keeping both entries will create issue with serve stale implementation since stale CNAME entry will be always returned
                    _entries.TryRemove(DnsResourceRecordType.CNAME, out _);
                    break;
            }
        }

        public void RemoveExpiredRecords()
        {
            foreach (DnsResourceRecordType type in _entries.Keys)
            {
                IReadOnlyList<DnsResourceRecord> records = _entries[type];

                foreach (DnsResourceRecord record in records)
                {
                    if (record.TtlValue < 1u)
                    {
                        //record is expired; update entry
                        List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Count);

                        foreach (DnsResourceRecord existingRecord in records)
                        {
                            if (existingRecord.TtlValue < 1u)
                                continue;

                            newRecords.Add(existingRecord);
                        }

                        if (newRecords.Count > 0)
                        {
                            //try update entry with non-expired records
                            _entries.TryUpdate(type, newRecords, records);
                        }
                        else
                        {
                            //all records expired; remove entry
                            _entries.TryRemove(type, out _);
                        }

                        break;
                    }
                }
            }
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool serveStale)
        {
            //check for CNAME
            if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
            {
                IReadOnlyList<DnsResourceRecord> filteredRecords = FilterExpiredRecords(type, existingCNAMERecords, serveStale);
                if (filteredRecords.Count > 0)
                    return existingCNAMERecords;
            }

            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                return FilterExpiredRecords(type, existingRecords, serveStale);

            return Array.Empty<DnsResourceRecord>();
        }

        public override bool ContainsNameServerRecords()
        {
            IReadOnlyList<DnsResourceRecord> records = QueryRecords(DnsResourceRecordType.NS, false);
            return (records.Count > 0) && (records[0].Type == DnsResourceRecordType.NS);
        }

        #endregion
    }
}
