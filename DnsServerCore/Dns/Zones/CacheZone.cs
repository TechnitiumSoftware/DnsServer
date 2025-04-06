/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class CacheZone : Zone
    {
        #region variables

        ConcurrentDictionary<NetworkAddress, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>> _ecsEntries;

        #endregion

        #region constructor

        public CacheZone(string name, int capacity)
            : base(name, capacity)
        { }

        private CacheZone(string name, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entries)
            : base(name, entries)
        { }

        #endregion

        #region static

        public static CacheZone ReadFrom(BinaryReader bR, bool serveStale)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    string name = bR.ReadString();
                    ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entries = ReadEntriesFrom(bR, serveStale);

                    CacheZone cacheZone = new CacheZone(name, entries);

                    //write all ECS cache records
                    {
                        int ecsCount = bR.ReadInt32();
                        if (ecsCount > 0)
                        {
                            ConcurrentDictionary<NetworkAddress, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>> ecsEntries = new ConcurrentDictionary<NetworkAddress, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>>(-1, ecsCount);

                            for (int i = 0; i < ecsCount; i++)
                            {
                                NetworkAddress key = NetworkAddress.ReadFrom(bR);
                                ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> ecsEntry = ReadEntriesFrom(bR, serveStale);

                                if (!ecsEntry.IsEmpty)
                                    ecsEntries.TryAdd(key, ecsEntry);
                            }

                            if (!ecsEntries.IsEmpty)
                                cacheZone._ecsEntries = ecsEntries;
                        }
                    }

                    return cacheZone;

                default:
                    throw new InvalidDataException("CacheZone format version not supported.");
            }
        }

        #endregion

        #region private

        private static IReadOnlyList<DnsResourceRecord> ValidateRRSet(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, bool serveStale, bool skipSpecialCacheRecord)
        {
            foreach (DnsResourceRecord record in records)
            {
                if (record.IsExpired(serveStale))
                    return Array.Empty<DnsResourceRecord>(); //RR Set is expired

                if (skipSpecialCacheRecord && (record.RDATA is DnsCache.DnsSpecialCacheRecordData))
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

            //update last used on
            DateTime utcNow = DateTime.UtcNow;

            foreach (DnsResourceRecord record in records)
                record.GetCacheRecordInfo().LastUsedOn = utcNow;

            return records;
        }

        private static ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> ReadEntriesFrom(BinaryReader bR, bool serveStale)
        {
            int count = bR.ReadInt32();
            ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(-1, count);

            for (int i = 0; i < count; i++)
            {
                DnsResourceRecordType key = (DnsResourceRecordType)bR.ReadUInt16();
                int rrCount = bR.ReadInt32();
                DnsResourceRecord[] records = new DnsResourceRecord[rrCount];

                for (int j = 0; j < rrCount; j++)
                {
                    records[j] = DnsResourceRecord.ReadCacheRecordFrom(bR, delegate (DnsResourceRecord record)
                    {
                        record.Tag = new CacheRecordInfo(bR);
                    });
                }

                if (!DnsResourceRecord.IsRRSetExpired(records, serveStale))
                    entries.TryAdd(key, records);
            }

            return entries;
        }

        private static void WriteEntriesTo(ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entries, BinaryWriter bW)
        {
            bW.Write(entries.Count);

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in entries)
            {
                bW.Write((ushort)entry.Key);
                bW.Write(entry.Value.Count);

                foreach (DnsResourceRecord record in entry.Value)
                {
                    record.WriteCacheRecordTo(bW, delegate ()
                    {
                        if (record.Tag is not CacheRecordInfo rrInfo)
                            rrInfo = CacheRecordInfo.Default; //default info

                        rrInfo.WriteTo(bW);
                    });
                }
            }
        }

        #endregion

        #region public

        public bool SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, bool serveStale)
        {
            if (records.Count == 0)
                return false;

            ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entries;

            CacheRecordInfo cacheRecordInfo = records[0].GetCacheRecordInfo();
            NetworkAddress eDnsClientSubnet = cacheRecordInfo.EDnsClientSubnet;

            if (eDnsClientSubnet is null)
            {
                entries = _entries;
            }
            else
            {
                if (_ecsEntries is null)
                {
                    _ecsEntries = new ConcurrentDictionary<NetworkAddress, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>>(-1, 5);
                    entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(-1, 1);
                    if (!_ecsEntries.TryAdd(eDnsClientSubnet, entries))
                        return false;
                }
                else if (!_ecsEntries.TryGetValue(eDnsClientSubnet, out entries))
                {
                    entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(-1, 1);
                    if (!_ecsEntries.TryAdd(eDnsClientSubnet, entries))
                        return false;
                }
            }

            bool isFailureRecord = false;

            if (records[0].RDATA is DnsCache.DnsSpecialCacheRecordData splRecord)
            {
                if (splRecord.IsFailureOrBadCache)
                {
                    //call trying to cache failure record
                    isFailureRecord = true;

                    if (entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords) && (existingRecords.Count > 0) && !DnsResourceRecord.IsRRSetExpired(existingRecords, serveStale))
                    {
                        if ((existingRecords[0].RDATA is not DnsCache.DnsSpecialCacheRecordData existingSplRecord) || !existingSplRecord.IsFailureOrBadCache)
                            return false; //skip to avoid overwriting a useful record with a failure record

                        //copy extended errors from existing spl record
                        splRecord.CopyExtendedDnsErrorsFrom(existingSplRecord);
                    }
                }
            }
            else if (records[0].Type == DnsResourceRecordType.CHILD_NS)
            {
                //convert back RRSet to correct type
                DnsResourceRecord[] newRecords = new DnsResourceRecord[records.Count];

                for (int i = 0; i < records.Count; i++)
                {
                    DnsResourceRecord record = records[i];

                    if (record.Type == DnsResourceRecordType.CHILD_NS)
                        record = record.CloneAs(DnsResourceRecordType.NS);

                    newRecords[i] = record;
                }

                records = newRecords;
            }

            //set last used date time
            DateTime utcNow = DateTime.UtcNow;

            foreach (DnsResourceRecord record in records)
                record.GetCacheRecordInfo().LastUsedOn = utcNow;

            //set records
            bool added = true;

            entries.AddOrUpdate(type, records, delegate (DnsResourceRecordType key, IReadOnlyList<DnsResourceRecord> existingRecords)
            {
                added = false;
                return records;
            });

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

                        if (entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                        {
                            if ((existingCNAMERecords.Count > 0) && (existingCNAMERecords[0].RDATA is DnsCNAMERecordData) && existingCNAMERecords[0].IsStale)
                            {
                                //delete CNAME entry only when it contains stale DnsCNAMERecord RDATA and not special cache records
                                entries.TryRemove(DnsResourceRecordType.CNAME, out _);
                            }
                        }
                        break;
                }
            }

            return added;
        }

        public int RemoveExpiredRecords(bool serveStale)
        {
            int removedEntries = 0;

            if (_ecsEntries is not null)
            {
                foreach (KeyValuePair<NetworkAddress, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>> ecsEntry in _ecsEntries)
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in ecsEntry.Value)
                    {
                        if (DnsResourceRecord.IsRRSetExpired(entry.Value, serveStale))
                        {
                            if (ecsEntry.Value.TryRemove(entry.Key, out _)) //RR Set is expired; remove entry
                                removedEntries++;
                        }
                    }

                    if (ecsEntry.Value.IsEmpty)
                        _ecsEntries.TryRemove(ecsEntry.Key, out _);
                }
            }

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                if (DnsResourceRecord.IsRRSetExpired(entry.Value, serveStale))
                {
                    if (_entries.TryRemove(entry.Key, out _)) //RR Set is expired; remove entry
                        removedEntries++;
                }
            }

            return removedEntries;
        }

        public int RemoveLeastUsedRecords(DateTime cutoff)
        {
            int removedEntries = 0;

            if (_ecsEntries is not null)
            {
                foreach (KeyValuePair<NetworkAddress, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>> ecsEntry in _ecsEntries)
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in ecsEntry.Value)
                    {
                        if ((entry.Value.Count == 0) || (entry.Value[0].GetCacheRecordInfo().LastUsedOn < cutoff))
                        {
                            if (ecsEntry.Value.TryRemove(entry.Key, out _)) //RR Set was last used before cutoff; remove entry
                                removedEntries++;
                        }
                    }

                    if (ecsEntry.Value.IsEmpty)
                        _ecsEntries.TryRemove(ecsEntry.Key, out _);
                }
            }

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                if ((entry.Value.Count == 0) || (entry.Value[0].GetCacheRecordInfo().LastUsedOn < cutoff))
                {
                    if (_entries.TryRemove(entry.Key, out _)) //RR Set was last used before cutoff; remove entry
                        removedEntries++;
                }
            }

            return removedEntries;
        }

        public int DeleteEDnsClientSubnetData()
        {
            if (_ecsEntries is null)
                return 0;

            int count = 0;

            foreach (KeyValuePair<NetworkAddress, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>> ecsEntry in _ecsEntries)
                count += ecsEntry.Value.Count;

            _ecsEntries = null;

            return count;
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool serveStale, bool skipSpecialCacheRecord, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet)
        {
            ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entries;

            if (eDnsClientSubnet is null)
            {
                entries = _entries;
            }
            else
            {
                if (_ecsEntries is null)
                    return Array.Empty<DnsResourceRecord>();

                if (advancedForwardingClientSubnet)
                {
                    if (!_ecsEntries.TryGetValue(eDnsClientSubnet, out entries))
                        return Array.Empty<DnsResourceRecord>();
                }
                else
                {
                    NetworkAddress selectedNetwork = null;
                    entries = null;

                    foreach (KeyValuePair<NetworkAddress, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>> ecsEntry in _ecsEntries)
                    {
                        NetworkAddress cacheSubnet = ecsEntry.Key;

                        if (cacheSubnet.PrefixLength > eDnsClientSubnet.PrefixLength)
                            continue;

                        if (cacheSubnet.Equals(eDnsClientSubnet) || cacheSubnet.Contains(eDnsClientSubnet.Address))
                        {
                            if ((selectedNetwork is null) || (cacheSubnet.PrefixLength < selectedNetwork.PrefixLength))
                            {
                                selectedNetwork = cacheSubnet;
                                entries = ecsEntry.Value;
                            }
                        }
                    }

                    if (entries is null)
                        return Array.Empty<DnsResourceRecord>();
                }
            }

            switch (type)
            {
                case DnsResourceRecordType.DS:
                    {
                        //since some zones have CNAME at apex so no CNAME lookup for DS queries!
                        if (entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                            return ValidateRRSet(type, existingRecords, serveStale, skipSpecialCacheRecord);
                    }
                    break;

                case DnsResourceRecordType.SOA:
                case DnsResourceRecordType.DNSKEY:
                    {
                        //since some zones have CNAME at apex!
                        if (entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                            return ValidateRRSet(type, existingRecords, serveStale, skipSpecialCacheRecord);

                        if (entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                        {
                            IReadOnlyList<DnsResourceRecord> rrset = ValidateRRSet(type, existingCNAMERecords, serveStale, skipSpecialCacheRecord);
                            if (rrset.Count > 0)
                            {
                                if ((type == DnsResourceRecordType.CNAME) || (rrset[0].RDATA is DnsCNAMERecordData))
                                    return rrset;
                            }
                        }
                    }
                    break;

                case DnsResourceRecordType.ANY:
                    List<DnsResourceRecord> anyRecords = new List<DnsResourceRecord>(entries.Count * 2);

                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in entries)
                    {
                        if (entry.Key == DnsResourceRecordType.DS)
                            continue;

                        anyRecords.AddRange(ValidateRRSet(type, entry.Value, serveStale, true));
                    }

                    return anyRecords;

                default:
                    {
                        if (entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                        {
                            IReadOnlyList<DnsResourceRecord> rrset = ValidateRRSet(type, existingCNAMERecords, serveStale, skipSpecialCacheRecord);
                            if (rrset.Count > 0)
                            {
                                if ((type == DnsResourceRecordType.CNAME) || (rrset[0].RDATA is DnsCNAMERecordData))
                                    return rrset;
                            }
                        }

                        if (entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                            return ValidateRRSet(type, existingRecords, serveStale, skipSpecialCacheRecord);
                    }
                    break;
            }

            return Array.Empty<DnsResourceRecord>();
        }

        public override void ListAllRecords(List<DnsResourceRecord> records)
        {
            if (_ecsEntries is not null)
            {
                foreach (KeyValuePair<NetworkAddress, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>> ecsEntry in _ecsEntries)
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in ecsEntry.Value)
                        records.AddRange(entry.Value);
                }
            }

            base.ListAllRecords(records);
        }

        public override bool ContainsNameServerRecords()
        {
            if (!_entries.TryGetValue(DnsResourceRecordType.NS, out IReadOnlyList<DnsResourceRecord> records))
            {
                if ((_name.Length > 0) || !_entries.TryGetValue(DnsResourceRecordType.CHILD_NS, out records)) //root zone case
                    return false;
            }

            foreach (DnsResourceRecord record in records)
            {
                if (record.IsStale)
                    continue;

                if (record.RDATA is DnsNSRecordData)
                    return true;
            }

            return false;
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version

            //cache zone info
            bW.Write(_name);

            //write all cache records
            WriteEntriesTo(_entries, bW);

            //write all ECS cache records
            if (_ecsEntries is null)
            {
                bW.Write(0);
            }
            else
            {
                bW.Write(_ecsEntries.Count);

                foreach (KeyValuePair<NetworkAddress, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>> ecsEntry in _ecsEntries)
                {
                    ecsEntry.Key.WriteTo(bW);
                    WriteEntriesTo(ecsEntry.Value, bW);
                }
            }
        }

        #endregion

        #region properties

        public override bool IsEmpty
        {
            get
            {
                if (_ecsEntries is null)
                    return _entries.IsEmpty;

                return _ecsEntries.IsEmpty && _entries.IsEmpty;
            }
        }

        public int TotalEntries
        {
            get
            {
                if (_ecsEntries is null)
                    return _entries.Count;

                int count = _entries.Count;

                foreach (KeyValuePair<NetworkAddress, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>> ecsEntry in _ecsEntries)
                    count += ecsEntry.Value.Count;

                return count;
            }
        }

        #endregion
    }
}
