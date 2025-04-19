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
using System.Collections.Generic;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    abstract class AuthZone : Zone
    {
        #region variables

        bool _disabled;

        #endregion

        #region constructor

        protected AuthZone(AuthZoneInfo zoneInfo)
            : base(zoneInfo.Name)
        {
            _disabled = zoneInfo.Disabled;
        }

        protected AuthZone(string name)
            : base(name)
        { }

        #endregion

        #region private

        private IReadOnlyList<DnsResourceRecord> FilterDisabledRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (_disabled)
                return Array.Empty<DnsResourceRecord>();

            if (records.Count == 1)
            {
                GenericRecordInfo authRecordInfo = records[0].GetAuthGenericRecordInfo();

                if (authRecordInfo.Disabled)
                    return Array.Empty<DnsResourceRecord>(); //record disabled

                //update last used on
                authRecordInfo.LastUsedOn = DateTime.UtcNow;

                return records;
            }

            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Count);
            DateTime utcNow = DateTime.UtcNow;

            foreach (DnsResourceRecord record in records)
            {
                GenericRecordInfo authRecordInfo = record.GetAuthGenericRecordInfo();

                if (authRecordInfo.Disabled)
                    continue; //record disabled

                //update last used on
                authRecordInfo.LastUsedOn = utcNow;

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

        private IReadOnlyList<DnsResourceRecord> AppendRRSigTo(IReadOnlyList<DnsResourceRecord> records)
        {
            IReadOnlyList<DnsResourceRecord> rrsigRecords = GetRecords(DnsResourceRecordType.RRSIG);
            if (rrsigRecords.Count == 0)
                return records;

            DnsResourceRecordType type = records[0].Type;
            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Count + 2);
            newRecords.AddRange(records);

            DateTime utcNow = DateTime.UtcNow;

            foreach (DnsResourceRecord rrsigRecord in rrsigRecords)
            {
                if ((rrsigRecord.RDATA as DnsRRSIGRecordData).TypeCovered == type)
                {
                    rrsigRecord.GetAuthGenericRecordInfo().LastUsedOn = utcNow;
                    newRecords.Add(rrsigRecord);
                }
            }

            return newRecords;
        }

        #endregion

        #region versioning

        internal bool TrySetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, out IReadOnlyList<DnsResourceRecord> deletedRecords)
        {
            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                    if ((!_entries.IsEmpty) && !_entries.ContainsKey(DnsResourceRecordType.CNAME))
                        throw new InvalidOperationException("Cannot add record: a CNAME record cannot exists with other record types for the same name.");

                    break;

                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.RRSIG:
                    break; //ignore

                default:
                    if (_entries.ContainsKey(DnsResourceRecordType.CNAME))
                        throw new InvalidOperationException("Cannot add record: a CNAME record cannot exists with other record types for the same name.");

                    break;
            }

            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
            {
                deletedRecords = existingRecords;
                return _entries.TryUpdate(type, records, existingRecords);
            }
            else
            {
                deletedRecords = Array.Empty<DnsResourceRecord>();
                return _entries.TryAdd(type, records);
            }
        }

        internal bool TryDeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata, out DnsResourceRecord deletedRecord)
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

                    if (deletedRecord is null)
                        return false; //not found

                    return _entries.TryUpdate(type, updatedRecords, existingRecords);
                }
            }

            deletedRecord = null;
            return false;
        }

        internal bool TryDeleteRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, out IReadOnlyList<DnsResourceRecord> deletedRecords)
        {
            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
            {
                if (existingRecords.Count == 1)
                {
                    DnsResourceRecord existingRecord = existingRecords[0];

                    foreach (DnsResourceRecord record in records)
                    {
                        if (record.RDATA.Equals(existingRecord.RDATA))
                        {
                            if (_entries.TryRemove(type, out IReadOnlyList<DnsResourceRecord> removedRecords))
                            {
                                deletedRecords = removedRecords;
                                return true;
                            }
                        }
                    }
                }
                else
                {
                    List<DnsResourceRecord> deleted = new List<DnsResourceRecord>(records.Count);
                    List<DnsResourceRecord> updatedRecords = new List<DnsResourceRecord>(existingRecords.Count);

                    foreach (DnsResourceRecord existingRecord in existingRecords)
                    {
                        bool found = false;

                        foreach (DnsResourceRecord record in records)
                        {
                            if (record.RDATA.Equals(existingRecord.RDATA))
                            {
                                found = true;
                                break;
                            }
                        }

                        if (found)
                            deleted.Add(existingRecord);
                        else
                            updatedRecords.Add(existingRecord);
                    }

                    if (deleted.Count > 0)
                    {
                        deletedRecords = deleted;

                        if (updatedRecords.Count > 0)
                            return _entries.TryUpdate(type, updatedRecords, existingRecords);

                        return _entries.TryRemove(type, out _);
                    }
                }
            }

            deletedRecords = null;
            return false;
        }

        internal void AddOrUpdateRRSigRecords(IReadOnlyList<DnsResourceRecord> newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords)
        {
            IReadOnlyList<DnsResourceRecord> deleted = null;

            _entries.AddOrUpdate(DnsResourceRecordType.RRSIG, delegate (DnsResourceRecordType key)
            {
                deleted = Array.Empty<DnsResourceRecord>();
                return newRRSigRecords;
            },
            delegate (DnsResourceRecordType key, IReadOnlyList<DnsResourceRecord> existingRecords)
            {
                List<DnsResourceRecord> updatedRecords = new List<DnsResourceRecord>(existingRecords.Count + newRRSigRecords.Count);
                List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord existingRecord in existingRecords)
                {
                    bool found = false;
                    DnsRRSIGRecordData existingRRSig = existingRecord.RDATA as DnsRRSIGRecordData;

                    foreach (DnsResourceRecord newRRSigRecord in newRRSigRecords)
                    {
                        DnsRRSIGRecordData newRRSig = newRRSigRecord.RDATA as DnsRRSIGRecordData;

                        if ((newRRSig.TypeCovered == existingRRSig.TypeCovered) && (newRRSig.KeyTag == existingRRSig.KeyTag))
                        {
                            deletedRecords.Add(existingRecord);
                            found = true;
                            break;
                        }
                    }

                    if (!found)
                        updatedRecords.Add(existingRecord);
                }

                updatedRecords.AddRange(newRRSigRecords);

                deleted = deletedRecords;
                return updatedRecords;
            });

            deletedRRSigRecords = deleted;
        }

        internal void AddRecord(DnsResourceRecord record, out IReadOnlyList<DnsResourceRecord> addedRecords, out IReadOnlyList<DnsResourceRecord> deletedRecords)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.DNAME:
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot add record: use SetRecords() for " + record.Type.ToString() + " record.");

                default:
                    if (_entries.ContainsKey(DnsResourceRecordType.CNAME))
                        throw new InvalidOperationException("Cannot add record: a CNAME record cannot exists with other record types for the same name.");

                    break;
            }

            List<DnsResourceRecord> added = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deleted = new List<DnsResourceRecord>();

            addedRecords = added;
            deletedRecords = deleted;

            _entries.AddOrUpdate(record.Type, delegate (DnsResourceRecordType key)
            {
                added.Add(record);
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

                foreach (DnsResourceRecord existingRecord in existingRecords)
                {
                    if (existingRecord.OriginalTtlValue == record.OriginalTtlValue)
                    {
                        updatedRecords.Add(existingRecord);
                    }
                    else
                    {
                        DnsResourceRecord updatedExistingRecord = new DnsResourceRecord(existingRecord.Name, existingRecord.Type, existingRecord.Class, record.OriginalTtlValue, existingRecord.RDATA);
                        updatedRecords.Add(updatedExistingRecord);

                        added.Add(updatedExistingRecord);
                        deleted.Add(existingRecord);
                    }
                }

                updatedRecords.Add(record);

                added.Add(record);
                return updatedRecords;
            });
        }

        #endregion

        #region catalog zones

        protected IEnumerable<KeyValuePair<string, string>> EnumerateCatalogMemberZones(DnsServer dnsServer)
        {
            List<string> subDomains = new List<string>();
            dnsServer.AuthZoneManager.ListSubDomains("zones." + _name, subDomains);

            foreach (string subDomain in subDomains)
            {
                IReadOnlyList<DnsResourceRecord> ptrRecords = dnsServer.AuthZoneManager.GetRecords(_name, subDomain + ".zones." + _name, DnsResourceRecordType.PTR);
                if (ptrRecords.Count > 0)
                    yield return new KeyValuePair<string, string>((ptrRecords[0].RDATA as DnsPTRRecordData).Domain, ptrRecords[0].Name);
            }
        }

        #endregion

        #region DNSSEC

        internal IReadOnlyList<DnsResourceRecord> SignAllRRSets()
        {
            List<DnsResourceRecord> rrsigRecords = new List<DnsResourceRecord>(_entries.Count);

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                if (entry.Key == DnsResourceRecordType.RRSIG)
                    continue;

                rrsigRecords.AddRange(SignRRSet(entry.Value));
            }

            return rrsigRecords;
        }

        internal IReadOnlyList<DnsResourceRecord> RemoveAllDnssecRecords()
        {
            List<DnsResourceRecord> allRemovedRecords = new List<DnsResourceRecord>();

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                switch (entry.Key)
                {
                    case DnsResourceRecordType.DNSKEY:
                    case DnsResourceRecordType.RRSIG:
                    case DnsResourceRecordType.NSEC:
                    case DnsResourceRecordType.NSEC3PARAM:
                    case DnsResourceRecordType.NSEC3:
                        if (_entries.TryRemove(entry.Key, out IReadOnlyList<DnsResourceRecord> removedRecords))
                            allRemovedRecords.AddRange(removedRecords);

                        break;
                }
            }

            return allRemovedRecords;
        }

        internal IReadOnlyList<DnsResourceRecord> RemoveNSecRecordsWithRRSig()
        {
            List<DnsResourceRecord> allRemovedRecords = new List<DnsResourceRecord>(2);

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                switch (entry.Key)
                {
                    case DnsResourceRecordType.NSEC:
                        if (_entries.TryRemove(entry.Key, out IReadOnlyList<DnsResourceRecord> removedRecords))
                            allRemovedRecords.AddRange(removedRecords);

                        break;

                    case DnsResourceRecordType.RRSIG:
                        List<DnsResourceRecord> recordsToRemove = new List<DnsResourceRecord>(1);

                        foreach (DnsResourceRecord rrsigRecord in entry.Value)
                        {
                            DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;
                            if (rrsig.TypeCovered == DnsResourceRecordType.NSEC)
                                recordsToRemove.Add(rrsigRecord);
                        }

                        if (recordsToRemove.Count > 0)
                        {
                            if (TryDeleteRecords(DnsResourceRecordType.RRSIG, recordsToRemove, out IReadOnlyList<DnsResourceRecord> deletedRecords))
                                allRemovedRecords.AddRange(deletedRecords);
                        }

                        break;
                }
            }

            return allRemovedRecords;
        }

        internal IReadOnlyList<DnsResourceRecord> RemoveNSec3RecordsWithRRSig()
        {
            List<DnsResourceRecord> allRemovedRecords = new List<DnsResourceRecord>(2);

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                switch (entry.Key)
                {
                    case DnsResourceRecordType.NSEC3:
                    case DnsResourceRecordType.NSEC3PARAM:
                        if (_entries.TryRemove(entry.Key, out IReadOnlyList<DnsResourceRecord> removedRecords))
                            allRemovedRecords.AddRange(removedRecords);

                        break;

                    case DnsResourceRecordType.RRSIG:
                        List<DnsResourceRecord> recordsToRemove = new List<DnsResourceRecord>(1);

                        foreach (DnsResourceRecord rrsigRecord in entry.Value)
                        {
                            DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;
                            switch (rrsig.TypeCovered)
                            {
                                case DnsResourceRecordType.NSEC3:
                                case DnsResourceRecordType.NSEC3PARAM:
                                    recordsToRemove.Add(rrsigRecord);
                                    break;
                            }
                        }

                        if (recordsToRemove.Count > 0)
                        {
                            if (TryDeleteRecords(DnsResourceRecordType.RRSIG, recordsToRemove, out IReadOnlyList<DnsResourceRecord> deletedRecords))
                                allRemovedRecords.AddRange(deletedRecords);
                        }

                        break;
                }
            }

            return allRemovedRecords;
        }

        internal bool HasOnlyNSec3Records()
        {
            if (!_entries.ContainsKey(DnsResourceRecordType.NSEC3))
                return false;

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                switch (entry.Key)
                {
                    case DnsResourceRecordType.NSEC3:
                    case DnsResourceRecordType.RRSIG:
                        break;

                    default:
                        //found non NSEC3 records
                        return false;
                }
            }

            return true;
        }

        internal IReadOnlyList<DnsResourceRecord> RefreshSignatures()
        {
            if (!_entries.TryGetValue(DnsResourceRecordType.RRSIG, out IReadOnlyList<DnsResourceRecord> rrsigRecords))
            {
                if ((_entries.Count == 1) && _entries.TryGetValue(DnsResourceRecordType.NS, out _))
                    return Array.Empty<DnsResourceRecord>(); //delegation NS records are not signed

                throw new InvalidOperationException();
            }

            List<DnsResourceRecordType> typesToRefresh = new List<DnsResourceRecordType>();
            DateTime utcNow = DateTime.UtcNow;

            foreach (DnsResourceRecord rrsigRecord in rrsigRecords)
            {
                DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;

                uint signatureValidityPeriod = rrsig.SignatureExpiration - rrsig.SignatureInception;
                uint refreshPeriod = signatureValidityPeriod / 3;

                if (utcNow > DateTime.UnixEpoch.AddSeconds(rrsig.SignatureExpiration - refreshPeriod))
                    typesToRefresh.Add(rrsig.TypeCovered);
            }

            List<DnsResourceRecord> newRRSigRecords = new List<DnsResourceRecord>(typesToRefresh.Count);

            foreach (DnsResourceRecordType type in typesToRefresh)
            {
                if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> records))
                    newRRSigRecords.AddRange(SignRRSet(records));
            }

            return newRRSigRecords;
        }

        internal virtual IReadOnlyList<DnsResourceRecord> SignRRSet(IReadOnlyList<DnsResourceRecord> records)
        {
            throw new NotImplementedException();
        }

        internal IReadOnlyList<DnsResourceRecord> GetUpdatedNSecRRSet(string nextDomainName, uint ttl)
        {
            List<DnsResourceRecordType> types = new List<DnsResourceRecordType>(_entries.Count);

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                types.Add(entry.Key);

            if (!types.Contains(DnsResourceRecordType.NSEC))
            {
                types.Add(DnsResourceRecordType.NSEC);

                if (!types.Contains(DnsResourceRecordType.RRSIG))
                    types.Add(DnsResourceRecordType.RRSIG);
            }

            types.Sort();

            DnsNSECRecordData newNSecRecord = new DnsNSECRecordData(nextDomainName, types);

            if (!_entries.TryGetValue(DnsResourceRecordType.NSEC, out IReadOnlyList<DnsResourceRecord> existingRecords) || (existingRecords[0].TTL != ttl) || !existingRecords[0].RDATA.Equals(newNSecRecord))
                return new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.NSEC, DnsClass.IN, ttl, newNSecRecord) };

            return Array.Empty<DnsResourceRecord>();
        }

        internal IReadOnlyList<DnsResourceRecord> GetUpdatedNSec3RRSet(IReadOnlyList<DnsResourceRecord> newNSec3Records)
        {
            if (!_entries.TryGetValue(DnsResourceRecordType.NSEC3, out IReadOnlyList<DnsResourceRecord> existingRecords) || (existingRecords[0].TTL != newNSec3Records[0].TTL) || !existingRecords[0].RDATA.Equals(newNSec3Records[0].RDATA))
                return newNSec3Records;

            return Array.Empty<DnsResourceRecord>();
        }

        internal IReadOnlyList<DnsResourceRecord> CreateNSec3RRSet(string hashedOwnerName, byte[] nextHashedOwnerName, uint ttl, ushort iterations, byte[] salt)
        {
            List<DnsResourceRecordType> types = new List<DnsResourceRecordType>(_entries.Count);

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                switch (entry.Key)
                {
                    case DnsResourceRecordType.NSEC3:
                        //rare case when there is a record created at the same name as that of an existing NSEC3
                        continue;

                    default:
                        types.Add(entry.Key);
                        break;
                }
            }

            types.Sort();

            DnsNSEC3RecordData newNSec3 = new DnsNSEC3RecordData(DnssecNSEC3HashAlgorithm.SHA1, DnssecNSEC3Flags.None, iterations, salt, nextHashedOwnerName, types);
            return new DnsResourceRecord[] { new DnsResourceRecord(hashedOwnerName, DnsResourceRecordType.NSEC3, DnsClass.IN, ttl, newNSec3) };
        }

        internal DnsResourceRecord GetPartialNSec3Record(string zoneName, uint ttl, ushort iterations, byte[] salt)
        {
            List<DnsResourceRecordType> types = new List<DnsResourceRecordType>(_entries.Count);

            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                switch (entry.Key)
                {
                    case DnsResourceRecordType.NSEC3:
                        //rare case when there is a record created at the same name as that of an existing NSEC3
                        continue;

                    default:
                        types.Add(entry.Key);
                        break;
                }
            }

            if (_name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
            {
                if (!types.Contains(DnsResourceRecordType.NSEC3PARAM))
                    types.Add(DnsResourceRecordType.NSEC3PARAM); //add NSEC3PARAM type to NSEC3 for unsigned zone apex
            }

            types.Sort();

            DnsNSEC3RecordData newNSec3Record = new DnsNSEC3RecordData(DnssecNSEC3HashAlgorithm.SHA1, DnssecNSEC3Flags.None, iterations, salt, Array.Empty<byte>(), types);
            return new DnsResourceRecord(newNSec3Record.ComputeHashedOwnerName(_name) + (zoneName.Length > 0 ? "." + zoneName : ""), DnsResourceRecordType.NSEC3, DnsClass.IN, ttl, newNSec3Record);
        }

        #endregion

        #region public

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
            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.DNAME:
                case DnsResourceRecordType.APP:
                    if ((!_entries.IsEmpty) && !_entries.ContainsKey(type))
                        throw new InvalidOperationException($"Cannot add record: {type} record already exists for the same name.");

                    break;

                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.RRSIG:
                    break; //ignore

                default:
                    if (_entries.ContainsKey(DnsResourceRecordType.CNAME))
                        throw new InvalidOperationException("Cannot add record: a CNAME record cannot exists with other record types for the same name.");

                    break;
            }

            _entries[type] = records;
        }

        public virtual bool AddRecord(DnsResourceRecord record)
        {
            AddRecord(record, out IReadOnlyList<DnsResourceRecord> addedRecords, out _);

            return addedRecords.Count > 0;
        }

        public virtual bool DeleteRecords(DnsResourceRecordType type)
        {
            return _entries.TryRemove(type, out _);
        }

        public virtual bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            return TryDeleteRecord(type, rdata, out _);
        }

        public virtual void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            if (oldRecord.Type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot update record: use SetRecords() for " + oldRecord.Type.ToString() + " record");

            if (oldRecord.Type != newRecord.Type)
                throw new InvalidOperationException("Old and new record types do not match.");

            if (!DeleteRecord(oldRecord.Type, oldRecord.RDATA))
                throw new DnsWebServiceException("Cannot update record: the old record does not exists.");

            AddRecord(newRecord);
        }

        public virtual IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool dnssecOk)
        {
            switch (type)
            {
                case DnsResourceRecordType.APP:
                case DnsResourceRecordType.FWD:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3:
                    {
                        //return only exact type if exists
                        if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                        {
                            IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingRecords);
                            if (filteredRecords.Count > 0)
                            {
                                if (dnssecOk)
                                    return AppendRRSigTo(filteredRecords);

                                return filteredRecords;
                            }
                        }
                    }
                    break;

                case DnsResourceRecordType.ANY:
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

                default:
                    {
                        //check for CNAME
                        if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                        {
                            IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingCNAMERecords);
                            if (filteredRecords.Count > 0)
                            {
                                if (dnssecOk)
                                    return AppendRRSigTo(filteredRecords);

                                return filteredRecords;
                            }
                        }

                        //check for exact type
                        if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                        {
                            IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingRecords);
                            if (filteredRecords.Count > 0)
                            {
                                if (dnssecOk)
                                    return AppendRRSigTo(filteredRecords);

                                return filteredRecords;
                            }
                        }

                        //check special processing
                        switch (type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                //check for ANAME
                                if (_entries.TryGetValue(DnsResourceRecordType.ANAME, out IReadOnlyList<DnsResourceRecord> anameRecords))
                                    return FilterDisabledRecords(type, anameRecords);

                                //check for ALIAS
                                if (_entries.TryGetValue(DnsResourceRecordType.ALIAS, out IReadOnlyList<DnsResourceRecord> aliasRecords))
                                {
                                    List<DnsResourceRecord> newAliasRecords = new List<DnsResourceRecord>(aliasRecords.Count);

                                    foreach (DnsResourceRecord aliasRecord in aliasRecords)
                                    {
                                        if ((aliasRecord.RDATA is DnsALIASRecordData alias) && (alias.Type == type))
                                            newAliasRecords.Add(aliasRecord);
                                    }

                                    if (newAliasRecords.Count > 0)
                                        return FilterDisabledRecords(type, newAliasRecords);
                                }

                                break;
                        }
                    }
                    break;
            }

            return Array.Empty<DnsResourceRecord>();
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecordsWildcard(DnsResourceRecordType type, bool dnssecOk, string queryDomain)
        {
            IReadOnlyList<DnsResourceRecord> answers = QueryRecords(type, dnssecOk);

            if ((answers.Count > 0) && _name.StartsWith('*') && !_name.Equals(queryDomain, StringComparison.OrdinalIgnoreCase))
            {
                //wildcard zone; generate new answer records
                DnsResourceRecord[] wildcardAnswers = new DnsResourceRecord[answers.Count];

                for (int i = 0; i < answers.Count; i++)
                    wildcardAnswers[i] = new DnsResourceRecord(queryDomain, answers[i].Type, answers[i].Class, answers[i].TTL, answers[i].RDATA) { Tag = answers[i].Tag };

                answers = wildcardAnswers;
            }

            return answers;
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
                if (record.GetAuthGenericRecordInfo().Disabled)
                    continue;

                return true;
            }

            return false;
        }

        #endregion

        #region properties

        public IReadOnlyDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> Entries
        { get { return _entries; } }

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
