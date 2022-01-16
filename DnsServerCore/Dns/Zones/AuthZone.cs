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
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    abstract class AuthZone : Zone, IDisposable
    {
        #region variables

        protected bool _disabled;

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

        private IReadOnlyList<DnsResourceRecord> AddRRSIGs(IReadOnlyList<DnsResourceRecord> records)
        {
            IReadOnlyList<DnsResourceRecord> rrsigRecords = GetRecords(DnsResourceRecordType.RRSIG);
            if (rrsigRecords.Count == 0)
                return records;

            DnsResourceRecordType type = records[0].Type;
            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Count + 2);
            newRecords.AddRange(records);

            foreach (DnsResourceRecord rrsigRecord in rrsigRecords)
            {
                if ((rrsigRecord.RDATA as DnsRRSIGRecord).TypeCovered == type)
                    newRecords.Add(rrsigRecord);
            }

            return newRecords;
        }

        #endregion

        #region protected

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

        public virtual IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool dnssecOk)
        {
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

            //check for CNAME
            if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
            {
                IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingCNAMERecords);
                if (filteredRecords.Count > 0)
                {
                    if (dnssecOk)
                        return AddRRSIGs(filteredRecords);

                    return filteredRecords;
                }
            }

            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
            {
                IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingRecords);
                if (filteredRecords.Count > 0)
                {
                    if (dnssecOk)
                        return AddRRSIGs(filteredRecords);

                    return filteredRecords;
                }
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

        public virtual bool IsActive
        {
            get { return !_disabled; }
        }

        #endregion
    }
}
