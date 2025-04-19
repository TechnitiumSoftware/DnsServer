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

using System;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class ForwarderSubDomainZone : SubDomainZone
    {
        #region variables

        readonly ForwarderZone _forwarderZone;

        #endregion

        #region constructor

        public ForwarderSubDomainZone(ForwarderZone forwarderZone, string name)
            : base(forwarderZone, name)
        {
            _forwarderZone = forwarderZone;
        }

        #endregion

        #region public

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot set SOA record on sub domain.");

                case DnsResourceRecordType.DS:
                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot set DNSSEC records.");

                default:
                    if (records[0].OriginalTtlValue > _forwarderZone.GetZoneSoaExpire())
                        throw new DnsServerException("Cannot set records: TTL cannot be greater than SOA EXPIRE.");

                    if (!TrySetRecords(type, records, out IReadOnlyList<DnsResourceRecord> deletedRecords))
                        throw new DnsServerException("Cannot set records. Please try again.");

                    _forwarderZone.CommitAndIncrementSerial(deletedRecords, records);

                    _forwarderZone.TriggerNotify();
                    break;
            }
        }

        public override bool AddRecord(DnsResourceRecord record)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.DS:
                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot add DNSSEC record.");

                default:
                    if (record.OriginalTtlValue > _forwarderZone.GetZoneSoaExpire())
                        throw new DnsServerException("Cannot add record: TTL cannot be greater than SOA EXPIRE.");

                    AddRecord(record, out IReadOnlyList<DnsResourceRecord> addedRecords, out IReadOnlyList<DnsResourceRecord> deletedRecords);

                    if (addedRecords.Count > 0)
                    {
                        _forwarderZone.CommitAndIncrementSerial(deletedRecords, addedRecords);

                        _forwarderZone.TriggerNotify();

                        return true;
                    }

                    return false;
            }
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            if (_entries.TryRemove(type, out IReadOnlyList<DnsResourceRecord> removedRecords))
            {
                _forwarderZone.CommitAndIncrementSerial(removedRecords);

                _forwarderZone.TriggerNotify();

                return true;
            }

            return false;
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            if (TryDeleteRecord(type, rdata, out DnsResourceRecord deletedRecord))
            {
                _forwarderZone.CommitAndIncrementSerial([deletedRecord]);

                _forwarderZone.TriggerNotify();

                return true;
            }

            return false;
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            switch (oldRecord.Type)
            {
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot update record: use SetRecords() for " + oldRecord.Type.ToString() + " record.");

                default:
                    if (oldRecord.Type != newRecord.Type)
                        throw new InvalidOperationException("Old and new record types do not match.");

                    if (newRecord.OriginalTtlValue > _forwarderZone.GetZoneSoaExpire())
                        throw new DnsServerException("Cannot update record: TTL cannot be greater than SOA EXPIRE.");

                    if (!TryDeleteRecord(oldRecord.Type, oldRecord.RDATA, out DnsResourceRecord deletedRecord))
                        throw new InvalidOperationException("Cannot update record: the record does not exists to be updated.");

                    AddRecord(newRecord, out IReadOnlyList<DnsResourceRecord> addedRecords, out IReadOnlyList<DnsResourceRecord> deletedRecords);

                    List<DnsResourceRecord> allDeletedRecords = new List<DnsResourceRecord>(deletedRecords.Count + 1);
                    allDeletedRecords.Add(deletedRecord);
                    allDeletedRecords.AddRange(deletedRecords);

                    _forwarderZone.CommitAndIncrementSerial(allDeletedRecords, addedRecords);

                    _forwarderZone.TriggerNotify();
                    break;
            }
        }

        #endregion
    }
}
