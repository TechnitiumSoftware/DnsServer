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
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class PrimarySubDomainZone : SubDomainZone
    {
        #region variables

        readonly PrimaryZone _primaryZone;

        #endregion

        #region constructor

        public PrimarySubDomainZone(PrimaryZone primaryZone, string name)
            : base(primaryZone, name)
        {
            _primaryZone = primaryZone;
        }

        #endregion

        #region DNSSEC

        internal override IReadOnlyList<DnsResourceRecord> SignRRSet(IReadOnlyList<DnsResourceRecord> records)
        {
            return _primaryZone.SignRRSet(records);
        }

        #endregion

        #region public

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (_primaryZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned)
            {
                switch (type)
                {
                    case DnsResourceRecordType.ANAME:
                    case DnsResourceRecordType.APP:
                        throw new DnsServerException("The record type is not supported by DNSSEC signed primary zones.");

                    default:
                        foreach (DnsResourceRecord record in records)
                        {
                            if (record.GetAuthGenericRecordInfo().Disabled)
                                throw new DnsServerException("Cannot set records: disabling records in a signed zones is not supported.");
                        }

                        break;
                }
            }

            switch (type)
            {
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot set SOA record on sub domain.");

                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot set DNSSEC records.");

                case DnsResourceRecordType.FWD:
                    throw new DnsServerException("The record type is not supported by primary zones.");

                default:
                    if (records[0].OriginalTtlValue > _primaryZone.GetZoneSoaExpire())
                        throw new DnsServerException("Cannot set records: TTL cannot be greater than SOA EXPIRE.");

                    if (!TrySetRecords(type, records, out IReadOnlyList<DnsResourceRecord> deletedRecords))
                        throw new DnsServerException("Cannot set records. Please try again.");

                    _primaryZone.CommitAndIncrementSerial(deletedRecords, records);

                    if (_primaryZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned)
                        _primaryZone.UpdateDnssecRecordsFor(this, type);

                    _primaryZone.TriggerNotify();
                    break;
            }
        }

        public override bool AddRecord(DnsResourceRecord record)
        {
            if (_primaryZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned)
            {
                switch (record.Type)
                {
                    case DnsResourceRecordType.ANAME:
                    case DnsResourceRecordType.APP:
                        throw new DnsServerException("The record type is not supported by DNSSEC signed primary zones.");

                    default:
                        if (record.GetAuthGenericRecordInfo().Disabled)
                            throw new DnsServerException("Cannot add record: disabling records in a signed zones is not supported.");

                        break;
                }
            }

            switch (record.Type)
            {
                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot add DNSSEC record.");

                case DnsResourceRecordType.FWD:
                    throw new DnsServerException("The record type is not supported by primary zones.");

                default:
                    if (record.OriginalTtlValue > _primaryZone.GetZoneSoaExpire())
                        throw new DnsServerException("Cannot add record: TTL cannot be greater than SOA EXPIRE.");

                    AddRecord(record, out IReadOnlyList<DnsResourceRecord> addedRecords, out IReadOnlyList<DnsResourceRecord> deletedRecords);

                    if (addedRecords.Count > 0)
                    {
                        _primaryZone.CommitAndIncrementSerial(deletedRecords, addedRecords);

                        if (_primaryZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned)
                            _primaryZone.UpdateDnssecRecordsFor(this, record.Type);

                        _primaryZone.TriggerNotify();

                        return true;
                    }

                    return false;
            }
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            switch (type)
            {
                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot delete DNSSEC records.");

                default:
                    if (_entries.TryRemove(type, out IReadOnlyList<DnsResourceRecord> removedRecords))
                    {
                        _primaryZone.CommitAndIncrementSerial(removedRecords);

                        if (_primaryZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned)
                            _primaryZone.UpdateDnssecRecordsFor(this, type);

                        _primaryZone.TriggerNotify();

                        return true;
                    }

                    return false;
            }
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            switch (type)
            {
                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot delete DNSSEC records.");

                default:
                    if (TryDeleteRecord(type, rdata, out DnsResourceRecord deletedRecord))
                    {
                        _primaryZone.CommitAndIncrementSerial([deletedRecord]);

                        if (_primaryZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned)
                            _primaryZone.UpdateDnssecRecordsFor(this, type);

                        _primaryZone.TriggerNotify();

                        return true;
                    }

                    return false;
            }
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            switch (oldRecord.Type)
            {
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot update record: use SetRecords() for " + oldRecord.Type.ToString() + " record.");

                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot update DNSSEC records.");

                default:
                    if (oldRecord.Type != newRecord.Type)
                        throw new InvalidOperationException("Old and new record types do not match.");

                    if ((_primaryZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned) && newRecord.GetAuthGenericRecordInfo().Disabled)
                        throw new DnsServerException("Cannot update record: disabling records in a signed zones is not supported.");

                    if (newRecord.OriginalTtlValue > _primaryZone.GetZoneSoaExpire())
                        throw new DnsServerException("Cannot update record: TTL cannot be greater than SOA EXPIRE.");

                    if (!TryDeleteRecord(oldRecord.Type, oldRecord.RDATA, out DnsResourceRecord deletedRecord))
                        throw new InvalidOperationException("Cannot update record: the record does not exists to be updated.");

                    AddRecord(newRecord, out IReadOnlyList<DnsResourceRecord> addedRecords, out IReadOnlyList<DnsResourceRecord> deletedRecords);

                    List<DnsResourceRecord> allDeletedRecords = new List<DnsResourceRecord>(deletedRecords.Count + 1);
                    allDeletedRecords.Add(deletedRecord);
                    allDeletedRecords.AddRange(deletedRecords);

                    _primaryZone.CommitAndIncrementSerial(allDeletedRecords, addedRecords);

                    if (_primaryZone.DnssecStatus != AuthZoneDnssecStatus.Unsigned)
                        _primaryZone.UpdateDnssecRecordsFor(this, oldRecord.Type);

                    _primaryZone.TriggerNotify();
                    break;
            }
        }

        #endregion
    }
}
