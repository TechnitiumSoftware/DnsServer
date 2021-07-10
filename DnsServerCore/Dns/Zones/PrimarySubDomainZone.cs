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
using TechnitiumLibrary.Net.Dns;

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

        #region public

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (!SetRecords(type, records, out IReadOnlyList<DnsResourceRecord> deletedRecords))
                throw new DnsServerException("Failed to set records. Please try again.");

            _primaryZone.CommitAndIncrementSerial(deletedRecords, records);
            _primaryZone.TriggerNotify();
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            base.AddRecord(record);

            _primaryZone.CommitAndIncrementSerial(null, new DnsResourceRecord[] { record });
            _primaryZone.TriggerNotify();
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            if (_entries.TryRemove(type, out IReadOnlyList<DnsResourceRecord> removedRecords))
            {
                _primaryZone.CommitAndIncrementSerial(removedRecords);
                _primaryZone.TriggerNotify();

                return true;
            }

            return false;
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            if (DeleteRecord(type, rdata, out DnsResourceRecord deletedRecord))
            {
                _primaryZone.CommitAndIncrementSerial(new DnsResourceRecord[] { deletedRecord });
                _primaryZone.TriggerNotify();

                return true;
            }

            return false;
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            if (oldRecord.Type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot update record: use SetRecords() for " + oldRecord.Type.ToString() + " record");

            if (oldRecord.Type != newRecord.Type)
                throw new InvalidOperationException("Old and new record types do not match.");

            DeleteRecord(oldRecord.Type, oldRecord.RDATA, out DnsResourceRecord deletedRecord);
            base.AddRecord(newRecord);

            _primaryZone.CommitAndIncrementSerial(new DnsResourceRecord[] { deletedRecord }, new DnsResourceRecord[] { newRecord });
            _primaryZone.TriggerNotify();
        }

        #endregion
    }
}
