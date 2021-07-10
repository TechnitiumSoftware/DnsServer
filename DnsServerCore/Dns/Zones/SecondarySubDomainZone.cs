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
    class SecondarySubDomainZone : SubDomainZone
    {
        #region constructor

        public SecondarySubDomainZone(SecondaryZone secondaryZone, string name)
            : base(secondaryZone, name)
        { }

        #endregion

        #region public

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            throw new InvalidOperationException("Cannot set records in secondary zone.");
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            throw new InvalidOperationException("Cannot add record in secondary zone.");
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            throw new InvalidOperationException("Cannot delete record in secondary zone.");
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            throw new InvalidOperationException("Cannot delete records in secondary zone.");
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            throw new InvalidOperationException("Cannot update record in secondary zone.");
        }

        #endregion
    }
}
