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

using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns.Zones
{
    class ApplicationSubDomainZone : SubDomainZone
    {
        #region variables

        readonly ApplicationZone _applicationZone;

        #endregion

        #region constructor

        public ApplicationSubDomainZone(ApplicationZone applicationZone, string name)
            : base(name)
        {
            _applicationZone = applicationZone;
        }

        #endregion

        #region public

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            base.SetRecords(type, records);

            _applicationZone.IncrementSoaSerial();
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            base.AddRecord(record);

            _applicationZone.IncrementSoaSerial();
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            if (base.DeleteRecords(type))
            {
                _applicationZone.IncrementSoaSerial();

                return true;
            }

            return false;
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            if (base.DeleteRecord(type, record))
            {
                _applicationZone.IncrementSoaSerial();

                return true;
            }

            return false;
        }

        #endregion
    }
}
