/*
Technitium DNS Server
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    public sealed class StubZone : AuthZone
    {
        #region constructor

        public StubZone(string name, DnsSOARecord soa)
            : base(name, soa)
        { }

        public StubZone(string name, bool disabled)
            : base(name)
        {
            _disabled = disabled;
        }

        #endregion

        #region public

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            throw new InvalidOperationException("Cannot set records for stub zone.");
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            throw new InvalidOperationException("Cannot add record for stub zone.");
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            throw new InvalidOperationException("Cannot delete record for stub zone.");
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            throw new InvalidOperationException("Cannot delete records for stub zone.");
        }

        #endregion
    }
}
