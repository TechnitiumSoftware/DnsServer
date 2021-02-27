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
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class ApplicationZone : AuthZone
    {
        #region constructor

        public ApplicationZone(AuthZoneInfo zoneInfo)
            : base(zoneInfo.Name)
        {
            _disabled = zoneInfo.Disabled;
        }

        public ApplicationZone(string name, string package, string classPath, string data)
            : base(name)
        {
            DnsResourceRecord appRecord = new DnsResourceRecord(name, DnsResourceRecordType.APP, DnsClass.IN, 60, new DnsApplicationRecord(package, classPath, data));

            _entries[DnsResourceRecordType.APP] = new DnsResourceRecord[] { appRecord };
        }

        #endregion

        #region public

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                    throw new InvalidOperationException("Cannot set CNAME record to zone root.");

                case DnsResourceRecordType.NS:
                    throw new InvalidOperationException("Cannot set NS record to application zone root.");

                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot set SOA record to application zone root.");

                default:
                    base.SetRecords(type, records);
                    break;
            }
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.APP:
                    throw new InvalidOperationException("Cannot add record: use SetRecords() for " + record.Type.ToString() + " record");

                case DnsResourceRecordType.NS:
                    throw new InvalidOperationException("Cannot add NS record at application zone root.");

                default:
                    base.AddRecord(record);
                    break;
            }
        }

        #endregion
    }
}
