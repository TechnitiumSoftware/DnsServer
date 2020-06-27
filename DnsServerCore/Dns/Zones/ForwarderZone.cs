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
    class ForwarderZone : AuthZone
    {
        #region constructor

        public ForwarderZone(AuthZoneInfo zoneInfo)
            : base(zoneInfo.Name)
        {
            _disabled = zoneInfo.Disabled;
        }

        public ForwarderZone(string name, DnsTransportProtocol forwarderProtocol, string forwarder)
            : base(name)
        {
            DnsResourceRecord fwdRecord = new DnsResourceRecord(name, DnsResourceRecordType.FWD, DnsClass.IN, 0, new DnsForwarderRecord(forwarderProtocol, forwarder));

            _entries[DnsResourceRecordType.FWD] = new DnsResourceRecord[] { fwdRecord };
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
                    throw new InvalidOperationException("Cannot set NS record to forwarder zone root.");

                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot set SOA record to forwarder zone root.");

                default:
                    base.SetRecords(type, records);
                    break;
            }
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.NS:
                    throw new InvalidOperationException("Cannot add NS record at forwarder zone root.");

                default:
                    base.AddRecord(record);
                    break;
            }
        }

        #endregion
    }
}
