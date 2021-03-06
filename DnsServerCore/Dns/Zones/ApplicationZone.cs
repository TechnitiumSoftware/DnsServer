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

        public ApplicationZone(string name, string primaryNameServer, string appName, string classPath, string data)
            : base(name)
        {
            DnsSOARecord soa = new DnsSOARecord(primaryNameServer, _name.Length == 0 ? "hostadmin" : "hostadmin." + _name, 1, 14400, 3600, 604800, 900);

            _entries[DnsResourceRecordType.SOA] = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Refresh, soa) };
            _entries[DnsResourceRecordType.NS] = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, soa.Refresh, new DnsNSRecord(soa.PrimaryNameServer)) };

            DnsResourceRecord appRecord = new DnsResourceRecord(name, DnsResourceRecordType.APP, DnsClass.IN, 60, new DnsApplicationRecord(appName, classPath, data));

            _entries[DnsResourceRecordType.APP] = new DnsResourceRecord[] { appRecord };
        }

        #endregion

        #region public

        public void IncrementSoaSerial()
        {
            DnsResourceRecord record = _entries[DnsResourceRecordType.SOA][0];
            DnsSOARecord soa = record.RDATA as DnsSOARecord;

            uint serial = soa.Serial;
            if (serial < uint.MaxValue)
                serial++;
            else
                serial = 0;

            DnsResourceRecord newRecord = new DnsResourceRecord(record.Name, record.Type, record.Class, record.TtlValue, new DnsSOARecord(soa.PrimaryNameServer, soa.ResponsiblePerson, serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum)) { Tag = record.Tag };
            _entries[DnsResourceRecordType.SOA] = new DnsResourceRecord[] { newRecord };
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                    throw new InvalidOperationException("Cannot set CNAME record to zone root.");

                case DnsResourceRecordType.SOA:
                    if ((records.Count != 1) || !records[0].Name.Equals(_name, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Invalid SOA record.");

                    //remove any resource record info
                    records[0].Tag = null;
                    break;
            }

            base.SetRecords(type, records);

            IncrementSoaSerial();
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            if (record.Type == DnsResourceRecordType.APP)
                throw new InvalidOperationException("Cannot add record: use SetRecords() for " + record.Type.ToString() + " record");

            base.AddRecord(record);

            IncrementSoaSerial();
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            if (type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot delete SOA record.");

            if (base.DeleteRecords(type))
            {
                IncrementSoaSerial();

                return true;
            }

            return false;
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            if (type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot delete SOA record.");

            if (base.DeleteRecord(type, record))
            {
                IncrementSoaSerial();

                return true;
            }

            return false;
        }

        #endregion
    }
}
