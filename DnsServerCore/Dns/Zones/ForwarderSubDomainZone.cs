/*
Technitium DNS Server
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
                case DnsResourceRecordType.DS:
                    throw new DnsServerException("The record type is not supported by forwarder zones.");

                default:
                    base.SetRecords(type, records);
                    _forwarderZone.UpdateLastModified();
                    break;
            }
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.DS:
                    throw new DnsServerException("The record type is not supported by forwarder zones.");

                default:
                    base.AddRecord(record);
                    _forwarderZone.UpdateLastModified();
                    break;
            }
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            if (base.DeleteRecords(type))
            {
                _forwarderZone.UpdateLastModified();
                return true;
            }

            return false;
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            if (base.DeleteRecord(type, rdata))
            {
                _forwarderZone.UpdateLastModified();
                return true;
            }

            return false;
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            base.UpdateRecord(oldRecord, newRecord);
            _forwarderZone.UpdateLastModified();
        }

        #endregion
    }
}
