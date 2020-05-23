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
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    public abstract class AuthZone : Zone
    {
        #region variables

        protected bool _disabled;

        #endregion

        #region constructor

        protected AuthZone(string name)
            : base(name)
        { }

        protected AuthZone(string name, DnsSOARecord soa)
            : base(name)
        {
            _entries[DnsResourceRecordType.SOA] = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Refresh, soa) };
            _entries[DnsResourceRecordType.NS] = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, soa.Refresh, new DnsNSRecord(soa.MasterNameServer)) };
        }

        protected AuthZone(string name, DnsSOARecord soa, DnsNSRecord ns)
            : base(name)
        {
            _entries[DnsResourceRecordType.SOA] = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Refresh, soa) };
            _entries[DnsResourceRecordType.NS] = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, soa.Refresh, ns) };
        }

        #endregion

        #region private

        private IReadOnlyList<DnsResourceRecord> FilterDisabledRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (_disabled)
                return Array.Empty<DnsResourceRecord>();

            if (records.Count == 1)
            {
                if (records[0].IsDisabled())
                    return Array.Empty<DnsResourceRecord>(); //record disabled

                return records;
            }

            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                if (record.IsDisabled())
                    continue; //record disabled

                newRecords.Add(record);
            }

            if (newRecords.Count > 1)
            {
                switch (type)
                {
                    case DnsResourceRecordType.A:
                    case DnsResourceRecordType.AAAA:
                        newRecords.Shuffle(); //shuffle records to allow load balancing
                        break;
                }
            }

            return newRecords;
        }

        #endregion

        #region public

        public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type)
        {
            //check for CNAME
            if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
            {
                IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingCNAMERecords);
                if (filteredRecords.Count > 0)
                    return existingCNAMERecords;
            }

            if (type == DnsResourceRecordType.ANY)
            {
                List<DnsResourceRecord> records = new List<DnsResourceRecord>(_entries.Count * 2);

                foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                {
                    if (entry.Key != DnsResourceRecordType.ANY)
                        records.AddRange(entry.Value);
                }

                return FilterDisabledRecords(type, records);
            }

            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                return FilterDisabledRecords(type, existingRecords);

            return Array.Empty<DnsResourceRecord>();
        }

        public override bool ContainsNameServerRecords()
        {
            IReadOnlyList<DnsResourceRecord> records = QueryRecords(DnsResourceRecordType.NS);
            return (records.Count > 0) && (records[0].Type == DnsResourceRecordType.NS);
        }

        public bool AreAllRecordsDisabled()
        {
            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                foreach (DnsResourceRecord record in entry.Value)
                {
                    if (!record.IsDisabled())
                        return false;
                }
            }

            return true;
        }

        #endregion

        #region properties

        public bool Disabled
        {
            get { return _disabled; }
            set { _disabled = value; }
        }

        #endregion
    }
}
