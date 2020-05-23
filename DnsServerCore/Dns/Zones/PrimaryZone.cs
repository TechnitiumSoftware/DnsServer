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
    public sealed class PrimaryZone : AuthZone
    {
        #region variables

        readonly bool _internal;

        #endregion

        #region constructor

        public PrimaryZone(string name, DnsSOARecord soa, bool @internal)
            : base(name, soa)
        {
            _internal = @internal;
        }

        public PrimaryZone(string name, DnsSOARecord soa, DnsNSRecord ns, bool @internal)
            : base(name, soa, ns)
        {
            _internal = @internal;
        }

        public PrimaryZone(string name, bool disabled)
            : base(name)
        {
            _disabled = disabled;
        }

        #endregion

        #region public

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (type == DnsResourceRecordType.CNAME)
                throw new InvalidOperationException("Cannot add CNAME record to zone root.");

            base.SetRecords(type, records);
        }

        #endregion

        #region properties

        public bool Internal
        { get { return _internal; } }

        #endregion
    }
}
