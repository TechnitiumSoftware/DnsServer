/*
Technitium DNS Server
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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

namespace DnsServerCore.Dns
{
    class ResolverDnsCache : DnsCache
    {
        #region variables

        const uint NEGATIVE_RECORD_TTL = 300u;
        const uint MINIMUM_RECORD_TTL = 10u;
        const uint SERVE_STALE_TTL = 7 * 24 * 60 * 60; //7 days serve stale ttl as per draft-ietf-dnsop-serve-stale-04

        readonly protected Zone _cacheZoneRoot;

        #endregion

        #region constructor

        public ResolverDnsCache(Zone cacheZoneRoot)
            : base(NEGATIVE_RECORD_TTL, MINIMUM_RECORD_TTL, SERVE_STALE_TTL)
        {
            _cacheZoneRoot = cacheZoneRoot;
        }

        #endregion

        #region public

        public override DnsDatagram Query(DnsDatagram request)
        {
            return _cacheZoneRoot.Query(request);
        }

        protected override void CacheRecords(ICollection<DnsResourceRecord> resourceRecords)
        {
            _cacheZoneRoot.SetRecords(resourceRecords);
        }

        #endregion
    }
}
