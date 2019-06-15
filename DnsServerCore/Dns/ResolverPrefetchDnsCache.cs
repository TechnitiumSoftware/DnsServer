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

using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns
{
    class ResolverPrefetchDnsCache : ResolverDnsCache
    {
        #region variables

        readonly DnsQuestionRecord _prefetchQuery;

        #endregion

        #region constructor

        public ResolverPrefetchDnsCache(Zone cacheZoneRoot, DnsQuestionRecord prefetchQuery)
            : base(cacheZoneRoot)
        {
            _prefetchQuery = prefetchQuery;
        }

        #endregion

        #region public

        public override DnsDatagram Query(DnsDatagram request)
        {
            if (_prefetchQuery.Equals(request.Question[0]))
                return _cacheZoneRoot.QueryCacheGetClosestNameServers(request); //return closest name servers so that the recursive resolver queries them to refreshes cache instead of returning response from cache

            return _cacheZoneRoot.Query(request);
        }

        #endregion
    }
}
