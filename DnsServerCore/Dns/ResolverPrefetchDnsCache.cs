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

using DnsServerCore.Dns.ZoneManagers;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns
{
    class ResolverPrefetchDnsCache : ResolverDnsCache
    {
        #region variables

        readonly DnsQuestionRecord _prefetchQuery;

        #endregion

        #region constructor

        public ResolverPrefetchDnsCache(AuthZoneManager authZoneManager, CacheZoneManager cacheZoneManager, DnsQuestionRecord prefetchQuery)
            : base(authZoneManager, cacheZoneManager)
        {
            _prefetchQuery = prefetchQuery;
        }

        #endregion

        #region public

        public override DnsDatagram Query(DnsDatagram request, bool serveStale = false)
        {
            if (_prefetchQuery.Equals(request.Question[0]))
            {
                //return closest name servers so that the recursive resolver queries them to refreshes cache instead of returning response from cache
                DnsDatagram authResponse = _authZoneManager.QueryClosestDelegation(request);
                DnsDatagram cacheResponse = _cacheZoneManager.QueryClosestDelegation(request);

                if ((authResponse.Authority.Count > 0) && (cacheResponse.Authority.Count > 0))
                {
                    if (authResponse.Authority[0].Name.Length >= cacheResponse.Authority[0].Name.Length)
                        return authResponse;

                    return cacheResponse;
                }
                else if (authResponse.Authority.Count > 0)
                {
                    return authResponse;
                }
                else
                {
                    return cacheResponse;
                }
            }

            return base.Query(request, serveStale);
        }

        #endregion
    }
}
