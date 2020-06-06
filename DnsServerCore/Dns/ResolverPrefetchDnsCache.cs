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
    class ResolverPrefetchDnsCache : IDnsCache
    {
        #region variables

        readonly CacheZoneManager _cacheZoneManager;
        readonly DnsQuestionRecord _prefetchQuery;

        #endregion

        #region constructor

        public ResolverPrefetchDnsCache(CacheZoneManager cacheZoneManager, DnsQuestionRecord prefetchQuery)
        {
            _cacheZoneManager = cacheZoneManager;
            _prefetchQuery = prefetchQuery;
        }

        #endregion

        #region public

        public DnsDatagram Query(DnsDatagram request, bool serveStale = false)
        {
            if (_prefetchQuery.Equals(request.Question[0]))
            {
                //return closest name servers so that the recursive resolver queries them to refreshes cache instead of returning response from cache
                return _cacheZoneManager.QueryClosestDelegation(request);
            }

            return _cacheZoneManager.Query(request, serveStale);
        }

        public void CacheResponse(DnsDatagram response)
        {
            _cacheZoneManager.CacheResponse(response);
        }

        #endregion
    }
}
