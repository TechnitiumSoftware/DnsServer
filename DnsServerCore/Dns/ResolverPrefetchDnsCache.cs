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

using DnsServerCore.Dns.Applications;
using DnsServerCore.Dns.ZoneManagers;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns
{
    class ResolverPrefetchDnsCache : ResolverDnsCache
    {
        #region variables

        readonly DnsQuestionRecord _prefetchQuestion;

        #endregion

        #region constructor

        public ResolverPrefetchDnsCache(DnsApplicationManager dnsApplicationManager, AuthZoneManager authZoneManager, CacheZoneManager cacheZoneManager, LogManager log, bool skipDnsAppAuthoritativeRequestHandlers, DnsQuestionRecord prefetchQuestion)
            : base(dnsApplicationManager, authZoneManager, cacheZoneManager, log, skipDnsAppAuthoritativeRequestHandlers)
        {
            _prefetchQuestion = prefetchQuestion;
        }

        #endregion

        #region public

        public override DnsDatagram Query(DnsDatagram request, bool serveStaleAndResetExpiry = false, bool findClosestNameServers = false)
        {
            if (_prefetchQuestion.Equals(request.Question[0]))
            {
                //request is for prefetch question

                if (!findClosestNameServers)
                    return null; //dont give answer from cache for prefetch question

                //return closest name servers so that the recursive resolver queries them to refreshes cache instead of returning response from cache
                return QueryClosestDelegation(request);
            }

            return base.Query(request, serveStaleAndResetExpiry, findClosestNameServers);
        }

        #endregion
    }
}
