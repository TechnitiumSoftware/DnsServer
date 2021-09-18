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

using DnsServerCore.ApplicationCommon;
using DnsServerCore.Dns.Applications;
using DnsServerCore.Dns.ZoneManagers;
using System.Net;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns
{
    class ResolverPrefetchDnsCache : ResolverDnsCache
    {
        #region variables

        readonly DnsQuestionRecord _prefetchQuery;

        #endregion

        #region constructor

        public ResolverPrefetchDnsCache(DnsApplicationManager dnsApplicationManager, AuthZoneManager authZoneManager, CacheZoneManager cacheZoneManager, DnsQuestionRecord prefetchQuery)
            : base(dnsApplicationManager, authZoneManager, cacheZoneManager)
        {
            _prefetchQuery = prefetchQuery;
        }

        #endregion

        #region private

        private DnsDatagram DnsApplicationQueryClosestDelegation(DnsDatagram request)
        {
            if ((_dnsApplicationManager.DnsAuthoritativeRequestHandlers.Count < 1) || (request.Question.Count != 1))
                return null;

            IPEndPoint localEP = new IPEndPoint(IPAddress.Any, 0);
            DnsQuestionRecord question = request.Question[0];
            string currentDomain = question.Name;

            while (true)
            {
                DnsDatagram nsRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(currentDomain, DnsResourceRecordType.NS, DnsClass.IN) });

                foreach (IDnsAuthoritativeRequestHandler requestHandler in _dnsApplicationManager.DnsAuthoritativeRequestHandlers)
                {
                    DnsDatagram nsResponse = requestHandler.ProcessRequestAsync(nsRequest, localEP, DnsTransportProtocol.Tcp, false).Sync();
                    if (nsResponse is not null)
                    {
                        if ((nsResponse.Answer.Count > 0) && (nsResponse.Answer[0].Type == DnsResourceRecordType.NS))
                            return new DnsDatagram(request.Identifier, true, nsResponse.OPCODE, nsResponse.AuthoritativeAnswer, nsResponse.Truncation, nsResponse.RecursionDesired, nsResponse.RecursionAvailable, nsResponse.AuthenticData, nsResponse.CheckingDisabled, nsResponse.RCODE, request.Question, null, nsResponse.Answer, nsResponse.Additional);
                        else if ((nsResponse.Authority.Count > 0) && (nsResponse.Authority[0].Type == DnsResourceRecordType.NS))
                            return new DnsDatagram(request.Identifier, true, nsResponse.OPCODE, nsResponse.AuthoritativeAnswer, nsResponse.Truncation, nsResponse.RecursionDesired, nsResponse.RecursionAvailable, nsResponse.AuthenticData, nsResponse.CheckingDisabled, nsResponse.RCODE, request.Question, null, nsResponse.Authority, nsResponse.Additional);
                    }
                }

                //get parent domain
                int i = currentDomain.IndexOf('.');
                if (i < 0)
                    break;

                currentDomain = currentDomain.Substring(i + 1);
            }

            return null;
        }

        #endregion

        #region public

        public override DnsDatagram Query(DnsDatagram request, bool serveStaleAndResetExpiry = false, bool findClosestNameServers = false)
        {
            if (findClosestNameServers && _prefetchQuery.Equals(request.Question[0]))
            {
                //return closest name servers so that the recursive resolver queries them to refreshes cache instead of returning response from cache
                DnsDatagram authResponse = DnsApplicationQueryClosestDelegation(request);
                if (authResponse is null)
                    authResponse = _authZoneManager.QueryClosestDelegation(request);

                DnsDatagram cacheResponse = _cacheZoneManager.QueryClosestDelegation(request);

                if ((authResponse is not null) && (authResponse.Authority.Count > 0))
                {
                    if ((cacheResponse is not null) && (cacheResponse.Authority.Count > 0))
                    {
                        if (cacheResponse.Authority[0].Name.Length > authResponse.Authority[0].Name.Length)
                            return cacheResponse;
                    }

                    return authResponse;
                }
                else
                {
                    return cacheResponse;
                }
            }

            return base.Query(request, serveStaleAndResetExpiry, findClosestNameServers);
        }

        #endregion
    }
}
