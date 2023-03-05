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

using DnsServerCore.ApplicationCommon;
using DnsServerCore.Dns.Applications;
using DnsServerCore.Dns.ZoneManagers;
using System;
using System.Net;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns
{
    class ResolverDnsCache : IDnsCache
    {
        #region variables

        readonly DnsApplicationManager _dnsApplicationManager;
        readonly AuthZoneManager _authZoneManager;
        readonly CacheZoneManager _cacheZoneManager;
        readonly LogManager _log;
        readonly bool _skipDnsAppAuthoritativeRequestHandlers;

        #endregion

        #region constructor

        public ResolverDnsCache(DnsApplicationManager dnsApplicationManager, AuthZoneManager authZoneManager, CacheZoneManager cacheZoneManager, LogManager log, bool skipDnsAppAuthoritativeRequestHandlers)
        {
            _dnsApplicationManager = dnsApplicationManager;
            _authZoneManager = authZoneManager;
            _cacheZoneManager = cacheZoneManager;
            _log = log;
            _skipDnsAppAuthoritativeRequestHandlers = skipDnsAppAuthoritativeRequestHandlers;
        }

        #endregion

        #region private

        private DnsDatagram DnsApplicationQueryClosestDelegation(DnsDatagram request)
        {
            if (_skipDnsAppAuthoritativeRequestHandlers || (_dnsApplicationManager.DnsAuthoritativeRequestHandlers.Count < 1) || (request.Question.Count != 1))
                return null;

            IPEndPoint localEP = new IPEndPoint(IPAddress.Any, 0);
            DnsQuestionRecord question = request.Question[0];
            string currentDomain = question.Name;

            while (true)
            {
                DnsDatagram nsRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(currentDomain, DnsResourceRecordType.NS, DnsClass.IN) });

                foreach (IDnsAuthoritativeRequestHandler requestHandler in _dnsApplicationManager.DnsAuthoritativeRequestHandlers)
                {
                    try
                    {
                        DnsDatagram nsResponse = requestHandler.ProcessRequestAsync(nsRequest, localEP, DnsTransportProtocol.Tcp, false).Sync();
                        if (nsResponse is not null)
                        {
                            if ((nsResponse.Answer.Count > 0) && (nsResponse.Answer[0].Type == DnsResourceRecordType.NS))
                                return new DnsDatagram(request.Identifier, true, nsResponse.OPCODE, nsResponse.AuthoritativeAnswer, nsResponse.Truncation, nsResponse.RecursionDesired, nsResponse.RecursionAvailable, nsResponse.AuthenticData, nsResponse.CheckingDisabled, nsResponse.RCODE, request.Question, null, nsResponse.Answer, nsResponse.Additional);
                            else if ((nsResponse.Authority.Count > 0) && (nsResponse.FindFirstAuthorityType() == DnsResourceRecordType.NS))
                                return new DnsDatagram(request.Identifier, true, nsResponse.OPCODE, nsResponse.AuthoritativeAnswer, nsResponse.Truncation, nsResponse.RecursionDesired, nsResponse.RecursionAvailable, nsResponse.AuthenticData, nsResponse.CheckingDisabled, nsResponse.RCODE, request.Question, null, nsResponse.Authority, nsResponse.Additional);
                        }
                    }
                    catch (Exception ex)
                    {
                        if (_log is not null)
                            _log.Write(ex);
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

        public DnsDatagram QueryClosestDelegation(DnsDatagram request)
        {
            DnsDatagram authResponse = DnsApplicationQueryClosestDelegation(request);
            if (authResponse is null)
                authResponse = _authZoneManager.QueryClosestDelegation(request);

            DnsDatagram cacheResponse = _cacheZoneManager.QueryClosestDelegation(request);

            if ((authResponse is not null) && (authResponse.Authority.Count > 0))
            {
                if ((cacheResponse is not null) && (cacheResponse.Authority.Count > 0))
                {
                    DnsResourceRecord authResponseFirstAuthority = authResponse.FindFirstAuthorityRecord();
                    DnsResourceRecord cacheResponseFirstAuthority = cacheResponse.FindFirstAuthorityRecord();

                    if (cacheResponseFirstAuthority.Name.Length > authResponseFirstAuthority.Name.Length)
                        return cacheResponse;
                }

                return authResponse;
            }
            else
            {
                return cacheResponse;
            }
        }

        public virtual DnsDatagram Query(DnsDatagram request, bool serveStaleAndResetExpiry = false, bool findClosestNameServers = false)
        {
            DnsDatagram authResponse = null;

            if (!_skipDnsAppAuthoritativeRequestHandlers)
            {
                foreach (IDnsAuthoritativeRequestHandler requestHandler in _dnsApplicationManager.DnsAuthoritativeRequestHandlers)
                {
                    try
                    {
                        authResponse = requestHandler.ProcessRequestAsync(request, new IPEndPoint(IPAddress.Any, 0), DnsTransportProtocol.Tcp, true).Sync();
                        if (authResponse is not null)
                        {
                            if ((authResponse.RCODE != DnsResponseCode.NoError) || (authResponse.Answer.Count > 0) || (authResponse.Authority.Count == 0) || authResponse.IsFirstAuthoritySOA())
                                return authResponse;
                        }
                    }
                    catch (Exception ex)
                    {
                        if (_log is not null)
                            _log.Write(ex);
                    }
                }
            }

            if (authResponse is null)
            {
                authResponse = _authZoneManager.Query(request, true);
                if (authResponse is not null)
                {
                    if ((authResponse.RCODE != DnsResponseCode.NoError) || (authResponse.Answer.Count > 0) || (authResponse.Authority.Count == 0) || authResponse.IsFirstAuthoritySOA())
                        return authResponse;
                }
            }

            DnsDatagram cacheResponse = _cacheZoneManager.Query(request, serveStaleAndResetExpiry, findClosestNameServers);
            if (cacheResponse is not null)
            {
                if ((cacheResponse.RCODE != DnsResponseCode.NoError) || (cacheResponse.Answer.Count > 0) || (cacheResponse.Authority.Count == 0) || cacheResponse.IsFirstAuthoritySOA())
                    return cacheResponse;
            }

            if ((authResponse is not null) && (authResponse.Authority.Count > 0))
            {
                if ((cacheResponse is not null) && (cacheResponse.Authority.Count > 0))
                {
                    DnsResourceRecord authResponseFirstAuthority = authResponse.FindFirstAuthorityRecord();
                    DnsResourceRecord cacheResponseFirstAuthority = cacheResponse.FindFirstAuthorityRecord();

                    if (cacheResponseFirstAuthority.Name.Length > authResponseFirstAuthority.Name.Length)
                        return cacheResponse;
                }

                return authResponse;
            }
            else
            {
                return cacheResponse;
            }
        }

        public void CacheResponse(DnsDatagram response, bool isDnssecBadCache = false, string zoneCut = null)
        {
            _cacheZoneManager.CacheResponse(response, isDnssecBadCache, zoneCut);
        }

        #endregion
    }
}
