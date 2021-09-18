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
    class ResolverDnsCache : IDnsCache
    {
        #region variables

        readonly protected DnsApplicationManager _dnsApplicationManager;
        readonly protected AuthZoneManager _authZoneManager;
        readonly protected CacheZoneManager _cacheZoneManager;

        #endregion

        #region constructor

        public ResolverDnsCache(DnsApplicationManager dnsApplicationManager, AuthZoneManager authZoneManager, CacheZoneManager cacheZoneManager)
        {
            _dnsApplicationManager = dnsApplicationManager;
            _authZoneManager = authZoneManager;
            _cacheZoneManager = cacheZoneManager;
        }

        #endregion

        #region public

        public virtual DnsDatagram Query(DnsDatagram request, bool serveStaleAndResetExpiry = false, bool findClosestNameServers = false)
        {
            DnsDatagram authResponse = null;

            foreach (IDnsAuthoritativeRequestHandler requestHandler in _dnsApplicationManager.DnsAuthoritativeRequestHandlers)
            {
                authResponse = requestHandler.ProcessRequestAsync(request, new IPEndPoint(IPAddress.Any, 0), DnsTransportProtocol.Tcp, false).Sync();
                if (authResponse is not null)
                {
                    if ((authResponse.RCODE != DnsResponseCode.NoError) || (authResponse.Answer.Count > 0) || (authResponse.Authority.Count == 0) || (authResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                        return authResponse;
                }
            }

            if (authResponse is null)
            {
                authResponse = _authZoneManager.Query(request, true);
                if (authResponse is not null)
                {
                    if ((authResponse.RCODE != DnsResponseCode.NoError) || (authResponse.Answer.Count > 0) || (authResponse.Authority.Count == 0) || (authResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                        return authResponse;
                }
            }

            DnsDatagram cacheResponse = _cacheZoneManager.Query(request, serveStaleAndResetExpiry, findClosestNameServers);
            if (cacheResponse is not null)
            {
                if ((cacheResponse.RCODE != DnsResponseCode.NoError) || (cacheResponse.Answer.Count > 0) || (cacheResponse.Authority.Count == 0) || (cacheResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                    return cacheResponse;
            }

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

        public void CacheResponse(DnsDatagram response)
        {
            _cacheZoneManager.CacheResponse(response);
        }

        #endregion
    }
}
