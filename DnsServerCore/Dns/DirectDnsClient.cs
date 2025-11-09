/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns
{
    class DirectDnsClient : DnsClient, IDnsCache
    {
        #region variables

        readonly DnsServer _dnsServer;

        #endregion

        #region constructor

        public DirectDnsClient(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            //set dummy cache to avoid DnsCache from overwriting DnsResourceRecord.Tag properties which currently has GenericRecordInfo objects
            //caching here is also not required since DNS server already does caching
            Cache = this;
        }

        #endregion

        #region protected

        protected override async Task<DnsDatagram> InternalResolveAsync(DnsDatagram request, Func<DnsDatagram, CancellationToken, Task<DnsDatagram>> getValidatedResponseAsync = null, bool doNotReorderNameServers = false, CancellationToken cancellationToken = default)
        {
            DnsDatagram response = await _dnsServer.DirectQueryAsync(request, Timeout, cancellationToken: cancellationToken);

            //return DNSSEC validated response
            return await getValidatedResponseAsync(response, cancellationToken);
        }

        #endregion

        #region public

        public Task<DnsDatagram> QueryAsync(DnsDatagram request, bool serveStale = false, bool findClosestNameServers = false, bool resetExpiry = false)
        {
            return Task.FromResult<DnsDatagram>(null); //no cache available
        }

        public void CacheResponse(DnsDatagram response, bool isDnssecBadCache = false, string zoneCut = null)
        {
            //do nothing to prevent caching
        }

        #endregion
    }
}
