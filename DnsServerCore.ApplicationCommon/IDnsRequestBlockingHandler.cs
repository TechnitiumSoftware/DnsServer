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

using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.ApplicationCommon
{
    /// <summary>
    /// Lets DNS Apps provide DNS level domain name blocking feature.
    /// </summary>
    public interface IDnsRequestBlockingHandler
    {
        /// <summary>
        /// Specifies if the query domain name in the incoming DNS request is allowed to bypass any configured block lists (including for DNS server's built-in blocking feature).
        /// </summary>
        /// <param name="request">The incoming DNS request to be processed.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <returns>Returns <c>true</c> if the query domain name in the incoming DNS request is allowed to bypass blocking.</returns>
        Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP);

        /// <summary>
        /// Specifies if the query domain name in the incoming DNS request is blocked based on the app's own configured block lists.
        /// </summary>
        /// <param name="request">The incoming DNS request to be processed.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <returns>The blocked DNS response for the DNS request or <c>null</c> to let the DNS server core process the request as usual.</returns>
        Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP);
    }
}
