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

using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.ApplicationCommon
{
    /// <summary>
    /// Lets a DNS App to handle incoming requests for the DNS server authoritatively allowing it to act as an authoritative zone by itself and respond to any requests.
    /// </summary>
    public interface IDnsAuthoritativeRequestHandler
    {
        /// <summary>
        /// Allows a DNS App to respond to an incoming DNS request authoritatively. Response returned may be further processed to resolve CNAME or ANAME records, or referral response.
        /// </summary>
        /// <param name="request">The incoming DNS request to be processed.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <param name="protocol">The protocol using which the request was received.</param>
        /// <param name="isRecursionAllowed">Tells if the DNS server is configured to allow recursion for the client making this request.</param>
        /// <returns>The DNS response for the DNS request or <c>null</c> to let the DNS server core process the request as usual.</returns>
        Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed);
    }
}
