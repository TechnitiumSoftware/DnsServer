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

using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.ApplicationCommon
{
    public enum DnsRequestControllerAction
    {
        /// <summary>
        /// Allow the request to be processed.
        /// </summary>
        Allow = 0,

        /// <summary>
        /// Drop the request without any response.
        /// </summary>
        DropSilently = 1,

        /// <summary>
        /// Drop the request with a Refused response.
        /// </summary>
        DropWithRefused = 2
    }

    /// <summary>
    /// Allows a DNS App to inspect and optionally drop incoming DNS requests before they are processed by the DNS Server core.
    /// </summary>
    public interface IDnsRequestController
    {
        /// <summary>
        /// Allows a DNS App to inspect an incoming DNS request and decide whether to allow or drop it. This method is called by the DNS Server before an incoming request is processed.
        /// </summary>
        /// <param name="request">The incoming DNS request.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <param name="protocol">The protocol using which the request was received.</param>
        /// <returns>The action that must be taken by the DNS server i.e. if the request must be allowed or dropped.</returns>
        Task<DnsRequestControllerAction> GetRequestActionAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol);
    }
}
