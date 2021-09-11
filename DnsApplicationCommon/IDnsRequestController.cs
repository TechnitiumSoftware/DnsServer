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

using System;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsApplicationCommon
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
    /// Allows a DNS App to inspect and optionally block incoming DNS requests before they are processed by the DNS Server core.
    /// </summary>
    public interface IDnsRequestController : IDisposable
    {
        /// <summary>
        /// Allows initializing the DNS application with a config. This function is also called when the config is updated to allow reloading.
        /// </summary>
        /// <param name="dnsServer">The DNS server interface object that allows access to DNS server properties.</param>
        /// <param name="config">The DNS application config stored in the <c>dnsApp.config</c> file.</param>
        Task InitializeAsync(IDnsServer dnsServer, string config);

        /// <summary>
        /// Allows a DNS App to inspect an incoming DNS request and decide whether to allow or block it. This method is called by the DNS Server before an incoming request is processed.
        /// </summary>
        /// <param name="request">The incoming DNS request.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <param name="protocol">The protocol using which the request was received.</param>
        /// <returns>The action that must be taken by the DNS server i.e. if the request must be allowed or dropped.</returns>
        Task<DnsRequestControllerAction> GetRequestActionAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol);

        /// <summary>
        /// The description about this app to be shown in the Apps section of the DNS web console.
        /// </summary>
        string Description { get; }
    }
}
