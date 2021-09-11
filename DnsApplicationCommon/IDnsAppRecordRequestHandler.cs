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
    /// <summary>
    /// Allows a DNS App to handle incoming DNS requests for configured APP records in the DNS server zones.
    /// </summary>
    public interface IDnsAppRecordRequestHandler : IDisposable
    {
        /// <summary>
        /// Allows initializing the DNS application with a config. This function is also called when the config is updated to allow reloading.
        /// </summary>
        /// <param name="dnsServer">The DNS server interface object that allows access to DNS server properties.</param>
        /// <param name="config">The DNS application config stored in the <c>dnsApp.config</c> file.</param>
        Task InitializeAsync(IDnsServer dnsServer, string config);

        /// <summary>
        /// Allows a DNS App to respond to the incoming DNS requests for an APP record in a primary or secondary zone.
        /// </summary>
        /// <param name="request">The incoming DNS request to be processed.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <param name="protocol">The protocol using which the request was received.</param>
        /// <param name="isRecursionAllowed">Tells if the DNS server is configured to allow recursion for the client making this request.</param>
        /// <param name="zoneName">The name of the application zone that the APP record belongs to.</param>
        /// <param name="appRecordTtl">The TTL value set in the APP record.</param>
        /// <param name="appRecordData">The record data in the APP record as required for processing the request.</param>
        /// <returns>The DNS response for the DNS request or <c>null</c> to send no answer response with an SOA authority.</returns>
        Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, uint appRecordTtl, string appRecordData);

        /// <summary>
        /// The description about this app to be shown in the Apps section of the DNS web console.
        /// </summary>
        string Description { get; }

        /// <summary>
        /// A template of the record data format that is required by this app. This template is populated in the UI to allow the user to edit in the expected values. The format could be JSON or any other custom text based format which the app is programmed to parse. This property is optional and can return <c>null</c> if no APP record data is required by the app.
        /// </summary>
        string ApplicationRecordDataTemplate { get; }
    }
}
