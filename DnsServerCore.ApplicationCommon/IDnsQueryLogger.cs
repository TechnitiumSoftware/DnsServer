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
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.ApplicationCommon
{
    public enum DnsServerResponseType : byte
    {
        Authoritative = 1,
        Recursive = 2,
        Cached = 3,
        Blocked = 4,
        UpstreamBlocked = 5,
        UpstreamBlockedCached = 6,
        Dropped = 7
    }

    /// <summary>
    /// Allows a DNS App to log incoming DNS requests and their corresponding responses.
    /// </summary>
    public interface IDnsQueryLogger
    {
        /// <summary>
        /// Allows a DNS App to log incoming DNS requests and responses. This method is called by the DNS Server after an incoming request is processed and a response is sent.
        /// </summary>
        /// <param name="timestamp">The time stamp of the log entry.</param>
        /// <param name="request">The incoming DNS request that was received.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <param name="protocol">The protocol using which the request was received.</param>
        /// <param name="response">The DNS response that was sent.</param>
        Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response);
    }
}
