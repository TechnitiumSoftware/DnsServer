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
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore.ApplicationCommon
{
    /// <summary>
    /// Provides an interface to access the internal DNS Server core.
    /// </summary>
    public interface IDnsServer
    {
        /// <summary>
        /// Allows querying the DNS server core directly. This call supports recursion even if its not enabled in the DNS server configuration. The request wont be routed to any of the installed DNS Apps except for processing APP records. The request and its response are not counted in any stats or logged.
        /// </summary>
        /// <param name="question">The question record containing the details to query.</param>
        /// <returns>The DNS response for the DNS query or <c>null</c> if the request timed out.</returns>
        Task<DnsDatagram> DirectQueryAsync(DnsQuestionRecord question);

        /// <summary>
        /// Writes a log entry to the DNS server log file.
        /// </summary>
        /// <param name="message">The message to log.</param>
        void WriteLog(string message);

        /// <summary>
        /// Writes a log entry to the DNS server log file.
        /// </summary>
        /// <param name="ex">The exception to log.</param>
        void WriteLog(Exception ex);

        /// <summary>
        /// The name of this installed application.
        /// </summary>
        string ApplicationName { get; }

        /// <summary>
        /// The folder where this application is saved on the disk. Can be used to create temp files, read/write files, etc. for this application.
        /// </summary>
        string ApplicationFolder { get; }

        /// <summary>
        /// The primary domain name used by this DNS Server to identify itself.
        /// </summary>
        string ServerDomain { get; }

        /// <summary>
        /// The DNS cache object which provides direct access to the DNS server cache.
        /// </summary>
        IDnsCache DnsCache { get; }

        /// <summary>
        /// The proxy server setting on the DNS server to be used when required to make any outbound network connection.
        /// </summary>
        NetProxy Proxy { get; }

        /// <summary>
        /// Tells if the DNS server prefers using IPv6 as per the settings.
        /// </summary>
        bool PreferIPv6 { get; }
    }
}
