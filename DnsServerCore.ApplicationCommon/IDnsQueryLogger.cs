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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.ApplicationCommon
{
    public sealed class DnsQueryLogMetadata
    {
        public DnsQueryLogMetadata(IReadOnlyDictionary<string, string>? values = null)
        {
            Values = values is null ? new Dictionary<string, string>(0, StringComparer.OrdinalIgnoreCase) : new Dictionary<string, string>(values, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Structured metadata key/value pairs (example keys: <c>source</c>, <c>domain</c>, <c>blockListUrl</c>).
        /// </summary>
        public IReadOnlyDictionary<string, string> Values { get; }

        public string ToReportString()
        {
            if (Values.Count < 1)
                return string.Empty;

            return string.Join("; ", Values.Select(kv => Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(kv.Value)));
        }

        public static DnsQueryLogMetadata? ParseReportString(string? report)
        {
            if (string.IsNullOrWhiteSpace(report))
                return null;

            string[] parts = report.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 1)
                return null;

            Dictionary<string, string> values = new Dictionary<string, string>(parts.Length, StringComparer.OrdinalIgnoreCase);

            foreach (string part in parts)
            {
                int separatorIndex = part.IndexOf('=');
                if ((separatorIndex < 1) || (separatorIndex >= (part.Length - 1)))
                    continue;

                string key = part[..separatorIndex].Trim();
                string value = part[(separatorIndex + 1)..].Trim();

                try
                {
                    key = Uri.UnescapeDataString(key);
                    value = Uri.UnescapeDataString(value);
                }
                catch
                {
                    continue;
                }

                if ((key.Length < 1) || (value.Length < 1))
                    continue;

                values[key] = value;
            }

            if (values.Count < 1)
                return null;

            return new DnsQueryLogMetadata(values);
        }
    }

    public sealed class DnsServerResponseMetadata
    {
        public DnsServerResponseMetadata(DnsServerResponseType responseType, DnsQueryLogMetadata? logMetadata = null)
        {
            ResponseType = responseType;
            LogMetadata = logMetadata;
        }

        public DnsServerResponseType ResponseType { get; }
        public DnsQueryLogMetadata? LogMetadata { get; }
    }

    public static class DnsServerResponseTag
    {
        public static DnsServerResponseType GetResponseType(object? tag)
        {
            if (tag is null)
                return DnsServerResponseType.Recursive;

            if (tag is DnsServerResponseType responseType)
                return responseType;

            if (tag is DnsServerResponseMetadata responseMetadata)
                return responseMetadata.ResponseType;

            return DnsServerResponseType.Recursive;
        }

        public static DnsQueryLogMetadata? GetLogMetadata(object? tag)
        {
            if (tag is DnsServerResponseMetadata responseMetadata)
                return responseMetadata.LogMetadata;

            return null;
        }
    }

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

    /// <summary>
    /// Allows a DNS App to receive extended query log metadata.
    /// </summary>
    public interface IDnsQueryLoggerEx : IDnsQueryLogger
    {
        /// <summary>
        /// Allows a DNS App to log incoming DNS requests and responses, including metadata that may not be present in the wire response.
        /// </summary>
        /// <param name="timestamp">The time stamp of the log entry.</param>
        /// <param name="request">The incoming DNS request that was received.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <param name="protocol">The protocol using which the request was received.</param>
        /// <param name="response">The DNS response that was sent.</param>
        /// <param name="metadata">Optional metadata for logging.</param>
        Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response, DnsQueryLogMetadata? metadata);
    }
}
