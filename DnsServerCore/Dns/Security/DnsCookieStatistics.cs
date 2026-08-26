/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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

namespace DnsServerCore.Dns.Security
{
    /// <summary>
    /// DNS Cookie statistics per RFC 7873 §7 and RFC 9018 §9.
    /// These counters help operators detect DNS amplification attacks and tune rotation frequency.
    /// RFC 9018 §9: "If the server detects that more than a certain percentage of queries
    /// result in a server cookie, the server might want to generate fresh keys more frequently."
    /// </summary>
    public class DnsCookieStatistics
    {
        #region constructor

        public DnsCookieStatistics(long validationInvocations, long validCount, long invalidCount, long missingCount, long badCookieSentCount, long clientOnlyCount)
        {
            ValidationInvocations = validationInvocations;
            ValidCount = validCount;
            InvalidCount = invalidCount;
            MissingCount = missingCount;
            BadCookieSentCount = badCookieSentCount;
            ClientOnlyCount = clientOnlyCount;
        }

        #endregion

        #region properties

        /// <summary>
        /// Total number of times cookie classification was invoked (all requests with EDNS enabled).
        /// </summary>
        public long ValidationInvocations { get; }

        /// <summary>
        /// Number of requests with valid server cookies (bypassed reflection RRL).
        /// High ratio indicates legitimate traffic or an active attack from a sophisticated resolver.
        /// </summary>
        public long ValidCount { get; }

        /// <summary>
        /// Number of requests with invalid (rejected) server cookies.
        /// Can indicate: (1) forged cookies, (2) expired keys, (3) anycast clock skew, (4) truncation/corruption.
        /// </summary>
        public long InvalidCount { get; }

        /// <summary>
        /// Number of requests with no server cookie (client cookie only, or neither).
        /// Expected for first-time queries; high ratio for repeated clients may indicate client loss or attack.
        /// </summary>
        public long MissingCount { get; }

        /// <summary>
        /// Number of times BADCOOKIE (RCODE 23) was sent due to invalid server cookie.
        /// High rate indicates attack attempts or widespread key rotation/clock skew.
        /// RFC 9018 §9: If high rate detected, rotate keys more frequently.
        /// </summary>
        public long BadCookieSentCount { get; }

        /// <summary>
        /// Number of requests with client cookie but no server cookie (initial acquisition phase).
        /// Expected for first ~5 minutes after server restart; should stabilize as clients cache cookies.
        /// </summary>
        public long ClientOnlyCount { get; }

        #endregion
    }
}
