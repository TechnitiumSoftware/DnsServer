/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace DnsServerCore.Auth
{
    sealed class LdapAuthResult
    {
        public bool Success { get; init; }
        public string LdapIdentifier { get; init; }
        public string DisplayName { get; init; }
        public IReadOnlyList<string> Groups { get; init; }
        public string ErrorMessage { get; init; }

        public static LdapAuthResult Failed(string message) =>
            new LdapAuthResult { Success = false, ErrorMessage = message };
    }

    sealed class LdapAuthProvider
    {
        #region variables

        readonly string _server;
        readonly int _port;
        readonly bool _useSsl;
        readonly bool _ignoreSslErrors;
        readonly string _bindDn;
        readonly string _bindPassword;
        readonly string _searchBase;
        readonly string _userFilter;
        readonly string _groupAttribute;

        #endregion

        #region constructor

        public LdapAuthProvider(string server, int port, bool useSsl, bool ignoreSslErrors, string bindDn, string bindPassword, string searchBase, string userFilter, string groupAttribute)
        {
            _server = server;
            _port = port;
            _useSsl = useSsl;
            _ignoreSslErrors = ignoreSslErrors;
            _bindDn = bindDn;
            _bindPassword = bindPassword;
            _searchBase = searchBase;
            _userFilter = string.IsNullOrWhiteSpace(userFilter) ? "(sAMAccountName={0})" : userFilter;
            _groupAttribute = string.IsNullOrWhiteSpace(groupAttribute) ? "memberOf" : groupAttribute;
        }

        #endregion

        #region private

        private LdapConnection CreateBoundConnection(string bindDn, string bindPassword)
        {
            var identifier = new LdapDirectoryIdentifier(_server, _port);
            var conn = new LdapConnection(identifier);
            conn.SessionOptions.ProtocolVersion = 3;
            conn.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            conn.Timeout = TimeSpan.FromSeconds(15);
            conn.AuthType = AuthType.Basic;

            if (_ignoreSslErrors)
                conn.SessionOptions.VerifyServerCertificate = (connection, certificate) => true;

            // Port 636 = LDAPS (SSL-wrapped from the start); all other ports use StartTLS
            bool useLdaps = _useSsl && _port == 636;
            if (useLdaps)
                conn.SessionOptions.SecureSocketLayer = true;

            if (_useSsl && !useLdaps)
                conn.SessionOptions.StartTransportLayerSecurity(null);

            conn.Credential = new NetworkCredential(bindDn, bindPassword);
            conn.Bind();
            return conn;
        }

        private static string LdapFilterEscape(string value)
        {
            // RFC 4515 escape special filter characters
            return new StringBuilder(value)
                .Replace("\\", "\\5c")
                .Replace("*", "\\2a")
                .Replace("(", "\\28")
                .Replace(")", "\\29")
                .Replace("\0", "\\00")
                .ToString();
        }

        private static string GetCnFromDn(string dn)
        {
            if (string.IsNullOrEmpty(dn))
                return dn;

            int eq = dn.IndexOf('=');
            int comma = dn.IndexOf(',');

            if (eq < 0)
                return dn;

            int end = comma > eq ? comma : dn.Length;
            return dn.Substring(eq + 1, end - eq - 1).Trim();
        }

        private static string GetAttributeValue(SearchResultEntry entry, string attributeName)
        {
            DirectoryAttribute attr = entry.Attributes[attributeName];
            if (attr == null || attr.Count == 0)
                return null;
            return attr[0] as string;
        }

        #endregion

        #region public

        public Task<LdapAuthResult> AuthenticateAsync(string username, string password)
        {
            return Task.Run(() =>
            {
                // Step 1: bind service account and search for the user
                string userDn;
                string displayName;
                string userPrincipalName;
                List<string> groups;

                try
                {
                    using LdapConnection searchConn = CreateBoundConnection(_bindDn, _bindPassword);

                    string filter = string.Format(_userFilter, LdapFilterEscape(username));
                    string[] attrs = new[] { "distinguishedName", "cn", "displayName", "userPrincipalName", _groupAttribute };

                    var request = new SearchRequest(_searchBase, filter, SearchScope.Subtree, attrs);
                    request.TimeLimit = TimeSpan.FromSeconds(15);

                    var response = (SearchResponse)searchConn.SendRequest(request);

                    SearchResultEntry entry = response.Entries.Count > 0 ? response.Entries[0] : null;

                    if (entry is null)
                        return LdapAuthResult.Failed("User not found in directory.");

                    userDn = entry.DistinguishedName;

                    displayName = GetAttributeValue(entry, "displayName");
                    if (string.IsNullOrEmpty(displayName))
                        displayName = GetAttributeValue(entry, "cn");
                    if (string.IsNullOrEmpty(displayName))
                        displayName = username;

                    userPrincipalName = GetAttributeValue(entry, "userPrincipalName");

                    groups = new List<string>();
                    DirectoryAttribute groupAttr = entry.Attributes[_groupAttribute];
                    if (groupAttr != null)
                    {
                        foreach (string groupDn in (string[])groupAttr.GetValues(typeof(string)))
                        {
                            string cn = GetCnFromDn(groupDn);
                            if (!string.IsNullOrEmpty(cn))
                                groups.Add(cn);
                        }
                    }
                }
                catch (LdapException ex) when (ex.ErrorCode == 49)
                {
                    return LdapAuthResult.Failed("Service account credentials are invalid.");
                }
                catch (Exception ex)
                {
                    return LdapAuthResult.Failed($"Service account bind/search failed: {ex.Message}");
                }

                // Step 2: re-bind as the user to validate their password
                // Prefer UPN (user@domain) over full DN — more reliable with AD
                string bindUsername = !string.IsNullOrEmpty(userPrincipalName) ? userPrincipalName : userDn;

                try
                {
                    using LdapConnection userConn = CreateBoundConnection(bindUsername, password);
                }
                catch (LdapException ex) when (ex.ErrorCode == 49)
                {
                    return LdapAuthResult.Failed("Invalid credentials.");
                }
                catch (Exception ex)
                {
                    return LdapAuthResult.Failed($"User bind failed: {ex.Message}");
                }

                return new LdapAuthResult
                {
                    Success = true,
                    LdapIdentifier = userDn,
                    DisplayName = displayName,
                    Groups = groups
                };
            });
        }

        public Task<string> TestConnectionAsync()
        {
            return Task.Run(() =>
            {
                try
                {
                    using LdapConnection conn = CreateBoundConnection(_bindDn, _bindPassword);
                    return (string)null; // null = success
                }
                catch (Exception ex)
                {
                    Exception inner = ex;
                    while (inner.InnerException != null) inner = inner.InnerException;
                    return inner == ex ? ex.Message : $"{ex.Message} → {inner.GetType().Name}: {inner.Message}";
                }
            });
        }

        #endregion
    }
}
