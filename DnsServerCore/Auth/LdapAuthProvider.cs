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

using DnsServerCore.Dns;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Auth
{
    enum LdapAuthSslOption : byte
    {
        None = 0,
        StartTLS = 1,
        LDAPS = 2
    }

    sealed class LdapAuthProvider
    {
        #region variables

        readonly DnsServer _dnsServer;
        readonly string _server;
        readonly int _port;
        readonly LdapAuthSslOption _sslOption;
        readonly bool _ignoreSslErrors;
        readonly string _bindUsername;
        readonly string _bindPassword;
        readonly string _searchBase;
        readonly string _userSearchFilter;
        readonly string _groupAttribute;

        #endregion

        #region constructor

        public LdapAuthProvider(DnsServer dnsServer, string server, int port, LdapAuthSslOption sslOption, bool ignoreSslErrors, string bindUsername, string bindPassword, string searchBase, string userSearchFilter = null, string groupAttribute = null)
        {
            _dnsServer = dnsServer;
            _server = server;
            _port = port;
            _sslOption = sslOption;
            _ignoreSslErrors = ignoreSslErrors;
            _bindUsername = bindUsername;
            _bindPassword = bindPassword;
            _searchBase = searchBase;
            _userSearchFilter = string.IsNullOrWhiteSpace(userSearchFilter) ? "(sAMAccountName={0})" : userSearchFilter;
            _groupAttribute = string.IsNullOrWhiteSpace(groupAttribute) ? "memberOf" : groupAttribute;
        }

        #endregion

        #region private

        private LdapConnection CreateBoundConnection(string bindUsername, string bindPassword)
        {
            LdapDirectoryIdentifier ldapDirectoryIdentifier;

            if (IPAddress.TryParse(_server, out IPAddress serverIP))
            {
                ldapDirectoryIdentifier = new LdapDirectoryIdentifier(serverIP.ToString(), _port, false, false);
            }
            else
            {
                IReadOnlyList<IPAddress> ipAddresses = DnsClient.ResolveIPAsync(_dnsServer, _server, _dnsServer.IPv6Mode).Sync();
                string[] servers = [.. ipAddresses.Convert(delegate (IPAddress ipAddress) { return ipAddress.ToString(); })];

                ldapDirectoryIdentifier = new LdapDirectoryIdentifier(servers, _port, false, false);
            }

            LdapConnection connection = new LdapConnection(ldapDirectoryIdentifier);
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            connection.Timeout = TimeSpan.FromSeconds(15);
            connection.AuthType = AuthType.Basic;

            switch (_sslOption)
            {
                case LdapAuthSslOption.StartTLS:
                    connection.SessionOptions.StartTransportLayerSecurity(null);
                    break;

                case LdapAuthSslOption.LDAPS:
                    connection.SessionOptions.SecureSocketLayer = true;
                    break;
            }

            if (_ignoreSslErrors && (_sslOption != LdapAuthSslOption.None))
            {
                connection.SessionOptions.VerifyServerCertificate = static delegate (LdapConnection connection, X509Certificate certificate)
                {
                    return true;
                };
            }

            connection.Credential = new NetworkCredential(bindUsername, bindPassword);
            connection.Bind();

            return connection;
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
            if ((attr is null) || attr.Count == 0)
                return null;

            return attr[0] as string;
        }

        #endregion

        #region public

        public Task<AuthInfo> AuthenticateAsync(string username, string password)
        {
            return Task.Run(() =>
            {
                // Step 1: bind service account and search for the user
                string userDistinguishedName;
                string displayName;
                string userPrincipalName;
                List<string> groups;

                LdapConnection searchConnection = null;

                try
                {
                    //bind service account
                    try
                    {
                        searchConnection = CreateBoundConnection(_bindUsername, _bindPassword);
                    }
                    catch (LdapException ex) when (ex.ErrorCode == 49)
                    {
                        throw new LdapAuthException("LDAP service account credentials are invalid.", ex);
                    }
                    catch (Exception ex)
                    {
                        throw new LdapAuthException($"LDAP service account failed to bind.", ex);
                    }

                    //search for the user
                    try
                    {
                        string searchFilter = string.Format(_userSearchFilter, LdapFilterEscape(username));
                        string[] attributeList = ["distinguishedName", "cn", "displayName", "userPrincipalName", _groupAttribute];

                        SearchRequest request = new SearchRequest(_searchBase, searchFilter, SearchScope.Subtree, attributeList);
                        request.TimeLimit = TimeSpan.FromSeconds(15);

                        SearchResponse response = (SearchResponse)searchConnection.SendRequest(request);

                        SearchResultEntry entry = response.Entries.Count > 0 ? response.Entries[0] : null;
                        if (entry is null)
                            throw new LdapAuthFailedException("User was not found in the directory: " + username);

                        userDistinguishedName = entry.DistinguishedName;

                        displayName = GetAttributeValue(entry, "displayName");
                        if (string.IsNullOrEmpty(displayName))
                        {
                            displayName = GetAttributeValue(entry, "cn");
                            if (string.IsNullOrEmpty(displayName))
                                displayName = username;
                        }

                        userPrincipalName = GetAttributeValue(entry, "userPrincipalName");

                        groups = new List<string>();

                        DirectoryAttribute groupAttr = entry.Attributes[_groupAttribute];
                        if (groupAttr is not null)
                        {
                            foreach (string groupDn in (string[])groupAttr.GetValues(typeof(string)))
                            {
                                string cn = GetCnFromDn(groupDn);
                                if (!string.IsNullOrEmpty(cn))
                                    groups.Add(cn);
                            }
                        }

                        if (groups.Count == 0)
                        {
                            // Fallback for directories that don't maintain a reverse group-membership
                            // attribute on the user entry (e.g. stock OpenLDAP without the memberof
                            // overlay loaded). Search for groups that list this user as a member
                            // instead of relying on the user entry carrying _groupAttribute.
                            // Best-effort: some directories (e.g. AD without RFC2307/Unix attributes)
                            // don't define uniqueMember/memberUid at all, which errors instead of just
                            // not matching - swallow that so it degrades to "no groups", same as before.
                            try
                            {
                                string reverseFilter = "(|(member=" + LdapFilterEscape(userDistinguishedName) + ")(uniqueMember=" + LdapFilterEscape(userDistinguishedName) + ")(memberUid=" + LdapFilterEscape(username) + "))";

                                SearchRequest groupRequest = new SearchRequest(_searchBase, reverseFilter, SearchScope.Subtree, ["cn"]);
                                groupRequest.TimeLimit = TimeSpan.FromSeconds(15);

                                SearchResponse groupResponse = (SearchResponse)searchConnection.SendRequest(groupRequest);

                                foreach (SearchResultEntry groupEntry in groupResponse.Entries)
                                {
                                    string cn = GetAttributeValue(groupEntry, "cn");
                                    if (!string.IsNullOrEmpty(cn))
                                        groups.Add(cn);
                                }
                            }
                            catch
                            { }
                        }
                    }
                    catch (Exception ex)
                    {
                        throw new LdapAuthException($"LDAP service account failed to search.", ex);
                    }
                }
                finally
                {
                    searchConnection?.Dispose();
                }

                // Step 2: re-bind as the user to validate their password
                // Prefer UPN (user@domain) over full DN — more reliable with AD
                string foundUsername = string.IsNullOrEmpty(userPrincipalName) ? userDistinguishedName : userPrincipalName;

                try
                {
                    using LdapConnection userConnection = CreateBoundConnection(foundUsername, password);
                }
                catch (LdapException ex) when (ex.ErrorCode == 49)
                {
                    throw new LdapAuthFailedException("Invalid password for user: " + username, ex);
                }
                catch (Exception ex)
                {
                    throw new LdapAuthException("LDAP user account failed to bind.", ex);
                }

                return new AuthInfo
                {
                    DisplayName = displayName,
                    Groups = groups
                };
            });
        }

        public Task TestConnectionAsync()
        {
            return Task.Run(() =>
            {
                using LdapConnection conn = CreateBoundConnection(_bindUsername, _bindPassword);
            });
        }

        #endregion

        public readonly struct AuthInfo
        {
            public string DisplayName { get; init; }
            public IReadOnlyList<string> Groups { get; init; }
        }
    }
}
