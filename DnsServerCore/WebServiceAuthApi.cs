/*
Technitium DNS Server
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.Auth;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace DnsServerCore
{
    sealed class WebServiceAuthApi
    {
        #region variables

        readonly DnsWebService _dnsWebService;

        #endregion

        #region constructor

        public WebServiceAuthApi(DnsWebService dnsWebService)
        {
            _dnsWebService = dnsWebService;
        }

        #endregion

        #region private

        private void WriteCurrentSessionDetails(JsonTextWriter jsonWriter, UserSession currentSession, bool includeInfo)
        {
            if (currentSession.Type == UserSessionType.ApiToken)
            {
                jsonWriter.WritePropertyName("username");
                jsonWriter.WriteValue(currentSession.User.Username);

                jsonWriter.WritePropertyName("tokenName");
                jsonWriter.WriteValue(currentSession.TokenName);

                jsonWriter.WritePropertyName("token");
                jsonWriter.WriteValue(currentSession.Token);
            }
            else
            {
                jsonWriter.WritePropertyName("displayName");
                jsonWriter.WriteValue(currentSession.User.DisplayName);

                jsonWriter.WritePropertyName("username");
                jsonWriter.WriteValue(currentSession.User.Username);

                jsonWriter.WritePropertyName("token");
                jsonWriter.WriteValue(currentSession.Token);
            }

            if (includeInfo)
            {
                jsonWriter.WritePropertyName("info");
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("version");
                jsonWriter.WriteValue(_dnsWebService.GetServerVersion());

                jsonWriter.WritePropertyName("dnsServerDomain");
                jsonWriter.WriteValue(_dnsWebService.DnsServer.ServerDomain);

                jsonWriter.WritePropertyName("defaultRecordTtl");
                jsonWriter.WriteValue(_dnsWebService.ZonesApi.DefaultRecordTtl);

                jsonWriter.WritePropertyName("permissions");
                jsonWriter.WriteStartObject();

                for (int i = 1; i <= 11; i++)
                {
                    PermissionSection section = (PermissionSection)i;

                    jsonWriter.WritePropertyName(section.ToString());
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("canView");
                    jsonWriter.WriteValue(_dnsWebService.AuthManager.IsPermitted(section, currentSession.User, PermissionFlag.View));

                    jsonWriter.WritePropertyName("canModify");
                    jsonWriter.WriteValue(_dnsWebService.AuthManager.IsPermitted(section, currentSession.User, PermissionFlag.Modify));

                    jsonWriter.WritePropertyName("canDelete");
                    jsonWriter.WriteValue(_dnsWebService.AuthManager.IsPermitted(section, currentSession.User, PermissionFlag.Delete));

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndObject();

                jsonWriter.WriteEndObject();
            }
        }

        private void WriteUserDetails(JsonTextWriter jsonWriter, User user, UserSession currentSession, bool includeMoreDetails, bool includeGroups)
        {
            jsonWriter.WritePropertyName("displayName");
            jsonWriter.WriteValue(user.DisplayName);

            jsonWriter.WritePropertyName("username");
            jsonWriter.WriteValue(user.Username);

            jsonWriter.WritePropertyName("disabled");
            jsonWriter.WriteValue(user.Disabled);

            jsonWriter.WritePropertyName("previousSessionLoggedOn");
            jsonWriter.WriteValue(user.PreviousSessionLoggedOn);

            jsonWriter.WritePropertyName("previousSessionRemoteAddress");
            jsonWriter.WriteValue(user.PreviousSessionRemoteAddress.ToString());

            jsonWriter.WritePropertyName("recentSessionLoggedOn");
            jsonWriter.WriteValue(user.RecentSessionLoggedOn);

            jsonWriter.WritePropertyName("recentSessionRemoteAddress");
            jsonWriter.WriteValue(user.RecentSessionRemoteAddress.ToString());

            if (includeMoreDetails)
            {
                jsonWriter.WritePropertyName("sessionTimeoutSeconds");
                jsonWriter.WriteValue(user.SessionTimeoutSeconds);

                jsonWriter.WritePropertyName("memberOfGroups");
                jsonWriter.WriteStartArray();

                List<Group> memberOfGroups = new List<Group>(user.MemberOfGroups);
                memberOfGroups.Sort();

                foreach (Group group in memberOfGroups)
                {
                    if (group.Name.Equals("Everyone", StringComparison.OrdinalIgnoreCase))
                        continue;

                    jsonWriter.WriteValue(group.Name);
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WritePropertyName("sessions");
                jsonWriter.WriteStartArray();

                List<UserSession> sessions = _dnsWebService.AuthManager.GetSessions(user);
                sessions.Sort();

                foreach (UserSession session in sessions)
                    WriteUserSessionDetails(jsonWriter, session, currentSession);

                jsonWriter.WriteEndArray();
            }

            if (includeGroups)
            {
                List<Group> groups = new List<Group>(_dnsWebService.AuthManager.Groups);
                groups.Sort();

                jsonWriter.WritePropertyName("groups");
                jsonWriter.WriteStartArray();

                foreach (Group group in groups)
                {
                    if (group.Name.Equals("Everyone", StringComparison.OrdinalIgnoreCase))
                        continue;

                    jsonWriter.WriteValue(group.Name);
                }

                jsonWriter.WriteEndArray();
            }
        }

        private static void WriteUserSessionDetails(JsonTextWriter jsonWriter, UserSession session, UserSession currentSession)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WritePropertyName("username");
            jsonWriter.WriteValue(session.User.Username);

            jsonWriter.WritePropertyName("isCurrentSession");
            jsonWriter.WriteValue(session.Equals(currentSession));

            jsonWriter.WritePropertyName("partialToken");
            jsonWriter.WriteValue(session.Token.Substring(0, 16));

            jsonWriter.WritePropertyName("type");
            jsonWriter.WriteValue(session.Type.ToString());

            jsonWriter.WritePropertyName("tokenName");
            jsonWriter.WriteValue(session.TokenName);

            jsonWriter.WritePropertyName("lastSeen");
            jsonWriter.WriteValue(session.LastSeen);

            jsonWriter.WritePropertyName("lastSeenRemoteAddress");
            jsonWriter.WriteValue(session.LastSeenRemoteAddress.ToString());

            jsonWriter.WritePropertyName("lastSeenUserAgent");
            jsonWriter.WriteValue(session.LastSeenUserAgent);

            jsonWriter.WriteEndObject();
        }

        private void WriteGroupDetails(JsonTextWriter jsonWriter, Group group, bool includeMembers, bool includeUsers)
        {
            jsonWriter.WritePropertyName("name");
            jsonWriter.WriteValue(group.Name);

            jsonWriter.WritePropertyName("description");
            jsonWriter.WriteValue(group.Description);

            if (includeMembers)
            {
                jsonWriter.WritePropertyName("members");
                jsonWriter.WriteStartArray();

                List<User> members = _dnsWebService.AuthManager.GetGroupMembers(group);
                members.Sort();

                foreach (User user in members)
                    jsonWriter.WriteValue(user.Username);

                jsonWriter.WriteEndArray();
            }

            if (includeUsers)
            {
                List<User> users = new List<User>(_dnsWebService.AuthManager.Users);
                users.Sort();

                jsonWriter.WritePropertyName("users");
                jsonWriter.WriteStartArray();

                foreach (User user in users)
                    jsonWriter.WriteValue(user.Username);

                jsonWriter.WriteEndArray();
            }
        }

        private void WritePermissionDetails(JsonTextWriter jsonWriter, Permission permission, string subItem, bool includeUsersAndGroups)
        {
            jsonWriter.WritePropertyName("section");
            jsonWriter.WriteValue(permission.Section.ToString());

            if (subItem is not null)
            {
                jsonWriter.WritePropertyName("subItem");
                jsonWriter.WriteValue(subItem.Length == 0 ? "." : subItem);
            }

            jsonWriter.WritePropertyName("userPermissions");
            jsonWriter.WriteStartArray();

            List<KeyValuePair<User, PermissionFlag>> userPermissions = new List<KeyValuePair<User, PermissionFlag>>(permission.UserPermissions);

            userPermissions.Sort(delegate (KeyValuePair<User, PermissionFlag> x, KeyValuePair<User, PermissionFlag> y)
            {
                return x.Key.Username.CompareTo(y.Key.Username);
            });

            foreach (KeyValuePair<User, PermissionFlag> userPermission in userPermissions)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("username");
                jsonWriter.WriteValue(userPermission.Key.Username);

                jsonWriter.WritePropertyName("canView");
                jsonWriter.WriteValue(userPermission.Value.HasFlag(PermissionFlag.View));

                jsonWriter.WritePropertyName("canModify");
                jsonWriter.WriteValue(userPermission.Value.HasFlag(PermissionFlag.Modify));

                jsonWriter.WritePropertyName("canDelete");
                jsonWriter.WriteValue(userPermission.Value.HasFlag(PermissionFlag.Delete));

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("groupPermissions");
            jsonWriter.WriteStartArray();

            List<KeyValuePair<Group, PermissionFlag>> groupPermissions = new List<KeyValuePair<Group, PermissionFlag>>(permission.GroupPermissions);

            groupPermissions.Sort(delegate (KeyValuePair<Group, PermissionFlag> x, KeyValuePair<Group, PermissionFlag> y)
            {
                return x.Key.Name.CompareTo(y.Key.Name);
            });

            foreach (KeyValuePair<Group, PermissionFlag> groupPermission in groupPermissions)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("name");
                jsonWriter.WriteValue(groupPermission.Key.Name);

                jsonWriter.WritePropertyName("canView");
                jsonWriter.WriteValue(groupPermission.Value.HasFlag(PermissionFlag.View));

                jsonWriter.WritePropertyName("canModify");
                jsonWriter.WriteValue(groupPermission.Value.HasFlag(PermissionFlag.Modify));

                jsonWriter.WritePropertyName("canDelete");
                jsonWriter.WriteValue(groupPermission.Value.HasFlag(PermissionFlag.Delete));

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();

            if (includeUsersAndGroups)
            {
                List<User> users = new List<User>(_dnsWebService.AuthManager.Users);
                users.Sort();

                List<Group> groups = new List<Group>(_dnsWebService.AuthManager.Groups);
                groups.Sort();

                jsonWriter.WritePropertyName("users");
                jsonWriter.WriteStartArray();

                foreach (User user in users)
                    jsonWriter.WriteValue(user.Username);

                jsonWriter.WriteEndArray();

                jsonWriter.WritePropertyName("groups");
                jsonWriter.WriteStartArray();

                foreach (Group group in groups)
                    jsonWriter.WriteValue(group.Name);

                jsonWriter.WriteEndArray();
            }
        }

        #endregion

        #region public

        public async Task LoginAsync(HttpListenerRequest request, JsonTextWriter jsonWriter, UserSessionType sessionType)
        {
            string strUsername = request.QueryString["user"];
            if (string.IsNullOrEmpty(strUsername))
                throw new DnsWebServiceException("Parameter 'user' missing.");

            string strPassword = request.QueryString["pass"];
            if (string.IsNullOrEmpty(strPassword))
                throw new DnsWebServiceException("Parameter 'pass' missing.");

            string strTokenName = null;

            if (sessionType == UserSessionType.ApiToken)
            {
                strTokenName = request.QueryString["tokenName"];
                if (string.IsNullOrEmpty(strTokenName))
                    throw new DnsWebServiceException("Parameter 'tokenName' missing.");
            }

            bool includeInfo;
            string strIncludeInfo = request.QueryString["includeInfo"];
            if (string.IsNullOrEmpty(strIncludeInfo))
                includeInfo = false;
            else
                includeInfo = bool.Parse(strIncludeInfo);

            IPEndPoint remoteEP = DnsWebService.GetRequestRemoteEndPoint(request);

            UserSession session = await _dnsWebService.AuthManager.CreateSessionAsync(sessionType, strTokenName, strUsername, strPassword, remoteEP.Address, request.UserAgent);

            _dnsWebService.Log.Write(remoteEP, "[" + session.User.Username + "] User logged in.");

            _dnsWebService.AuthManager.SaveConfigFile();

            WriteCurrentSessionDetails(jsonWriter, session, includeInfo);
        }

        public void Logout(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new DnsWebServiceException("Parameter 'token' missing.");

            UserSession session = _dnsWebService.AuthManager.DeleteSession(strToken);
            if (session is not null)
            {
                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] User logged out.");

                _dnsWebService.AuthManager.SaveConfigFile();
            }
        }

        public void GetCurrentSessionDetails(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            if (!_dnsWebService.TryGetSession(request, out UserSession session))
                throw new InvalidTokenWebServiceException("Invalid token or session expired.");

            WriteCurrentSessionDetails(jsonWriter, session, true);
        }

        public void ChangePassword(HttpListenerRequest request)
        {
            UserSession session = _dnsWebService.GetSession(request);

            if (session.Type != UserSessionType.Standard)
                throw new DnsWebServiceException("Access was denied.");

            string strPassword = request.QueryString["pass"];
            if (string.IsNullOrEmpty(strPassword))
                throw new DnsWebServiceException("Parameter 'pass' missing.");

            session.User.ChangePassword(strPassword);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Password was changed successfully.");

            _dnsWebService.AuthManager.SaveConfigFile();
        }

        public void GetProfile(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            UserSession session = _dnsWebService.GetSession(request);

            WriteUserDetails(jsonWriter, session.User, session, true, false);
        }

        public void SetProfile(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            UserSession session = _dnsWebService.GetSession(request);

            if (session.Type != UserSessionType.Standard)
                throw new DnsWebServiceException("Access was denied.");

            string strDisplayName = request.QueryString["displayName"];
            if (!string.IsNullOrEmpty(strDisplayName))
                session.User.DisplayName = strDisplayName;

            string strSessionTimeoutSeconds = request.QueryString["sessionTimeoutSeconds"];
            if (!string.IsNullOrEmpty(strSessionTimeoutSeconds))
                session.User.SessionTimeoutSeconds = int.Parse(strSessionTimeoutSeconds);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] User profile was updated successfully.");

            _dnsWebService.AuthManager.SaveConfigFile();

            WriteUserDetails(jsonWriter, session.User, session, true, false);
        }

        public void ListSessions(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            UserSession session = _dnsWebService.GetSession(request);

            jsonWriter.WritePropertyName("sessions");
            jsonWriter.WriteStartArray();

            List<UserSession> sessions = new List<UserSession>(_dnsWebService.AuthManager.Sessions);
            sessions.Sort();

            foreach (UserSession activeSession in sessions)
            {
                if (!activeSession.HasExpired())
                    WriteUserSessionDetails(jsonWriter, activeSession, session);
            }

            jsonWriter.WriteEndArray();
        }

        public void CreateApiToken(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strUsername = request.QueryString["user"];
            if (string.IsNullOrEmpty(strUsername))
                throw new DnsWebServiceException("Parameter 'user' missing.");

            string strTokenName = request.QueryString["tokenName"];
            if (string.IsNullOrEmpty(strTokenName))
                throw new DnsWebServiceException("Parameter 'tokenName' missing.");

            IPEndPoint remoteEP = DnsWebService.GetRequestRemoteEndPoint(request);

            UserSession session = _dnsWebService.AuthManager.CreateApiToken(strTokenName, strUsername, remoteEP.Address, request.UserAgent);

            _dnsWebService.Log.Write(remoteEP, "[" + session.User.Username + "] API token [" + strTokenName + "] was created successfully for user: " + strUsername);

            _dnsWebService.AuthManager.SaveConfigFile();

            jsonWriter.WritePropertyName("username");
            jsonWriter.WriteValue(session.User.Username);

            jsonWriter.WritePropertyName("tokenName");
            jsonWriter.WriteValue(session.TokenName);

            jsonWriter.WritePropertyName("token");
            jsonWriter.WriteValue(session.Token);
        }

        public void DeleteSession(HttpListenerRequest request, bool isAdminContext)
        {
            string strPartialToken = request.QueryString["partialToken"];
            if (string.IsNullOrEmpty(strPartialToken))
                throw new DnsWebServiceException("Parameter 'partialToken' missing.");

            UserSession session = _dnsWebService.GetSession(request);

            if (session.Token.StartsWith(strPartialToken))
                throw new InvalidOperationException("Invalid operation: cannot delete current session.");

            string token = null;

            foreach (UserSession activeSession in _dnsWebService.AuthManager.Sessions)
            {
                if (activeSession.Token.StartsWith(strPartialToken))
                {
                    token = activeSession.Token;
                    break;
                }
            }

            if (token is null)
                throw new DnsWebServiceException("No such active session was found for partial token: " + strPartialToken);

            if (!isAdminContext)
            {
                UserSession sessionToDelete = _dnsWebService.AuthManager.GetSession(token);
                if (sessionToDelete.User != session.User)
                    throw new DnsWebServiceException("Access was denied.");
            }

            UserSession deletedSession = _dnsWebService.AuthManager.DeleteSession(token);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] User session [" + strPartialToken + "] was deleted successfully for user: " + deletedSession.User.Username);

            _dnsWebService.AuthManager.SaveConfigFile();
        }

        public void ListUsers(JsonTextWriter jsonWriter)
        {
            List<User> users = new List<User>(_dnsWebService.AuthManager.Users);
            users.Sort();

            jsonWriter.WritePropertyName("users");
            jsonWriter.WriteStartArray();

            foreach (User user in users)
            {
                jsonWriter.WriteStartObject();

                WriteUserDetails(jsonWriter, user, null, false, false);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        public void CreateUser(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strDisplayName = request.QueryString["displayName"];

            string strUsername = request.QueryString["user"];
            if (string.IsNullOrEmpty(strUsername))
                throw new DnsWebServiceException("Parameter 'user' missing.");

            string strPassword = request.QueryString["pass"];
            if (string.IsNullOrEmpty(strPassword))
                throw new DnsWebServiceException("Parameter 'pass' missing.");

            User user = _dnsWebService.AuthManager.CreateUser(strDisplayName, strUsername, strPassword);

            UserSession session = _dnsWebService.GetSession(request);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] User account was created successfully with username: " + user.Username);

            _dnsWebService.AuthManager.SaveConfigFile();

            WriteUserDetails(jsonWriter, user, null, false, false);
        }

        public void GetUserDetails(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strUsername = request.QueryString["user"];
            if (string.IsNullOrEmpty(strUsername))
                throw new DnsWebServiceException("Parameter 'user' missing.");

            bool includeGroups;
            string strIncludeGroups = request.QueryString["includeGroups"];
            if (string.IsNullOrEmpty(strIncludeGroups))
                includeGroups = false;
            else
                includeGroups = bool.Parse(strIncludeGroups);

            User user = _dnsWebService.AuthManager.GetUser(strUsername);
            if (user is null)
                throw new DnsWebServiceException("No such user exists: " + strUsername);

            WriteUserDetails(jsonWriter, user, null, true, includeGroups);
        }

        public void SetUserDetails(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strUsername = request.QueryString["user"];
            if (string.IsNullOrEmpty(strUsername))
                throw new DnsWebServiceException("Parameter 'user' missing.");

            User user = _dnsWebService.AuthManager.GetUser(strUsername);
            if (user is null)
                throw new DnsWebServiceException("No such user exists: " + strUsername);

            string strDisplayName = request.QueryString["displayName"];
            if (!string.IsNullOrEmpty(strDisplayName))
                user.DisplayName = strDisplayName;

            string strNewUsername = request.QueryString["newUser"];
            if (!string.IsNullOrEmpty(strNewUsername))
                _dnsWebService.AuthManager.ChangeUsername(user, strNewUsername);

            UserSession session = _dnsWebService.GetSession(request);

            string strDisabled = request.QueryString["disabled"];
            if (!string.IsNullOrEmpty(strDisabled) && (session.User != user)) //to avoid self lockout
            {
                user.Disabled = bool.Parse(strDisabled);

                if (user.Disabled)
                {
                    foreach (UserSession userSession in _dnsWebService.AuthManager.Sessions)
                    {
                        if (userSession.Type == UserSessionType.ApiToken)
                            continue;

                        if (userSession.User == user)
                            _dnsWebService.AuthManager.DeleteSession(userSession.Token);
                    }
                }
            }

            string strSessionTimeoutSeconds = request.QueryString["sessionTimeoutSeconds"];
            if (!string.IsNullOrEmpty(strSessionTimeoutSeconds))
                user.SessionTimeoutSeconds = int.Parse(strSessionTimeoutSeconds);

            string strNewPassword = request.QueryString["newPass"];
            if (!string.IsNullOrWhiteSpace(strNewPassword))
            {
                int iterations;
                string strIterations = request.QueryString["iterations"];
                if (string.IsNullOrEmpty(strIterations))
                    iterations = User.DEFAULT_ITERATIONS;
                else
                    iterations = int.Parse(strIterations);

                user.ChangePassword(strNewPassword, iterations);
            }

            string strMemberOfGroups = request.QueryString["memberOfGroups"];
            if (strMemberOfGroups is not null)
            {
                string[] parts = strMemberOfGroups.Split(',');
                Dictionary<string, Group> groups = new Dictionary<string, Group>(parts.Length);

                foreach (string part in parts)
                {
                    if (part.Length == 0)
                        continue;

                    Group group = _dnsWebService.AuthManager.GetGroup(part);
                    if (group is null)
                        throw new DnsWebServiceException("No such group exists: " + part);

                    groups.Add(group.Name.ToLower(), group);
                }

                //ensure user is member of everyone group
                Group everyone = _dnsWebService.AuthManager.GetGroup(Group.EVERYONE);
                groups[everyone.Name.ToLower()] = everyone;

                if (session.User == user)
                {
                    //ensure current admin user is member of administrators group to avoid self lockout
                    Group admins = _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS);
                    groups[admins.Name.ToLower()] = admins;
                }

                user.SyncGroups(groups);
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] User account details were updated successfully for user: " + strUsername);

            _dnsWebService.AuthManager.SaveConfigFile();

            WriteUserDetails(jsonWriter, user, null, true, false);
        }

        public void DeleteUser(HttpListenerRequest request)
        {
            string strUsername = request.QueryString["user"];
            if (string.IsNullOrEmpty(strUsername))
                throw new DnsWebServiceException("Parameter 'user' missing.");

            UserSession session = _dnsWebService.GetSession(request);

            if (session.User.Username.Equals(strUsername, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Invalid operation: cannot delete current user.");

            if (!_dnsWebService.AuthManager.DeleteUser(strUsername))
                throw new DnsWebServiceException("Failed to delete user: " + strUsername);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] User account was deleted successfully with username: " + strUsername);

            _dnsWebService.AuthManager.SaveConfigFile();
        }

        public void ListGroups(JsonTextWriter jsonWriter)
        {
            List<Group> groups = new List<Group>(_dnsWebService.AuthManager.Groups);
            groups.Sort();

            jsonWriter.WritePropertyName("groups");
            jsonWriter.WriteStartArray();

            foreach (Group group in groups)
            {
                if (group.Name.Equals("Everyone", StringComparison.OrdinalIgnoreCase))
                    continue;

                jsonWriter.WriteStartObject();

                WriteGroupDetails(jsonWriter, group, false, false);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        public void CreateGroup(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strGroup = request.QueryString["group"];
            if (string.IsNullOrEmpty(strGroup))
                throw new DnsWebServiceException("Parameter 'group' missing.");

            string strDescription = request.QueryString["description"];
            if (string.IsNullOrEmpty(strDescription))
                strDescription = "";

            Group group = _dnsWebService.AuthManager.CreateGroup(strGroup, strDescription);

            UserSession session = _dnsWebService.GetSession(request);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Group was created successfully with name: " + group.Name);

            _dnsWebService.AuthManager.SaveConfigFile();

            WriteGroupDetails(jsonWriter, group, false, false);
        }

        public void GetGroupDetails(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strGroup = request.QueryString["group"];
            if (string.IsNullOrEmpty(strGroup))
                throw new DnsWebServiceException("Parameter 'group' missing.");

            bool includeUsers;
            string strIncludeGroups = request.QueryString["includeUsers"];
            if (string.IsNullOrEmpty(strIncludeGroups))
                includeUsers = false;
            else
                includeUsers = bool.Parse(strIncludeGroups);

            Group group = _dnsWebService.AuthManager.GetGroup(strGroup);
            if (group is null)
                throw new DnsWebServiceException("No such group exists: " + strGroup);

            WriteGroupDetails(jsonWriter, group, true, includeUsers);
        }

        public void SetGroupDetails(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strGroup = request.QueryString["group"];
            if (string.IsNullOrEmpty(strGroup))
                throw new DnsWebServiceException("Parameter 'group' missing.");

            Group group = _dnsWebService.AuthManager.GetGroup(strGroup);
            if (group is null)
                throw new DnsWebServiceException("No such group exists: " + strGroup);

            string strNewGroup = request.QueryString["newGroup"];
            if (!string.IsNullOrEmpty(strNewGroup))
                _dnsWebService.AuthManager.RenameGroup(group, strNewGroup);

            string strDescription = request.QueryString["description"];
            if (!string.IsNullOrEmpty(strDescription))
                group.Description = strDescription;

            UserSession session = _dnsWebService.GetSession(request);

            string strMembers = request.QueryString["members"];
            if (strMembers is not null)
            {
                string[] parts = strMembers.Split(',');
                Dictionary<string, User> users = new Dictionary<string, User>();

                foreach (string part in parts)
                {
                    if (part.Length == 0)
                        continue;

                    User user = _dnsWebService.AuthManager.GetUser(part);
                    if (user is null)
                        throw new DnsWebServiceException("No such user exists: " + part);

                    users.Add(user.Username, user);
                }

                if (group.Name.Equals("administrators", StringComparison.OrdinalIgnoreCase))
                    users[session.User.Username] = session.User; //ensure current admin user is member of administrators group to avoid self lockout

                _dnsWebService.AuthManager.SyncGroupMembers(group, users);
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Group details were updated successfully for group: " + strGroup);

            _dnsWebService.AuthManager.SaveConfigFile();

            WriteGroupDetails(jsonWriter, group, true, false);
        }

        public void DeleteGroup(HttpListenerRequest request)
        {
            string strGroup = request.QueryString["group"];
            if (string.IsNullOrEmpty(strGroup))
                throw new DnsWebServiceException("Parameter 'group' missing.");

            if (!_dnsWebService.AuthManager.DeleteGroup(strGroup))
                throw new DnsWebServiceException("Failed to delete group: " + strGroup);

            UserSession session = _dnsWebService.GetSession(request);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Group was deleted successfully with name: " + strGroup);

            _dnsWebService.AuthManager.SaveConfigFile();
        }

        public void ListPermissions(JsonTextWriter jsonWriter)
        {
            List<Permission> permissions = new List<Permission>(_dnsWebService.AuthManager.Permissions);
            permissions.Sort();

            jsonWriter.WritePropertyName("permissions");
            jsonWriter.WriteStartArray();

            foreach (Permission permission in permissions)
            {
                jsonWriter.WriteStartObject();

                WritePermissionDetails(jsonWriter, permission, null, false);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        public void GetPermissionDetails(HttpListenerRequest request, JsonTextWriter jsonWriter, PermissionSection section)
        {
            if (section == PermissionSection.Unknown)
            {
                string strSection = request.QueryString["section"];
                if (string.IsNullOrEmpty(strSection))
                    throw new DnsWebServiceException("Parameter 'section' missing.");

                if (!Enum.TryParse(strSection, true, out section))
                    throw new DnsWebServiceException("No such permission section exists: " + strSection);
            }

            string strSubItem;

            switch (section)
            {
                case PermissionSection.Zones:
                    strSubItem = request.QueryString["zone"];

                    if (strSubItem is not null)
                        strSubItem = strSubItem.TrimEnd('.');

                    break;

                default:
                    strSubItem = null;
                    break;
            }

            bool includeUsersAndGroups;
            string strIncludeUsersAndGroups = request.QueryString["includeUsersAndGroups"];
            if (string.IsNullOrEmpty(strIncludeUsersAndGroups))
                includeUsersAndGroups = false;
            else
                includeUsersAndGroups = bool.Parse(strIncludeUsersAndGroups);

            if (strSubItem is not null)
            {
                UserSession session = _dnsWebService.GetSession(request);

                if (!_dnsWebService.AuthManager.IsPermitted(section, strSubItem, session.User, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");
            }

            Permission permission;

            if (strSubItem is null)
                permission = _dnsWebService.AuthManager.GetPermission(section);
            else
                permission = _dnsWebService.AuthManager.GetPermission(section, strSubItem);

            if (permission is null)
                throw new DnsWebServiceException("No permissions exists for section: " + section.ToString() + (strSubItem is null ? "" : "/" + strSubItem));

            WritePermissionDetails(jsonWriter, permission, strSubItem, includeUsersAndGroups);
        }

        public void SetPermissionsDetails(HttpListenerRequest request, JsonTextWriter jsonWriter, PermissionSection section)
        {
            if (section == PermissionSection.Unknown)
            {
                string strSection = request.QueryString["section"];
                if (string.IsNullOrEmpty(strSection))
                    throw new DnsWebServiceException("Parameter 'section' missing.");

                if (!Enum.TryParse(strSection, true, out section))
                    throw new DnsWebServiceException("No such permission section exists: " + strSection);
            }

            string strSubItem;

            switch (section)
            {
                case PermissionSection.Zones:
                    strSubItem = request.QueryString["zone"];

                    if (strSubItem is not null)
                        strSubItem = strSubItem.TrimEnd('.');

                    break;

                default:
                    strSubItem = null;
                    break;
            }

            UserSession session = _dnsWebService.GetSession(request);

            if (strSubItem is not null)
            {
                if (!_dnsWebService.AuthManager.IsPermitted(section, strSubItem, session.User, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");
            }

            Permission permission;

            if (strSubItem is null)
                permission = _dnsWebService.AuthManager.GetPermission(section);
            else
                permission = _dnsWebService.AuthManager.GetPermission(section, strSubItem);

            if (permission is null)
                throw new DnsWebServiceException("No permissions exists for section: " + section.ToString() + (strSubItem is null ? "" : "/" + strSubItem));

            string strUserPermissions = request.QueryString["userPermissions"];
            if (strUserPermissions is not null)
            {
                string[] parts = strUserPermissions.Split('|');
                Dictionary<User, PermissionFlag> userPermissions = new Dictionary<User, PermissionFlag>();

                for (int i = 0; i < parts.Length; i += 4)
                {
                    if (parts[i].Length == 0)
                        continue;

                    User user = _dnsWebService.AuthManager.GetUser(parts[i]);
                    bool canView = bool.Parse(parts[i + 1]);
                    bool canModify = bool.Parse(parts[i + 2]);
                    bool canDelete = bool.Parse(parts[i + 3]);

                    if (user is not null)
                    {
                        PermissionFlag permissionFlag = PermissionFlag.None;

                        if (canView)
                            permissionFlag |= PermissionFlag.View;

                        if (canModify)
                            permissionFlag |= PermissionFlag.Modify;

                        if (canDelete)
                            permissionFlag |= PermissionFlag.Delete;

                        userPermissions[user] = permissionFlag;
                    }
                }

                permission.SyncPermissions(userPermissions);
            }

            string strGroupPermissions = request.QueryString["groupPermissions"];
            if (strGroupPermissions is not null)
            {
                string[] parts = strGroupPermissions.Split('|');
                Dictionary<Group, PermissionFlag> groupPermissions = new Dictionary<Group, PermissionFlag>();

                for (int i = 0; i < parts.Length; i += 4)
                {
                    if (parts[i].Length == 0)
                        continue;

                    Group group = _dnsWebService.AuthManager.GetGroup(parts[i]);
                    bool canView = bool.Parse(parts[i + 1]);
                    bool canModify = bool.Parse(parts[i + 2]);
                    bool canDelete = bool.Parse(parts[i + 3]);

                    if (group is not null)
                    {
                        PermissionFlag permissionFlag = PermissionFlag.None;

                        if (canView)
                            permissionFlag |= PermissionFlag.View;

                        if (canModify)
                            permissionFlag |= PermissionFlag.Modify;

                        if (canDelete)
                            permissionFlag |= PermissionFlag.Delete;

                        groupPermissions[group] = permissionFlag;
                    }
                }

                //ensure administrators group always has all permissions
                Group admins = _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS);
                groupPermissions[admins] = PermissionFlag.ViewModifyDelete;

                switch (section)
                {
                    case PermissionSection.Zones:
                        //ensure DNS administrators group always has all permissions
                        Group dnsAdmins = _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS);
                        groupPermissions[dnsAdmins] = PermissionFlag.ViewModifyDelete;
                        break;

                    case PermissionSection.DhcpServer:
                        //ensure DHCP administrators group always has all permissions
                        Group dhcpAdmins = _dnsWebService.AuthManager.GetGroup(Group.DHCP_ADMINISTRATORS);
                        groupPermissions[dhcpAdmins] = PermissionFlag.ViewModifyDelete;
                        break;
                }

                permission.SyncPermissions(groupPermissions);
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Permissions were updated successfully for section: " + section.ToString() + (string.IsNullOrEmpty(strSubItem) ? "" : "/" + strSubItem));

            _dnsWebService.AuthManager.SaveConfigFile();

            WritePermissionDetails(jsonWriter, permission, strSubItem, false);
        }

        #endregion
    }
}
