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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Security.OTP;

namespace DnsServerCore.Auth
{
    sealed class AuthManager : IDisposable
    {
        #region variables

        ConcurrentDictionary<string, Group> _groups = new ConcurrentDictionary<string, Group>(1, 4);
        ConcurrentDictionary<string, User> _users = new ConcurrentDictionary<string, User>(1, 4);
        ConcurrentDictionary<PermissionSection, Permission> _permissions = new ConcurrentDictionary<PermissionSection, Permission>(1, 11);
        ConcurrentDictionary<string, UserSession> _sessions = new ConcurrentDictionary<string, UserSession>(1, 10);

        readonly ConcurrentDictionary<IPAddress, int> _failedLoginAttemptNetworks = new ConcurrentDictionary<IPAddress, int>(1, 10);
        const int MAX_LOGIN_ATTEMPTS = 5;

        readonly ConcurrentDictionary<IPAddress, DateTime> _blockedNetworks = new ConcurrentDictionary<IPAddress, DateTime>(1, 10);
        const int BLOCK_NETWORK_INTERVAL = 5 * 60 * 1000;

        readonly string _configFolder;
        readonly LogManager _log;

        bool _ssoEnabled;
        Uri _ssoAuthority;
        string _ssoClientId;
        string _ssoClientSecret;
        Uri _ssoMetadataAddress;
        bool _ssoAllowSignup;
        bool _ssoAllowSignupOnlyForMappedUsers = true;
        IReadOnlyDictionary<string, string> _ssoGroupMap;

        readonly Lock _saveLock = new Lock();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        public AuthManager(string configFolder, LogManager log)
        {
            _configFolder = configFolder;
            _log = log;

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveConfigFileInternal();
                            _pendingSave = false;
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);

                            //set timer to retry again
                            _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                        }
                    }
                }
            });

            LoadConfigFile();
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                //always save config here to write user login timestamps details
                try
                {
                    SaveConfigFileInternal();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
                finally
                {
                    _pendingSave = false;
                }
            }

            _disposed = true;
        }

        #endregion

        #region config

        private void LoadConfigFile()
        {
            string configFile = Path.Combine(_configFolder, "auth.config");

            try
            {
                bool passwordResetOption = false;

                if (!File.Exists(configFile))
                {
                    string passwordResetConfigFile = Path.Combine(_configFolder, "resetadmin.config");

                    if (File.Exists(passwordResetConfigFile))
                    {
                        passwordResetOption = true;
                        configFile = passwordResetConfigFile;
                    }
                }

                using (FileStream fS = new FileStream(configFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS, false, out bool _);
                }

                _log.Write("DNS Server auth config file was loaded: " + configFile);

                if (passwordResetOption)
                {
                    User adminUser = GetUser("admin");
                    if (adminUser is null)
                    {
                        adminUser = CreateUser("Administrator", "admin", "admin");
                    }
                    else
                    {
                        adminUser.ChangePassword("admin");
                        adminUser.Disabled = false;

                        if (adminUser.TOTPEnabled)
                            adminUser.DisableTOTP();
                    }

                    adminUser.AddToGroup(GetGroup(Group.ADMINISTRATORS));

                    _log.Write("DNS Server has reset the password for user: admin");
                    SaveConfigFileInternal();

                    try
                    {
                        File.Delete(configFile);
                    }
                    catch
                    { }
                }
            }
            catch (FileNotFoundException)
            {
                CreateDefaultConfig();

                string strSsoEnabled = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_ENABLED");
                if (!string.IsNullOrEmpty(strSsoEnabled))
                    _ssoEnabled = bool.Parse(strSsoEnabled);

                string strSsoAuthority = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_AUTHORITY");
                if (!string.IsNullOrEmpty(strSsoAuthority))
                    _ssoAuthority = new Uri(strSsoAuthority);

                string strSsoClientId = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_CLIENT_ID");
                if (!string.IsNullOrEmpty(strSsoClientId))
                    _ssoClientId = strSsoClientId;

                string strSsoClientSecret = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_CLIENT_SECRET");
                string strSsoClientSecretFile = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_CLIENT_SECRET_FILE");

                if (!string.IsNullOrEmpty(strSsoClientSecret))
                {
                    _ssoClientSecret = strSsoClientSecret;
                }
                else if (!string.IsNullOrEmpty(strSsoClientSecretFile))
                {
                    using (StreamReader sR = new StreamReader(strSsoClientSecretFile, true))
                    {
                        _ssoClientSecret = sR.ReadLine();
                    }
                }

                string strSsoMetadataAddress = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_METADATA_ADDRESS");
                if (!string.IsNullOrEmpty(strSsoMetadataAddress))
                    _ssoMetadataAddress = new Uri(strSsoMetadataAddress);

                string strSsoAllowSignup = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_ALLOW_SIGNUP");
                if (!string.IsNullOrEmpty(strSsoAllowSignup))
                    _ssoAllowSignup = bool.Parse(strSsoAllowSignup);

                string strSsoAllowSignupOnlyForMappedUsers = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_ALLOW_SIGNUP_ONLY_FOR_MAPPED_USERS");
                if (!string.IsNullOrEmpty(strSsoAllowSignupOnlyForMappedUsers))
                    _ssoAllowSignupOnlyForMappedUsers = bool.Parse(strSsoAllowSignupOnlyForMappedUsers);

                string strGroupMap = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_GROUP_MAP");
                if (!string.IsNullOrEmpty(strGroupMap))
                {
                    string[] entries = strGroupMap.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    Dictionary<string, string> groupMap = new Dictionary<string, string>(entries.Length);

                    foreach (string entry in entries)
                    {
                        string[] parts = entry.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        if (parts.Length == 2)
                            groupMap.TryAdd(parts[0], parts[1]);
                    }

                    _ssoGroupMap = groupMap;
                }

                SaveConfigFileInternal();
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading auth config file: " + configFile + "\r\n" + ex.ToString());
                _log.Write("Note: You may try deleting the auth config file to fix this issue. However, you will lose auth settings but, rest of the DNS settings and zone data wont be affected.");
                throw;
            }
        }

        public void LoadOldConfig(string password, bool isPasswordHash)
        {
            User user = GetUser("admin");
            if (user is null)
                user = CreateUser("Administrator", "admin", "admin");

            user.AddToGroup(GetGroup(Group.ADMINISTRATORS));

            if (isPasswordHash)
                user.LoadOldSchemeCredentials(password);
            else
                user.ChangePassword(password);

            lock (_saveLock)
            {
                SaveConfigFileInternal();
            }
        }

        public void LoadConfig(Stream s, bool isConfigTransfer, out bool restartWebService, UserSession implantSession = null)
        {
            lock (_saveLock)
            {
                ReadConfigFrom(s, isConfigTransfer, out restartWebService);

                if (!isConfigTransfer)
                {
                    if (implantSession is not null)
                    {
                        //implant current user and session into config while restoring backup config
                        using (MemoryStream mS = new MemoryStream())
                        {
                            //implant current user
                            implantSession.User.WriteTo(new BinaryWriter(mS));

                            mS.Position = 0;
                            User newUser = new User(new BinaryReader(mS), _groups);
                            newUser.AddToGroup(GetGroup(Group.ADMINISTRATORS));
                            _users[newUser.Username] = newUser;

                            //implant current session
                            mS.SetLength(0);
                            implantSession.WriteTo(new BinaryWriter(mS));

                            mS.Position = 0;
                            UserSession newSession = new UserSession(new BinaryReader(mS), _users);
                            _sessions[newSession.Token] = newSession;
                        }
                    }
                }

                //save config file
                SaveConfigFileInternal();

                if (_pendingSave)
                {
                    _pendingSave = false;
                    _saveTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
        }

        private void SaveConfigFileInternal()
        {
            string tmpConfigFile = Path.Combine(_configFolder, "auth.tmp");
            string configFile = Path.Combine(_configFolder, "auth.config");

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize config
                WriteConfigTo(mS);

                //write config
                mS.Position = 0;

                using (FileStream fS = new FileStream(tmpConfigFile, FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            File.Move(tmpConfigFile, configFile, true);

            _log.Write("DNS Server auth config file was saved: " + configFile);
        }

        public void SaveConfigFile()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void ReadConfigFrom(Stream s, bool isConfigTransfer, out bool restartWebService)
        {
            if (Encoding.ASCII.GetString(s.ReadExactly(2)) != "AS") //format
                throw new InvalidDataException("DNS Server auth config file format is invalid.");

            restartWebService = false;

            ConcurrentDictionary<string, Group> groups = new ConcurrentDictionary<string, Group>(1, 4);
            ConcurrentDictionary<string, User> users = new ConcurrentDictionary<string, User>(1, 4);
            ConcurrentDictionary<PermissionSection, Permission> permissions = new ConcurrentDictionary<PermissionSection, Permission>(1, 11);
            ConcurrentDictionary<string, UserSession> sessions = new ConcurrentDictionary<string, UserSession>(1, 10);

            BinaryReader bR = new BinaryReader(s);

            int version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                    {
                        int count = bR.ReadByte();

                        for (int i = 0; i < count; i++)
                        {
                            Group group = new Group(bR);
                            groups.TryAdd(group.Name.ToLowerInvariant(), group);
                        }
                    }

                    {
                        int count = bR.ReadByte();

                        for (int i = 0; i < count; i++)
                        {
                            User user = new User(bR, groups);
                            users.TryAdd(user.Username, user);
                        }
                    }

                    {
                        int count = bR.ReadInt32();

                        for (int i = 0; i < count; i++)
                        {
                            Permission permission = new Permission(bR, users, groups);
                            permissions.TryAdd(permission.Section, permission);
                        }
                    }

                    {
                        int count = bR.ReadInt32();

                        for (int i = 0; i < count; i++)
                        {
                            UserSession session = new UserSession(bR, users);
                            if (!session.HasExpired())
                                sessions.TryAdd(session.Token, session);
                        }
                    }

                    if (version >= 2)
                    {
                        bool ssoIsStillDisabled = false;

                        bool ssoEnabled = bR.ReadBoolean();
                        if (_ssoEnabled == ssoEnabled)
                        {
                            ssoIsStillDisabled = !ssoEnabled;
                        }
                        else
                        {
                            _ssoEnabled = ssoEnabled;
                            restartWebService = true;
                        }

                        string strSsoAuthority = s.ReadShortString();
                        Uri ssoAuthority;
                        if (strSsoAuthority.Length == 0)
                            ssoAuthority = null;
                        else
                            ssoAuthority = new Uri(strSsoAuthority);

                        if (_ssoAuthority != ssoAuthority)
                        {
                            _ssoAuthority = ssoAuthority;
                            restartWebService = true;
                        }

                        string ssoClientId = s.ReadShortString();
                        if (ssoClientId.Length == 0)
                            ssoClientId = null;

                        if (_ssoClientId != ssoClientId)
                        {
                            _ssoClientId = ssoClientId;
                            restartWebService = true;
                        }

                        string ssoClientSecret = s.ReadShortString();
                        if (ssoClientSecret.Length == 0)
                            ssoClientSecret = null;

                        if (_ssoClientSecret != ssoClientSecret)
                        {
                            _ssoClientSecret = ssoClientSecret;
                            restartWebService = true;
                        }

                        string strSsoMetadataAddress = s.ReadShortString();
                        Uri ssoMetadataAddress;
                        if (strSsoMetadataAddress.Length == 0)
                            ssoMetadataAddress = null;
                        else
                            ssoMetadataAddress = new Uri(strSsoMetadataAddress);

                        if (_ssoMetadataAddress != ssoMetadataAddress)
                        {
                            _ssoMetadataAddress = ssoMetadataAddress;
                            restartWebService = true;
                        }

                        _ssoAllowSignup = bR.ReadBoolean();
                        _ssoAllowSignupOnlyForMappedUsers = bR.ReadBoolean();

                        {
                            int count = bR.ReadByte();
                            Dictionary<string, string> ssoGroupMap = new Dictionary<string, string>(count);

                            for (int i = 0; i < count; i++)
                            {
                                string key = s.ReadShortString();
                                string value = s.ReadShortString();

                                ssoGroupMap.TryAdd(key, value);
                            }

                            _ssoGroupMap = ssoGroupMap;
                        }

                        restartWebService = !ssoIsStillDisabled && restartWebService;
                    }

                    break;

                default:
                    throw new InvalidDataException("DNS Server auth config version not supported.");
            }

            _groups = groups;
            _users = users;

            if (isConfigTransfer)
            {
                //sync only required permissions from newly loaded config
                foreach (KeyValuePair<PermissionSection, Permission> permission in permissions)
                {
                    switch (permission.Key)
                    {
                        case PermissionSection.Zones:
                            //sync user and group permissions as-is for zones section
                            Permission zonesPermission = _permissions[PermissionSection.Zones];

                            zonesPermission.SyncPermissions(permission.Value.UserPermissions);
                            zonesPermission.SyncPermissions(permission.Value.GroupPermissions);
                            break;

                        default:
                            _permissions[permission.Key] = permission.Value;
                            break;
                    }
                }

                //update all user objects in existing sessions to reflect the newly loaded config
                foreach (KeyValuePair<string, UserSession> session in _sessions)
                    session.Value.UpdateUserObject(_users);

                //sync only API sessions from newly loaded config
                foreach (KeyValuePair<string, UserSession> existingSession in _sessions)
                {
                    switch (existingSession.Value.Type)
                    {
                        case UserSessionType.ApiToken:
                            if (!sessions.ContainsKey(existingSession.Key))
                                _sessions.TryRemove(existingSession);

                            break;
                    }
                }

                foreach (KeyValuePair<string, UserSession> session in sessions)
                {
                    switch (session.Value.Type)
                    {
                        case UserSessionType.ApiToken:
                            _sessions[session.Key] = session.Value;
                            break;
                    }
                }
            }
            else
            {
                _permissions = permissions;
                _sessions = sessions;
            }
        }

        private void WriteConfigTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("AS")); //format
            bW.Write((byte)2); //version

            bW.Write(Convert.ToByte(_groups.Count));

            foreach (KeyValuePair<string, Group> group in _groups)
                group.Value.WriteTo(bW);

            bW.Write(Convert.ToByte(_users.Count));

            foreach (KeyValuePair<string, User> user in _users)
                user.Value.WriteTo(bW);

            bW.Write(_permissions.Count);

            foreach (KeyValuePair<PermissionSection, Permission> permission in _permissions)
                permission.Value.WriteTo(bW);

            List<UserSession> activeSessions = new List<UserSession>(_sessions.Count);

            foreach (KeyValuePair<string, UserSession> session in _sessions)
            {
                if (session.Value.HasExpired())
                    _sessions.TryRemove(session.Key, out _);
                else
                    activeSessions.Add(session.Value);
            }

            bW.Write(activeSessions.Count);

            foreach (UserSession session in activeSessions)
                session.WriteTo(bW);

            bW.Write(_ssoEnabled);

            if (_ssoAuthority is null)
                s.WriteShortString("");
            else
                s.WriteShortString(_ssoAuthority.OriginalString);

            if (_ssoClientId is null)
                s.WriteShortString("");
            else
                s.WriteShortString(_ssoClientId);

            if (_ssoClientSecret is null)
                s.WriteShortString("");
            else
                s.WriteShortString(_ssoClientSecret);

            if (_ssoMetadataAddress is null)
                s.WriteShortString("");
            else
                s.WriteShortString(_ssoMetadataAddress.OriginalString);

            bW.Write(_ssoAllowSignup);
            bW.Write(_ssoAllowSignupOnlyForMappedUsers);

            if ((_ssoGroupMap is null) || (_ssoGroupMap.Count == 0))
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_ssoGroupMap.Count));

                foreach (KeyValuePair<string, string> entry in _ssoGroupMap)
                {
                    s.WriteShortString(entry.Key);
                    s.WriteShortString(entry.Value);
                }
            }
        }

        #endregion

        #region private

        private void CreateDefaultConfig()
        {
            Group adminGroup = CreateGroup(Group.ADMINISTRATORS, "Super administrators");
            Group dnsAdminGroup = CreateGroup(Group.DNS_ADMINISTRATORS, "DNS service administrators");
            Group dhcpAdminGroup = CreateGroup(Group.DHCP_ADMINISTRATORS, "DHCP service administrators");
            Group everyoneGroup = CreateGroup(Group.EVERYONE, "All users");

            SetPermission(PermissionSection.Dashboard, adminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Zones, adminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Cache, adminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Allowed, adminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Blocked, adminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Apps, adminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.DnsClient, adminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Settings, adminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.DhcpServer, adminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Administration, adminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Logs, adminGroup, PermissionFlag.ViewModifyDelete);

            SetPermission(PermissionSection.Zones, dnsAdminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Cache, dnsAdminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Allowed, dnsAdminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Blocked, dnsAdminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Apps, dnsAdminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.DnsClient, dnsAdminGroup, PermissionFlag.ViewModifyDelete);
            SetPermission(PermissionSection.Settings, dnsAdminGroup, PermissionFlag.ViewModifyDelete);

            SetPermission(PermissionSection.DhcpServer, dhcpAdminGroup, PermissionFlag.ViewModifyDelete);

            SetPermission(PermissionSection.Dashboard, everyoneGroup, PermissionFlag.View);
            SetPermission(PermissionSection.Zones, everyoneGroup, PermissionFlag.View);
            SetPermission(PermissionSection.Cache, everyoneGroup, PermissionFlag.View);
            SetPermission(PermissionSection.Allowed, everyoneGroup, PermissionFlag.View);
            SetPermission(PermissionSection.Blocked, everyoneGroup, PermissionFlag.View);
            SetPermission(PermissionSection.Apps, everyoneGroup, PermissionFlag.View);
            SetPermission(PermissionSection.DnsClient, everyoneGroup, PermissionFlag.View);
            SetPermission(PermissionSection.DhcpServer, everyoneGroup, PermissionFlag.View);
            SetPermission(PermissionSection.Logs, everyoneGroup, PermissionFlag.View);

            string adminPassword = Environment.GetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD");
            string adminPasswordFile = Environment.GetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD_FILE");

            User adminUser;

            if (!string.IsNullOrEmpty(adminPassword))
            {
                adminUser = CreateUser("Administrator", "admin", adminPassword);
            }
            else if (!string.IsNullOrEmpty(adminPasswordFile))
            {
                try
                {
                    using (StreamReader sR = new StreamReader(adminPasswordFile, true))
                    {
                        string password = sR.ReadLine();
                        adminUser = CreateUser("Administrator", "admin", password);
                    }
                }
                catch (Exception ex)
                {
                    _log.Write(ex);

                    adminUser = CreateUser("Administrator", "admin", "admin");
                }
            }
            else
            {
                adminUser = CreateUser("Administrator", "admin", "admin");
            }

            adminUser.AddToGroup(adminGroup);
        }

        private async Task<User> AuthenticateUserAsync(string username, string password, string totp, IPAddress remoteAddress)
        {
            IPAddress network = GetClientNetwork(remoteAddress);

            if (IsNetworkBlocked(network))
                throw new DnsWebServiceException("Max limit of " + MAX_LOGIN_ATTEMPTS + " attempts exceeded. Access blocked for " + (BLOCK_NETWORK_INTERVAL / 1000) + " seconds.");

            User user = GetUser(username);

            if ((user is null) || user.IsSsoUser || !user.PasswordHash.Equals(user.GetPasswordHashFor(password), StringComparison.Ordinal))
            {
                if ((username != "admin") || (password != "admin"))
                {
                    MarkFailedLoginAttempt(network);

                    if (HasLoginAttemptExceedLimit(network, MAX_LOGIN_ATTEMPTS))
                        BlockNetwork(network, BLOCK_NETWORK_INTERVAL);
                }

                await Task.Delay(1000);

                throw new DnsWebServiceException("Invalid username or password for user: " + username);
            }

            if (user.TOTPEnabled)
            {
                if (string.IsNullOrEmpty(totp))
                    throw new TwoFactorAuthRequiredWebServiceException("A time-based one-time password (TOTP) is required for user: " + username);

                Authenticator authenticator = new Authenticator(user.TOTPKeyUri);

                if (!authenticator.IsTOTPValid(totp))
                {
                    MarkFailedLoginAttempt(network);

                    if (HasLoginAttemptExceedLimit(network, MAX_LOGIN_ATTEMPTS))
                        BlockNetwork(network, BLOCK_NETWORK_INTERVAL);

                    await Task.Delay(1000);

                    throw new DnsWebServiceException("Invalid time-based one-time password (TOTP) was attempted for user: " + username);
                }
            }

            ResetFailedLoginAttempts(network);

            if (user.Disabled)
                throw new DnsWebServiceException("User account is disabled. Please contact your administrator.");

            return user;
        }

        private static IPAddress GetClientNetwork(IPAddress address)
        {
            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    return address.GetNetworkAddress(32);

                case AddressFamily.InterNetworkV6:
                    return address.GetNetworkAddress(64);

                default:
                    throw new InvalidOperationException();
            }
        }

        private void MarkFailedLoginAttempt(IPAddress network)
        {
            _failedLoginAttemptNetworks.AddOrUpdate(network, 1, delegate (IPAddress key, int attempts)
            {
                return attempts + 1;
            });
        }

        private bool HasLoginAttemptExceedLimit(IPAddress network, int limit)
        {
            if (!_failedLoginAttemptNetworks.TryGetValue(network, out int attempts))
                return false;

            return attempts >= limit;
        }

        private void ResetFailedLoginAttempts(IPAddress network)
        {
            _failedLoginAttemptNetworks.TryRemove(network, out _);
        }

        private void BlockNetwork(IPAddress network, int interval)
        {
            _blockedNetworks.TryAdd(network, DateTime.UtcNow.AddMilliseconds(interval));
        }

        private bool IsNetworkBlocked(IPAddress network)
        {
            if (!_blockedNetworks.TryGetValue(network, out DateTime expiry))
                return false;

            if (expiry > DateTime.UtcNow)
            {
                return true;
            }
            else
            {
                UnblockNetwork(network);
                ResetFailedLoginAttempts(network);

                return false;
            }
        }

        private void UnblockNetwork(IPAddress network)
        {
            _blockedNetworks.TryRemove(network, out _);
        }

        #endregion

        #region public

        public User GetUser(string username)
        {
            if (_users.TryGetValue(username.ToLowerInvariant(), out User user))
                return user;

            return null;
        }

        public User GetSsoUser(string ssoIdentifier)
        {
            foreach (KeyValuePair<string, User> user in _users)
            {
                if (ssoIdentifier.Equals(user.Value.SsoIdentifier, StringComparison.Ordinal) && user.Value.IsSsoUser)
                    return user.Value;
            }

            return null;
        }

        public User CreateUser(string displayName, string username, string password, int iterations = User.DEFAULT_ITERATIONS)
        {
            if (_users.Count >= byte.MaxValue)
                throw new DnsWebServiceException("Cannot create more than 255 users.");

            username = username.ToLowerInvariant();

            User user = User.CreateLocalUser(displayName, username, password, iterations);

            if (_users.TryAdd(username, user))
            {
                if (_users.Count > byte.MaxValue)
                {
                    _users.TryRemove(username, out _); //undo
                    throw new DnsWebServiceException("Cannot create more than 255 users.");
                }

                user.AddToGroup(GetGroup(Group.EVERYONE));
                return user;
            }

            throw new DnsWebServiceException("User already exists: " + username);
        }

        public User CreateSsoUser(string displayName, string username, string ssoIdentifier)
        {
            if (_users.Count >= byte.MaxValue)
                throw new DnsWebServiceException("Cannot create more than 255 users.");

            username = username.ToLowerInvariant();

            User user = User.CreateSsoUser(displayName, username, ssoIdentifier);

            if (_users.TryAdd(username, user))
            {
                if (_users.Count > byte.MaxValue)
                {
                    _users.TryRemove(username, out _); //undo
                    throw new DnsWebServiceException("Cannot create more than 255 users.");
                }

                user.AddToGroup(GetGroup(Group.EVERYONE));
                return user;
            }

            throw new DnsWebServiceException("User already exists: " + username);
        }

        public void ChangeUsername(User user, string newUsername)
        {
            if (user.Username.Equals(newUsername, StringComparison.OrdinalIgnoreCase))
                return;

            string oldUsername = user.Username;
            user.SetUsername(newUsername);

            if (!_users.TryAdd(user.Username, user))
            {
                user.SetUsername(oldUsername); //revert
                throw new DnsWebServiceException("User already exists: " + newUsername);
            }

            _users.TryRemove(oldUsername, out _);
        }

        public async Task<User> ChangePasswordAsync(string username, string password, string totp, IPAddress remoteAddress, string newPassword, int iterations)
        {
            User user = await AuthenticateUserAsync(username, password, totp, remoteAddress);

            user.ChangePassword(newPassword, iterations);

            return user;
        }

        public bool DeleteUser(string username)
        {
            if (_users.TryRemove(username.ToLowerInvariant(), out User deletedUser))
            {
                //delete all sessions
                foreach (UserSession session in GetSessions(deletedUser))
                    DeleteSession(session.Token);

                //delete all permissions
                foreach (KeyValuePair<PermissionSection, Permission> permission in _permissions)
                {
                    permission.Value.RemovePermission(deletedUser);
                    permission.Value.RemoveAllSubItemPermissions(deletedUser);
                }

                return true;
            }

            return false;
        }

        public Group GetGroup(string name)
        {
            if (_groups.TryGetValue(name.ToLowerInvariant(), out Group group))
                return group;

            return null;
        }

        public List<User> GetGroupMembers(Group group)
        {
            List<User> members = new List<User>();

            foreach (KeyValuePair<string, User> user in _users)
            {
                if (user.Value.IsMemberOfGroup(group))
                    members.Add(user.Value);
            }

            return members;
        }

        public void SyncGroupMembers(Group group, IReadOnlyDictionary<string, User> users)
        {
            //remove
            foreach (KeyValuePair<string, User> user in _users)
            {
                if (!users.ContainsKey(user.Key))
                    user.Value.RemoveFromGroup(group);
            }

            //set
            foreach (KeyValuePair<string, User> user in users)
                user.Value.AddToGroup(group);
        }

        public Group CreateGroup(string name, string description)
        {
            if (_groups.Count >= byte.MaxValue)
                throw new DnsWebServiceException("Cannot create more than 255 groups.");

            Group group = new Group(name, description);

            if (_groups.TryAdd(name.ToLowerInvariant(), group))
            {
                if (_groups.Count > byte.MaxValue)
                {
                    _groups.TryRemove(name.ToLowerInvariant(), out _); //undo
                    throw new DnsWebServiceException("Cannot create more than 255 groups.");
                }

                return group;
            }

            throw new DnsWebServiceException("Group already exists: " + name);
        }

        public void RenameGroup(Group group, string newGroupName)
        {
            if (group.Name.Equals(newGroupName, StringComparison.OrdinalIgnoreCase))
            {
                group.Name = newGroupName;
                return;
            }

            string oldGroupName = group.Name;
            group.Name = newGroupName;

            if (!_groups.TryAdd(group.Name.ToLowerInvariant(), group))
            {
                group.Name = oldGroupName; //revert
                throw new DnsWebServiceException("Group already exists: " + newGroupName);
            }

            _groups.TryRemove(oldGroupName.ToLowerInvariant(), out _);

            //update users
            foreach (KeyValuePair<string, User> user in _users)
                user.Value.RenameGroup(oldGroupName);
        }

        public bool DeleteGroup(string name)
        {
            name = name.ToLowerInvariant();

            switch (name)
            {
                case "everyone":
                case "administrators":
                case "dns administrators":
                case "dhcp administrators":
                    throw new InvalidOperationException("Access was denied.");

                default:
                    if (_groups.TryRemove(name, out Group deletedGroup))
                    {
                        //remove all users from deleted group
                        foreach (KeyValuePair<string, User> user in _users)
                            user.Value.RemoveFromGroup(deletedGroup);

                        //delete all permissions
                        foreach (KeyValuePair<PermissionSection, Permission> permission in _permissions)
                        {
                            permission.Value.RemovePermission(deletedGroup);
                            permission.Value.RemoveAllSubItemPermissions(deletedGroup);
                        }

                        return true;
                    }

                    return false;
            }
        }

        public UserSession GetSession(string token)
        {
            if ((token is not null) && _sessions.TryGetValue(token, out UserSession session))
                return session;

            return null;
        }

        public List<UserSession> GetSessions(User user)
        {
            List<UserSession> userSessions = new List<UserSession>();

            foreach (KeyValuePair<string, UserSession> session in _sessions)
            {
                if (session.Value.User.Equals(user) && !session.Value.HasExpired())
                    userSessions.Add(session.Value);
            }

            return userSessions;
        }

        public async Task<UserSession> CreateSessionAsync(UserSessionType type, string tokenName, string username, string password, string totp, IPAddress remoteAddress, string userAgent)
        {
            User user = await AuthenticateUserAsync(username, password, totp, remoteAddress);

            if (type == UserSessionType.ClusterApiToken)
                throw new InvalidOperationException();

            UserSession session = new UserSession(type, tokenName, user, remoteAddress, userAgent);

            if (!_sessions.TryAdd(session.Token, session))
                throw new DnsWebServiceException("Error while creating session. Please try again.");

            user.LoggedInFrom(remoteAddress);

            return session;
        }

        public UserSession CreateSession(UserSessionType type, string tokenName, string username, IPAddress remoteAddress, string userAgent)
        {
            User user = GetUser(username);
            if (user is null)
                throw new DnsWebServiceException("No such user exists: " + username);

            return CreateSession(type, tokenName, user, remoteAddress, userAgent);
        }

        public UserSession CreateSession(UserSessionType type, string tokenName, User user, IPAddress remoteAddress, string userAgent)
        {
            if (user.Disabled)
                throw new DnsWebServiceException("User account is disabled. Please contact your administrator.");

            UserSession session = new UserSession(type, tokenName, user, remoteAddress, userAgent);

            if (!_sessions.TryAdd(session.Token, session))
                throw new DnsWebServiceException("Error while creating session. Please try again.");

            user.LoggedInFrom(remoteAddress);

            return session;
        }

        public UserSession DeleteSession(string token)
        {
            if (_sessions.TryRemove(token, out UserSession session))
                return session;

            return null;
        }

        public Permission GetPermission(PermissionSection section)
        {
            if (_permissions.TryGetValue(section, out Permission permission))
                return permission;

            return null;
        }

        public Permission GetPermission(PermissionSection section, string subItemName)
        {
            if (_permissions.TryGetValue(section, out Permission permission))
                return permission.GetSubItemPermission(subItemName);

            return null;
        }

        public void SetPermission(PermissionSection section, User user, PermissionFlag flags)
        {
            Permission permission = _permissions.GetOrAdd(section, delegate (PermissionSection key)
            {
                return new Permission(key);
            });

            permission.SetPermission(user, flags);
        }

        public void SetPermission(PermissionSection section, string subItemName, User user, PermissionFlag flags)
        {
            Permission permission = _permissions.GetOrAdd(section, delegate (PermissionSection key)
            {
                return new Permission(key);
            });

            permission.SetSubItemPermission(subItemName, user, flags);
        }

        public void SetPermission(PermissionSection section, Group group, PermissionFlag flags)
        {
            Permission permission = _permissions.GetOrAdd(section, delegate (PermissionSection key)
            {
                return new Permission(key);
            });

            permission.SetPermission(group, flags);
        }

        public void SetPermission(PermissionSection section, string subItemName, Group group, PermissionFlag flags)
        {
            Permission permission = _permissions.GetOrAdd(section, delegate (PermissionSection key)
            {
                return new Permission(key);
            });

            permission.SetSubItemPermission(subItemName, group, flags);
        }

        public bool RemovePermission(PermissionSection section, User user)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.RemovePermission(user);
        }

        public bool RemovePermission(PermissionSection section, string subItemName, User user)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.RemoveSubItemPermission(subItemName, user);
        }

        public bool RemovePermission(PermissionSection section, Group group)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.RemovePermission(group);
        }

        public bool RemovePermission(PermissionSection section, string subItemName, Group group)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.RemoveSubItemPermission(subItemName, group);
        }

        public bool RemoveAllPermissions(PermissionSection section, string subItemName)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.RemoveAllSubItemPermissions(subItemName);
        }

        public bool IsPermitted(PermissionSection section, User user, PermissionFlag flag)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.IsPermitted(user, flag);
        }

        public bool IsPermitted(PermissionSection section, string subItemName, User user, PermissionFlag flag)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.IsSubItemPermitted(subItemName, user, flag);
        }

        #endregion

        #region properties

        public ICollection<Group> Groups
        { get { return _groups.Values; } }

        public ICollection<User> Users
        { get { return _users.Values; } }

        public ICollection<Permission> Permissions
        { get { return _permissions.Values; } }

        public ICollection<UserSession> Sessions
        { get { return _sessions.Values; } }

        public bool SsoEnabled
        {
            get { return _ssoEnabled; }
            set { _ssoEnabled = value; }
        }

        public Uri SsoAuthority
        {
            get { return _ssoAuthority; }
            set
            {
                if (value is not null)
                {
                    if (value.OriginalString.Length > 255)
                        throw new ArgumentException("The SSO Authority URL length cannot be more than 255 chars.", nameof(SsoAuthority));

                    switch (value.Scheme.ToLowerInvariant())
                    {
                        case "http":
                        case "https":
                            break;

                        default:
                            throw new ArgumentException("The SSO Authority URL scheme can be 'http' or 'https' only.", nameof(SsoAuthority));
                    }
                }

                _ssoAuthority = value;
            }
        }

        public string SsoClientId
        {
            get { return _ssoClientId; }
            set
            {
                if (value is not null)
                {
                    if (value.Length == 0)
                        value = null;
                    else if (value.Length > 255)
                        throw new ArgumentException("The SSO Client ID length cannot be more than 255 chars.", nameof(SsoClientId));
                }

                _ssoClientId = value;
            }
        }

        public string SsoClientSecret
        {
            get { return _ssoClientSecret; }
            set
            {
                if (value is not null)
                {
                    if (value.Length == 0)
                        value = null;
                    else if (value.Length > 255)
                        throw new ArgumentException("The SSO Client Secret length cannot be more than 255 chars.", nameof(SsoClientSecret));
                }

                _ssoClientSecret = value;
            }
        }

        public Uri SsoMetadataAddress
        {
            get { return _ssoMetadataAddress; }
            set
            {
                if (value is not null)
                {
                    if (value.OriginalString.Length > 255)
                        throw new ArgumentException("The SSO Metadata Address URL length cannot be more than 255 chars.", nameof(SsoMetadataAddress));

                    switch (value.Scheme.ToLowerInvariant())
                    {
                        case "http":
                        case "https":
                            break;

                        default:
                            throw new ArgumentException("The SSO Metadata Address URL scheme can be 'http' or 'https' only.", nameof(SsoMetadataAddress));
                    }
                }

                _ssoMetadataAddress = value;
            }
        }

        public bool SsoAllowSignup
        {
            get { return _ssoAllowSignup; }
            set { _ssoAllowSignup = value; }
        }

        public bool SsoAllowSignupOnlyForMappedUsers
        {
            get { return _ssoAllowSignupOnlyForMappedUsers; }
            set { _ssoAllowSignupOnlyForMappedUsers = value; }
        }

        public IReadOnlyDictionary<string, string> SsoGroupMap
        {
            get { return _ssoGroupMap; }
            set
            {
                if (value is not null)
                {
                    if (value.Count == 0)
                        value = null;
                    else if (value.Count > 255)
                        throw new ArgumentException("The SSO Group Map cannot have more than 255 entries.", nameof(SsoGroupMap));
                }

                _ssoGroupMap = value;
            }
        }

        public bool SsoManagedGroups
        { get { return _ssoGroupMap is not null; } }

        #endregion
    }
}
