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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore.Auth
{
    sealed class AuthManager : IDisposable
    {
        #region variables

        readonly ConcurrentDictionary<string, Group> _groups = new ConcurrentDictionary<string, Group>(1, 4);
        readonly ConcurrentDictionary<string, User> _users = new ConcurrentDictionary<string, User>(1, 4);

        readonly ConcurrentDictionary<PermissionSection, Permission> _permissions = new ConcurrentDictionary<PermissionSection, Permission>(1, 11);

        readonly ConcurrentDictionary<string, UserSession> _sessions = new ConcurrentDictionary<string, UserSession>(1, 10);

        readonly ConcurrentDictionary<IPAddress, int> _failedLoginAttempts = new ConcurrentDictionary<IPAddress, int>(1, 10);
        const int MAX_LOGIN_ATTEMPTS = 5;

        readonly ConcurrentDictionary<IPAddress, DateTime> _blockedAddresses = new ConcurrentDictionary<IPAddress, DateTime>(1, 10);
        const int BLOCK_ADDRESS_INTERVAL = 5 * 60 * 1000;

        readonly string _configFolder;
        readonly LogManager _log;

        readonly object _lockObj = new object();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 10000;

        #endregion

        #region constructor

        public AuthManager(string configFolder, LogManager log)
        {
            _configFolder = configFolder;
            _log = log;

            _saveTimer = new Timer(SaveTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            if (_saveTimer is not null)
                _saveTimer.Dispose();

            lock (_lockObj)
            {
                SaveConfigFileInternal();
            }

            _disposed = true;
        }

        #endregion

        #region private

        private void SaveTimerCallback(object state)
        {
            try
            {
                lock (_lockObj)
                {
                    _pendingSave = false;
                    SaveConfigFileInternal();
                }
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
        }

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

        private void LoadConfigFileInternal(UserSession implantSession)
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
                    ReadConfigFrom(new BinaryReader(fS));
                }

                if (implantSession is not null)
                {
                    using (MemoryStream mS = new MemoryStream())
                    {
                        //implant current user
                        implantSession.User.WriteTo(new BinaryWriter(mS));

                        mS.Position = 0;
                        User newUser = new User(new BinaryReader(mS), this);
                        newUser.AddToGroup(GetGroup(Group.ADMINISTRATORS));
                        _users[newUser.Username] = newUser;

                        //implant current session
                        mS.SetLength(0);
                        implantSession.WriteTo(new BinaryWriter(mS));

                        mS.Position = 0;
                        UserSession newSession = new UserSession(new BinaryReader(mS), this);
                        _sessions.TryAdd(newSession.Token, newSession);

                        //save config
                        SaveConfigFileInternal();
                    }
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
                    }

                    adminUser.AddToGroup(GetGroup(Group.ADMINISTRATORS));

                    _log.Write("DNS Server reset password for user: admin");
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
                _log.Write("DNS Server auth config file was not found: " + configFile);
                _log.Write("DNS Server is restoring default auth config file.");

                CreateDefaultConfig();

                SaveConfigFileInternal();
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading auth config file: " + configFile + "\r\n" + ex.ToString());
                _log.Write("Note: You may try deleting the auth config file to fix this issue. However, you will lose auth settings but, rest of the DNS settings and zone data wont be affected.");
                throw;
            }
        }

        private void SaveConfigFileInternal()
        {
            string configFile = Path.Combine(_configFolder, "auth.config");

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize config
                WriteConfigTo(new BinaryWriter(mS));

                //write config
                mS.Position = 0;

                using (FileStream fS = new FileStream(configFile, FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _log.Write("DNS Server auth config file was saved: " + configFile);
        }

        private void ReadConfigFrom(BinaryReader bR)
        {
            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "AS") //format
                throw new InvalidDataException("DNS Server auth config file format is invalid.");

            int version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    {
                        int count = bR.ReadByte();
                        for (int i = 0; i < count; i++)
                        {
                            Group group = new Group(bR);
                            _groups.TryAdd(group.Name.ToLower(), group);
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        for (int i = 0; i < count; i++)
                        {
                            User user = new User(bR, this);
                            _users.TryAdd(user.Username, user);
                        }
                    }

                    {
                        int count = bR.ReadInt32();
                        for (int i = 0; i < count; i++)
                        {
                            Permission permission = new Permission(bR, this);
                            _permissions.TryAdd(permission.Section, permission);
                        }
                    }

                    {
                        int count = bR.ReadInt32();
                        for (int i = 0; i < count; i++)
                        {
                            UserSession session = new UserSession(bR, this);
                            if (!session.HasExpired())
                                _sessions.TryAdd(session.Token, session);
                        }
                    }
                    break;

                default:
                    throw new InvalidDataException("DNS Server auth config version not supported.");
            }
        }

        private void WriteConfigTo(BinaryWriter bW)
        {
            bW.Write(Encoding.ASCII.GetBytes("AS")); //format
            bW.Write((byte)1); //version

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
        }

        private void FailedLoginAttempt(IPAddress address)
        {
            _failedLoginAttempts.AddOrUpdate(address, 1, delegate (IPAddress key, int attempts)
            {
                return attempts + 1;
            });
        }

        private bool LoginAttemptsExceedLimit(IPAddress address, int limit)
        {
            if (!_failedLoginAttempts.TryGetValue(address, out int attempts))
                return false;

            return attempts >= limit;
        }

        private void ResetFailedLoginAttempt(IPAddress address)
        {
            _failedLoginAttempts.TryRemove(address, out _);
        }

        private void BlockAddress(IPAddress address, int interval)
        {
            _blockedAddresses.TryAdd(address, DateTime.UtcNow.AddMilliseconds(interval));
        }

        private bool IsAddressBlocked(IPAddress address)
        {
            if (!_blockedAddresses.TryGetValue(address, out DateTime expiry))
                return false;

            if (expiry > DateTime.UtcNow)
            {
                return true;
            }
            else
            {
                UnblockAddress(address);
                ResetFailedLoginAttempt(address);

                return false;
            }
        }

        private void UnblockAddress(IPAddress address)
        {
            _blockedAddresses.TryRemove(address, out _);
        }

        #endregion

        #region public

        public User GetUser(string username)
        {
            if (_users.TryGetValue(username.ToLower(), out User user))
                return user;

            return null;
        }

        public User CreateUser(string displayName, string username, string password, int iterations = User.DEFAULT_ITERATIONS)
        {
            if (_users.Count >= byte.MaxValue)
                throw new DnsWebServiceException("Cannot create more than 255 users.");

            username = username.ToLower();

            User user = new User(displayName, username, password, iterations);

            if (_users.TryAdd(username, user))
            {
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
            user.Username = newUsername;

            if (!_users.TryAdd(user.Username, user))
            {
                user.Username = oldUsername; //revert
                throw new DnsWebServiceException("User already exists: " + newUsername);
            }

            _users.TryRemove(oldUsername, out _);
        }

        public bool DeleteUser(string username)
        {
            if (_users.TryRemove(username.ToLower(), out User deletedUser))
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
            if (_groups.TryGetValue(name.ToLower(), out Group group))
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

            if (_groups.TryAdd(name.ToLower(), group))
                return group;

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

            if (!_groups.TryAdd(group.Name.ToLower(), group))
            {
                group.Name = oldGroupName; //revert
                throw new DnsWebServiceException("Group already exists: " + newGroupName);
            }

            _groups.TryRemove(oldGroupName.ToLower(), out _);

            //update users
            foreach (KeyValuePair<string, User> user in _users)
                user.Value.RenameGroup(oldGroupName);
        }

        public bool DeleteGroup(string name)
        {
            name = name.ToLower();

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
            if (_sessions.TryGetValue(token, out UserSession session))
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

        public async Task<UserSession> CreateSessionAsync(UserSessionType type, string tokenName, string username, string password, IPAddress remoteAddress, string userAgent)
        {
            if (IsAddressBlocked(remoteAddress))
                throw new DnsWebServiceException("Max limit of " + MAX_LOGIN_ATTEMPTS + " attempts exceeded. Access blocked for " + (BLOCK_ADDRESS_INTERVAL / 1000) + " seconds.");

            User user = GetUser(username);

            if ((user is null) || !user.PasswordHash.Equals(user.GetPasswordHashFor(password), StringComparison.Ordinal))
            {
                if (password != "admin")
                {
                    FailedLoginAttempt(remoteAddress);

                    if (LoginAttemptsExceedLimit(remoteAddress, MAX_LOGIN_ATTEMPTS))
                        BlockAddress(remoteAddress, BLOCK_ADDRESS_INTERVAL);

                    await Task.Delay(1000);
                }

                throw new DnsWebServiceException("Invalid username or password for user: " + username);
            }

            ResetFailedLoginAttempt(remoteAddress);

            if (user.Disabled)
                throw new DnsWebServiceException("User account is disabled. Please contact your administrator.");

            UserSession session = new UserSession(type, tokenName, user, remoteAddress, userAgent);

            if (!_sessions.TryAdd(session.Token, session))
                throw new DnsWebServiceException("Error while creating session. Please try again.");

            user.LoggedInFrom(remoteAddress);

            return session;
        }

        public UserSession CreateApiToken(string tokenName, string username, IPAddress remoteAddress, string userAgent)
        {
            if (IsAddressBlocked(remoteAddress))
                throw new DnsWebServiceException("Max limit of " + MAX_LOGIN_ATTEMPTS + " attempts exceeded. Access blocked for " + (BLOCK_ADDRESS_INTERVAL / 1000) + " seconds.");

            User user = GetUser(username);
            if (user is null)
                throw new DnsWebServiceException("No such user exists: " + username);

            if (user.Disabled)
                throw new DnsWebServiceException("Account is suspended.");

            UserSession session = new UserSession(UserSessionType.ApiToken, tokenName, user, remoteAddress, userAgent);

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

            lock (_lockObj)
            {
                SaveConfigFileInternal();
            }
        }

        public void LoadConfigFile(UserSession implantSession = null)
        {
            lock (_lockObj)
            {
                _groups.Clear();
                _users.Clear();
                _permissions.Clear();
                _sessions.Clear();

                LoadConfigFileInternal(implantSession);
            }
        }

        public void SaveConfigFile()
        {
            lock (_lockObj)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
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

        #endregion
    }
}
