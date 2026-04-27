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
using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Security.OTP;

namespace DnsServerCore.Auth
{
    enum UserPasswordHashType : byte
    {
        Unknown = 0,
        OldScheme = 1,
        PBKDF2_SHA256 = 2
    }

    class User : IComparable<User>
    {
        #region variables

        public const int DEFAULT_ITERATIONS = 100000;

        string _displayName;
        string _username;
        bool _isSsoUser;
        string _ssoIdentifier;
        UserPasswordHashType _passwordHashType;
        int _iterations;
        byte[] _salt;
        string _passwordHash;
        AuthenticatorKeyUri _totpKeyUri;
        bool _totpEnabled;
        bool _disabled;
        int _sessionTimeoutSeconds = 30 * 60; //default 30 mins

        DateTime _previousSessionLoggedOn;
        IPAddress _previousSessionRemoteAddress;
        DateTime _recentSessionLoggedOn;
        IPAddress _recentSessionRemoteAddress;

        readonly ConcurrentDictionary<string, Group> _memberOfGroups;

        #endregion

        #region constructor

        private User()
        {
            _previousSessionRemoteAddress = IPAddress.Any;
            _recentSessionRemoteAddress = IPAddress.Any;

            _memberOfGroups = new ConcurrentDictionary<string, Group>(1, 2);
        }

        public User(BinaryReader bR, IReadOnlyDictionary<string, Group> groups)
        {
            int version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                case 3:
                    _displayName = bR.BaseStream.ReadShortString();
                    _username = bR.BaseStream.ReadShortString();

                    if (version >= 3)
                        _isSsoUser = bR.ReadBoolean();

                    if (_isSsoUser)
                    {
                        _ssoIdentifier = bR.BaseStream.ReadShortString();
                    }
                    else
                    {
                        _passwordHashType = (UserPasswordHashType)bR.ReadByte();
                        _iterations = bR.ReadInt32();
                        _salt = bR.ReadBuffer();
                        _passwordHash = bR.BaseStream.ReadShortString();

                        if (version >= 2)
                        {
                            string otpKeyUri = bR.ReadString();
                            if (!string.IsNullOrEmpty(otpKeyUri))
                                _totpKeyUri = AuthenticatorKeyUri.Parse(otpKeyUri);

                            _totpEnabled = bR.ReadBoolean();
                        }
                    }

                    _disabled = bR.ReadBoolean();
                    _sessionTimeoutSeconds = bR.ReadInt32();

                    _previousSessionLoggedOn = bR.BaseStream.ReadDateTime();
                    _previousSessionRemoteAddress = IPAddressExtensions.ReadFrom(bR);
                    _recentSessionLoggedOn = bR.BaseStream.ReadDateTime();
                    _recentSessionRemoteAddress = IPAddressExtensions.ReadFrom(bR);

                    {
                        int count = bR.ReadByte();
                        _memberOfGroups = new ConcurrentDictionary<string, Group>(1, count);

                        for (int i = 0; i < count; i++)
                        {
                            if (groups.TryGetValue(bR.BaseStream.ReadShortString().ToLowerInvariant(), out Group group))
                                _memberOfGroups.TryAdd(group.Name.ToLowerInvariant(), group);
                        }
                    }
                    break;

                default:
                    throw new InvalidDataException("Invalid data or version not supported.");
            }
        }

        #endregion

        #region static

        public static User CreateLocalUser(string displayName, string username, string password, int iterations = DEFAULT_ITERATIONS)
        {
            User user = new User();

            user.SetUsername(username);
            user.DisplayName = displayName;

            user.ChangePassword(password, iterations);

            return user;
        }

        public static User CreateSsoUser(string displayName, string username, string ssoIdentifier)
        {
            User user = new User();

            user.SetUsername(username);
            user.DisplayName = displayName;
            user._isSsoUser = true;
            user._ssoIdentifier = ssoIdentifier;

            return user;
        }

        public static bool IsUsernameValid(string username, bool throwException = false)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                if (throwException)
                    throw new ArgumentException("Username cannot be null or empty.", nameof(Username));

                return false;
            }

            if (username.Length > 255)
            {
                if (throwException)
                    throw new ArgumentException("Username length cannot exceed 255 characters.", nameof(Username));

                return false;
            }

            foreach (char c in username)
            {
                if ((c >= 97) && (c <= 122)) //[a-z]
                    continue;

                if ((c >= 65) && (c <= 90)) //[A-Z]
                    continue;

                if ((c >= 48) && (c <= 57)) //[0-9]
                    continue;

                if (c == '@')
                    continue;

                if (c == '-')
                    continue;

                if (c == '_')
                    continue;

                if (c == '.')
                    continue;

                if (throwException)
                    throw new ArgumentException("Username can contain only alpha numeric, '@', '-', '_', or '.' characters.", nameof(Username));

                return false;
            }

            return true;
        }

        #endregion

        #region internal

        internal void SetUsername(string username)
        {
            if (_passwordHashType == UserPasswordHashType.OldScheme)
                throw new InvalidOperationException("Cannot change username when using old password hash scheme. Change password once and try again.");

            IsUsernameValid(username, true);

            _username = username.ToLowerInvariant();
        }

        internal void RenameGroup(string oldName)
        {
            if (_memberOfGroups.TryRemove(oldName.ToLowerInvariant(), out Group renamedGroup))
                _memberOfGroups.TryAdd(renamedGroup.Name.ToLowerInvariant(), renamedGroup);
        }

        #endregion

        #region public

        public string GetPasswordHashFor(string password)
        {
            switch (_passwordHashType)
            {
                case UserPasswordHashType.OldScheme:
                    using (HMAC hmac = new HMACSHA256(Encoding.UTF8.GetBytes(password)))
                    {
                        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(_username))).ToLowerInvariant();
                    }

                case UserPasswordHashType.PBKDF2_SHA256:
                    return Convert.ToHexString(Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), _salt, _iterations, HashAlgorithmName.SHA256, 32)).ToLowerInvariant();

                default:
                    throw new NotSupportedException();
            }
        }

        public void ChangePassword(string newPassword, int iterations = DEFAULT_ITERATIONS)
        {
            if (_isSsoUser)
                throw new InvalidOperationException("Cannot change password for SSO users.");

            _passwordHashType = UserPasswordHashType.PBKDF2_SHA256;
            _iterations = iterations;

            _salt = new byte[32];
            RandomNumberGenerator.Fill(_salt);

            _passwordHash = GetPasswordHashFor(newPassword);
        }

        public void LoadOldSchemeCredentials(string passwordHash)
        {
            if (_isSsoUser)
                throw new InvalidOperationException();

            _passwordHashType = UserPasswordHashType.OldScheme;
            _passwordHash = passwordHash;
        }

        public AuthenticatorKeyUri InitializedTOTP(string issuer)
        {
            if (_isSsoUser)
                throw new InvalidOperationException("Time-based one-time password (TOTP) feature is not available for SSO users.");

            if (_totpEnabled)
                throw new InvalidOperationException("Time-based one-time password (TOTP) is already enabled for user: " + _username);

            _totpKeyUri = AuthenticatorKeyUri.Generate(issuer, _username);

            return _totpKeyUri;
        }

        public void EnableTOTP(string totp)
        {
            if (_isSsoUser)
                throw new InvalidOperationException("Time-based one-time password (TOTP) feature is not available for SSO users.");

            if (_totpKeyUri is null)
                throw new InvalidOperationException("Time-based one-time password (TOTP) was not initialized for user: " + _username);

            if (_totpEnabled)
                throw new InvalidOperationException("Time-based one-time password (TOTP) is already enabled for user: " + _username);

            Authenticator authenticator = new Authenticator(_totpKeyUri);

            if (!authenticator.IsTOTPValid(totp))
                throw new Exception("Invalid time-based one-time password (TOTP) was attempted for user: " + _username);

            _totpEnabled = true;
        }

        public void DisableTOTP()
        {
            if (_isSsoUser)
                throw new InvalidOperationException("Time-based one-time password (TOTP) feature is not available for SSO users.");

            if (!_totpEnabled)
                throw new InvalidOperationException("Time-based one-time password (TOTP) is already disabled for user: " + _username);

            _totpKeyUri = null;
            _totpEnabled = false;
        }

        public void LoggedInFrom(IPAddress remoteAddress)
        {
            if (remoteAddress.IsIPv4MappedToIPv6)
                remoteAddress = remoteAddress.MapToIPv4();

            _previousSessionLoggedOn = _recentSessionLoggedOn;
            _previousSessionRemoteAddress = _recentSessionRemoteAddress;

            _recentSessionLoggedOn = DateTime.UtcNow;
            _recentSessionRemoteAddress = remoteAddress;
        }

        public void AddToGroup(Group group)
        {
            if (_memberOfGroups.Count == 255)
                throw new InvalidOperationException("Cannot add user to group: user can be member of max 255 groups.");

            _memberOfGroups.TryAdd(group.Name.ToLowerInvariant(), group);
        }

        public bool RemoveFromGroup(Group group)
        {
            if (group.Name.Equals("everyone", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Access was denied.");

            return _memberOfGroups.TryRemove(group.Name.ToLowerInvariant(), out _);
        }

        public void SyncGroups(IReadOnlyDictionary<string, Group> groups)
        {
            //remove non-existent groups
            foreach (KeyValuePair<string, Group> group in _memberOfGroups)
            {
                if (!groups.ContainsKey(group.Key))
                    _memberOfGroups.TryRemove(group.Key, out _);
            }

            //set new groups
            foreach (KeyValuePair<string, Group> group in groups)
                _memberOfGroups[group.Key] = group.Value;
        }

        public bool IsMemberOfGroup(Group group)
        {
            return _memberOfGroups.ContainsKey(group.Name.ToLowerInvariant());
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)3);

            bW.BaseStream.WriteShortString(_displayName);
            bW.BaseStream.WriteShortString(_username);
            bW.Write(_isSsoUser);

            if (_isSsoUser)
            {
                bW.BaseStream.WriteShortString(_ssoIdentifier);
            }
            else
            {
                bW.Write((byte)_passwordHashType);
                bW.Write(_iterations);
                bW.WriteBuffer(_salt);
                bW.BaseStream.WriteShortString(_passwordHash);

                if (_totpKeyUri is null)
                    bW.Write("");
                else
                    bW.Write(_totpKeyUri.ToString());

                bW.Write(_totpEnabled);
            }

            bW.Write(_disabled);
            bW.Write(_sessionTimeoutSeconds);

            bW.BaseStream.WriteDateTime(_previousSessionLoggedOn);
            IPAddressExtensions.WriteTo(_previousSessionRemoteAddress, bW);
            bW.BaseStream.WriteDateTime(_recentSessionLoggedOn);
            IPAddressExtensions.WriteTo(_recentSessionRemoteAddress, bW);

            bW.Write(Convert.ToByte(_memberOfGroups.Count));

            foreach (KeyValuePair<string, Group> group in _memberOfGroups)
                bW.BaseStream.WriteShortString(group.Value.Name.ToLowerInvariant());
        }

        public override bool Equals(object obj)
        {
            if (obj is not User other)
                return false;

            return _username.Equals(other._username, StringComparison.OrdinalIgnoreCase);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_username);
        }

        public override string ToString()
        {
            return _username;
        }

        public int CompareTo(User other)
        {
            return _username.CompareTo(other._username);
        }

        #endregion

        #region properties

        public string DisplayName
        {
            get { return _displayName; }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    _displayName = _username;
                else if (value.Length > 255)
                    throw new ArgumentException("Display name length cannot exceed 255 characters.", nameof(DisplayName));
                else
                    _displayName = value;
            }
        }

        public string Username
        { get { return _username; } }

        public bool IsSsoUser
        { get { return _isSsoUser; } }

        public string SsoIdentifier
        { get { return _ssoIdentifier; } }

        public UserPasswordHashType PasswordHashType
        { get { return _passwordHashType; } }

        public string PasswordHash
        { get { return _passwordHash; } }

        public AuthenticatorKeyUri TOTPKeyUri
        { get { return _totpKeyUri; } }

        public bool TOTPEnabled
        { get { return _totpEnabled; } }

        public bool Disabled
        {
            get { return _disabled; }
            set { _disabled = value; }
        }

        public int SessionTimeoutSeconds
        {
            get { return _sessionTimeoutSeconds; }
            set
            {
                if ((value < 0) || (value > 604800))
                    throw new ArgumentOutOfRangeException(nameof(SessionTimeoutSeconds), "Session timeout value must be between 0-604800 seconds.");

                if ((value > 0) && (value < 60))
                    value = 60; //to prevent issues with too low timeout set by mistake

                _sessionTimeoutSeconds = value;
            }
        }

        public DateTime PreviousSessionLoggedOn
        { get { return _previousSessionLoggedOn; } }

        public IPAddress PreviousSessionRemoteAddress
        { get { return _previousSessionRemoteAddress; } }

        public DateTime RecentSessionLoggedOn
        { get { return _recentSessionLoggedOn; } }

        public IPAddress RecentSessionRemoteAddress
        { get { return _recentSessionRemoteAddress; } }

        public ICollection<Group> MemberOfGroups
        { get { return _memberOfGroups.Values; } }

        #endregion
    }
}
