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
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns.Zones
{
    public enum AuthZoneType : byte
    {
        Unknown = 0,
        Primary = 1,
        Secondary = 2,
        Stub = 3,
        Forwarder = 4,
        Application = 5
    }

    public sealed class AuthZoneInfo : IComparable<AuthZoneInfo>
    {
        #region variables

        readonly AuthZone _zone;

        readonly string _name;
        readonly AuthZoneType _type;
        readonly bool _disabled;
        readonly DateTime _expiry;

        #endregion

        #region constructor

        public AuthZoneInfo(string name, AuthZoneType type, bool disabled)
        {
            _name = name;
            _type = type;
            _disabled = disabled;
        }

        public AuthZoneInfo(BinaryReader bR)
        {
            switch (bR.ReadByte())
            {
                case 1:
                    _name = bR.ReadShortString();
                    _type = (AuthZoneType)bR.ReadByte();
                    _disabled = bR.ReadBoolean();

                    switch (_type)
                    {
                        case AuthZoneType.Secondary:
                            _expiry = bR.ReadDate();
                            break;

                        case AuthZoneType.Stub:
                            _expiry = bR.ReadDate();
                            break;
                    }

                    break;

                default:
                    throw new InvalidDataException("AuthZoneInfo format version not supported.");
            }
        }

        internal AuthZoneInfo(AuthZone zone)
        {
            _zone = zone;
            _name = _zone.Name;

            if (_zone is PrimaryZone)
                _type = AuthZoneType.Primary;
            else if (_zone is SecondaryZone)
                _type = AuthZoneType.Secondary;
            else if (_zone is StubZone)
                _type = AuthZoneType.Stub;
            else if (_zone is ForwarderZone)
                _type = AuthZoneType.Forwarder;
            else if (_zone is ApplicationZone)
                _type = AuthZoneType.Application;
            else
                _type = AuthZoneType.Unknown;

            _disabled = _zone.Disabled;

            switch (_type)
            {
                case AuthZoneType.Secondary:
                    _expiry = (_zone as SecondaryZone).Expiry;
                    break;

                case AuthZoneType.Stub:
                    _expiry = (_zone as StubZone).Expiry;
                    break;
            }
        }

        #endregion

        #region public

        public IReadOnlyList<DnsResourceRecord> GetRecords(DnsResourceRecordType type)
        {
            if (_zone == null)
                throw new InvalidOperationException();

            return _zone.GetRecords(type);
        }

        public void NotifyNameServers()
        {
            if (_zone == null)
                throw new InvalidOperationException();

            switch (_type)
            {
                case AuthZoneType.Primary:
                    (_zone as PrimaryZone).NotifyNameServers();
                    break;

                default:
                    throw new InvalidOperationException();
            }
        }

        public void RefreshZone()
        {
            if (_zone == null)
                throw new InvalidOperationException();

            switch (_type)
            {
                case AuthZoneType.Secondary:
                    (_zone as SecondaryZone).RefreshZone();
                    break;

                case AuthZoneType.Stub:
                    (_zone as StubZone).RefreshZone();
                    break;

                default:
                    throw new InvalidOperationException();
            }
        }

        public Task<IReadOnlyList<NameServerAddress>> GetPrimaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            if (_zone == null)
                throw new InvalidOperationException();

            return _zone.GetPrimaryNameServerAddressesAsync(dnsServer);
        }

        public Task<IReadOnlyList<NameServerAddress>> GetSecondaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            if (_zone == null)
                throw new InvalidOperationException();

            return _zone.GetSecondaryNameServerAddressesAsync(dnsServer);
        }

        public void WriteTo(BinaryWriter bW)
        {
            if (_zone == null)
                throw new InvalidOperationException();

            bW.Write((byte)1); //version

            bW.WriteShortString(_name);
            bW.Write((byte)_type);
            bW.Write(_disabled);

            switch (_type)
            {
                case AuthZoneType.Secondary:
                    bW.Write(_expiry);
                    break;

                case AuthZoneType.Stub:
                    bW.Write(_expiry);
                    break;
            }
        }

        public int CompareTo(AuthZoneInfo other)
        {
            return _name.CompareTo(other._name);
        }

        public override string ToString()
        {
            return _name;
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public AuthZoneType Type
        { get { return _type; } }

        public bool Disabled
        {
            get { return _disabled; }
            set
            {
                if (_zone == null)
                    throw new InvalidOperationException();

                _zone.Disabled = value;
            }
        }

        public DateTime Expiry
        { get { return _expiry; } }

        public bool IsExpired
        {
            get
            {
                if (_zone == null)
                    throw new InvalidOperationException();

                if (_zone is SecondaryZone)
                    return (_zone as SecondaryZone).IsExpired;

                if (_zone is StubZone)
                    return (_zone as StubZone).IsExpired;

                return false;
            }
        }

        public bool Internal
        {
            get
            {
                if (_zone == null)
                    throw new InvalidOperationException();

                if (_zone is PrimaryZone)
                    return (_zone as PrimaryZone).Internal;

                return false;
            }
        }

        #endregion
    }
}
