using System;
using System.Collections.Generic;
using System.IO;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns.Zones
{
    public enum AuthZoneType : byte
    {
        Unknown = 0,
        Primary = 1,
        Secondary = 2,
        Stub = 3
    }

    public class AuthZoneInfo : IComparable<AuthZoneInfo>
    {
        #region variables

        readonly string _name;
        readonly AuthZoneType _type;
        readonly bool _disabled;

        readonly AuthZone _zone;

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
                    break;

                default:
                    throw new InvalidDataException("AuthZoneInfo format version not supported.");
            }
        }

        public AuthZoneInfo(AuthZone zone)
        {
            _name = zone.Name;

            if (zone is PrimaryZone)
                _type = AuthZoneType.Primary;
            else if (zone is SecondaryZone)
                _type = AuthZoneType.Secondary;
            else if (zone is StubZone)
                _type = AuthZoneType.Stub;
            else
                _type = AuthZoneType.Unknown;

            _disabled = zone.Disabled;

            _zone = zone;
        }

        #endregion

        #region public

        public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type)
        {
            if (_zone == null)
                throw new InvalidOperationException();

            return _zone.QueryRecords(type);
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version

            bW.WriteShortString(_name);
            bW.Write((byte)_type);
            bW.Write(_disabled);
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
