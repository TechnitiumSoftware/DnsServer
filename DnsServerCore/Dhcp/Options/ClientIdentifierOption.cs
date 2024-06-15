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

using System;
using System.IO;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dhcp.Options
{
    public class ClientIdentifierOption : DhcpOption, IEquatable<ClientIdentifierOption>
    {
        #region variables

        byte _type;
        byte[] _identifier;

        #endregion

        #region constructor

        public ClientIdentifierOption(byte type, byte[] identifier)
            : base(DhcpOptionCode.ClientIdentifier)
        {
            _type = type;
            _identifier = identifier;
        }

        public ClientIdentifierOption(Stream s)
            : base(DhcpOptionCode.ClientIdentifier, s)
        { }

        #endregion

        #region static

        public static ClientIdentifierOption Parse(string clientIdentifier)
        {
            string[] parts = clientIdentifier.Split('-');
            return new ClientIdentifierOption(byte.Parse(parts[0]), Convert.FromHexString(parts[1]));
        }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            if (s.Length < 2)
                throw new InvalidDataException();

            int type = s.ReadByte();
            if (type < 0)
                throw new EndOfStreamException();

            _type = (byte)type;
            _identifier = s.ReadExactly((int)s.Length - 1);
        }

        protected override void WriteOptionValue(Stream s)
        {
            s.WriteByte(_type);
            s.Write(_identifier);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            return Equals(obj as ClientIdentifierOption);
        }

        public bool Equals(ClientIdentifierOption other)
        {
            if (other is null)
                return false;

            if (this._type != other._type)
                return false;

            if (this._identifier.Length != other._identifier.Length)
                return false;

            for (int i = 0; i < this._identifier.Length; i++)
            {
                if (this._identifier[i] != other._identifier[i])
                    return false;
            }

            return true;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_type, _identifier.GetArrayHashCode());
        }

        public override string ToString()
        {
            return _type.ToString() + "-" + Convert.ToHexString(_identifier);
        }

        #endregion

        #region properties

        public byte Type
        { get { return _type; } }

        public byte[] Identifier
        { get { return _identifier; } }

        #endregion
    }
}
