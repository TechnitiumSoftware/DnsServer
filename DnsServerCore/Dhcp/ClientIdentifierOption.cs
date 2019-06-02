/*
Technitium DNS Server
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dhcp
{
    class ClientIdentifierOption : DhcpOption
    {
        #region variables

        readonly byte _type;
        readonly byte[] _identifier;

        #endregion

        #region constructor

        public ClientIdentifierOption(Stream s)
            : base(DhcpOptionCode.ClientIdentifier)
        {
            int len = s.ReadByte();
            if (len < 0)
                throw new EndOfStreamException();

            if (len < 2)
                throw new InvalidDataException();

            int type = s.ReadByte();
            if (type < 0)
                throw new EndOfStreamException();

            _type = (byte)type;
            _identifier = s.ReadBytes(len - 1);
        }

        #endregion

        #region protected

        protected override void WriteOptionTo(Stream s)
        {
            s.WriteByte(Convert.ToByte(_identifier.Length + 1));
            s.WriteByte(_type);
            s.Write(_identifier);
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
