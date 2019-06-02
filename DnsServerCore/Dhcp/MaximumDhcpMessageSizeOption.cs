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
    class MaximumDhcpMessageSizeOption : DhcpOption
    {
        #region variables

        readonly ushort _length;

        #endregion

        #region constructor

        public MaximumDhcpMessageSizeOption(Stream s)
            : base(DhcpOptionCode.MaximumDhcpMessageSize)
        {
            int len = s.ReadByte();
            if (len < 0)
                throw new EndOfStreamException();

            if (len != 2)
                throw new InvalidDataException();

            _length = BitConverter.ToUInt16(s.ReadBytes(2), 0);
        }

        #endregion

        #region protected

        protected override void WriteOptionTo(Stream s)
        {
            s.WriteByte(2);
            s.Write(BitConverter.GetBytes(_length));
        }

        #endregion

        #region properties

        public uint Length
        { get { return _length; } }

        #endregion
    }
}
