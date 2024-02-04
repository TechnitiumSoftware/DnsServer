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
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dhcp.Options
{
    class MaximumDhcpMessageSizeOption : DhcpOption
    {
        #region variables

        ushort _length;

        #endregion

        #region constructor

        public MaximumDhcpMessageSizeOption(ushort length)
            : base(DhcpOptionCode.MaximumDhcpMessageSize)
        {
            if (length < 576)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be 576 bytes or more.");

            _length = length;
        }

        public MaximumDhcpMessageSizeOption(Stream s)
            : base(DhcpOptionCode.MaximumDhcpMessageSize, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            if (s.Length != 2)
                throw new InvalidDataException();

            byte[] buffer = s.ReadExactly(2);
            Array.Reverse(buffer);
            _length = BitConverter.ToUInt16(buffer, 0);

            if (_length < 576)
                _length = 576;
        }

        protected override void WriteOptionValue(Stream s)
        {
            byte[] buffer = BitConverter.GetBytes(_length);
            Array.Reverse(buffer);
            s.Write(buffer);
        }

        #endregion

        #region properties

        public uint Length
        { get { return _length; } }

        #endregion
    }
}
