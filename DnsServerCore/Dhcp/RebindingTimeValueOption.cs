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
    class RebindingTimeValueOption : DhcpOption
    {
        #region variables

        readonly uint _t2Interval;

        #endregion

        #region constructor

        public RebindingTimeValueOption(Stream s)
            : base(DhcpOptionCode.RebindingTimeValue)
        {
            int len = s.ReadByte();
            if (len < 0)
                throw new EndOfStreamException();

            if (len != 4)
                throw new InvalidDataException();

            _t2Interval = BitConverter.ToUInt32(s.ReadBytes(4), 0);
        }

        #endregion

        #region protected

        protected override void WriteOptionTo(Stream s)
        {
            s.WriteByte(4);
            s.Write(BitConverter.GetBytes(_t2Interval));
        }

        #endregion

        #region properties

        public uint T2Interval
        { get { return _t2Interval; } }

        #endregion
    }
}
