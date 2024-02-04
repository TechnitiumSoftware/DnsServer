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
    class RebindingTimeValueOption : DhcpOption
    {
        #region variables

        uint _t2Interval;

        #endregion

        #region constructor

        public RebindingTimeValueOption(uint t2Interval)
            : base(DhcpOptionCode.RebindingTimeValue)
        {
            _t2Interval = t2Interval;
        }

        public RebindingTimeValueOption(Stream s)
            : base(DhcpOptionCode.RebindingTimeValue, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            if (s.Length != 4)
                throw new InvalidDataException();

            byte[] buffer = s.ReadExactly(4);
            Array.Reverse(buffer);
            _t2Interval = BitConverter.ToUInt32(buffer, 0);
        }

        protected override void WriteOptionValue(Stream s)
        {
            byte[] buffer = BitConverter.GetBytes(_t2Interval);
            Array.Reverse(buffer);
            s.Write(buffer);
        }

        #endregion

        #region properties

        public uint T2Interval
        { get { return _t2Interval; } }

        #endregion
    }
}
