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
    class RenewalTimeValueOption : DhcpOption
    {
        #region variables

        uint _t1Interval;

        #endregion

        #region constructor

        public RenewalTimeValueOption(uint t1Interval)
            : base(DhcpOptionCode.RenewalTimeValue)
        {
            _t1Interval = t1Interval;
        }

        public RenewalTimeValueOption(Stream s)
            : base(DhcpOptionCode.RenewalTimeValue, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            if (s.Length != 4)
                throw new InvalidDataException();

            byte[] buffer = s.ReadExactly(4);
            Array.Reverse(buffer);
            _t1Interval = BitConverter.ToUInt32(buffer, 0);
        }

        protected override void WriteOptionValue(Stream s)
        {
            byte[] buffer = BitConverter.GetBytes(_t1Interval);
            Array.Reverse(buffer);
            s.Write(buffer);
        }

        #endregion

        #region properties

        public uint T1Interval
        { get { return _t1Interval; } }

        #endregion
    }
}
