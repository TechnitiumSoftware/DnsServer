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
    public class VendorSpecificInformationOption : DhcpOption
    {
        #region variables

        byte[] _information;

        #endregion

        #region constructor

        public VendorSpecificInformationOption(string hexInfo)
            : base(DhcpOptionCode.VendorSpecificInformation)
        {
            if (hexInfo.Contains(':'))
                _information = hexInfo.ParseColonHexString();
            else
                _information = Convert.FromHexString(hexInfo);
        }

        public VendorSpecificInformationOption(byte[] information)
            : base(DhcpOptionCode.VendorSpecificInformation)
        {
            _information = information;
        }

        public VendorSpecificInformationOption(Stream s)
            : base(DhcpOptionCode.VendorSpecificInformation, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            _information = s.ReadExactly((int)s.Length);
        }

        protected override void WriteOptionValue(Stream s)
        {
            s.Write(_information);
        }

        #endregion

        #region properties

        public byte[] Information
        { get { return _information; } }

        #endregion
    }
}
