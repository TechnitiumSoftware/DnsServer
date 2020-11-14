/*
Technitium DNS Server
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using System.Globalization;
using System.IO;
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
            _information = ParseHexString(hexInfo);
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

        #region private

        private static byte[] ParseHexString(string value)
        {
            int i;
            int j = -1;
            string strHex;
            int b;

            using (MemoryStream mS = new MemoryStream())
            {
                while (true)
                {
                    i = value.IndexOf(':', j + 1);
                    if (i < 0)
                        i = value.Length;

                    strHex = value.Substring(j + 1, i - j - 1);

                    if (!int.TryParse(strHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out b) || (b < byte.MinValue) || (b > byte.MaxValue))
                        throw new InvalidDataException("VendorSpecificInformation option data must be a colon (:) separated hex string.");

                    mS.WriteByte((byte)b);

                    if (i == value.Length)
                        break;

                    j = i;
                }

                return mS.ToArray();
            }
        }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            _information = s.ReadBytes((int)s.Length);
        }

        protected override void WriteOptionValue(Stream s)
        {
            s.Write(_information);
        }

        #endregion

        #region public

        public override string ToString()
        {
            return BitConverter.ToString(_information).Replace("-", ":");
        }

        #endregion

        #region properties

        public byte[] Information
        { get { return _information; } }

        #endregion
    }
}
