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

using System.IO;

namespace DnsServerCore.Dhcp.Options
{
    class ParameterRequestListOption : DhcpOption
    {
        #region variables

        DhcpOptionCode[] _optionCodes;

        #endregion

        #region constructor

        public ParameterRequestListOption(DhcpOptionCode[] optionCodes)
            : base(DhcpOptionCode.ParameterRequestList)
        {
            _optionCodes = optionCodes;
        }

        public ParameterRequestListOption(Stream s)
            : base(DhcpOptionCode.ParameterRequestList, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            if (s.Length < 1)
                throw new InvalidDataException();

            _optionCodes = new DhcpOptionCode[s.Length];
            int optionCode;

            for (int i = 0; i < _optionCodes.Length; i++)
            {
                optionCode = s.ReadByte();
                if (optionCode < 0)
                    throw new EndOfStreamException();

                _optionCodes[i] = (DhcpOptionCode)optionCode;
            }
        }

        protected override void WriteOptionValue(Stream s)
        {
            foreach (DhcpOptionCode optionCode in _optionCodes)
                s.WriteByte((byte)optionCode);
        }

        #endregion

        #region properties

        public DhcpOptionCode[] OptionCodes
        { get { return _optionCodes; } }

        #endregion
    }
}
