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

namespace DnsServerCore.Dhcp
{
    enum OptionOverloadValue : byte
    {
        FileFieldUsed = 1,
        SnameFieldUsed = 2,
        BothFieldsUsed = 3
    }

    class OptionOverloadOption : DhcpOption
    {
        #region variables

        readonly OptionOverloadValue _value;

        #endregion

        #region constructor

        public OptionOverloadOption(Stream s)
            : base(DhcpOptionCode.OptionOverload)
        {
            int len = s.ReadByte();
            if (len < 0)
                throw new EndOfStreamException();

            if (len != 1)
                throw new InvalidDataException();

            int value = s.ReadByte();
            if (value < 0)
                throw new EndOfStreamException();

            _value = (OptionOverloadValue)value;
        }

        #endregion

        #region protected

        protected override void WriteOptionTo(Stream s)
        {
            s.WriteByte(4);
            s.WriteByte((byte)_value);
        }

        #endregion

        #region properties

        public OptionOverloadValue Value
        { get { return _value; } }

        #endregion
    }
}
