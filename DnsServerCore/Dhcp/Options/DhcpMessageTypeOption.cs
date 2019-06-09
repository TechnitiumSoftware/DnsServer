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
    enum DhcpMessageType : byte
    {
        Unknown = 0,
        Discover = 1,
        Offer = 2,
        Request = 3,
        Decline = 4,
        Ack = 5,
        Nak = 6,
        Release = 7,
        Inform = 8
    }

    class DhcpMessageTypeOption : DhcpOption
    {
        #region variables

        DhcpMessageType _type;

        #endregion

        #region constructor

        public DhcpMessageTypeOption(DhcpMessageType type)
            : base(DhcpOptionCode.DhcpMessageType)
        {
            _type = type;
        }

        public DhcpMessageTypeOption(Stream s)
            : base(DhcpOptionCode.DhcpMessageType, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            if (s.Length != 1)
                throw new InvalidDataException();

            int type = s.ReadByte();
            if (type < 0)
                throw new EndOfStreamException();

            _type = (DhcpMessageType)type;
        }

        protected override void WriteOptionValue(Stream s)
        {
            s.WriteByte((byte)_type);
        }

        #endregion

        #region string

        public override string ToString()
        {
            return _type.ToString();
        }

        #endregion

        #region properties

        public DhcpMessageType Type
        { get { return _type; } }

        #endregion
    }
}
