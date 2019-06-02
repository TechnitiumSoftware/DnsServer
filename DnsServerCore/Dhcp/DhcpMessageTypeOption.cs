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
    enum DhcpMessageType : byte
    {
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

        readonly DhcpMessageType _messageType;

        #endregion

        #region constructor

        public DhcpMessageTypeOption(Stream s)
            : base(DhcpOptionCode.DhcpMessageType)
        {
            int len = s.ReadByte();
            if (len < 0)
                throw new EndOfStreamException();

            if (len != 1)
                throw new InvalidDataException();

            int type = s.ReadByte();
            if (type < 0)
                throw new EndOfStreamException();

            _messageType = (DhcpMessageType)type;
        }

        #endregion

        #region protected

        protected override void WriteOptionTo(Stream s)
        {
            s.WriteByte(1);
            s.WriteByte((byte)_messageType);
        }

        #endregion

        #region properties

        public DhcpMessageType MessageType
        { get { return _messageType; } }

        #endregion
    }
}
