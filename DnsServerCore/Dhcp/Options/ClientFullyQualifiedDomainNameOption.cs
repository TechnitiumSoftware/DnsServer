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
using System.Text;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dhcp.Options
{
    [Flags]
    enum ClientFullyQualifiedDomainNameFlags : byte
    {
        None = 0,
        ShouldUpdateDns = 1,
        OverrideByServer = 2,
        EncodeUsingCanonicalWireFormat = 4,
        NoDnsUpdate = 8,
    }

    class ClientFullyQualifiedDomainNameOption : DhcpOption
    {
        #region variables

        ClientFullyQualifiedDomainNameFlags _flags;
        byte _rcode1;
        byte _rcode2;
        string _domainName;

        #endregion

        #region constructor

        public ClientFullyQualifiedDomainNameOption(ClientFullyQualifiedDomainNameFlags flags, byte rcode1, byte rcode2, string domainName)
            : base(DhcpOptionCode.ClientFullyQualifiedDomainName)
        {
            _flags = flags;
            _rcode1 = rcode1;
            _rcode2 = rcode2;
            _domainName = domainName;
        }

        public ClientFullyQualifiedDomainNameOption(Stream s)
            : base(DhcpOptionCode.ClientFullyQualifiedDomainName, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            if (s.Length < 3)
                throw new InvalidDataException();

            int flags = s.ReadByte();
            if (flags < 0)
                throw new EndOfStreamException();

            _flags = (ClientFullyQualifiedDomainNameFlags)flags;

            int rcode;

            rcode = s.ReadByte();
            if (rcode < 0)
                throw new EndOfStreamException();

            _rcode1 = (byte)rcode;

            rcode = s.ReadByte();
            if (rcode < 0)
                throw new EndOfStreamException();

            _rcode2 = (byte)rcode;

            if (_flags.HasFlag(ClientFullyQualifiedDomainNameFlags.EncodeUsingCanonicalWireFormat))
                _domainName = DnsDatagram.DeserializeDomainName(s, 0, true);
            else
                _domainName = Encoding.ASCII.GetString(s.ReadExactly((int)s.Length - 3));
        }

        protected override void WriteOptionValue(Stream s)
        {
            s.WriteByte((byte)_flags);
            s.WriteByte(_rcode1);
            s.WriteByte(_rcode2);

            if (_flags.HasFlag(ClientFullyQualifiedDomainNameFlags.EncodeUsingCanonicalWireFormat))
                DnsDatagram.SerializeDomainName(_domainName, s);
            else
                s.Write(Encoding.ASCII.GetBytes(_domainName));
        }

        #endregion

        #region properties

        public ClientFullyQualifiedDomainNameFlags Flags
        { get { return _flags; } }

        public byte RCODE1
        { get { return _rcode1; } }

        public byte RCODE2
        { get { return _rcode2; } }

        public string DomainName
        { get { return _domainName; } }

        #endregion
    }
}
