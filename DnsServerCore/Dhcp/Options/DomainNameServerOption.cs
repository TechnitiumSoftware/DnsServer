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

using System.Collections.Generic;
using System.IO;
using System.Net;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dhcp.Options
{
    class DomainNameServerOption : DhcpOption
    {
        #region variables

        IReadOnlyCollection<IPAddress> _addresses;

        #endregion

        #region constructor

        public DomainNameServerOption(IReadOnlyCollection<IPAddress> addresses)
            : base(DhcpOptionCode.DomainNameServer)
        {
            _addresses = addresses;
        }

        public DomainNameServerOption(Stream s)
            : base(DhcpOptionCode.DomainNameServer, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            if ((s.Length % 4 != 0) || (s.Length < 4))
                throw new InvalidDataException();

            IPAddress[] addresses = new IPAddress[s.Length / 4];

            for (int i = 0; i < addresses.Length; i++)
                addresses[i] = new IPAddress(s.ReadExactly(4));

            _addresses = addresses;
        }

        protected override void WriteOptionValue(Stream s)
        {
            foreach (IPAddress address in _addresses)
                s.Write(address.GetAddressBytes());
        }

        #endregion

        #region properties

        public IReadOnlyCollection<IPAddress> Addresses
        { get { return _addresses; } }

        #endregion
    }
}
