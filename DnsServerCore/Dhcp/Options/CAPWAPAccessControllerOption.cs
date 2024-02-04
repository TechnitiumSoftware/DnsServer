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
    class CAPWAPAccessControllerOption : DhcpOption
    {
        #region variables

        IReadOnlyCollection<IPAddress> _apIpAddresses;

        #endregion

        #region constructor

        public CAPWAPAccessControllerOption(IReadOnlyCollection<IPAddress> apIpAddresses)
            : base(DhcpOptionCode.CAPWAPAccessControllerAddresses)
        {
            _apIpAddresses = apIpAddresses;
        }

        public CAPWAPAccessControllerOption(Stream s)
            : base(DhcpOptionCode.CAPWAPAccessControllerAddresses, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            if (s.Length < 1)
                throw new InvalidDataException();

            List<IPAddress> apIpAddresses = new List<IPAddress>();

            while (s.Length > 0)
                apIpAddresses.Add(new IPAddress(s.ReadExactly(4)));

            _apIpAddresses = apIpAddresses;
        }

        protected override void WriteOptionValue(Stream s)
        {
            foreach (IPAddress apIpAddress in _apIpAddresses)
                s.Write(apIpAddress.GetAddressBytes());
        }

        #endregion

        #region properties

        public IReadOnlyCollection<IPAddress> ApIpAddresses
        { get { return _apIpAddresses; } }

        #endregion
    }
}
