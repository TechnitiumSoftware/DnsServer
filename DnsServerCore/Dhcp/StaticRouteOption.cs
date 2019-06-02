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

using System;
using System.IO;
using System.Net;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dhcp
{
    class StaticRouteOption : DhcpOption
    {
        #region variables

        readonly Tuple<IPAddress, IPAddress>[] _routes;

        #endregion

        #region constructor

        public StaticRouteOption(Stream s)
            : base(DhcpOptionCode.StaticRoute)
        {
            int len = s.ReadByte();
            if (len < 0)
                throw new EndOfStreamException();

            if ((len % 8 != 0) || (len < 8))
                throw new InvalidDataException();

            _routes = new Tuple<IPAddress, IPAddress>[len / 8];

            for (int i = 0; i < _routes.Length; i++)
                _routes[i] = new Tuple<IPAddress, IPAddress>(new IPAddress(s.ReadBytes(4)), new IPAddress(s.ReadBytes(4)));
        }

        #endregion

        #region protected

        protected override void WriteOptionTo(Stream s)
        {
            s.WriteByte(Convert.ToByte(_routes.Length * 4));

            foreach (Tuple<IPAddress, IPAddress> route in _routes)
            {
                s.Write(route.Item1.GetAddressBytes());
                s.Write(route.Item2.GetAddressBytes());
            }
        }

        #endregion

        #region properties

        public Tuple<IPAddress, IPAddress>[] Routes
        { get { return _routes; } }

        #endregion
    }
}
