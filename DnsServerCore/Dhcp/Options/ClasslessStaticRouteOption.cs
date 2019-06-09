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
using System.Collections.Generic;
using System.IO;
using System.Net;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dhcp.Options
{
    class ClasslessStaticRouteOption : DhcpOption
    {
        #region variables

        ICollection<Route> _routes;

        #endregion

        #region constructor

        public ClasslessStaticRouteOption(ICollection<Route> routes)
            : base(DhcpOptionCode.ClasslessStaticRoute)
        {
            _routes = routes;
        }

        public ClasslessStaticRouteOption(Stream s)
            : base(DhcpOptionCode.ClasslessStaticRoute, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            if (s.Length < 5)
                throw new InvalidDataException();

            _routes = new List<Route>();

            while (s.Position < s.Length)
            {
                _routes.Add(new Route(s));
            }
        }

        protected override void WriteOptionValue(Stream s)
        {
            foreach (Route route in _routes)
                route.WriteTo(s);
        }

        #endregion

        #region properties

        public ICollection<Route> Routes
        { get { return _routes; } }

        #endregion

        public class Route
        {
            #region private

            readonly IPAddress _destination;
            readonly IPAddress _subnetMask;
            readonly IPAddress _router;

            #endregion

            #region constructor

            public Route(IPAddress destination, IPAddress subnetMask, IPAddress router)
            {
                _destination = destination;
                _subnetMask = subnetMask;
                _router = router;
            }

            public Route(Stream s)
            {
                int subnetMaskWidth = s.ReadByte();
                if (subnetMaskWidth < 0)
                    throw new EndOfStreamException();

                _destination = new IPAddress(s.ReadBytes(Convert.ToInt32(Math.Ceiling(Convert.ToDecimal(subnetMaskWidth) / 8))));

                byte[] subnetMaskBuffer = BitConverter.GetBytes(0xFFFFFFFFu << (32 - subnetMaskWidth));
                Array.Reverse(subnetMaskBuffer);
                _subnetMask = new IPAddress(subnetMaskBuffer);

                _router = new IPAddress(s.ReadBytes(4));
            }

            #endregion

            #region public

            public void WriteTo(Stream s)
            {
                byte[] subnetMaskBuffer = _subnetMask.GetAddressBytes();
                Array.Reverse(subnetMaskBuffer);
                uint subnetMaskNumber = BitConverter.ToUInt32(subnetMaskBuffer, 0);

                byte subnetMaskWidth = 0;

                while (subnetMaskNumber > 0u)
                {
                    subnetMaskNumber <<= 1;
                    subnetMaskWidth++;
                }

                s.WriteByte(subnetMaskWidth);
                s.Write(_destination.GetAddressBytes(), 0, Convert.ToInt32(Math.Ceiling(Convert.ToDecimal(subnetMaskWidth) / 8)));
                s.Write(_router.GetAddressBytes());
            }

            #endregion

            #region properties

            public IPAddress Destination
            { get { return _destination; } }

            public IPAddress SubnetMask
            { get { return _subnetMask; } }

            public IPAddress Router
            { get { return _router; } }

            #endregion
        }
    }
}
