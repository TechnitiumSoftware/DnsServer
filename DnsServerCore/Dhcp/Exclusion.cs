/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using TechnitiumLibrary.Net;

namespace DnsServerCore.Dhcp
{
    public class Exclusion
    {
        #region variables

        readonly IPAddress _startingAddress;
        readonly IPAddress _endingAddress;

        #endregion

        #region constructor

        public Exclusion(IPAddress startingAddress, IPAddress endingAddress)
        {
            if (startingAddress.ConvertIpToNumber() > endingAddress.ConvertIpToNumber())
                throw new ArgumentException("Exclusion ending address must be greater than or equal to starting address.");

            _startingAddress = startingAddress;
            _endingAddress = endingAddress;
        }

        #endregion

        #region properties

        public IPAddress StartingAddress
        { get { return _startingAddress; } }

        public IPAddress EndingAddress
        { get { return _endingAddress; } }

        #endregion
    }
}
