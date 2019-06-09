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

using DnsServerCore.Dhcp.Options;
using System;
using System.Net;

namespace DnsServerCore.Dhcp
{
    public class Lease
    {
        #region variables

        readonly ClientIdentifierOption _clientIdentifier;
        readonly string _hostName;
        readonly byte[] _hardwareAddress;
        readonly IPAddress _address;
        DateTime _leaseObtained;
        DateTime _leaseExpires;

        #endregion

        #region constructor

        internal Lease(ClientIdentifierOption clientIdentifier, string hostName, byte[] hardwareAddress, IPAddress address, uint leaseTime)
        {
            _clientIdentifier = clientIdentifier;
            _hostName = hostName;
            _hardwareAddress = hardwareAddress;
            _address = address;

            ResetLeaseTime(leaseTime);
        }

        internal Lease(byte[] hardwareAddress, IPAddress address, uint leaseTime)
            : this(new ClientIdentifierOption(1, hardwareAddress), null, hardwareAddress, address, leaseTime)
        { }

        #endregion

        #region public

        public void ResetLeaseTime(uint leaseTime)
        {
            _leaseObtained = DateTime.UtcNow;
            _leaseExpires = DateTime.UtcNow.AddSeconds(leaseTime);
        }

        #endregion

        #region properties

        internal ClientIdentifierOption ClientIdentifier
        { get { return _clientIdentifier; } }

        public string HostName
        { get { return _hostName; } }

        public byte[] HardwareAddress
        { get { return _hardwareAddress; } }

        public IPAddress Address
        { get { return _address; } }

        public DateTime LeaseObtained
        { get { return _leaseObtained; } }

        public DateTime LeaseExpires
        { get { return _leaseExpires; } }

        #endregion
    }
}
