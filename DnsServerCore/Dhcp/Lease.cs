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
using System.Globalization;
using System.IO;
using System.Net;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;

namespace DnsServerCore.Dhcp
{
    public class Lease : IComparable<Lease>
    {
        #region variables

        readonly ClientIdentifierOption _clientIdentifier;
        string _hostName;
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

        internal Lease(string hardwareAddress, IPAddress address)
            : this(ParseHardwareAddress(hardwareAddress), address, 0)
        { }

        internal Lease(BinaryReader bR)
        {
            switch (bR.ReadByte())
            {
                case 1:
                    _clientIdentifier = DhcpOption.Parse(bR.BaseStream) as ClientIdentifierOption;
                    _clientIdentifier.ParseOptionValue();

                    _hostName = bR.ReadShortString();
                    if (_hostName == "")
                        _hostName = null;

                    _hardwareAddress = bR.ReadBuffer();
                    _address = IPAddressExtension.Parse(bR);
                    _leaseObtained = bR.ReadDate();
                    _leaseExpires = bR.ReadDate();
                    break;

                default:
                    throw new InvalidDataException("Lease data format version not supported.");
            }
        }

        #endregion

        #region private

        private static byte[] ParseHardwareAddress(string hardwareAddress)
        {
            string[] parts = hardwareAddress.Split(new char[] { '-', ':' });
            byte[] address = new byte[parts.Length];

            for (int i = 0; i < parts.Length; i++)
                address[i] = byte.Parse(parts[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture);

            return address;
        }

        internal void SetHostName(string hostName)
        {
            _hostName = hostName;
        }

        #endregion

        #region public

        public void ResetLeaseTime(uint leaseTime)
        {
            _leaseObtained = DateTime.UtcNow;
            _leaseExpires = DateTime.UtcNow.AddSeconds(leaseTime);
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version

            _clientIdentifier.WriteTo(bW.BaseStream);

            if (string.IsNullOrEmpty(_hostName))
                bW.Write((byte)0);
            else
                bW.WriteShortString(_hostName);

            bW.WriteBuffer(_hardwareAddress);
            _address.WriteTo(bW);
            bW.Write(_leaseObtained);
            bW.Write(_leaseExpires);
        }

        public string GetClientFullIdentifier()
        {
            string hardwareAddress = BitConverter.ToString(_hardwareAddress);

            if (string.IsNullOrEmpty(_hostName))
                return "[" + hardwareAddress + "]";

            return _hostName + " [" + hardwareAddress + "]";
        }

        public int CompareTo(Lease other)
        {
            return _address.ConvertIpToNumber().CompareTo(other._address.ConvertIpToNumber());
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
