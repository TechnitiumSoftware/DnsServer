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

using DnsServerCore.Dhcp.Options;
using System;
using System.Globalization;
using System.IO;
using System.Net;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;

namespace DnsServerCore.Dhcp
{
    public enum LeaseType : byte
    {
        None = 0,
        Dynamic = 1,
        Reserved = 2
    }

    public class Lease : IComparable<Lease>
    {
        #region variables

        static readonly char[] _hyphenColonSeparator = new char[] { '-', ':' };

        LeaseType _type;
        readonly ClientIdentifierOption _clientIdentifier;
        string _hostName;
        readonly byte[] _hardwareAddress;
        readonly IPAddress _address;
        string _comments;
        readonly DateTime _leaseObtained;
        DateTime _leaseExpires;

        #endregion

        #region constructor

        internal Lease(LeaseType type, ClientIdentifierOption clientIdentifier, string hostName, byte[] hardwareAddress, IPAddress address, string comments, uint leaseTime)
        {
            _type = type;
            _clientIdentifier = clientIdentifier;
            _hostName = hostName;
            _hardwareAddress = hardwareAddress;
            _address = address;
            _comments = comments;
            _leaseObtained = DateTime.UtcNow;

            ExtendLease(leaseTime);
        }

        internal Lease(LeaseType type, string hostName, DhcpMessageHardwareAddressType hardwareAddressType, byte[] hardwareAddress, IPAddress address, string comments)
            : this(type, new ClientIdentifierOption((byte)hardwareAddressType, hardwareAddress), hostName, hardwareAddress, address, comments, 0)
        { }

        internal Lease(LeaseType type, string hostName, DhcpMessageHardwareAddressType hardwareAddressType, string hardwareAddress, IPAddress address, string comments)
            : this(type, hostName, hardwareAddressType, ParseHardwareAddress(hardwareAddress), address, comments)
        { }

        internal Lease(BinaryReader bR)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                    _type = (LeaseType)bR.ReadByte();
                    _clientIdentifier = DhcpOption.Parse(bR.BaseStream) as ClientIdentifierOption;
                    _clientIdentifier.ParseOptionValue();

                    _hostName = bR.ReadShortString();
                    if (string.IsNullOrWhiteSpace(_hostName))
                        _hostName = null;

                    _hardwareAddress = bR.ReadBuffer();
                    _address = IPAddressExtensions.ReadFrom(bR);

                    if (version >= 2)
                    {
                        _comments = bR.ReadShortString();
                        if (string.IsNullOrWhiteSpace(_comments))
                            _comments = null;
                    }

                    _leaseObtained = bR.ReadDateTime();
                    _leaseExpires = bR.ReadDateTime();
                    break;

                default:
                    throw new InvalidDataException("Lease data format version not supported.");
            }
        }

        #endregion

        #region internal

        internal static byte[] ParseHardwareAddress(string hardwareAddress)
        {
            string[] parts = hardwareAddress.Split(_hyphenColonSeparator);
            byte[] address = new byte[parts.Length];

            for (int i = 0; i < parts.Length; i++)
                address[i] = byte.Parse(parts[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture);

            return address;
        }

        internal void ConvertToReserved()
        {
            _type = LeaseType.Reserved;
        }

        internal void ConvertToDynamic()
        {
            _type = LeaseType.Dynamic;
        }

        internal void SetHostName(string hostName)
        {
            _hostName = hostName;
        }

        #endregion

        #region public

        public void ExtendLease(uint leaseTime)
        {
            _leaseExpires = DateTime.UtcNow.AddSeconds(leaseTime);
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)2); //version

            bW.Write((byte)_type);
            _clientIdentifier.WriteTo(bW.BaseStream);

            if (string.IsNullOrWhiteSpace(_hostName))
                bW.Write((byte)0);
            else
                bW.WriteShortString(_hostName);

            bW.WriteBuffer(_hardwareAddress);
            _address.WriteTo(bW);

            if (string.IsNullOrWhiteSpace(_comments))
                bW.Write((byte)0);
            else
                bW.WriteShortString(_comments);

            bW.Write(_leaseObtained);
            bW.Write(_leaseExpires);
        }

        public string GetClientInfo()
        {
            string hardwareAddress = BitConverter.ToString(_hardwareAddress);

            if (string.IsNullOrWhiteSpace(_hostName))
                return "[" + hardwareAddress + "]";

            return _hostName + " [" + hardwareAddress + "]";
        }

        public int CompareTo(Lease other)
        {
            return _address.ConvertIpToNumber().CompareTo(other._address.ConvertIpToNumber());
        }

        #endregion

        #region properties

        public LeaseType Type
        { get { return _type; } }

        internal ClientIdentifierOption ClientIdentifier
        { get { return _clientIdentifier; } }

        public string HostName
        { get { return _hostName; } }

        public byte[] HardwareAddress
        { get { return _hardwareAddress; } }

        public IPAddress Address
        { get { return _address; } }

        public string Comments
        {
            get { return _comments; }
            set { _comments = value; }
        }

        public DateTime LeaseObtained
        { get { return _leaseObtained; } }

        public DateTime LeaseExpires
        { get { return _leaseExpires; } }

        #endregion
    }
}
