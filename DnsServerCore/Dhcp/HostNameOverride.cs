/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.IO;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dhcp
{
    public class HostNameOverride
    {
        #region variables

        readonly ClientIdentifierOption _clientIdentifier;
        string _hostName;
        readonly byte[] _hardwareAddress;
        string _comments;

        #endregion

        #region constructor

        internal HostNameOverride(string hostName, DhcpMessageHardwareAddressType hardwareAddressType, byte[] hardwareAddress, string comments)
        {
            _clientIdentifier = new ClientIdentifierOption((byte)hardwareAddressType, hardwareAddress);
            _hostName = hostName;
            _hardwareAddress = hardwareAddress;
            _comments = comments;
        }

        internal HostNameOverride(string hostName, DhcpMessageHardwareAddressType hardwareAddressType, string hardwareAddress, string comments)
            : this(hostName, hardwareAddressType, Lease.ParseHardwareAddress(hardwareAddress), comments)
        { }

        internal HostNameOverride(BinaryReader bR)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    _clientIdentifier = DhcpOption.Parse(bR.BaseStream) as ClientIdentifierOption;
                    _clientIdentifier.ParseOptionValue();

                    _hostName = bR.BaseStream.ReadShortString();
                    if (string.IsNullOrWhiteSpace(_hostName))
                        _hostName = null;

                    _hardwareAddress = bR.ReadBuffer();

                    _comments = bR.BaseStream.ReadShortString();
                    if (string.IsNullOrWhiteSpace(_comments))
                        _comments = null;

                    break;

                default:
                    throw new InvalidDataException("HostNameOverride data format version not supported.");
            }
        }

        #endregion

        #region public

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version

            _clientIdentifier.WriteTo(bW.BaseStream);

            if (string.IsNullOrWhiteSpace(_hostName))
                bW.Write((byte)0);
            else
                bW.BaseStream.WriteShortString(_hostName);

            bW.WriteBuffer(_hardwareAddress);

            if (string.IsNullOrWhiteSpace(_comments))
                bW.Write((byte)0);
            else
                bW.BaseStream.WriteShortString(_comments);
        }

        #endregion

        #region properties

        internal ClientIdentifierOption ClientIdentifier
        { get { return _clientIdentifier; } }

        public string HostName
        { get { return _hostName; } }

        public byte[] HardwareAddress
        { get { return _hardwareAddress; } }

        public string Comments
        {
            get { return _comments; }
            set { _comments = value; }
        }

        #endregion
    }
}
