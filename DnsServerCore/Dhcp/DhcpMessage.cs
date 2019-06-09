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
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dhcp
{
    enum DhcpMessageOpCode : byte
    {
        BootRequest = 1,
        BootReply = 2
    }

    enum DhcpMessageHardwareAddressType : byte
    {
        Ethernet = 1
    }

    enum DhcpMessageFlags : ushort
    {
        None = 0,
        Broadcast = 0x8000
    }

    class DhcpMessage
    {
        #region variables

        const uint MAGIC_COOKIE = 0x63538263; //in reverse format

        readonly DhcpMessageOpCode _op;
        readonly DhcpMessageHardwareAddressType _htype;
        readonly byte _hlen;
        readonly byte _hops;

        readonly byte[] _xid;

        readonly byte[] _secs;
        readonly DhcpMessageFlags _flags;

        readonly IPAddress _ciaddr;
        readonly IPAddress _yiaddr;
        readonly IPAddress _siaddr;
        readonly IPAddress _giaddr;

        readonly byte[] _chaddr;
        readonly byte[] _sname;
        readonly byte[] _file;

        readonly IReadOnlyCollection<DhcpOption> _options;

        readonly byte[] _clientHardwareAddress;

        OptionOverloadOption _optionOverload;

        DhcpMessageTypeOption _dhcpMessageType;
        ClientIdentifierOption _clientIdentifier;
        HostNameOption _hostName;
        ClientFullyQualifiedDomainNameOption _clientFullyQualifiedDomainName;
        ParameterRequestListOption _parameterRequestList;
        MaximumDhcpMessageSizeOption _maximumDhcpMessageSize;
        ServerIdentifierOption _serverIdentifier;
        RequestedIpAddressOption _requestedIpAddress;

        #endregion

        #region constructor

        public DhcpMessage(DhcpMessageOpCode op, byte[] xid, byte[] secs, DhcpMessageFlags flags, IPAddress ciaddr, IPAddress yiaddr, IPAddress siaddr, IPAddress giaddr, byte[] clientHardwareAddress, IReadOnlyCollection<DhcpOption> options)
        {
            if (ciaddr.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", "ciaddr");

            if (yiaddr.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", "yiaddr");

            if (siaddr.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", "siaddr");

            if (giaddr.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", "giaddr");

            if ((clientHardwareAddress != null) && (clientHardwareAddress.Length != 6))
                throw new ArgumentException("Value must be 6 bytes long for a valid Ethernet hardware address.", "chaddr");

            if (xid.Length != 4)
                throw new ArgumentException("Transaction ID must be 4 bytes.", "xid");

            if (secs.Length != 2)
                throw new ArgumentException("Seconds elapsed must be 2 bytes.", "secs");

            _op = op;
            _htype = DhcpMessageHardwareAddressType.Ethernet;
            _hlen = 6;
            _hops = 0;

            _xid = xid;

            _secs = secs;
            _flags = flags;

            _ciaddr = ciaddr;
            _yiaddr = yiaddr;
            _siaddr = siaddr;
            _giaddr = giaddr;

            _clientHardwareAddress = clientHardwareAddress;
            _chaddr = new byte[16];
            Buffer.BlockCopy(_clientHardwareAddress, 0, _chaddr, 0, 6);

            _sname = new byte[64];
            _file = new byte[128];

            _options = options;
        }

        public DhcpMessage(DhcpMessage request, IPAddress yiaddr, IPAddress siaddr, IReadOnlyCollection<DhcpOption> options)
            : this(DhcpMessageOpCode.BootReply, request.TransactionId, request.SecondsElapsed, request.Flags, request.ClientIpAddress, yiaddr, siaddr, request.RelayAgentIpAddress, request.ClientHardwareAddress, options)
        { }

        public DhcpMessage(Stream s)
        {
            byte[] buffer = new byte[4];

            s.ReadBytes(buffer, 0, 4);
            _op = (DhcpMessageOpCode)buffer[0];
            _htype = (DhcpMessageHardwareAddressType)buffer[1];
            _hlen = buffer[2];
            _hops = buffer[3];

            _xid = s.ReadBytes(4);

            s.ReadBytes(buffer, 0, 4);
            _secs = new byte[2];
            Buffer.BlockCopy(buffer, 0, _secs, 0, 2);
            Array.Reverse(buffer);
            _flags = (DhcpMessageFlags)BitConverter.ToUInt16(buffer, 0);

            s.ReadBytes(buffer, 0, 4);
            _ciaddr = new IPAddress(buffer);

            s.ReadBytes(buffer, 0, 4);
            _yiaddr = new IPAddress(buffer);

            s.ReadBytes(buffer, 0, 4);
            _siaddr = new IPAddress(buffer);

            s.ReadBytes(buffer, 0, 4);
            _giaddr = new IPAddress(buffer);

            _chaddr = s.ReadBytes(16);
            _clientHardwareAddress = new byte[_hlen];
            Buffer.BlockCopy(_chaddr, 0, _clientHardwareAddress, 0, _hlen);

            _sname = s.ReadBytes(64);
            _file = s.ReadBytes(128);

            //read options
            List<DhcpOption> options = new List<DhcpOption>();
            _options = options;

            s.ReadBytes(buffer, 0, 4);
            uint magicCookie = BitConverter.ToUInt32(buffer, 0);

            if (magicCookie == MAGIC_COOKIE)
            {
                ParseOptions(s, options);

                if (_optionOverload != null)
                {
                    if (_optionOverload.Value.HasFlag(OptionOverloadValue.FileFieldUsed))
                    {
                        using (MemoryStream mS = new MemoryStream(_file))
                        {
                            ParseOptions(mS, options);
                        }
                    }

                    if (_optionOverload.Value.HasFlag(OptionOverloadValue.SnameFieldUsed))
                    {
                        using (MemoryStream mS = new MemoryStream(_sname))
                        {
                            ParseOptions(mS, options);
                        }
                    }
                }

                //parse all option values
                foreach (DhcpOption option in options)
                    option.ParseOptionValue();
            }

            if (_clientIdentifier == null)
                _clientIdentifier = new ClientIdentifierOption((byte)_htype, _clientHardwareAddress);

            if (_maximumDhcpMessageSize != null)
                _maximumDhcpMessageSize = new MaximumDhcpMessageSizeOption(576);
        }

        #endregion

        #region private

        private void ParseOptions(Stream s, List<DhcpOption> options)
        {
            while (true)
            {
                DhcpOption option = DhcpOption.Parse(s);
                if (option.Code == DhcpOptionCode.End)
                    break;

                if (option.Code == DhcpOptionCode.Pad)
                    continue;

                bool optionExists = false;

                foreach (DhcpOption existingOption in options)
                {
                    if (existingOption.Code == option.Code)
                    {
                        //option already exists so append current option value into existing option
                        existingOption.AppendOptionValue(option);
                        optionExists = true;
                        break;
                    }
                }

                if (optionExists)
                    continue;

                //add option to list
                options.Add(option);

                switch (option.Code)
                {
                    case DhcpOptionCode.DhcpMessageType:
                        _dhcpMessageType = option as DhcpMessageTypeOption;
                        break;

                    case DhcpOptionCode.ClientIdentifier:
                        _clientIdentifier = option as ClientIdentifierOption;
                        break;

                    case DhcpOptionCode.HostName:
                        _hostName = option as HostNameOption;
                        break;

                    case DhcpOptionCode.ClientFullyQualifiedDomainName:
                        _clientFullyQualifiedDomainName = option as ClientFullyQualifiedDomainNameOption;
                        break;

                    case DhcpOptionCode.ParameterRequestList:
                        _parameterRequestList = option as ParameterRequestListOption;
                        break;

                    case DhcpOptionCode.MaximumDhcpMessageSize:
                        _maximumDhcpMessageSize = option as MaximumDhcpMessageSizeOption;
                        break;

                    case DhcpOptionCode.ServerIdentifier:
                        _serverIdentifier = option as ServerIdentifierOption;
                        break;

                    case DhcpOptionCode.RequestedIpAddress:
                        _requestedIpAddress = option as RequestedIpAddressOption;
                        break;

                    case DhcpOptionCode.OptionOverload:
                        _optionOverload = option as OptionOverloadOption;
                        break;
                }
            }
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            s.WriteByte((byte)_op);
            s.WriteByte((byte)_htype);
            s.WriteByte(_hlen);
            s.WriteByte(_hops);

            s.Write(_xid);

            s.Write(_secs);
            byte[] buffer = BitConverter.GetBytes((ushort)_flags);
            Array.Reverse(buffer);
            s.Write(buffer);

            s.Write(_ciaddr.GetAddressBytes());
            s.Write(_yiaddr.GetAddressBytes());
            s.Write(_siaddr.GetAddressBytes());
            s.Write(_giaddr.GetAddressBytes());

            s.Write(_chaddr);
            s.Write(_sname);
            s.Write(_file);

            //write options
            s.Write(BitConverter.GetBytes(MAGIC_COOKIE));

            foreach (DhcpOption option in _options)
                option.WriteTo(s);
        }

        public string GetClientFullIdentifier()
        {
            string hardwareAddress = BitConverter.ToString(_clientHardwareAddress);

            if (_clientFullyQualifiedDomainName != null)
                return _clientFullyQualifiedDomainName.DomainName + " [" + hardwareAddress + "]";

            if (_hostName != null)
                return _hostName.HostName + " [" + hardwareAddress + "]";

            return "[" + hardwareAddress + "]";
        }

        #endregion

        #region properties

        public DhcpMessageOpCode OpCode
        { get { return _op; } }

        public DhcpMessageHardwareAddressType HardwareAddressType
        { get { return _htype; } }

        public byte HardwareAddressLength
        { get { return _hlen; } }

        public byte Hops
        { get { return _hops; } }

        public byte[] TransactionId
        { get { return _xid; } }

        public byte[] SecondsElapsed
        { get { return _secs; } }

        public DhcpMessageFlags Flags
        { get { return _flags; } }

        public IPAddress ClientIpAddress
        { get { return _ciaddr; } }

        public IPAddress YourClientIpAddress
        { get { return _yiaddr; } }

        public IPAddress NextServerIpAddress
        { get { return _siaddr; } }

        public IPAddress RelayAgentIpAddress
        { get { return _giaddr; } }

        public byte[] ClientHardwareAddress
        { get { return _clientHardwareAddress; } }

        public byte[] ServerHostName
        { get { return _sname; } }

        public byte[] BootFileName
        { get { return _file; } }

        public IReadOnlyCollection<DhcpOption> Options
        { get { return _options; } }

        public DhcpMessageTypeOption DhcpMessageType
        { get { return _dhcpMessageType; } }

        public ClientIdentifierOption ClientIdentifier
        { get { return _clientIdentifier; } }

        public HostNameOption HostName
        { get { return _hostName; } }

        public ClientFullyQualifiedDomainNameOption ClientFullyQualifiedDomainName
        { get { return _clientFullyQualifiedDomainName; } }

        public ParameterRequestListOption ParameterRequestList
        { get { return _parameterRequestList; } }

        public MaximumDhcpMessageSizeOption MaximumDhcpMessageSize
        { get { return _maximumDhcpMessageSize; } }

        public ServerIdentifierOption ServerIdentifier
        { get { return _serverIdentifier; } }

        public RequestedIpAddressOption RequestedIpAddress
        { get { return _requestedIpAddress; } }

        #endregion
    }
}
