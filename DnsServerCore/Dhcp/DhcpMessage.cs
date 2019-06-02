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
        Broadcast = 0x8000
    }

    class DhcpMessage
    {
        #region variables

        const uint MAGIC_COOKIE = 0x63825363;

        readonly DhcpMessageOpCode _op;
        readonly DhcpMessageHardwareAddressType _htype;
        readonly byte _hlen;
        readonly byte _hops;

        readonly uint _xid;

        readonly ushort _secs;
        readonly DhcpMessageFlags _flags;

        readonly IPAddress _ciaddr;
        readonly IPAddress _yiaddr;
        readonly IPAddress _siaddr;
        readonly IPAddress _giaddr;

        readonly byte[] _chaddr;
        readonly byte[] _sname;
        readonly byte[] _file;

        readonly List<DhcpOption> _options;

        #endregion

        #region constructor

        public DhcpMessage(DhcpMessageOpCode op, uint xid, ushort secs, DhcpMessageFlags flags, IPAddress ciaddr, IPAddress yiaddr, IPAddress siaddr, IPAddress giaddr, byte[] chaddr, List<DhcpOption> options)
        {
            if (ciaddr.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", "ciaddr");

            if (yiaddr.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", "yiaddr");

            if (siaddr.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", "siaddr");

            if (giaddr.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", "giaddr");

            if (chaddr == null)
            {
                chaddr = new byte[16];
            }
            else
            {
                if (chaddr.Length > 16)
                    throw new ArgumentException("Value cannot be greater that 16 bytes.", "chaddr");

                if (chaddr.Length < 16)
                {
                    byte[] newchaddr = new byte[16];
                    Buffer.BlockCopy(chaddr, 0, newchaddr, 0, chaddr.Length);
                    chaddr = newchaddr;
                }
            }

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

            _chaddr = chaddr;
            _sname = new byte[64];
            _file = new byte[128];

            _options = options;
        }

        public DhcpMessage(Stream s)
        {
            byte[] buffer = new byte[4];

            s.ReadBytes(buffer, 0, 4);
            _op = (DhcpMessageOpCode)buffer[0];
            _htype = (DhcpMessageHardwareAddressType)buffer[1];
            _hlen = buffer[2];
            _hops = buffer[3];

            s.ReadBytes(buffer, 0, 4);
            _xid = BitConverter.ToUInt32(buffer, 0);

            s.ReadBytes(buffer, 0, 4);
            _secs = BitConverter.ToUInt16(buffer, 0);
            _flags = (DhcpMessageFlags)BitConverter.ToUInt16(buffer, 2);

            s.ReadBytes(buffer, 0, 4);
            _ciaddr = new IPAddress(buffer);

            s.ReadBytes(buffer, 0, 4);
            _yiaddr = new IPAddress(buffer);

            s.ReadBytes(buffer, 0, 4);
            _siaddr = new IPAddress(buffer);

            s.ReadBytes(buffer, 0, 4);
            _giaddr = new IPAddress(buffer);

            _chaddr = s.ReadBytes(16);
            _sname = s.ReadBytes(64);
            _file = s.ReadBytes(128);

            //read options
            _options = new List<DhcpOption>();

            s.ReadBytes(buffer, 0, 4);
            Array.Reverse(buffer);
            uint magicCookie = BitConverter.ToUInt32(buffer, 0);

            if (magicCookie == MAGIC_COOKIE)
            {
                while (true)
                {
                    DhcpOption option = DhcpOption.Parse(s);
                    if (option.Code == DhcpOptionCode.End)
                        break;

                    _options.Add(option);
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

            s.Write(BitConverter.GetBytes(_xid));

            s.Write(BitConverter.GetBytes(_secs));
            s.Write(BitConverter.GetBytes((ushort)_flags));

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

        public uint TransactionId
        { get { return _xid; } }

        public ushort SecondsElapsed
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
        { get { return _chaddr; } }

        public byte[] ServerHostName
        { get { return _sname; } }

        public byte[] BootFileName
        { get { return _file; } }

        public IReadOnlyList<DhcpOption> Options
        { get { return _options; } }

        #endregion
    }
}
