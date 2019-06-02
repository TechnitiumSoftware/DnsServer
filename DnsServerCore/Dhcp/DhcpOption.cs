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
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dhcp
{
    enum DhcpOptionCode : byte
    {
        Pad = 0,
        SubnetMask = 1,
        TimeOffset = 2,
        Router = 3,
        TimeServer = 4,
        NameServer = 5,
        DomainNameServer = 6,
        LogServer = 7,
        CookieServer = 8,
        LprServer = 9,
        ImpressServer = 10,
        ResourceLocationServer = 11,
        HostName = 12,
        BootFileSize = 13,
        MeritDump = 14,
        DomainName = 15,
        SwapServer = 16,
        RootPath = 17,
        ExtensionPath = 18,
        IpForwarding = 19,
        NonLocalSourceRouting = 20,
        PolicyFilter = 21,
        MaximumDatagramReassemblySize = 22,
        DefaultIpTtl = 23,
        PathMtuAgingTimeout = 24,
        PathMtuPlateauTable = 25,
        InterfaceMtu = 26,
        AllSubnetAreLocal = 27,
        BroadcastAddress = 28,
        PerformMaskDiscovery = 29,
        MaskSupplier = 30,
        PerformRouterDiscovery = 31,
        RouterSolicitationAddress = 32,
        StaticRoute = 33,
        TrailerEncapsulation = 34,
        ArpCacheTimeout = 35,
        EthernetEncapsulation = 36,
        TcpDefaultTtl = 37,
        TcpKeepAliveInterval = 38,
        TcpKeepAliveGarbage = 39,
        NetworkInformationServiceDomain = 40,
        NetworkInformationServers = 41,
        NetworkTimeProtocolServers = 42,
        VendorSpecificInformation = 43,
        NetBiosOverTcpIpNameServer = 44,
        NetBiosOverTcpIpDatagramDistributionServer = 45,
        NetBiosOverTcpIpNodeType = 46,
        NetBiosOverTcpIpScope = 47,
        XWindowSystemFontServer = 48,
        XWindowSystemDisplayManager = 49,
        RequestedIpAddress = 50,
        IpAddressLeaseTime = 51,
        OptionOverload = 52,
        DhcpMessageType = 53,
        ServerIdentifier = 54,
        ParameterRequestList = 55,
        Message = 56,
        MaximumDhcpMessageSize = 57,
        RenewalTimeValue = 58,
        RebindingTimeValue = 59,
        VendorClassIdentifier = 60,
        ClientIdentifier = 61,
        NetworkInformationServicePlusDomain = 64,
        NetworkInformationServicePlusServers = 65,
        TftpServerName = 66,
        BootfileName = 67,
        MobileIpHomeAgent = 68,
        SmtpServer = 69,
        Pop3Server = 70,
        NntpServer = 71,
        DefaultWwwServer = 72,
        DefaultFingerServer = 73,
        DefaultIrc = 74,
        StreetTalkServer = 75,
        StreetTalkDirectoryAssistance = 76,
        End = 255
    }

    class DhcpOption
    {
        #region variables

        readonly DhcpOptionCode _code;
        readonly byte[] _value;

        #endregion

        #region constructor

        protected DhcpOption(DhcpOptionCode type)
        {
            _code = type;
        }

        private DhcpOption(DhcpOptionCode type, byte[] value)
        {
            _code = type;
            _value = value;
        }

        #endregion

        #region static

        public static DhcpOption CreateEndOption()
        {
            return new DhcpOption(DhcpOptionCode.End);
        }

        public static DhcpOption Parse(Stream s)
        {
            int code = s.ReadByte();
            if (code < 0)
                throw new EndOfStreamException();

            DhcpOptionCode optionCode = (DhcpOptionCode)code;

            switch (optionCode)
            {
                case DhcpOptionCode.SubnetMask:
                    return new SubnetMaskOption(s);

                case DhcpOptionCode.Router:
                    return new RouterOption(s);

                case DhcpOptionCode.DomainNameServer:
                    return new DomainNameServerOption(s);

                case DhcpOptionCode.HostName:
                    return new HostNameOption(s);

                case DhcpOptionCode.DomainName:
                    return new DomainNameOption(s);

                case DhcpOptionCode.BroadcastAddress:
                    return new BroadcastAddressOption(s);

                case DhcpOptionCode.StaticRoute:
                    return new StaticRouteOption(s);

                case DhcpOptionCode.NetBiosOverTcpIpNameServer:
                    return new NetBiosNameServerOption(s);

                case DhcpOptionCode.RequestedIpAddress:
                    return new RequestedIpAddressOption(s);

                case DhcpOptionCode.IpAddressLeaseTime:
                    return new IpAddressLeaseTimeOption(s);

                case DhcpOptionCode.OptionOverload:
                    return new OptionOverloadOption(s);

                case DhcpOptionCode.DhcpMessageType:
                    return new DhcpMessageTypeOption(s);

                case DhcpOptionCode.ServerIdentifier:
                    return new ServerIdentifierOption(s);

                case DhcpOptionCode.ParameterRequestList:
                    return new ParameterRequestListOption(s);

                case DhcpOptionCode.Message:
                    return new MessageOption(s);

                case DhcpOptionCode.MaximumDhcpMessageSize:
                    return new MaximumDhcpMessageSizeOption(s);

                case DhcpOptionCode.RenewalTimeValue:
                    return new RenewalTimeValueOption(s);

                case DhcpOptionCode.RebindingTimeValue:
                    return new RebindingTimeValueOption(s);

                case DhcpOptionCode.ClientIdentifier:
                    return new ClientIdentifierOption(s);

                case DhcpOptionCode.Pad:
                case DhcpOptionCode.End:
                    return new DhcpOption(optionCode, null);

                default:
                    //unknown option
                    int len = s.ReadByte();
                    if (len < 0)
                        throw new EndOfStreamException();

                    return new DhcpOption(optionCode, s.ReadBytes(len));
            }
        }

        #endregion

        #region protected

        protected virtual void WriteOptionTo(Stream s)
        {
            if (_value == null)
                throw new NotImplementedException();

            s.WriteByte(Convert.ToByte(_value.Length));
            s.Write(_value);
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            s.WriteByte((byte)_code);

            switch (_code)
            {
                case DhcpOptionCode.Pad:
                case DhcpOptionCode.End:
                    break;

                default:
                    WriteOptionTo(s);
                    break;
            }
        }

        #endregion

        #region properties

        public DhcpOptionCode Code
        { get { return _code; } }

        #endregion
    }
}
