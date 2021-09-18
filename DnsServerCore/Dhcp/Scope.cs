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

using DnsServerCore.Dhcp.Options;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dhcp
{
    public sealed class Scope : IComparable<Scope>, IDisposable
    {
        #region variables

        //required parameters
        string _name;
        bool _enabled;
        IPAddress _startingAddress;
        IPAddress _endingAddress;
        IPAddress _subnetMask;
        ushort _leaseTimeDays = 1; //default 1 day lease
        byte _leaseTimeHours = 0;
        byte _leaseTimeMinutes = 0;
        ushort _offerDelayTime;

        bool _pingCheckEnabled;
        ushort _pingCheckTimeout = 1000;
        byte _pingCheckRetries = 2;

        //dhcp options
        string _domainName;
        uint _dnsTtl = 900;
        IPAddress _serverAddress;
        string _serverHostName;
        string _bootFileName;
        IPAddress _routerAddress;
        bool _useThisDnsServer;
        IReadOnlyCollection<IPAddress> _dnsServers;
        IReadOnlyCollection<IPAddress> _winsServers;
        IReadOnlyCollection<IPAddress> _ntpServers;
        IReadOnlyCollection<ClasslessStaticRouteOption.Route> _staticRoutes;
        IReadOnlyDictionary<string, VendorSpecificInformationOption> _vendorInfo;

        //advanced options
        IReadOnlyCollection<Exclusion> _exclusions;
        readonly ConcurrentDictionary<ClientIdentifierOption, Lease> _reservedLeases = new ConcurrentDictionary<ClientIdentifierOption, Lease>();
        bool _allowOnlyReservedLeases;

        //leases
        readonly ConcurrentDictionary<ClientIdentifierOption, Lease> _leases = new ConcurrentDictionary<ClientIdentifierOption, Lease>();

        //internal computed parameters
        IPAddress _networkAddress;
        IPAddress _broadcastAddress;

        //internal parameters
        const int OFFER_EXPIRY_SECONDS = 60; //1 mins offer expiry
        readonly ConcurrentDictionary<ClientIdentifierOption, Lease> _offers = new ConcurrentDictionary<ClientIdentifierOption, Lease>();
        IPAddress _lastAddressOffered;
        readonly SemaphoreSlim _lastAddressOfferedLock = new SemaphoreSlim(1, 1);
        IPAddress _interfaceAddress;
        int _interfaceIndex;
        DateTime _lastModified = DateTime.UtcNow;

        #endregion

        #region constructor

        public Scope(string name, bool enabled, IPAddress startingAddress, IPAddress endingAddress, IPAddress subnetMask)
        {
            _name = name;
            _enabled = enabled;

            ChangeNetwork(startingAddress, endingAddress, subnetMask);
        }

        public Scope(BinaryReader bR)
        {
            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "SC")
                throw new InvalidDataException("DhcpServer scope file format is invalid.");

            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                    _name = bR.ReadShortString();
                    _enabled = bR.ReadBoolean();

                    ChangeNetwork(IPAddressExtension.Parse(bR), IPAddressExtension.Parse(bR), IPAddressExtension.Parse(bR));

                    _leaseTimeDays = bR.ReadUInt16();
                    _leaseTimeHours = bR.ReadByte();
                    _leaseTimeMinutes = bR.ReadByte();

                    _offerDelayTime = bR.ReadUInt16();

                    if (version >= 5)
                    {
                        _pingCheckEnabled = bR.ReadBoolean();
                        _pingCheckTimeout = bR.ReadUInt16();
                        _pingCheckRetries = bR.ReadByte();
                    }

                    _domainName = bR.ReadShortString();
                    if (string.IsNullOrWhiteSpace(_domainName))
                        _domainName = null;

                    _dnsTtl = bR.ReadUInt32();

                    if (version >= 2)
                    {
                        _serverAddress = IPAddressExtension.Parse(bR);
                        if (_serverAddress.Equals(IPAddress.Any))
                            _serverAddress = null;
                    }

                    if (version >= 3)
                    {
                        _serverHostName = bR.ReadShortString();
                        if (string.IsNullOrEmpty(_serverHostName))
                            _serverHostName = null;

                        _bootFileName = bR.ReadShortString();
                        if (string.IsNullOrEmpty(_bootFileName))
                            _bootFileName = null;
                    }

                    _routerAddress = IPAddressExtension.Parse(bR);
                    if (_routerAddress.Equals(IPAddress.Any))
                        _routerAddress = null;

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            if (count == 255)
                            {
                                _useThisDnsServer = true;
                                FindThisDnsServerAddress();
                            }
                            else
                            {
                                IPAddress[] dnsServers = new IPAddress[count];

                                for (int i = 0; i < count; i++)
                                    dnsServers[i] = IPAddressExtension.Parse(bR);

                                _dnsServers = dnsServers;
                            }
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            IPAddress[] winsServers = new IPAddress[count];

                            for (int i = 0; i < count; i++)
                                winsServers[i] = IPAddressExtension.Parse(bR);

                            _winsServers = winsServers;
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            IPAddress[] ntpServers = new IPAddress[count];

                            for (int i = 0; i < count; i++)
                                ntpServers[i] = IPAddressExtension.Parse(bR);

                            _ntpServers = ntpServers;
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            ClasslessStaticRouteOption.Route[] staticRoutes = new ClasslessStaticRouteOption.Route[count];

                            for (int i = 0; i < count; i++)
                                staticRoutes[i] = new ClasslessStaticRouteOption.Route(bR.BaseStream);

                            _staticRoutes = staticRoutes;
                        }
                    }

                    if (version >= 4)
                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            Dictionary<string, VendorSpecificInformationOption> vendorInfo = new Dictionary<string, VendorSpecificInformationOption>(count);

                            for (int i = 0; i < count; i++)
                            {
                                string vendorClassIdentifier = bR.ReadShortString();
                                VendorSpecificInformationOption vendorSpecificInformation = new VendorSpecificInformationOption(bR.ReadBuffer());

                                vendorInfo.Add(vendorClassIdentifier, vendorSpecificInformation);
                            }

                            _vendorInfo = vendorInfo;
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            Exclusion[] exclusions = new Exclusion[count];

                            for (int i = 0; i < count; i++)
                                exclusions[i] = new Exclusion(IPAddressExtension.Parse(bR), IPAddressExtension.Parse(bR));

                            _exclusions = exclusions;
                        }
                    }

                    {
                        int count = bR.ReadInt32();
                        if (count > 0)
                        {
                            for (int i = 0; i < count; i++)
                            {
                                Lease reservedLease = new Lease(bR);
                                _reservedLeases.TryAdd(reservedLease.ClientIdentifier, reservedLease);
                            }
                        }

                        _allowOnlyReservedLeases = bR.ReadBoolean();
                    }

                    {
                        int count = bR.ReadInt32();
                        if (count > 0)
                        {
                            for (int i = 0; i < count; i++)
                            {
                                Lease lease = new Lease(bR);

                                _leases.TryAdd(lease.ClientIdentifier, lease);
                            }
                        }
                    }

                    break;

                default:
                    throw new InvalidDataException("Scope data format version not supported.");
            }
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            if (_lastAddressOfferedLock is not null)
                _lastAddressOfferedLock.Dispose();

            _disposed = true;
        }

        #endregion

        #region static

        public static bool IsAddressInRange(IPAddress address, IPAddress startingAddress, IPAddress endingAddress)
        {
            uint addressNumber = address.ConvertIpToNumber();
            uint startingAddressNumber = startingAddress.ConvertIpToNumber();
            uint endingAddressNumber = endingAddress.ConvertIpToNumber();

            return (startingAddressNumber <= addressNumber) && (addressNumber <= endingAddressNumber);
        }

        #endregion

        #region private

        private uint GetLeaseTime()
        {
            return Convert.ToUInt32((_leaseTimeDays * 24 * 60 * 60) + (_leaseTimeHours * 60 * 60) + (_leaseTimeMinutes * 60));
        }

        private async Task<AddressStatus> IsAddressAvailableAsync(IPAddress address)
        {
            if (address.Equals(_routerAddress))
                return AddressStatus.FALSE;

            if ((_dnsServers != null) && _dnsServers.Contains(address))
                return AddressStatus.FALSE;

            if ((_winsServers != null) && _winsServers.Contains(address))
                return AddressStatus.FALSE;

            if ((_ntpServers != null) && _ntpServers.Contains(address))
                return AddressStatus.FALSE;

            if (_exclusions != null)
            {
                foreach (Exclusion exclusion in _exclusions)
                {
                    if (IsAddressInRange(address, exclusion.StartingAddress, exclusion.EndingAddress))
                        return new AddressStatus(false, exclusion.EndingAddress);
                }
            }

            foreach (KeyValuePair<ClientIdentifierOption, Lease> reservedLease in _reservedLeases)
            {
                if (address.Equals(reservedLease.Value.Address))
                    return AddressStatus.FALSE;
            }

            foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in _leases)
            {
                if (address.Equals(lease.Value.Address))
                    return AddressStatus.FALSE;
            }

            foreach (KeyValuePair<ClientIdentifierOption, Lease> offer in _offers)
            {
                if (address.Equals(offer.Value.Address))
                    return AddressStatus.FALSE;
            }

            if (_pingCheckEnabled)
            {
                try
                {
                    using (Ping ping = new Ping())
                    {
                        int retry = 0;
                        do
                        {
                            PingReply reply = await ping.SendPingAsync(address, _pingCheckTimeout);
                            if (reply.Status == IPStatus.Success)
                                return AddressStatus.FALSE; //address is in use
                        }
                        while (++retry < _pingCheckRetries);
                    }
                }
                catch
                { }
            }

            return AddressStatus.TRUE;
        }

        private bool IsAddressAlreadyAllocated(Lease reservedLease)
        {
            foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in _leases)
            {
                if (reservedLease.Address.Equals(lease.Value.Address))
                    return !lease.Key.Equals(reservedLease.ClientIdentifier);
            }

            foreach (KeyValuePair<ClientIdentifierOption, Lease> offer in _offers)
            {
                if (reservedLease.Address.Equals(offer.Value.Address))
                    return !offer.Key.Equals(reservedLease.ClientIdentifier);
            }

            return false;
        }

        private ClientFullyQualifiedDomainNameOption GetClientFullyQualifiedDomainNameOption(DhcpMessage request, string overrideClientDomainName)
        {
            ClientFullyQualifiedDomainNameFlags responseFlags = ClientFullyQualifiedDomainNameFlags.None;

            if (request.ClientFullyQualifiedDomainName.Flags.HasFlag(ClientFullyQualifiedDomainNameFlags.EncodeUsingCanonicalWireFormat))
                responseFlags |= ClientFullyQualifiedDomainNameFlags.EncodeUsingCanonicalWireFormat;

            if (request.ClientFullyQualifiedDomainName.Flags.HasFlag(ClientFullyQualifiedDomainNameFlags.NoDnsUpdate))
            {
                responseFlags |= ClientFullyQualifiedDomainNameFlags.ShouldUpdateDns;
                responseFlags |= ClientFullyQualifiedDomainNameFlags.OverrideByServer;
            }
            else if (request.ClientFullyQualifiedDomainName.Flags.HasFlag(ClientFullyQualifiedDomainNameFlags.ShouldUpdateDns))
            {
                responseFlags |= ClientFullyQualifiedDomainNameFlags.ShouldUpdateDns;
            }
            else
            {
                responseFlags |= ClientFullyQualifiedDomainNameFlags.ShouldUpdateDns;
                responseFlags |= ClientFullyQualifiedDomainNameFlags.OverrideByServer;
            }

            string clientDomainName;

            if (!string.IsNullOrWhiteSpace(overrideClientDomainName))
            {
                //domain name override by server
                clientDomainName = overrideClientDomainName;
            }
            else if (string.IsNullOrWhiteSpace(request.ClientFullyQualifiedDomainName.DomainName))
            {
                //client domain empty and expects server for a fqdn domain name
                if (request.HostName == null)
                    return null; //server unable to decide a name for client

                clientDomainName = request.HostName.HostName + "." + _domainName;
            }
            else if (request.ClientFullyQualifiedDomainName.DomainName.Contains("."))
            {
                //client domain is fqdn
                if (request.ClientFullyQualifiedDomainName.DomainName.EndsWith("." + _domainName, StringComparison.OrdinalIgnoreCase))
                {
                    clientDomainName = request.ClientFullyQualifiedDomainName.DomainName;
                }
                else
                {
                    string[] parts = request.ClientFullyQualifiedDomainName.DomainName.Split('.');
                    clientDomainName = parts[0] + "." + _domainName;
                }
            }
            else
            {
                //client domain is just hostname
                clientDomainName = request.ClientFullyQualifiedDomainName.DomainName + "." + _domainName;
            }

            return new ClientFullyQualifiedDomainNameOption(responseFlags, 255, 255, clientDomainName);
        }

        #endregion

        #region internal

        internal bool FindInterface()
        {
            //find network with static ip address in scope range
            uint networkAddressNumber = _networkAddress.ConvertIpToNumber();
            uint subnetMaskNumber = _subnetMask.ConvertIpToNumber();

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                IPInterfaceProperties ipInterface = nic.GetIPProperties();

                foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        uint addressNumber = ip.Address.ConvertIpToNumber();

                        if ((addressNumber & subnetMaskNumber) == networkAddressNumber)
                        {
                            //found interface for this scope range

                            //check if interface has dynamic ipv4 address assigned via dhcp
                            foreach (IPAddress dhcpServerAddress in ipInterface.DhcpServerAddresses)
                            {
                                if (dhcpServerAddress.AddressFamily == AddressFamily.InterNetwork)
                                    throw new DhcpServerException("DHCP Server requires static IP address to work correctly but the network interface was found to have a dynamic IP address [" + ip.Address.ToString() + "] assigned by another DHCP server: " + dhcpServerAddress.ToString());
                            }

                            _interfaceAddress = ip.Address;
                            _interfaceIndex = ipInterface.GetIPv4Properties().Index;
                            return true;
                        }
                    }
                }
            }

            //check if at least one interface has static ip address
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                IPInterfaceProperties ipInterface = nic.GetIPProperties();

                foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        //check if address is static
                        if (ipInterface.DhcpServerAddresses.Count < 1)
                        {
                            //found static ip address so this scope can be activated
                            //using ANY ip address for this scope interface since we dont know the relay agent network 
                            _interfaceAddress = IPAddress.Any;
                            _interfaceIndex = -1;
                            return true;
                        }
                    }
                }
            }

            //server has no static ip address configured
            return false;
        }

        internal void FindThisDnsServerAddress()
        {
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            //find interface in current scope network range
            uint networkAddressNumber = _networkAddress.ConvertIpToNumber();
            uint subnetMaskNumber = _subnetMask.ConvertIpToNumber();

            foreach (NetworkInterface nic in networkInterfaces)
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                IPInterfaceProperties ipInterface = nic.GetIPProperties();

                foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        uint addressNumber = ip.Address.ConvertIpToNumber();

                        if ((addressNumber & subnetMaskNumber) == networkAddressNumber)
                        {
                            //found address in this scope range to use as dns server
                            _dnsServers = new IPAddress[] { ip.Address };
                            return;
                        }
                    }
                }
            }

            //find unicast ip address on an interface which has gateway
            foreach (NetworkInterface nic in networkInterfaces)
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                IPInterfaceProperties ipInterface = nic.GetIPProperties();

                if (ipInterface.GatewayAddresses.Count > 0)
                {
                    foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            //use this address for dns
                            _dnsServers = new IPAddress[] { ip.Address };
                            return;
                        }
                    }
                }
            }

            //find any unicast ip address available
            foreach (NetworkInterface nic in networkInterfaces)
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                IPInterfaceProperties ipInterface = nic.GetIPProperties();

                foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        //use this address for dns
                        _dnsServers = new IPAddress[] { ip.Address };
                        return;
                    }
                }
            }

            //no useable address was found
            _dnsServers = null;
        }

        internal bool IsAddressInRange(IPAddress address)
        {
            return IsAddressInRange(address, _startingAddress, _endingAddress);
        }

        internal bool IsAddressInNetwork(IPAddress address)
        {
            uint addressNumber = address.ConvertIpToNumber();
            uint networkAddressNumber = _networkAddress.ConvertIpToNumber();
            uint broadcastAddressNumber = _broadcastAddress.ConvertIpToNumber();

            return (networkAddressNumber < addressNumber) && (addressNumber < broadcastAddressNumber);
        }

        internal bool IsAddressExcluded(IPAddress address)
        {
            if (_exclusions != null)
            {
                foreach (Exclusion exclusion in _exclusions)
                {
                    if (IsAddressInRange(address, exclusion.StartingAddress, exclusion.EndingAddress))
                        return true;
                }
            }

            return false;
        }

        internal bool IsAddressReserved(IPAddress address)
        {
            foreach (KeyValuePair<ClientIdentifierOption, Lease> reservedLease in _reservedLeases)
            {
                if (address.Equals(reservedLease.Value.Address))
                    return true;
            }

            return false;
        }

        internal Lease GetReservedLease(DhcpMessage request)
        {
            return GetReservedLease(new ClientIdentifierOption((byte)request.HardwareAddressType, request.ClientHardwareAddress));
        }

        internal Lease GetReservedLease(DhcpMessageHardwareAddressType hardwareAddressType, byte[] identifier)
        {
            return GetReservedLease(new ClientIdentifierOption((byte)hardwareAddressType, identifier));
        }

        private Lease GetReservedLease(ClientIdentifierOption clientIdentifier)
        {
            if (_reservedLeases.TryGetValue(clientIdentifier, out Lease reservedLease))
            {
                //reserved address exists
                if (IsAddressAlreadyAllocated(reservedLease))
                    return null; //reserved lease address is already allocated so ignore reserved lease

                return reservedLease;
            }

            return null;
        }

        internal async Task<Lease> GetOfferAsync(DhcpMessage request)
        {
            if (_leases.TryGetValue(request.ClientIdentifier, out Lease existingLease))
            {
                //lease already exists
                if ((existingLease.Type == LeaseType.Reserved) || !IsAddressExcluded(existingLease.Address))
                    return existingLease; //existing lease is reserved or dynamic allocation is not excluded

                //remove existing dynamic lease
                ReleaseLease(existingLease);
            }

            Lease reservedLease = GetReservedLease(request);
            if (reservedLease != null)
            {
                Lease reservedOffer = new Lease(LeaseType.Reserved, request.ClientIdentifier, null, request.ClientHardwareAddress, reservedLease.Address, null, GetLeaseTime());
                _offers[request.ClientIdentifier] = reservedOffer;
                return reservedOffer;
            }

            if (_allowOnlyReservedLeases)
                throw new DhcpServerException("DHCP Server failed to offer IP address to " + request.GetClientFullIdentifier() + ": scope allows only reserved lease allocations.");

            Lease dummyOffer = new Lease(LeaseType.None, null, null, null, null, null, 0);
            Lease existingOffer = _offers.GetOrAdd(request.ClientIdentifier, dummyOffer);

            if (dummyOffer != existingOffer)
            {
                if (existingOffer.Type == LeaseType.None)
                    return null; //dummy offer so another thread is handling offer; do nothing

                //offer already exists
                existingOffer.ExtendLease(GetLeaseTime());

                return existingOffer;
            }

            //find offer ip address
            IPAddress offerAddress = null;

            if (request.RequestedIpAddress != null)
            {
                //client wish to get this address
                IPAddress requestedAddress = request.RequestedIpAddress.Address;

                if (IsAddressInRange(requestedAddress))
                {
                    AddressStatus addressStatus = await IsAddressAvailableAsync(requestedAddress);
                    if (addressStatus.IsAddressAvailable)
                        offerAddress = requestedAddress;
                }
            }

            if (offerAddress == null)
            {
                await _lastAddressOfferedLock.WaitAsync();
                try
                {
                    //find free address from scope
                    offerAddress = _lastAddressOffered;
                    uint endingAddressNumber = _endingAddress.ConvertIpToNumber();
                    bool offerAddressWasResetFromEnd = false;

                    while (true)
                    {
                        uint nextOfferAddressNumber = offerAddress.ConvertIpToNumber() + 1u;

                        if (nextOfferAddressNumber > endingAddressNumber)
                        {
                            if (offerAddressWasResetFromEnd)
                                throw new DhcpServerException("DHCP Server failed to offer IP address to " + request.GetClientFullIdentifier() + ": address unavailable due to address pool exhaustion.");

                            offerAddress = IPAddressExtension.ConvertNumberToIp(_startingAddress.ConvertIpToNumber() - 1u);
                            offerAddressWasResetFromEnd = true;
                            continue;
                        }

                        offerAddress = IPAddressExtension.ConvertNumberToIp(nextOfferAddressNumber);

                        AddressStatus addressStatus = await IsAddressAvailableAsync(offerAddress);
                        if (addressStatus.IsAddressAvailable)
                            break;

                        if (addressStatus.NewAddress is not null)
                            offerAddress = addressStatus.NewAddress;
                    }

                    _lastAddressOffered = offerAddress;
                }
                finally
                {
                    _lastAddressOfferedLock.Release();
                }
            }

            Lease offerLease = new Lease(LeaseType.Dynamic, request.ClientIdentifier, null, request.ClientHardwareAddress, offerAddress, null, GetLeaseTime());
            return _offers[request.ClientIdentifier] = offerLease;
        }

        internal Lease GetExistingLeaseOrOffer(DhcpMessage request)
        {
            if (_leases.TryGetValue(request.ClientIdentifier, out Lease existingLease))
                return existingLease;

            if (_offers.TryGetValue(request.ClientIdentifier, out Lease existingOffer))
                return existingOffer;

            return null;
        }

        internal List<DhcpOption> GetOptions(DhcpMessage request, IPAddress serverIdentifierAddress, string overrideClientDomainName)
        {
            List<DhcpOption> options = new List<DhcpOption>();

            switch (request.DhcpMessageType.Type)
            {
                case DhcpMessageType.Discover:
                    options.Add(new DhcpMessageTypeOption(DhcpMessageType.Offer));
                    break;

                case DhcpMessageType.Request:
                case DhcpMessageType.Inform:
                    options.Add(new DhcpMessageTypeOption(DhcpMessageType.Ack));
                    break;

                default:
                    return null;
            }

            options.Add(new ServerIdentifierOption(serverIdentifierAddress));

            switch (request.DhcpMessageType.Type)
            {
                case DhcpMessageType.Discover:
                case DhcpMessageType.Request:
                    uint leaseTime = GetLeaseTime();

                    options.Add(new IpAddressLeaseTimeOption(leaseTime));
                    options.Add(new RenewalTimeValueOption(leaseTime / 2));
                    options.Add(new RebindingTimeValueOption(Convert.ToUInt32(leaseTime * 0.875)));
                    break;
            }

            if (request.ParameterRequestList == null)
            {
                options.Add(new SubnetMaskOption(_subnetMask));
                options.Add(new BroadcastAddressOption(_broadcastAddress));

                if (!string.IsNullOrEmpty(_domainName))
                {
                    options.Add(new DomainNameOption(_domainName));

                    if (request.ClientFullyQualifiedDomainName != null)
                        options.Add(GetClientFullyQualifiedDomainNameOption(request, overrideClientDomainName));
                }

                if (_routerAddress != null)
                    options.Add(new RouterOption(new IPAddress[] { _routerAddress }));

                if (_dnsServers != null)
                    options.Add(new DomainNameServerOption(_dnsServers));

                if (_winsServers != null)
                    options.Add(new NetBiosNameServerOption(_winsServers));

                if (_ntpServers != null)
                    options.Add(new NetworkTimeProtocolServersOption(_ntpServers));

                if (_staticRoutes != null)
                    options.Add(new ClasslessStaticRouteOption(_staticRoutes));
            }
            else
            {
                foreach (DhcpOptionCode optionCode in request.ParameterRequestList.OptionCodes)
                {
                    switch (optionCode)
                    {
                        case DhcpOptionCode.SubnetMask:
                            options.Add(new SubnetMaskOption(_subnetMask));
                            options.Add(new BroadcastAddressOption(_broadcastAddress));
                            break;

                        case DhcpOptionCode.DomainName:
                            if (!string.IsNullOrEmpty(_domainName))
                            {
                                options.Add(new DomainNameOption(_domainName));

                                if (request.ClientFullyQualifiedDomainName != null)
                                    options.Add(GetClientFullyQualifiedDomainNameOption(request, overrideClientDomainName));
                            }

                            break;

                        case DhcpOptionCode.Router:
                            if (_routerAddress != null)
                                options.Add(new RouterOption(new IPAddress[] { _routerAddress }));

                            break;

                        case DhcpOptionCode.DomainNameServer:
                            if (_dnsServers != null)
                                options.Add(new DomainNameServerOption(_dnsServers));

                            break;

                        case DhcpOptionCode.NetBiosOverTcpIpNameServer:
                            if (_winsServers != null)
                                options.Add(new NetBiosNameServerOption(_winsServers));

                            break;

                        case DhcpOptionCode.NetworkTimeProtocolServers:
                            if (_ntpServers != null)
                                options.Add(new NetworkTimeProtocolServersOption(_ntpServers));

                            break;

                        case DhcpOptionCode.ClasslessStaticRoute:
                            if (_staticRoutes != null)
                                options.Add(new ClasslessStaticRouteOption(_staticRoutes));

                            break;
                    }
                }
            }

            if ((_vendorInfo != null) && (request.VendorClassIdentifier != null))
            {
                VendorSpecificInformationOption vendorSpecificInformationOption;

                if (_vendorInfo.TryGetValue(request.VendorClassIdentifier.Identifier, out vendorSpecificInformationOption) || _vendorInfo.TryGetValue("", out vendorSpecificInformationOption))
                {
                    options.Add(new VendorClassIdentifierOption(request.VendorClassIdentifier.Identifier));
                    options.Add(vendorSpecificInformationOption);
                }
                else
                {
                    string match = "substring(vendor-class-identifier,";

                    foreach (KeyValuePair<string, VendorSpecificInformationOption> entry in _vendorInfo)
                    {
                        if (entry.Key.StartsWith(match))
                        {
                            int i = entry.Key.IndexOf(')', match.Length);
                            if (i < match.Length)
                                continue;

                            string[] parts = entry.Key.Substring(match.Length, i - match.Length).Split(',');

                            if (parts.Length != 2)
                                continue;

                            if (!int.TryParse(parts[0], out int startIndex))
                                continue;

                            if (!int.TryParse(parts[1], out int length))
                                continue;

                            int j = entry.Key.IndexOf("==", i);
                            if (j < i)
                                continue;

                            string value = entry.Key.Substring(j + 2);
                            value = value.Trim();
                            value = value.Trim('"');

                            if (request.VendorClassIdentifier.Identifier.Substring(startIndex, length).Equals(value))
                            {
                                options.Add(new VendorClassIdentifierOption(value));
                                options.Add(entry.Value);
                                break;
                            }
                        }
                    }
                }
            }

            options.Add(DhcpOption.CreateEndOption());

            return options;
        }

        internal void CommitLease(Lease lease)
        {
            lease.ExtendLease(GetLeaseTime());

            _leases[lease.ClientIdentifier] = lease;
            _offers.TryRemove(lease.ClientIdentifier, out _);

            _lastModified = DateTime.UtcNow;
        }

        internal void ReleaseLease(Lease lease)
        {
            _leases.TryRemove(lease.ClientIdentifier, out _);

            _lastModified = DateTime.UtcNow;
        }

        internal Lease RemoveLease(string hardwareAddress)
        {
            byte[] hardwareAddressBytes = Lease.ParseHardwareAddress(hardwareAddress);

            foreach (KeyValuePair<ClientIdentifierOption, Lease> entry in _leases)
            {
                if (BinaryNumber.Equals(entry.Value.HardwareAddress, hardwareAddressBytes))
                {
                    //remove lease
                    if (_leases.TryRemove(entry.Key, out Lease removedLease))
                    {
                        if (removedLease.Type == LeaseType.Reserved)
                        {
                            //remove reserved lease
                            Lease reservedLease = new Lease(LeaseType.Reserved, null, DhcpMessageHardwareAddressType.Ethernet, removedLease.HardwareAddress, removedLease.Address, null);
                            _reservedLeases.TryRemove(reservedLease.ClientIdentifier, out _);
                        }

                        return removedLease;
                    }
                }
            }

            throw new DhcpServerException("No lease was found for hardware address: " + hardwareAddress);
        }

        internal void SetEnabled(bool enabled)
        {
            _enabled = enabled;

            if (!enabled)
            {
                _interfaceAddress = null;
                _interfaceIndex = 0;
            }
        }

        internal void RemoveExpiredOffers()
        {
            DateTime utcNow = DateTime.UtcNow;

            foreach (KeyValuePair<ClientIdentifierOption, Lease> offer in _offers)
            {
                if (utcNow > offer.Value.LeaseObtained.AddSeconds(OFFER_EXPIRY_SECONDS))
                {
                    //offer expired
                    _offers.TryRemove(offer.Key, out _);
                }
            }
        }

        internal List<Lease> RemoveExpiredLeases()
        {
            List<Lease> expiredLeases = new List<Lease>();
            DateTime utcNow = DateTime.UtcNow;

            foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in _leases)
            {
                if (utcNow > lease.Value.LeaseExpires)
                {
                    //lease expired
                    if (_leases.TryRemove(lease.Key, out Lease expiredLease))
                        expiredLeases.Add(expiredLease);
                }
            }

            if (expiredLeases.Count > 0)
                _lastModified = DateTime.UtcNow;

            return expiredLeases;
        }

        #endregion

        #region public

        public void ChangeNetwork(IPAddress startingAddress, IPAddress endingAddress, IPAddress subnetMask)
        {
            if (startingAddress.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", nameof(startingAddress));

            if (endingAddress.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", nameof(endingAddress));

            if (subnetMask.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", nameof(subnetMask));

            uint startingAddressNumber = startingAddress.ConvertIpToNumber();
            uint endingAddressNumber = endingAddress.ConvertIpToNumber();

            if (startingAddressNumber >= endingAddressNumber)
                throw new ArgumentException("Ending address must be greater than starting address.");

            _startingAddress = startingAddress;
            _endingAddress = endingAddress;
            _subnetMask = subnetMask;

            //compute other parameters
            uint subnetMaskNumber = _subnetMask.ConvertIpToNumber();
            uint networkAddressNumber = startingAddressNumber & subnetMaskNumber;
            uint broadcastAddressNumber = networkAddressNumber | ~subnetMaskNumber;

            if (networkAddressNumber == startingAddressNumber)
                throw new ArgumentException("Starting address cannot be same as the network address.");

            if (broadcastAddressNumber == endingAddressNumber)
                throw new ArgumentException("Ending address cannot be same as the broadcast address.");

            _networkAddress = IPAddressExtension.ConvertNumberToIp(networkAddressNumber);
            _broadcastAddress = IPAddressExtension.ConvertNumberToIp(broadcastAddressNumber);

            _lastAddressOfferedLock.Wait();
            try
            {
                _lastAddressOffered = IPAddressExtension.ConvertNumberToIp(startingAddressNumber - 1u);
            }
            finally
            {
                _lastAddressOfferedLock.Release();
            }
        }

        public void ConvertToReservedLease(string hardwareAddress)
        {
            byte[] hardwareAddressBytes = Lease.ParseHardwareAddress(hardwareAddress);

            foreach (KeyValuePair<ClientIdentifierOption, Lease> entry in _leases)
            {
                Lease lease = entry.Value;

                if ((lease.Type == LeaseType.Dynamic) && BinaryNumber.Equals(lease.HardwareAddress, hardwareAddressBytes))
                {
                    //convert dynamic to reserved lease
                    lease.ConvertToReserved();

                    //add reserved lease
                    Lease reservedLease = new Lease(LeaseType.Reserved, null, DhcpMessageHardwareAddressType.Ethernet, lease.HardwareAddress, lease.Address, null);
                    _reservedLeases[reservedLease.ClientIdentifier] = reservedLease;
                    return;
                }
            }

            throw new DhcpServerException("No dynamic lease was found for hardware address: " + hardwareAddress);
        }

        public void ConvertToDynamicLease(string hardwareAddress)
        {
            byte[] hardwareAddressBytes = Lease.ParseHardwareAddress(hardwareAddress);

            foreach (KeyValuePair<ClientIdentifierOption, Lease> entry in _leases)
            {
                Lease lease = entry.Value;

                if ((lease.Type == LeaseType.Reserved) && BinaryNumber.Equals(lease.HardwareAddress, hardwareAddressBytes))
                {
                    //convert reserved to dynamic lease
                    lease.ConvertToDynamic();

                    //remove reserved lease
                    Lease reservedLease = new Lease(LeaseType.Reserved, null, DhcpMessageHardwareAddressType.Ethernet, lease.HardwareAddress, lease.Address, null);
                    _reservedLeases.TryRemove(reservedLease.ClientIdentifier, out _);

                    //remove any old single address exclusion entry
                    if (_exclusions != null)
                    {
                        foreach (Exclusion exclusion in _exclusions)
                        {
                            if (exclusion.StartingAddress.Equals(lease.Address) && exclusion.EndingAddress.Equals(lease.Address))
                            {
                                //remove single address exclusion entry
                                if (_exclusions.Count == 1)
                                {
                                    _exclusions = null;
                                }
                                else
                                {
                                    List<Exclusion> exclusions = new List<Exclusion>();

                                    foreach (Exclusion exc in _exclusions)
                                    {
                                        if (exc.Equals(exclusion))
                                            continue;

                                        exclusions.Add(exc);
                                    }

                                    _exclusions = exclusions;
                                }

                                break;
                            }
                        }
                    }
                }
            }
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write(Encoding.ASCII.GetBytes("SC"));
            bW.Write((byte)5); //version

            bW.WriteShortString(_name);
            bW.Write(_enabled);
            _startingAddress.WriteTo(bW);
            _endingAddress.WriteTo(bW);
            _subnetMask.WriteTo(bW);
            bW.Write(_leaseTimeDays);
            bW.Write(_leaseTimeHours);
            bW.Write(_leaseTimeMinutes);
            bW.Write(_offerDelayTime);

            bW.Write(_pingCheckEnabled);
            bW.Write(_pingCheckTimeout);
            bW.Write(_pingCheckRetries);

            if (string.IsNullOrWhiteSpace(_domainName))
                bW.Write((byte)0);
            else
                bW.WriteShortString(_domainName);

            bW.Write(_dnsTtl);

            if (_serverAddress == null)
                IPAddress.Any.WriteTo(bW);
            else
                _serverAddress.WriteTo(bW);

            if (string.IsNullOrEmpty(_serverHostName))
                bW.Write((byte)0);
            else
                bW.WriteShortString(_serverHostName);

            if (string.IsNullOrEmpty(_bootFileName))
                bW.Write((byte)0);
            else
                bW.WriteShortString(_bootFileName);

            if (_routerAddress == null)
                IPAddress.Any.WriteTo(bW);
            else
                _routerAddress.WriteTo(bW);

            if (_useThisDnsServer)
            {
                bW.Write((byte)255);
            }
            else if (_dnsServers == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_dnsServers.Count));

                foreach (IPAddress dnsServer in _dnsServers)
                    dnsServer.WriteTo(bW);
            }

            if (_winsServers == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_winsServers.Count));

                foreach (IPAddress winsServer in _winsServers)
                    winsServer.WriteTo(bW);
            }

            if (_ntpServers == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_ntpServers.Count));

                foreach (IPAddress ntpServer in _ntpServers)
                    ntpServer.WriteTo(bW);
            }

            if (_staticRoutes == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_staticRoutes.Count));

                foreach (ClasslessStaticRouteOption.Route route in _staticRoutes)
                    route.WriteTo(bW.BaseStream);
            }

            if (_vendorInfo == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_vendorInfo.Count));

                foreach (KeyValuePair<string, VendorSpecificInformationOption> entry in _vendorInfo)
                {
                    bW.WriteShortString(entry.Key);
                    bW.WriteBuffer(entry.Value.Information);
                }
            }

            if (_exclusions == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_exclusions.Count));

                foreach (Exclusion exclusion in _exclusions)
                {
                    exclusion.StartingAddress.WriteTo(bW);
                    exclusion.EndingAddress.WriteTo(bW);
                }
            }

            bW.Write(_reservedLeases.Count);

            foreach (KeyValuePair<ClientIdentifierOption, Lease> reservedLease in _reservedLeases)
                reservedLease.Value.WriteTo(bW);

            bW.Write(_allowOnlyReservedLeases);

            {
                bW.Write(_leases.Count);

                foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in _leases)
                    lease.Value.WriteTo(bW);
            }
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            return Equals(obj as Scope);
        }

        public bool Equals(Scope other)
        {
            if (other is null)
                return false;

            if (!_startingAddress.Equals(other._startingAddress))
                return false;

            if (!_endingAddress.Equals(other._endingAddress))
                return false;

            return true;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_startingAddress, _endingAddress, _subnetMask);
        }

        public override string ToString()
        {
            return _name;
        }

        public int CompareTo(Scope other)
        {
            return _name.CompareTo(other._name);
        }

        #endregion

        #region properties

        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }

        public bool Enabled
        { get { return _enabled; } }

        public IPAddress StartingAddress
        { get { return _startingAddress; } }

        public IPAddress EndingAddress
        { get { return _endingAddress; } }

        public IPAddress SubnetMask
        { get { return _subnetMask; } }

        public ushort LeaseTimeDays
        {
            get { return _leaseTimeDays; }
            set
            {
                if (value > 999)
                    throw new ArgumentOutOfRangeException(nameof(LeaseTimeDays), "Lease time in days must be between 0 to 999.");

                _leaseTimeDays = value;
            }
        }

        public byte LeaseTimeHours
        {
            get { return _leaseTimeHours; }
            set
            {
                if (value > 23)
                    throw new ArgumentOutOfRangeException(nameof(LeaseTimeHours), "Lease time in hours must be between 0 to 23.");

                _leaseTimeHours = value;
            }
        }

        public byte LeaseTimeMinutes
        {
            get { return _leaseTimeMinutes; }
            set
            {
                if (value > 59)
                    throw new ArgumentOutOfRangeException(nameof(LeaseTimeMinutes), "Lease time in minutes must be between 0 to 59.");

                _leaseTimeMinutes = value;
            }
        }

        public ushort OfferDelayTime
        {
            get { return _offerDelayTime; }
            set { _offerDelayTime = value; }
        }

        public bool PingCheckEnabled
        {
            get { return _pingCheckEnabled; }
            set { _pingCheckEnabled = value; }
        }

        public ushort PingCheckTimeout
        {
            get { return _pingCheckTimeout; }
            set { _pingCheckTimeout = value; }
        }

        public byte PingCheckRetries
        {
            get { return _pingCheckRetries; }
            set { _pingCheckRetries = value; }
        }

        public string DomainName
        {
            get { return _domainName; }
            set
            {
                if (value != null)
                    DnsClient.IsDomainNameValid(value, true);

                _domainName = value;
            }
        }

        public uint DnsTtl
        {
            get { return _dnsTtl; }
            set { _dnsTtl = value; }
        }

        public IPAddress ServerAddress
        {
            get { return _serverAddress; }
            set { _serverAddress = value; }
        }

        public string ServerHostName
        {
            get { return _serverHostName; }
            set
            {
                if ((value != null) && (value.Length >= 64))
                    throw new ArgumentException("Server host name cannot exceed 63 bytes.");

                _serverHostName = value;
            }
        }

        public string BootFileName
        {
            get { return _bootFileName; }
            set
            {
                if ((value != null) && (value.Length >= 128))
                    throw new ArgumentException("Boot file name cannot exceed 127 bytes.");

                _bootFileName = value;
            }
        }

        public IPAddress RouterAddress
        {
            get { return _routerAddress; }
            set { _routerAddress = value; }
        }

        public bool UseThisDnsServer
        {
            get { return _useThisDnsServer; }
            set
            {
                _useThisDnsServer = value;

                if (_useThisDnsServer)
                    FindThisDnsServerAddress();
            }
        }

        public IReadOnlyCollection<IPAddress> DnsServers
        {
            get { return _dnsServers; }
            set
            {
                _dnsServers = value;

                if ((_dnsServers != null) && _dnsServers.Count > 0)
                    _useThisDnsServer = false;
            }
        }

        public IReadOnlyCollection<IPAddress> WinsServers
        {
            get { return _winsServers; }
            set { _winsServers = value; }
        }

        public IReadOnlyCollection<IPAddress> NtpServers
        {
            get { return _ntpServers; }
            set { _ntpServers = value; }
        }

        public IReadOnlyCollection<ClasslessStaticRouteOption.Route> StaticRoutes
        {
            get { return _staticRoutes; }
            set { _staticRoutes = value; }
        }

        public IReadOnlyDictionary<string, VendorSpecificInformationOption> VendorInfo
        {
            get { return _vendorInfo; }
            set { _vendorInfo = value; }
        }

        public IReadOnlyCollection<Exclusion> Exclusions
        {
            get { return _exclusions; }
            set
            {
                if (value == null)
                {
                    _exclusions = null;
                }
                else
                {
                    foreach (Exclusion exclusion in value)
                    {
                        if (!IsAddressInRange(exclusion.StartingAddress))
                            throw new ArgumentOutOfRangeException(nameof(Exclusions), "Exclusion starting address must be in scope range.");

                        if (!IsAddressInRange(exclusion.EndingAddress))
                            throw new ArgumentOutOfRangeException(nameof(Exclusions), "Exclusion ending address must be in scope range.");
                    }

                    _exclusions = value;
                }
            }
        }

        public IReadOnlyCollection<Lease> ReservedLeases
        {
            get
            {
                List<Lease> leases = new List<Lease>(_reservedLeases.Count);

                foreach (KeyValuePair<ClientIdentifierOption, Lease> entry in _reservedLeases)
                    leases.Add(entry.Value);

                leases.Sort();
                return leases;
            }
            set
            {
                if (value == null)
                {
                    _reservedLeases.Clear();
                }
                else
                {
                    foreach (Lease reservedLease in value)
                    {
                        if (!IsAddressInRange(reservedLease.Address))
                            throw new ArgumentOutOfRangeException(nameof(ReservedLeases), "Reserved address must be in scope range.");
                    }

                    _reservedLeases.Clear();

                    foreach (Lease reservedLease in value)
                        _reservedLeases.TryAdd(reservedLease.ClientIdentifier, reservedLease);
                }
            }
        }

        public bool AllowOnlyReservedLeases
        {
            get { return _allowOnlyReservedLeases; }
            set { _allowOnlyReservedLeases = value; }
        }

        public IReadOnlyDictionary<ClientIdentifierOption, Lease> Leases
        { get { return _leases; } }

        public IPAddress NetworkAddress
        { get { return _networkAddress; } }

        public IPAddress BroadcastAddress
        { get { return _broadcastAddress; } }

        public IPAddress InterfaceAddress
        { get { return _interfaceAddress; } }

        internal int InterfaceIndex
        { get { return _interfaceIndex; } }

        internal DateTime LastModified
        { get { return _lastModified; } }

        #endregion

        class AddressStatus
        {
            public static readonly AddressStatus TRUE = new AddressStatus(true, null);
            public static readonly AddressStatus FALSE = new AddressStatus(false, null);

            public readonly bool IsAddressAvailable;
            public readonly IPAddress NewAddress;

            public AddressStatus(bool isAddressAvailable, IPAddress newAddress)
            {
                IsAddressAvailable = isAddressAvailable;
                NewAddress = newAddress;
            }
        }
    }
}
