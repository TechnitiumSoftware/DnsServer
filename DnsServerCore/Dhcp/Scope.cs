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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dhcp
{
    public class Scope : IComparable<Scope>
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

        //dhcp options
        string _domainName;
        uint _dnsTtl = 900;
        IPAddress _routerAddress;
        bool _useThisDnsServer;
        IPAddress[] _dnsServers;
        IPAddress[] _winsServers;
        IPAddress[] _ntpServers;
        ClasslessStaticRouteOption.Route[] _staticRoutes;

        //advanced options
        Exclusion[] _exclusions;
        Lease[] _reservedLeases;
        bool _allowOnlyReservedLeases;

        //leases
        readonly ConcurrentDictionary<ClientIdentifierOption, Lease> _leases = new ConcurrentDictionary<ClientIdentifierOption, Lease>();

        //internal computed parameters
        IPAddress _networkAddress;
        IPAddress _broadcastAddress;
        string _reverseZone;

        //internal parameters
        const int OFFER_EXPIRY_SECONDS = 60; //1 mins offer expiry
        readonly ConcurrentDictionary<ClientIdentifierOption, Lease> _offers = new ConcurrentDictionary<ClientIdentifierOption, Lease>();
        IPAddress _lastAddressOffered;
        readonly object _lastAddressOfferedLock = new object();
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

            switch (bR.ReadByte())
            {
                case 1:
                    _name = bR.ReadShortString();
                    _enabled = bR.ReadBoolean();

                    ChangeNetwork(IPAddressExtension.Parse(bR), IPAddressExtension.Parse(bR), IPAddressExtension.Parse(bR));

                    _leaseTimeDays = bR.ReadUInt16();
                    _leaseTimeHours = bR.ReadByte();
                    _leaseTimeMinutes = bR.ReadByte();

                    _offerDelayTime = bR.ReadUInt16();

                    _domainName = bR.ReadShortString();
                    if (_domainName == "")
                        _domainName = null;

                    _dnsTtl = bR.ReadUInt32();

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
                                _dnsServers = new IPAddress[count];

                                for (int i = 0; i < count; i++)
                                    _dnsServers[i] = IPAddressExtension.Parse(bR);
                            }
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            _winsServers = new IPAddress[count];

                            for (int i = 0; i < count; i++)
                                _winsServers[i] = IPAddressExtension.Parse(bR);
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            _ntpServers = new IPAddress[count];

                            for (int i = 0; i < count; i++)
                                _ntpServers[i] = IPAddressExtension.Parse(bR);
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            _staticRoutes = new ClasslessStaticRouteOption.Route[count];

                            for (int i = 0; i < count; i++)
                                _staticRoutes[i] = new ClasslessStaticRouteOption.Route(bR.BaseStream);
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            _exclusions = new Exclusion[count];

                            for (int i = 0; i < count; i++)
                                _exclusions[i] = new Exclusion(IPAddressExtension.Parse(bR), IPAddressExtension.Parse(bR));
                        }
                    }

                    {
                        int count = bR.ReadInt32();
                        if (count > 0)
                        {
                            _reservedLeases = new Lease[count];

                            for (int i = 0; i < count; i++)
                                _reservedLeases[i] = new Lease(bR);
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

        private bool IsAddressAvailable(ref IPAddress address)
        {
            if (address.Equals(_routerAddress))
                return false;

            if ((_dnsServers != null) && _dnsServers.Contains(address))
                return false;

            if ((_winsServers != null) && _winsServers.Contains(address))
                return false;

            if ((_ntpServers != null) && _ntpServers.Contains(address))
                return false;

            if (_exclusions != null)
            {
                foreach (Exclusion exclusion in _exclusions)
                {
                    if (IsAddressInRange(address, exclusion.StartingAddress, exclusion.EndingAddress))
                    {
                        address = exclusion.EndingAddress;
                        return false;
                    }
                }
            }

            if (_reservedLeases != null)
            {
                foreach (Lease reservedLease in _reservedLeases)
                {
                    if (address.Equals(reservedLease.Address))
                        return false;
                }
            }

            foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in _leases)
            {
                if (address.Equals(lease.Value.Address))
                    return false;
            }

            foreach (KeyValuePair<ClientIdentifierOption, Lease> offer in _offers)
            {
                if (address.Equals(offer.Value.Address))
                    return false;
            }

            return true;
        }

        private ClientFullyQualifiedDomainNameOption GetClientFullyQualifiedDomainNameOption(DhcpMessage request)
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

            if (request.ClientFullyQualifiedDomainName.DomainName == "")
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

        internal void FindInterface()
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

                            //check if address is static
                            if (ipInterface.DhcpServerAddresses.Count > 0)
                                throw new DhcpServerException("DHCP Server requires static IP address to work correctly but the network interface was found to have DHCP configured.");

                            _interfaceAddress = ip.Address;
                            _interfaceIndex = ipInterface.GetIPv4Properties().Index;
                            return;
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
                            return;
                        }
                    }
                }
            }

            //server has no static ip address configured
            throw new DhcpServerException("DHCP Server requires static IP address to work correctly but no network interface was found to have any static IP address configured.");
        }

        internal void FindThisDnsServerAddress()
        {
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            //find interface in current scope range
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

        internal static string GetReverseZone(IPAddress address, IPAddress subnetMask)
        {
            return GetReverseZone(address, subnetMask.GetSubnetMaskWidth());
        }

        internal static string GetReverseZone(IPAddress address, int subnetMaskWidth)
        {
            int addressByteCount = Convert.ToInt32(Math.Ceiling(Convert.ToDecimal(subnetMaskWidth) / 8));
            byte[] addressBytes = address.GetAddressBytes();
            string reverseZone = "";

            for (int i = 0; i < addressByteCount; i++)
                reverseZone = addressBytes[i] + "." + reverseZone;

            reverseZone += "in-addr.arpa";

            return reverseZone;
        }

        internal bool IsAddressInRange(IPAddress address)
        {
            return IsAddressInRange(address, _startingAddress, _endingAddress);
        }

        internal Lease GetOffer(DhcpMessage request)
        {
            if (_leases.TryGetValue(request.ClientIdentifier, out Lease existingLease))
            {
                //lease already exists
                return existingLease;
            }

            if (_reservedLeases != null)
            {
                ClientIdentifierOption clientIdentifierKey = new ClientIdentifierOption(1, request.ClientHardwareAddress);
                foreach (Lease reservedLease in _reservedLeases)
                {
                    if (reservedLease.ClientIdentifier.Equals(clientIdentifierKey))
                    {
                        //reserved address exists
                        if (request.HostName != null)
                            reservedLease.SetHostName(request.HostName.HostName); //update reserved lease entry with latest client hostname

                        Lease reservedOffer = new Lease(LeaseType.Reserved, request.ClientIdentifier, reservedLease.HostName, request.ClientHardwareAddress, reservedLease.Address, GetLeaseTime());

                        return _offers.AddOrUpdate(request.ClientIdentifier, reservedOffer, delegate (ClientIdentifierOption key, Lease existingValue)
                        {
                            return reservedOffer;
                        });
                    }
                }
            }

            if (_allowOnlyReservedLeases)
                return null; //client does not have reserved address as per scope requirements

            Lease dummyOffer = new Lease(LeaseType.None, null, null, null, null, 0);
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

                if (IsAddressInRange(requestedAddress) && IsAddressAvailable(ref requestedAddress))
                    offerAddress = requestedAddress;
            }

            if (offerAddress == null)
            {
                lock (_lastAddressOfferedLock)
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
                                return null; //ip pool exhausted

                            offerAddress = IPAddressExtension.ConvertNumberToIp(_startingAddress.ConvertIpToNumber() - 1u);
                            offerAddressWasResetFromEnd = true;
                            continue;
                        }

                        offerAddress = IPAddressExtension.ConvertNumberToIp(nextOfferAddressNumber);

                        if (IsAddressAvailable(ref offerAddress))
                            break;
                    }

                    _lastAddressOffered = offerAddress;
                }
            }

            Lease offerLease = new Lease(LeaseType.Dynamic, request.ClientIdentifier, request.HostName?.HostName, request.ClientHardwareAddress, offerAddress, GetLeaseTime());

            return _offers.AddOrUpdate(request.ClientIdentifier, offerLease, delegate (ClientIdentifierOption key, Lease existingValue)
            {
                return offerLease;
            });
        }

        internal Lease GetExistingLeaseOrOffer(DhcpMessage request)
        {
            if (_leases.TryGetValue(request.ClientIdentifier, out Lease existingLease))
                return existingLease;

            if (_offers.TryGetValue(request.ClientIdentifier, out Lease existingOffer))
                return existingOffer;

            return null;
        }

        internal List<DhcpOption> GetOptions(DhcpMessage request, IPAddress serverIdentifierAddress)
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
                        options.Add(GetClientFullyQualifiedDomainNameOption(request));
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
                                    options.Add(GetClientFullyQualifiedDomainNameOption(request));
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

            options.Add(DhcpOption.CreateEndOption());

            return options;
        }

        internal void CommitLease(Lease lease)
        {
            lease.ExtendLease(GetLeaseTime());

            _leases.AddOrUpdate(lease.ClientIdentifier, lease, delegate (ClientIdentifierOption key, Lease existingValue)
            {
                return lease;
            });

            _lastModified = DateTime.UtcNow;
        }

        internal void ReleaseLease(Lease lease)
        {
            _leases.TryRemove(lease.ClientIdentifier, out _);

            _lastModified = DateTime.UtcNow;
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
            List<ClientIdentifierOption> expiredOffers = new List<ClientIdentifierOption>();
            DateTime utcNow = DateTime.UtcNow;

            foreach (KeyValuePair<ClientIdentifierOption, Lease> offer in _offers)
            {
                if (utcNow > offer.Value.LeaseObtained.AddSeconds(OFFER_EXPIRY_SECONDS))
                {
                    //offer expired
                    expiredOffers.Add(offer.Key);
                }
            }

            foreach (ClientIdentifierOption expiredOffer in expiredOffers)
                _offers.TryRemove(expiredOffer, out _);
        }

        internal List<Lease> RemoveExpiredLeases()
        {
            List<ClientIdentifierOption> expiredLeaseKeys = new List<ClientIdentifierOption>();
            DateTime utcNow = DateTime.UtcNow;

            foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in _leases)
            {
                if (utcNow > lease.Value.LeaseExpires)
                {
                    //lease expired
                    expiredLeaseKeys.Add(lease.Key);
                }
            }

            List<Lease> expiredLeases = new List<Lease>();

            foreach (ClientIdentifierOption expiredLeaseKey in expiredLeaseKeys)
            {
                if (_leases.TryRemove(expiredLeaseKey, out Lease expiredLease))
                    expiredLeases.Add(expiredLease);
            }

            if (expiredLeaseKeys.Count > 0)
                _lastModified = DateTime.UtcNow;

            return expiredLeases;
        }

        #endregion

        #region public

        public void ChangeNetwork(IPAddress startingAddress, IPAddress endingAddress, IPAddress subnetMask)
        {
            if (startingAddress.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", "startingAddress");

            if (endingAddress.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", "endingAddress");

            if (subnetMask.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.", "subnetMask");

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
            _reverseZone = GetReverseZone(_networkAddress, _subnetMask);

            lock (_lastAddressOfferedLock)
            {
                _lastAddressOffered = IPAddressExtension.ConvertNumberToIp(startingAddressNumber - 1u);
            }
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write(Encoding.ASCII.GetBytes("SC"));
            bW.Write((byte)1); //version

            bW.WriteShortString(_name);
            bW.Write(_enabled);
            _startingAddress.WriteTo(bW);
            _endingAddress.WriteTo(bW);
            _subnetMask.WriteTo(bW);
            bW.Write(_leaseTimeDays);
            bW.Write(_leaseTimeHours);
            bW.Write(_leaseTimeMinutes);
            bW.Write(_offerDelayTime);

            if (string.IsNullOrEmpty(_domainName))
                bW.Write((byte)0);
            else
                bW.WriteShortString(_domainName);

            bW.Write(_dnsTtl);

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
                bW.Write(Convert.ToByte(_dnsServers.Length));

                foreach (IPAddress dnsServer in _dnsServers)
                    dnsServer.WriteTo(bW);
            }

            if (_winsServers == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_winsServers.Length));

                foreach (IPAddress winsServer in _winsServers)
                    winsServer.WriteTo(bW);
            }

            if (_ntpServers == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_ntpServers.Length));

                foreach (IPAddress ntpServer in _ntpServers)
                    ntpServer.WriteTo(bW);
            }

            if (_staticRoutes == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_staticRoutes.Length));

                foreach (ClasslessStaticRouteOption.Route route in _staticRoutes)
                    route.WriteTo(bW.BaseStream);
            }

            if (_exclusions == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_exclusions.Length));

                foreach (Exclusion exclusion in _exclusions)
                {
                    exclusion.StartingAddress.WriteTo(bW);
                    exclusion.EndingAddress.WriteTo(bW);
                }
            }

            if (_reservedLeases == null)
            {
                bW.Write(0);
            }
            else
            {
                bW.Write(_reservedLeases.Length);

                foreach (Lease reservedLease in _reservedLeases)
                    reservedLease.WriteTo(bW);
            }

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
            var hashCode = 206027136;
            hashCode = hashCode * -1521134295 + _startingAddress.GetHashCode();
            hashCode = hashCode * -1521134295 + _endingAddress.GetHashCode();
            hashCode = hashCode * -1521134295 + _subnetMask.GetHashCode();
            return hashCode;
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
                    throw new ArgumentOutOfRangeException("Lease time in days must be between 0 to 999.");

                _leaseTimeDays = value;
            }
        }

        public byte LeaseTimeHours
        {
            get { return _leaseTimeHours; }
            set
            {
                if (value > 23)
                    throw new ArgumentOutOfRangeException("Lease time in hours must be between 0 to 23.");

                _leaseTimeHours = value;
            }
        }

        public byte LeaseTimeMinutes
        {
            get { return _leaseTimeMinutes; }
            set
            {
                if (value > 59)
                    throw new ArgumentOutOfRangeException("Lease time in minutes must be between 0 to 59.");

                _leaseTimeMinutes = value;
            }
        }

        public ushort OfferDelayTime
        {
            get { return _offerDelayTime; }
            set { _offerDelayTime = value; }
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

        public IPAddress[] DnsServers
        {
            get { return _dnsServers; }
            set
            {
                _dnsServers = value;

                if ((_dnsServers != null) && _dnsServers.Length > 0)
                    _useThisDnsServer = false;
            }
        }

        public IPAddress[] WinsServers
        {
            get { return _winsServers; }
            set { _winsServers = value; }
        }

        public IPAddress[] NtpServers
        {
            get { return _ntpServers; }
            set { _ntpServers = value; }
        }

        public ClasslessStaticRouteOption.Route[] StaticRoutes
        {
            get { return _staticRoutes; }
            set { _staticRoutes = value; }
        }

        public Exclusion[] Exclusions
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
                            throw new ArgumentOutOfRangeException("Exclusion starting address must be in scope range.");

                        if (!IsAddressInRange(exclusion.EndingAddress))
                            throw new ArgumentOutOfRangeException("Exclusion ending address must be in scope range.");
                    }

                    _exclusions = value;
                }
            }
        }

        public Lease[] ReservedLeases
        {
            get { return _reservedLeases; }
            set
            {
                if (value == null)
                {
                    _reservedLeases = null;
                }
                else
                {
                    foreach (Lease reservedLease in value)
                    {
                        if (!IsAddressInRange(reservedLease.Address))
                            throw new ArgumentOutOfRangeException("Reserved address must be in scope range.");
                    }

                    _reservedLeases = value;
                }
            }
        }

        public bool AllowOnlyReservedLeases
        {
            get { return _allowOnlyReservedLeases; }
            set { _allowOnlyReservedLeases = value; }
        }

        public ICollection<Lease> Leases
        { get { return _leases.Values; } }

        public IPAddress NetworkAddress
        { get { return _networkAddress; } }

        public IPAddress BroadcastAddress
        { get { return _broadcastAddress; } }

        public string ReverseZone
        { get { return _reverseZone; } }

        public IPAddress InterfaceAddress
        { get { return _interfaceAddress; } }

        internal int InterfaceIndex
        { get { return _interfaceIndex; } }

        internal DateTime LastModified
        { get { return _lastModified; } }

        #endregion
    }
}
