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
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;

namespace DnsServerCore.Dhcp
{
    public class Scope : IDisposable, IEquatable<Scope>
    {
        #region variables

        //required parameters
        string _name;
        bool _enabled;
        IPAddress _startingAddress;
        IPAddress _endingAddress;
        IPAddress _subnetMask;

        //optional parameters
        string _domainName;
        IPAddress _routerAddress;
        IPAddress[] _dnsServers;
        IPAddress[] _winsServers;
        IPAddress[] _ntpServers;
        ClasslessStaticRouteOption.Route[] _staticRoutes;
        uint _leaseTime = 86400; //default 1 day lease
        ushort _delayTime;
        bool _autoRouter;
        bool _autoDnsServer;
        bool _reservedAddressOffersOnly;
        readonly List<Exclusion> _exclusions = new List<Exclusion>();
        readonly ConcurrentDictionary<ClientIdentifierOption, Lease> _reservedAddresses = new ConcurrentDictionary<ClientIdentifierOption, Lease>();

        //leases
        readonly ConcurrentDictionary<ClientIdentifierOption, Lease> _leases = new ConcurrentDictionary<ClientIdentifierOption, Lease>();

        //computed parameters
        IPAddress _networkAddress;
        IPAddress _broadcastAddress;
        uint _renewTime;
        uint _rebindTime;

        //internal parameters
        readonly ConcurrentDictionary<ClientIdentifierOption, Lease> _offers = new ConcurrentDictionary<ClientIdentifierOption, Lease>();
        IPAddress _lastAddressOffered;
        const int OFFER_EXPIRY_SECONDS = 120; //2 mins offer expiry

        bool _isActive;
        IPAddress _interfaceAddress;
        LogManager _log;

        Timer _maintenanceTimer;
        const int MAINTENANCE_TIMER_INTERVAL = 60000;

        #endregion

        #region constructor

        public Scope(string name, IPAddress startingAddress, IPAddress endingAddress, IPAddress subnetMask, bool enabled)
        {
            _name = name;
            _enabled = enabled;

            ChangeNetwork(startingAddress, endingAddress, subnetMask);

            _renewTime = _leaseTime / 2;
            _rebindTime = Convert.ToUInt32(_leaseTime * 0.875);

            StartMaintenanceTimer();
        }

        #endregion

        #region IDisposable 

        bool _disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_maintenanceTimer != null)
                    _maintenanceTimer.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region static

        public static bool IsAddressInRange(IPAddress address, IPAddress startingAddress, IPAddress endingAddress)
        {
            uint addressNumber = ConvertIpToNumber(address);
            uint startingAddressNumber = ConvertIpToNumber(startingAddress);
            uint endingAddressNumber = ConvertIpToNumber(endingAddress);

            return (startingAddressNumber <= addressNumber) && (addressNumber <= endingAddressNumber);
        }

        #endregion

        #region private

        private static uint ConvertIpToNumber(IPAddress address)
        {
            byte[] addr = address.GetAddressBytes();
            Array.Reverse(addr);
            return BitConverter.ToUInt32(addr, 0);
        }

        private static IPAddress ConvertNumberToIp(uint address)
        {
            byte[] addr = BitConverter.GetBytes(address);
            Array.Reverse(addr);
            return new IPAddress(addr);
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

            lock (_exclusions)
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

            foreach (KeyValuePair<ClientIdentifierOption, Lease> reservedAddress in _reservedAddresses)
            {
                if (address.Equals(reservedAddress.Value.Address))
                    return false;
            }

            foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in _leases)
            {
                if (address.Equals(lease.Value.Address))
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

            string responseDomainName;

            if (request.ClientFullyQualifiedDomainName.DomainName == "")
            {
                //client domain empty and expects server for a fqdn domain name
                if (request.HostName == null)
                    return null; //server unable to decide a name for client

                responseDomainName = request.HostName.HostName + "." + _domainName;
            }
            else if (request.ClientFullyQualifiedDomainName.DomainName.Contains("."))
            {
                //client domain is fqdn
                if (request.ClientFullyQualifiedDomainName.DomainName.EndsWith("." + _domainName, StringComparison.OrdinalIgnoreCase))
                {
                    responseDomainName = request.ClientFullyQualifiedDomainName.DomainName;
                }
                else
                {
                    string[] parts = request.ClientFullyQualifiedDomainName.DomainName.Split('.');
                    responseDomainName = parts[0] + "." + _domainName;
                }
            }
            else
            {
                //client domain is just hostname
                responseDomainName = request.ClientFullyQualifiedDomainName.DomainName + "." + _domainName;
            }

            return new ClientFullyQualifiedDomainNameOption(responseFlags, 255, 255, responseDomainName);
        }

        private void StartMaintenanceTimer()
        {
            if (_maintenanceTimer == null)
            {
                _maintenanceTimer = new Timer(delegate (object state)
                {
                    try
                    {
                        List<ClientIdentifierOption> expiredOffers = new List<ClientIdentifierOption>();
                        DateTime utcNow = DateTime.UtcNow;

                        foreach (KeyValuePair<ClientIdentifierOption, Lease> offer in _offers)
                        {
                            if (offer.Value.LeaseObtained.AddSeconds(OFFER_EXPIRY_SECONDS) > utcNow)
                            {
                                //offer expired
                                expiredOffers.Add(offer.Key);
                            }
                        }

                        foreach (ClientIdentifierOption expiredOffer in expiredOffers)
                            _offers.TryRemove(expiredOffer, out _);
                    }
                    catch (Exception ex)
                    {
                        LogManager log = _log;
                        if (log != null)
                            log.Write(ex);
                    }
                    finally
                    {
                        if (!_disposed)
                            _maintenanceTimer.Change(MAINTENANCE_TIMER_INTERVAL, Timeout.Infinite);
                    }
                }, null, MAINTENANCE_TIMER_INTERVAL, Timeout.Infinite);
            }
        }

        #endregion

        #region internal

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

            if (_reservedAddresses.TryGetValue(request.ClientIdentifier, out Lease existingReservedAddress))
            {
                //reserved address exists
                Lease reservedOffer = new Lease(request.ClientIdentifier, request.HostName?.HostName, request.ClientHardwareAddress, existingReservedAddress.Address, _leaseTime);

                return _offers.AddOrUpdate(request.ClientIdentifier, reservedOffer, delegate (ClientIdentifierOption key, Lease existingValue)
                {
                    return reservedOffer;
                });
            }

            if (_reservedAddressOffersOnly)
                return null; //client does not have reserved address as per scope requirements

            Lease dummyOffer = new Lease(request.ClientIdentifier, request.HostName?.HostName, request.ClientHardwareAddress, null, _leaseTime);
            Lease existingOffer = _offers.GetOrAdd(request.ClientIdentifier, dummyOffer);

            if (dummyOffer != existingOffer)
            {
                if (existingOffer.Address == null)
                    return null; //dummy offer so another thread is handling offer; do nothing

                //offer already exists
                existingOffer.ResetLeaseTime(_leaseTime);

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
                //find free address from scope
                offerAddress = _lastAddressOffered;
                bool offerAddressWasResetFromEnd = false;

                while (true)
                {
                    offerAddress = ConvertNumberToIp(ConvertIpToNumber(offerAddress) + 1u);

                    if (offerAddress.Equals(_endingAddress))
                    {
                        if (offerAddressWasResetFromEnd)
                            return null; //ip pool exhausted

                        offerAddress = _startingAddress;
                        offerAddressWasResetFromEnd = true;
                        continue;
                    }

                    if (IsAddressAvailable(ref offerAddress))
                        break;
                }

                _lastAddressOffered = offerAddress;
            }

            Lease offerLease = new Lease(request.ClientIdentifier, request.HostName?.HostName, request.ClientHardwareAddress, offerAddress, _leaseTime);

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

        internal List<DhcpOption> GetOptions(DhcpMessage request, IPAddress interfaceAddress)
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

            options.Add(new ServerIdentifierOption(interfaceAddress));

            switch (request.DhcpMessageType.Type)
            {
                case DhcpMessageType.Discover:
                case DhcpMessageType.Request:
                    options.Add(new IpAddressLeaseTimeOption(_leaseTime));
                    options.Add(new RenewalTimeValueOption(_renewTime));
                    options.Add(new RebindingTimeValueOption(_rebindTime));
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

                if (_autoRouter)
                    options.Add(new RouterOption(new IPAddress[] { interfaceAddress }));
                else if (_routerAddress != null)
                    options.Add(new RouterOption(new IPAddress[] { _routerAddress }));

                if (_autoDnsServer)
                    options.Add(new DomainNameServerOption(new IPAddress[] { interfaceAddress }));
                else if (_dnsServers != null)
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
                            if (_autoRouter)
                                options.Add(new RouterOption(new IPAddress[] { interfaceAddress }));
                            else if (_routerAddress != null)
                                options.Add(new RouterOption(new IPAddress[] { _routerAddress }));

                            break;

                        case DhcpOptionCode.DomainNameServer:
                            if (_autoDnsServer)
                                options.Add(new DomainNameServerOption(new IPAddress[] { interfaceAddress }));
                            else if (_dnsServers != null)
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
            lease.ResetLeaseTime(_leaseTime);

            _leases.AddOrUpdate(lease.ClientIdentifier, lease, delegate (ClientIdentifierOption key, Lease existingValue)
            {
                return lease;
            });
        }

        internal void ReleaseLease(Lease lease)
        {
            _leases.TryRemove(lease.ClientIdentifier, out _);
        }

        internal void SetActive(bool isActive)
        {
            _isActive = isActive;

            if (!_isActive)
                _interfaceAddress = null; //remove interface address on deactivation to allow finding it back on activation
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

            uint startingAddressNumber = ConvertIpToNumber(startingAddress);
            uint endingAddressNumber = ConvertIpToNumber(endingAddress);

            if (startingAddressNumber >= endingAddressNumber)
                throw new ArgumentException("Ending address must be greater than starting address.", "endingAddress");

            _startingAddress = startingAddress;
            _endingAddress = endingAddress;
            _subnetMask = subnetMask;

            //compute other parameters
            uint subnetMaskNumber = ConvertIpToNumber(_subnetMask);
            uint networkAddressNumber = startingAddressNumber & subnetMaskNumber;

            _networkAddress = ConvertNumberToIp(networkAddressNumber);
            _broadcastAddress = ConvertNumberToIp(networkAddressNumber | ~subnetMaskNumber);

            _lastAddressOffered = _startingAddress;
        }

        public void AddExclusion(IPAddress startingAddress, IPAddress endingAddress)
        {
            if (!IsAddressInRange(startingAddress))
                throw new ArgumentOutOfRangeException("startingAddress", "Exclusion address must be in scope range.");

            if (!IsAddressInRange(endingAddress))
                throw new ArgumentOutOfRangeException("endingAddress", "Exclusion address must be in scope range.");

            lock (_exclusions)
            {
                foreach (Exclusion exclusion in _exclusions)
                {
                    if (IsAddressInRange(startingAddress, exclusion.StartingAddress, exclusion.EndingAddress))
                        throw new ArgumentException("Exclusion range overlaps existing exclusion.");

                    if (IsAddressInRange(endingAddress, exclusion.StartingAddress, exclusion.EndingAddress))
                        throw new ArgumentException("Exclusion range overlaps existing exclusion.");
                }

                _exclusions.Add(new Exclusion(startingAddress, endingAddress));
            }
        }

        public bool RemoveExclusion(IPAddress startingAddress, IPAddress endingAddress)
        {
            lock (_exclusions)
            {
                Exclusion exclusionFound = null;

                foreach (Exclusion exclusion in _exclusions)
                {
                    if (exclusion.StartingAddress.Equals(startingAddress) && exclusion.EndingAddress.Equals(endingAddress))
                    {
                        exclusionFound = exclusion;
                        break;
                    }
                }

                if (exclusionFound == null)
                    return false;

                return _exclusions.Remove(exclusionFound);
            }
        }

        public void AddReservedAddress(byte[] hardwareAddress, IPAddress address)
        {
            if (!IsAddressInRange(address))
                throw new ArgumentOutOfRangeException("address", "Reserved address must be in scope range.");

            Lease reservedLease = new Lease(hardwareAddress, address, _leaseTime);

            _reservedAddresses.AddOrUpdate(new ClientIdentifierOption(1, hardwareAddress), reservedLease, delegate (ClientIdentifierOption key, Lease existingValue)
            {
                return reservedLease;
            });
        }

        public bool RemoveReservedAddress(byte[] hardwareAddress)
        {
            return _reservedAddresses.TryRemove(new ClientIdentifierOption(1, hardwareAddress), out _);
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

            if (!_subnetMask.Equals(other._subnetMask))
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

        #endregion

        #region properties

        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }

        public bool Enabled
        {
            get { return _enabled; }
            set { _enabled = value; }
        }

        public IPAddress StartingAddress
        { get { return _startingAddress; } }

        public IPAddress EndingAddress
        { get { return _endingAddress; } }

        public IPAddress SubnetMask
        { get { return _subnetMask; } }

        public string DomainName
        {
            get { return _domainName; }
            set { _domainName = value; }
        }

        public IPAddress RouterAddress
        {
            get { return _routerAddress; }
            set { _routerAddress = value; }
        }

        public IPAddress[] DnsServers
        {
            get { return _dnsServers; }
            set { _dnsServers = value; }
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

        public uint LeaseTime
        {
            get { return _leaseTime; }
            set
            {
                _leaseTime = value;
                _renewTime = _leaseTime / 2;
                _rebindTime = Convert.ToUInt32(_leaseTime * 0.875);
            }
        }

        public ushort DelayTime
        {
            get { return _delayTime; }
            set { _delayTime = value; }
        }

        public bool AutoRouter
        {
            get { return _autoRouter; }
            set { _autoRouter = value; }
        }

        public bool AutoDnsServer
        {
            get { return _autoDnsServer; }
            set { _autoDnsServer = value; }
        }

        public bool ReservedAddressOffersOnly
        {
            get { return _reservedAddressOffersOnly; }
            set { _reservedAddressOffersOnly = value; }
        }

        public Exclusion[] Exclusions
        {
            get
            {
                lock (_exclusions)
                {
                    return _exclusions.ToArray();
                }
            }
        }

        public ICollection<Lease> ReservedAddresses
        { get { return _reservedAddresses.Values; } }

        public ICollection<Lease> Leases
        { get { return _leases.Values; } }

        public IPAddress NetworkAddress
        { get { return _networkAddress; } }

        public IPAddress BroadcastAddress
        { get { return _broadcastAddress; } }

        public bool IsActive
        { get { return _isActive; } }

        public IPAddress InterfaceAddress
        {
            get
            {
                if (_interfaceAddress == null)
                {
                    uint networkAddressNumber = ConvertIpToNumber(_networkAddress);
                    uint subnetMaskNumber = ConvertIpToNumber(_subnetMask);

                    foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (nic.OperationalStatus != OperationalStatus.Up)
                            continue;

                        IPInterfaceProperties ipInterface = nic.GetIPProperties();

                        foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                        {
                            if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                uint addressNumber = ConvertIpToNumber(ip.Address);

                                if ((addressNumber & subnetMaskNumber) == networkAddressNumber)
                                    return ip.Address;
                            }
                        }
                    }

                    _interfaceAddress = IPAddress.Any;
                }

                return _interfaceAddress;
            }
        }

        internal LogManager LogManager
        {
            get { return _log; }
            set { _log = value; }
        }

        #endregion
    }
}
