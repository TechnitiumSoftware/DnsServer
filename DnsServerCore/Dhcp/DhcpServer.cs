/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.Auth;
using DnsServerCore.Dhcp.Options;
using DnsServerCore.Dns;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dhcp
{
    //Dynamic Host Configuration Protocol
    //https://datatracker.ietf.org/doc/html/rfc2131

    //DHCP Options and BOOTP Vendor Extensions
    //https://datatracker.ietf.org/doc/html/rfc2132

    //Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4)
    //https://datatracker.ietf.org/doc/html/rfc3396

    //Client Fully Qualified Domain Name(FQDN) Option
    //https://datatracker.ietf.org/doc/html/rfc4702

    public sealed class DhcpServer : IDisposable
    {
        #region enum

        enum ServiceState
        {
            Stopped = 0,
            Starting = 1,
            Running = 2,
            Stopping = 3
        }

        #endregion

        #region variables

        readonly string _scopesFolder;
        readonly LogManager _log;

        readonly ConcurrentDictionary<IPAddress, UdpListener> _udpListeners = new ConcurrentDictionary<IPAddress, UdpListener>();

        readonly ConcurrentDictionary<string, Scope> _scopes = new ConcurrentDictionary<string, Scope>();

        DnsServer _dnsServer;
        AuthManager _authManager;

        volatile ServiceState _state = ServiceState.Stopped;

        readonly IPEndPoint _dhcpDefaultEP = new IPEndPoint(IPAddress.Any, 67);

        Timer _maintenanceTimer;
        const int MAINTENANCE_TIMER_INTERVAL = 10000;

        DateTime _lastModifiedScopesSavedOn;

        #endregion

        #region constructor

        public DhcpServer(string scopesFolder, LogManager log)
        {
            _scopesFolder = scopesFolder;
            _log = log;

            if (!Directory.Exists(_scopesFolder))
            {
                Directory.CreateDirectory(_scopesFolder);

                //create default scope
                Scope scope = new Scope("Default", false, IPAddress.Parse("192.168.1.1"), IPAddress.Parse("192.168.1.254"), IPAddress.Parse("255.255.255.0"), _log, this);
                scope.Exclusions = new Exclusion[] { new Exclusion(IPAddress.Parse("192.168.1.1"), IPAddress.Parse("192.168.1.10")) };
                scope.RouterAddress = IPAddress.Parse("192.168.1.1");
                scope.UseThisDnsServer = true;
                scope.DomainName = "home";
                scope.LeaseTimeDays = 1;
                scope.IgnoreClientIdentifierOption = true;

                SaveScopeFile(scope);
            }
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _maintenanceTimer?.Dispose();

            Stop();

            if (_scopes is not null)
            {
                foreach (KeyValuePair<string, Scope> scope in _scopes)
                    scope.Value.Dispose();

                _scopes.Clear();
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        #endregion

        #region private

        private async Task ReadUdpRequestAsync(Socket udpListener)
        {
            byte[] recvBuffer = new byte[1500];

            try
            {
                bool processOnlyUnicastMessages = !(udpListener.LocalEndPoint as IPEndPoint).Address.Equals(IPAddress.Any); //only 0.0.0.0 ip should process broadcast to avoid duplicate offers on Windows

                EndPoint epAny = new IPEndPoint(IPAddress.Any, 0);

                SocketReceiveMessageFromResult result;

                while (true)
                {
                    try
                    {
                        result = await udpListener.ReceiveMessageFromAsync(recvBuffer, SocketFlags.None, epAny);
                    }
                    catch (SocketException ex)
                    {
                        switch (ex.SocketErrorCode)
                        {
                            case SocketError.ConnectionReset:
                            case SocketError.HostUnreachable:
                            case SocketError.NetworkReset:
                                result = default;
                                break;

                            case SocketError.MessageSize:
                                _log.Write(ex);

                                result = default;
                                break;

                            default:
                                throw;
                        }
                    }

                    if (result.ReceivedBytes > 0)
                    {
                        if (processOnlyUnicastMessages && result.PacketInformation.Address.Equals(IPAddress.Broadcast))
                            continue;

                        try
                        {
                            DhcpMessage request = new DhcpMessage(new MemoryStream(recvBuffer, 0, result.ReceivedBytes, false));

                            _ = ProcessDhcpRequestAsync(request, result.RemoteEndPoint as IPEndPoint, result.PacketInformation, udpListener);
                        }
                        catch (Exception ex)
                        {
                            _log.Write(result.RemoteEndPoint as IPEndPoint, ex);
                        }
                    }
                }
            }
            catch (ObjectDisposedException)
            {
                //server stopped
            }
            catch (SocketException ex)
            {
                switch (ex.SocketErrorCode)
                {
                    case SocketError.OperationAborted:
                    case SocketError.Interrupted:
                        break; //server stopping

                    default:
                        if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                            return; //server stopping

                        _log.Write(ex);
                        break;
                }
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                _log.Write(ex);
            }
        }

        private async Task ProcessDhcpRequestAsync(DhcpMessage request, IPEndPoint remoteEP, IPPacketInformation ipPacketInformation, Socket udpListener)
        {
            try
            {
                DhcpMessage response = await ProcessDhcpMessageAsync(request, remoteEP, ipPacketInformation);

                //send response
                if (response != null)
                {
                    byte[] sendBuffer = new byte[1024];
                    MemoryStream sendBufferStream = new MemoryStream(sendBuffer);

                    response.WriteTo(sendBufferStream);

                    //send dns datagram
                    if (!request.RelayAgentIpAddress.Equals(IPAddress.Any))
                    {
                        //received request via relay agent so send unicast response to relay agent on port 67
                        await udpListener.SendToAsync(new ArraySegment<byte>(sendBuffer, 0, (int)sendBufferStream.Position), SocketFlags.None, new IPEndPoint(request.RelayAgentIpAddress, 67));
                    }
                    else if (!request.ClientIpAddress.Equals(IPAddress.Any))
                    {
                        //client is already configured and renewing lease so send unicast response on port 68
                        await udpListener.SendToAsync(new ArraySegment<byte>(sendBuffer, 0, (int)sendBufferStream.Position), SocketFlags.None, new IPEndPoint(request.ClientIpAddress, 68));
                    }
                    else
                    {
                        Socket udpSocket;

                        //send response as broadcast on port 68 on appropriate interface bound socket
                        if (_udpListeners.TryGetValue(response.ServerIdentifier.Address, out UdpListener listener))
                            udpSocket = listener.Socket; //found scope specific socket
                        else
                            udpSocket = udpListener; //no appropriate socket found so use default socket

                        await udpSocket.SendToAsync(new ArraySegment<byte>(sendBuffer, 0, (int)sendBufferStream.Position), SocketFlags.DontRoute, new IPEndPoint(IPAddress.Broadcast, 68)); //no routing for broadcast
                    }
                }
            }
            catch (ObjectDisposedException)
            {
                //socket disposed
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                _log.Write(remoteEP, ex);
            }
        }

        private async Task<DhcpMessage> ProcessDhcpMessageAsync(DhcpMessage request, IPEndPoint remoteEP, IPPacketInformation ipPacketInformation)
        {
            if (request.OpCode != DhcpMessageOpCode.BootRequest)
                return null;

            switch (request.DhcpMessageType?.Type)
            {
                case DhcpMessageType.Discover:
                    {
                        Scope scope = FindScope(request, remoteEP.Address, ipPacketInformation);
                        if (scope == null)
                            return null; //no scope available; do nothing

                        if ((request.ServerHostName != null) && (request.ServerHostName != scope.ServerHostName))
                            return null; //discard request; since this request is for another server with the specified server host name

                        if ((request.BootFileName != null) && (request.BootFileName != scope.BootFileName))
                            return null; //discard request; since this request wants boot file not available on this server

                        if (scope.OfferDelayTime > 0)
                            await Task.Delay(scope.OfferDelayTime); //delay sending offer

                        Lease offer = await scope.GetOfferAsync(request);
                        if (offer == null)
                            return null; //no offer available, do nothing

                        IPAddress serverIdentifierAddress = scope.InterfaceAddress.Equals(IPAddress.Any) ? ipPacketInformation.Address : scope.InterfaceAddress;
                        string reservedLeaseHostName = null;

                        if (!string.IsNullOrWhiteSpace(scope.DomainName))
                        {
                            //get override host name from reserved lease
                            Lease reservedLease = scope.GetReservedLease(request);
                            if (reservedLease is not null)
                                reservedLeaseHostName = reservedLease.HostName;
                        }

                        List<DhcpOption> options = await scope.GetOptionsAsync(request, serverIdentifierAddress, reservedLeaseHostName, _dnsServer);
                        if (options is null)
                            return null;

                        //log ip offer
                        _log.Write(remoteEP, "DHCP Server offered IP address [" + offer.Address.ToString() + "] to " + request.GetClientFullIdentifier() + " for scope: " + scope.Name);

                        return DhcpMessage.CreateReply(request, offer.Address, scope.ServerAddress ?? serverIdentifierAddress, scope.ServerHostName, scope.BootFileName, options);
                    }

                case DhcpMessageType.Request:
                    {
                        //request ip address lease or extend existing lease
                        Scope scope = FindScope(request, remoteEP.Address, ipPacketInformation);
                        if (scope == null)
                            return null; //no scope available; do nothing

                        IPAddress serverIdentifierAddress = scope.InterfaceAddress.Equals(IPAddress.Any) ? ipPacketInformation.Address : scope.InterfaceAddress;

                        Lease leaseOffer;

                        if (request.ServerIdentifier == null)
                        {
                            if (request.RequestedIpAddress == null)
                            {
                                //renewing or rebinding

                                if (request.ClientIpAddress.Equals(IPAddress.Any))
                                    return null; //client must set IP address in ciaddr; do nothing

                                leaseOffer = scope.GetExistingLeaseOrOffer(request);
                                if (leaseOffer == null)
                                {
                                    //no existing lease or offer available for client
                                    //send nak
                                    return DhcpMessage.CreateReply(request, IPAddress.Any, IPAddress.Any, null, null, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                                }

                                if (!request.ClientIpAddress.Equals(leaseOffer.Address))
                                {
                                    //client ip is incorrect
                                    //send nak
                                    return DhcpMessage.CreateReply(request, IPAddress.Any, IPAddress.Any, null, null, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                                }
                            }
                            else
                            {
                                //init-reboot

                                leaseOffer = scope.GetExistingLeaseOrOffer(request);
                                if (leaseOffer == null)
                                {
                                    //no existing lease or offer available for client
                                    //send nak
                                    return DhcpMessage.CreateReply(request, IPAddress.Any, IPAddress.Any, null, null, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                                }

                                if (!request.RequestedIpAddress.Address.Equals(leaseOffer.Address))
                                {
                                    //the client's notion of its IP address is not correct - RFC 2131
                                    //send nak
                                    return DhcpMessage.CreateReply(request, IPAddress.Any, IPAddress.Any, null, null, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                                }
                            }

                            if ((leaseOffer.Type == LeaseType.Dynamic) && (scope.IsAddressExcluded(leaseOffer.Address) || scope.IsAddressReserved(leaseOffer.Address)))
                            {
                                //client ip is excluded/reserved for dynamic allocations
                                scope.ReleaseLease(leaseOffer);
                                //send nak
                                return DhcpMessage.CreateReply(request, IPAddress.Any, IPAddress.Any, null, null, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                            }

                            Lease reservedLease = scope.GetReservedLease(request);
                            if (reservedLease == null)
                            {
                                if (leaseOffer.Type == LeaseType.Reserved)
                                {
                                    //client's reserved lease has been removed so release the current lease and send NAK to allow it to get new allocation
                                    scope.ReleaseLease(leaseOffer);
                                    //send nak
                                    return DhcpMessage.CreateReply(request, IPAddress.Any, IPAddress.Any, null, null, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                                }
                            }
                            else
                            {
                                if (!reservedLease.Address.Equals(leaseOffer.Address))
                                {
                                    //client has a new reserved lease so release the current lease and send NAK to allow it to get new allocation
                                    scope.ReleaseLease(leaseOffer);
                                    //send nak
                                    return DhcpMessage.CreateReply(request, IPAddress.Any, IPAddress.Any, null, null, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                                }
                            }
                        }
                        else
                        {
                            //selecting offer

                            if (request.RequestedIpAddress == null)
                                return null; //client MUST include this option; do nothing

                            if (!request.ServerIdentifier.Address.Equals(serverIdentifierAddress))
                                return null; //offer declined by client; do nothing

                            leaseOffer = scope.GetExistingLeaseOrOffer(request);
                            if (leaseOffer == null)
                            {
                                //no existing lease or offer available for client
                                //send nak
                                return DhcpMessage.CreateReply(request, IPAddress.Any, IPAddress.Any, null, null, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                            }

                            if (!request.RequestedIpAddress.Address.Equals(leaseOffer.Address))
                            {
                                //requested ip is incorrect
                                //send nak
                                return DhcpMessage.CreateReply(request, IPAddress.Any, IPAddress.Any, null, null, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                            }
                        }

                        string reservedLeaseHostName = null;

                        if (!string.IsNullOrWhiteSpace(scope.DomainName))
                        {
                            //get override host name from reserved lease
                            Lease reservedLease = scope.GetReservedLease(request);
                            if (reservedLease is not null)
                                reservedLeaseHostName = reservedLease.HostName;
                        }

                        List<DhcpOption> options = await scope.GetOptionsAsync(request, serverIdentifierAddress, reservedLeaseHostName, _dnsServer);
                        if (options is null)
                            return null;

                        scope.CommitLease(leaseOffer);

                        //log ip lease
                        _log.Write(remoteEP, "DHCP Server leased IP address [" + leaseOffer.Address.ToString() + "] to " + request.GetClientFullIdentifier() + " for scope: " + scope.Name);

                        if (string.IsNullOrWhiteSpace(scope.DomainName))
                        {
                            //update lease hostname
                            leaseOffer.SetHostName(request.HostName?.HostName);
                        }
                        else
                        {
                            //update dns
                            string clientDomainName = null;

                            if (!string.IsNullOrWhiteSpace(reservedLeaseHostName))
                                clientDomainName = GetSanitizedHostName(reservedLeaseHostName) + "." + scope.DomainName;

                            if (string.IsNullOrWhiteSpace(clientDomainName))
                            {
                                foreach (DhcpOption option in options)
                                {
                                    if (option.Code == DhcpOptionCode.ClientFullyQualifiedDomainName)
                                    {
                                        clientDomainName = (option as ClientFullyQualifiedDomainNameOption).DomainName;
                                        break;
                                    }
                                }
                            }

                            if (string.IsNullOrWhiteSpace(clientDomainName))
                            {
                                if ((request.HostName is not null) && !string.IsNullOrWhiteSpace(request.HostName.HostName))
                                    clientDomainName = GetSanitizedHostName(request.HostName.HostName) + "." + scope.DomainName;
                            }

                            if (!string.IsNullOrWhiteSpace(clientDomainName))
                            {
                                if (!clientDomainName.Equals(leaseOffer.HostName, StringComparison.OrdinalIgnoreCase))
                                    UpdateDnsAuthZone(false, scope, leaseOffer); //hostname changed! delete old hostname entry from DNS

                                leaseOffer.SetHostName(clientDomainName);
                                UpdateDnsAuthZone(true, scope, leaseOffer);
                            }
                        }

                        return DhcpMessage.CreateReply(request, leaseOffer.Address, scope.ServerAddress ?? serverIdentifierAddress, scope.ServerHostName, scope.BootFileName, options);
                    }

                case DhcpMessageType.Decline:
                    {
                        //ip address is already in use as detected by client via ARP

                        if ((request.ServerIdentifier == null) || (request.RequestedIpAddress == null))
                            return null; //client MUST include these option; do nothing

                        Scope scope = FindScope(request, remoteEP.Address, ipPacketInformation);
                        if (scope == null)
                            return null; //no scope available; do nothing

                        IPAddress serverIdentifierAddress = scope.InterfaceAddress.Equals(IPAddress.Any) ? ipPacketInformation.Address : scope.InterfaceAddress;

                        if (!request.ServerIdentifier.Address.Equals(serverIdentifierAddress))
                            return null; //request not for this server; do nothing

                        Lease lease = scope.GetExistingLeaseOrOffer(request);
                        if (lease == null)
                            return null; //no existing lease or offer available for client; do nothing

                        if (!lease.Address.Equals(request.RequestedIpAddress.Address))
                            return null; //the client's notion of its IP address is not correct; do nothing

                        //remove lease since the IP address is used by someone else
                        scope.ReleaseLease(lease);

                        //log issue
                        _log.Write(remoteEP, "DHCP Server received DECLINE message for scope '" + scope.Name + "': " + lease.GetClientInfo() + " detected that IP address [" + lease.Address + "] is already in use.");

                        //update dns
                        UpdateDnsAuthZone(false, scope, lease);

                        //do nothing
                        return null;
                    }

                case DhcpMessageType.Release:
                    {
                        //cancel ip address lease

                        if (request.ServerIdentifier == null)
                            return null; //client MUST include this option; do nothing

                        Scope scope = FindScope(request, remoteEP.Address, ipPacketInformation);
                        if (scope == null)
                            return null; //no scope available; do nothing

                        IPAddress serverIdentifierAddress = scope.InterfaceAddress.Equals(IPAddress.Any) ? ipPacketInformation.Address : scope.InterfaceAddress;

                        if (!request.ServerIdentifier.Address.Equals(serverIdentifierAddress))
                            return null; //request not for this server; do nothing

                        Lease lease = scope.GetExistingLeaseOrOffer(request);
                        if (lease == null)
                            return null; //no existing lease or offer available for client; do nothing

                        if (!lease.Address.Equals(request.ClientIpAddress))
                            return null; //the client's notion of its IP address is not correct; do nothing

                        //release lease
                        scope.ReleaseLease(lease);

                        //log ip lease release
                        _log.Write(remoteEP, "DHCP Server released IP address [" + lease.Address.ToString() + "] that was leased to " + lease.GetClientInfo() + " for scope: " + scope.Name);

                        //update dns
                        UpdateDnsAuthZone(false, scope, lease);

                        //do nothing
                        return null;
                    }

                case DhcpMessageType.Inform:
                    {
                        //need only local config; already has ip address assigned externally/manually

                        Scope scope = FindScope(request, remoteEP.Address, ipPacketInformation);
                        if (scope == null)
                            return null; //no scope available; do nothing

                        IPAddress serverIdentifierAddress = scope.InterfaceAddress.Equals(IPAddress.Any) ? ipPacketInformation.Address : scope.InterfaceAddress;

                        //log inform
                        _log.Write(remoteEP, "DHCP Server received INFORM message from " + request.GetClientFullIdentifier() + " for scope: " + scope.Name);

                        List<DhcpOption> options = await scope.GetOptionsAsync(request, serverIdentifierAddress, null, _dnsServer);
                        if (options is null)
                            return null;

                        if (!string.IsNullOrWhiteSpace(scope.DomainName))
                        {
                            //update dns
                            string clientDomainName = null;

                            foreach (DhcpOption option in options)
                            {
                                if (option.Code == DhcpOptionCode.ClientFullyQualifiedDomainName)
                                {
                                    clientDomainName = (option as ClientFullyQualifiedDomainNameOption).DomainName;
                                    break;
                                }
                            }

                            if (string.IsNullOrWhiteSpace(clientDomainName))
                            {
                                if (request.HostName is not null)
                                    clientDomainName = GetSanitizedHostName(request.HostName.HostName) + "." + scope.DomainName;
                            }

                            if (!string.IsNullOrWhiteSpace(clientDomainName))
                                UpdateDnsAuthZone(true, scope, clientDomainName, request.ClientIpAddress, false);
                        }

                        return DhcpMessage.CreateReply(request, IPAddress.Any, scope.ServerAddress ?? serverIdentifierAddress, null, null, options);
                    }

                default:
                    return null;
            }
        }

        private Scope FindScope(DhcpMessage request, IPAddress remoteAddress, IPPacketInformation ipPacketInformation)
        {
            if (request.RelayAgentIpAddress.Equals(IPAddress.Any))
            {
                //no relay agent
                if (request.ClientIpAddress.Equals(IPAddress.Any))
                {
                    if (!ipPacketInformation.Address.Equals(IPAddress.Broadcast))
                        return null; //message destination address must be broadcast address

                    //broadcast request
                    Scope foundScope = null;

                    foreach (KeyValuePair<string, Scope> entry in _scopes)
                    {
                        Scope scope = entry.Value;

                        if (scope.Enabled && (scope.InterfaceIndex == ipPacketInformation.Interface))
                        {
                            if (scope.GetReservedLease(request) != null)
                                return scope; //found reserved lease on this scope

                            if ((foundScope == null) && !scope.AllowOnlyReservedLeases)
                                foundScope = scope;
                        }
                    }

                    return foundScope;
                }
                else
                {
                    if ((request.DhcpMessageType?.Type != DhcpMessageType.Decline) && !remoteAddress.Equals(request.ClientIpAddress))
                        return null; //client ip must match udp src addr

                    //unicast request
                    foreach (KeyValuePair<string, Scope> entry in _scopes)
                    {
                        Scope scope = entry.Value;

                        if (scope.Enabled && scope.IsAddressInRange(request.ClientIpAddress))
                            return scope;
                    }

                    return null;
                }
            }
            else
            {
                //relay agent unicast
                Scope foundScope = null;

                foreach (KeyValuePair<string, Scope> entry in _scopes)
                {
                    Scope scope = entry.Value;

                    if (scope.Enabled && scope.InterfaceAddress.Equals(IPAddress.Any) && scope.IsAddressInNetwork(request.RelayAgentIpAddress))
                    {
                        if (scope.GetReservedLease(request) != null)
                            return scope; //found reserved lease on this scope

                        if (!request.ClientIpAddress.Equals(IPAddress.Any) && scope.IsAddressInRange(request.ClientIpAddress))
                            return scope; //client IP address is in scope range

                        if ((foundScope == null) && !scope.AllowOnlyReservedLeases)
                            foundScope = scope;
                    }
                }

                return foundScope;
            }
        }

        internal static string GetSanitizedHostName(string hostname)
        {
            StringBuilder sb = new StringBuilder(hostname.Length);

            foreach (char c in hostname)
            {
                if ((c >= 97) && (c <= 122)) //[a-z]
                    sb.Append(c);
                else if ((c >= 65) && (c <= 90)) //[A-Z]
                    sb.Append(c);
                else if ((c >= 48) && (c <= 57)) //[0-9]
                    sb.Append(c);
                else if (c == 45) //[-]
                    sb.Append(c);
                else if (c == 95) //[_]
                    sb.Append(c);
                else if (c == '.')
                    sb.Append(c);
                else if (c == ' ')
                    sb.Append('-');
            }

            return sb.ToString();
        }

        internal void UpdateDnsAuthZone(bool add, Scope scope, Lease lease)
        {
            UpdateDnsAuthZone(add, scope, lease.HostName, lease.Address, lease.Type == LeaseType.Reserved);
        }

        private void UpdateDnsAuthZone(bool add, Scope scope, string domain, IPAddress address, bool isReservedLease)
        {
            if ((_dnsServer is null) || (_authManager is null))
                return;

            if (string.IsNullOrWhiteSpace(scope.DomainName) || !scope.DnsUpdates)
                return;

            if (string.IsNullOrWhiteSpace(domain))
                return;

            if (!DnsClient.IsDomainNameValid(domain))
                return;

            if (!domain.EndsWith("." + scope.DomainName, StringComparison.OrdinalIgnoreCase))
                return; //domain does not end with scope domain name

            try
            {
                string zoneName = null;
                string reverseDomain = Zone.GetReverseZone(address, 32);
                string reverseZoneName = null;

                if (add)
                {
                    //update forward zone
                    AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.FindAuthZoneInfo(scope.DomainName);
                    if (zoneInfo is null)
                    {
                        //zone does not exists; create new primary zone
                        zoneInfo = _dnsServer.AuthZoneManager.CreatePrimaryZone(scope.DomainName);
                        if (zoneInfo is null)
                        {
                            _log.Write("DHCP Server failed to create DNS primary zone '" + scope.DomainName + "'.");
                            return;
                        }

                        //set permissions
                        _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _authManager.GetGroup(Group.DHCP_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SaveConfigFile();

                        _log.Write("DHCP Server create DNS primary zone '" + zoneInfo.DisplayName + "'.");
                    }
                    else if ((zoneInfo.Type != AuthZoneType.Primary) && (zoneInfo.Type != AuthZoneType.Forwarder))
                    {
                        if (zoneInfo.Name.Equals(scope.DomainName, StringComparison.OrdinalIgnoreCase))
                            throw new DhcpServerException("Cannot update DNS zone '" + zoneInfo.DisplayName + "': not a primary or a forwarder zone.");

                        //create new primary zone
                        zoneInfo = _dnsServer.AuthZoneManager.CreatePrimaryZone(scope.DomainName);
                        if (zoneInfo is null)
                        {
                            _log.Write("DHCP Server failed to create DNS primary zone '" + scope.DomainName + "'.");
                            return;
                        }

                        //set permissions
                        _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _authManager.GetGroup(Group.DHCP_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SaveConfigFile();

                        _log.Write("DHCP Server create DNS primary zone '" + zoneInfo.DisplayName + "'.");
                    }

                    zoneName = zoneInfo.Name;

                    if (!isReservedLease)
                    {
                        //check for existing record for the dynamic leases
                        IReadOnlyList<DnsResourceRecord> existingRecords = _dnsServer.AuthZoneManager.GetRecords(zoneName, domain, DnsResourceRecordType.A);
                        if (existingRecords.Count > 0)
                        {
                            foreach (DnsResourceRecord existingRecord in existingRecords)
                            {
                                IPAddress existingAddress = (existingRecord.RDATA as DnsARecordData).Address;
                                if (!existingAddress.Equals(address))
                                {
                                    //a DNS record already exists for the specified domain name with a different address
                                    //do not change DNS record for this dynamic lease
                                    _log.Write("DHCP Server cannot update DNS: an A record already exists for '" + domain + "' with a different IP address [" + existingAddress.ToString() + "].");
                                    return;
                                }
                            }
                        }
                    }

                    DnsResourceRecord aRecord = new DnsResourceRecord(domain, DnsResourceRecordType.A, DnsClass.IN, scope.DnsTtl, new DnsARecordData(address));

                    GenericRecordInfo aRecordInfo = aRecord.GetAuthGenericRecordInfo();
                    aRecordInfo.LastModified = DateTime.UtcNow;
                    aRecordInfo.ExpiryTtl = scope.GetLeaseTime();
                    aRecordInfo.Comments = $"Via '{scope.Name}' DHCP scope";

                    _dnsServer.AuthZoneManager.SetRecord(zoneName, aRecord);
                    _log.Write("DHCP Server updated DNS A record '" + domain + "' with IP address [" + address.ToString() + "].");

                    //update reverse zone
                    AuthZoneInfo reverseZoneInfo = _dnsServer.AuthZoneManager.FindAuthZoneInfo(reverseDomain);
                    if (reverseZoneInfo is null)
                    {
                        string reverseZone = Zone.GetReverseZone(address, scope.SubnetMask);

                        //reverse zone does not exists; create new reverse primary zone
                        reverseZoneInfo = _dnsServer.AuthZoneManager.CreatePrimaryZone(reverseZone);
                        if (reverseZoneInfo is null)
                        {
                            _log.Write("DHCP Server failed to create DNS primary zone '" + reverseZone + "'.");
                            return;
                        }

                        //set permissions
                        _authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _authManager.GetGroup(Group.DHCP_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SaveConfigFile();

                        _log.Write("DHCP Server create DNS primary zone '" + reverseZoneInfo.DisplayName + "'.");
                    }
                    else if ((reverseZoneInfo.Type != AuthZoneType.Primary) && (reverseZoneInfo.Type != AuthZoneType.Forwarder))
                    {
                        string reverseZone = Zone.GetReverseZone(address, scope.SubnetMask);

                        if (reverseZoneInfo.Name.Equals(reverseZone, StringComparison.OrdinalIgnoreCase))
                            throw new DhcpServerException("Cannot update reverse DNS zone '" + reverseZoneInfo.DisplayName + "': not a primary or a forwarder zone.");

                        //create new reverse primary zone
                        reverseZoneInfo = _dnsServer.AuthZoneManager.CreatePrimaryZone(reverseZone);
                        if (reverseZoneInfo is null)
                        {
                            _log.Write("DHCP Server failed to create DNS primary zone '" + reverseZone + "'.");
                            return;
                        }

                        //set permissions
                        _authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _authManager.GetGroup(Group.DHCP_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _authManager.SaveConfigFile();

                        _log.Write("DHCP Server create DNS primary zone '" + reverseZoneInfo.DisplayName + "'.");
                    }

                    reverseZoneName = reverseZoneInfo.Name;

                    DnsResourceRecord ptrRecord = new DnsResourceRecord(reverseDomain, DnsResourceRecordType.PTR, DnsClass.IN, scope.DnsTtl, new DnsPTRRecordData(domain));

                    GenericRecordInfo ptrRecordInfo = aRecord.GetAuthGenericRecordInfo();
                    ptrRecordInfo.LastModified = DateTime.UtcNow;
                    ptrRecordInfo.ExpiryTtl = scope.GetLeaseTime();
                    ptrRecordInfo.Comments = $"Via '{scope.Name}' DHCP scope";

                    _dnsServer.AuthZoneManager.SetRecord(reverseZoneName, ptrRecord);

                    _log.Write("DHCP Server updated DNS PTR record '" + reverseDomain + "' with domain name '" + domain + "'.");
                }
                else
                {
                    //remove from forward zone
                    AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.FindAuthZoneInfo(domain);
                    if ((zoneInfo is not null) && ((zoneInfo.Type == AuthZoneType.Primary) || (zoneInfo.Type == AuthZoneType.Forwarder)))
                    {
                        //primary zone exists
                        zoneName = zoneInfo.Name;
                        _dnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, DnsResourceRecordType.A, new DnsARecordData(address));
                        _log.Write("DHCP Server deleted DNS A record '" + domain + "' with address [" + address.ToString() + "].");
                    }

                    //remove from reverse zone
                    AuthZoneInfo reverseZoneInfo = _dnsServer.AuthZoneManager.FindAuthZoneInfo(reverseDomain);
                    if ((reverseZoneInfo != null) && ((reverseZoneInfo.Type == AuthZoneType.Primary) || (reverseZoneInfo.Type == AuthZoneType.Forwarder)))
                    {
                        //primary reverse zone exists
                        reverseZoneName = reverseZoneInfo.Name;
                        _dnsServer.AuthZoneManager.DeleteRecord(reverseZoneName, reverseDomain, DnsResourceRecordType.PTR, new DnsPTRRecordData(domain));
                        _log.Write("DHCP Server deleted DNS PTR record '" + reverseDomain + "' with domain '" + domain + "'.");
                    }
                }

                //save auth zone file
                if (zoneName is not null)
                    _dnsServer?.AuthZoneManager.SaveZoneFile(zoneName);

                //save reverse auth zone file
                if (reverseZoneName is not null)
                    _dnsServer?.AuthZoneManager.SaveZoneFile(reverseZoneName);
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
        }

        private void BindUdpListener(IPEndPoint dhcpEP)
        {
            UdpListener listener = _udpListeners.GetOrAdd(dhcpEP.Address, delegate (IPAddress key)
            {
                Socket udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

                try
                {
                    #region this code ignores ICMP port unreachable responses which creates SocketException in ReceiveFrom()

                    if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                    {
                        const uint IOC_IN = 0x80000000;
                        const uint IOC_VENDOR = 0x18000000;
                        const uint SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

                        udpSocket.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { Convert.ToByte(false) }, null);
                    }

                    #endregion

                    //bind to interface address
                    if (Environment.OSVersion.Platform == PlatformID.Unix)
                        udpSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1); //to allow binding to same port with different addresses

                    udpSocket.EnableBroadcast = true;
                    udpSocket.ExclusiveAddressUse = false;

                    udpSocket.Bind(dhcpEP);

                    //start reading dhcp packets
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return ReadUdpRequestAsync(udpSocket);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);

                    return new UdpListener(udpSocket);
                }
                catch
                {
                    udpSocket.Dispose();
                    throw;
                }
            });

            listener.IncrementScopeCount();
        }

        private bool UnbindUdpListener(IPEndPoint dhcpEP)
        {
            if (_udpListeners.TryGetValue(dhcpEP.Address, out UdpListener listener))
            {
                listener.DecrementScopeCount();

                if (listener.ScopeCount < 1)
                {
                    if (_udpListeners.TryRemove(dhcpEP.Address, out _))
                    {
                        listener.Socket.Dispose();
                        return true;
                    }
                }
            }

            return false;
        }

        private async Task<bool> ActivateScopeAsync(Scope scope, bool waitForInterface, bool throwException = false)
        {
            IPEndPoint dhcpEP = null;

            try
            {
                //find scope interface for binding socket
                if (waitForInterface)
                {
                    //retry for 30 seconds for interface to come up
                    int tries = 0;
                    while (true)
                    {
                        if (scope.FindInterface())
                        {
                            if (!scope.InterfaceAddress.Equals(IPAddress.Any))
                                break; //break only when specific interface address is found
                        }

                        if (++tries >= 30)
                        {
                            if (scope.InterfaceAddress == null)
                                throw new DhcpServerException("DHCP Server requires static IP address to work correctly but no network interface was found to have any static IP address configured.");

                            break; //use the available ANY interface address
                        }

                        await Task.Delay(1000);
                    }
                }
                else
                {
                    if (!scope.FindInterface())
                        throw new DhcpServerException("DHCP Server requires static IP address to work correctly but no network interface was found to have any static IP address configured.");
                }

                //find this dns server address in case the network config has changed
                if (scope.UseThisDnsServer)
                    scope.FindThisDnsServerAddress();

                dhcpEP = new IPEndPoint(scope.InterfaceAddress, 67);

                if (!dhcpEP.Address.Equals(IPAddress.Any))
                {
                    int tries = 0;

                    do
                    {
                        try
                        {
                            BindUdpListener(dhcpEP);
                            break;
                        }
                        catch
                        {
                            if (!waitForInterface || (++tries >= 3))
                                throw;

                            await Task.Delay(5000);
                        }
                    }
                    while (waitForInterface);
                }

                try
                {
                    BindUdpListener(_dhcpDefaultEP);
                }
                catch
                {
                    if (!dhcpEP.Address.Equals(IPAddress.Any))
                        UnbindUdpListener(dhcpEP);

                    throw;
                }

                if (_dnsServer is not null)
                {
                    //update valid leases into dns
                    DateTime utcNow = DateTime.UtcNow;

                    foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in scope.Leases)
                        UpdateDnsAuthZone(utcNow < lease.Value.LeaseExpires, scope, lease.Value); //lease valid
                }

                _log.Write(dhcpEP, "DHCP Server successfully activated scope: " + scope.Name);

                return true;
            }
            catch (Exception ex)
            {
                _log.Write(dhcpEP, "DHCP Server failed to activate scope: " + scope.Name + "\r\n" + ex.ToString());

                if (throwException)
                    throw;
            }

            return false;
        }

        private bool DeactivateScope(Scope scope, bool throwException = false)
        {
            IPEndPoint dhcpEP = null;

            try
            {
                IPAddress interfaceAddress = scope.InterfaceAddress;
                dhcpEP = new IPEndPoint(interfaceAddress, 67);

                if (!interfaceAddress.Equals(IPAddress.Any))
                    UnbindUdpListener(dhcpEP);

                UnbindUdpListener(_dhcpDefaultEP);

                if (_dnsServer is not null)
                {
                    //remove all leases from dns
                    foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in scope.Leases)
                        UpdateDnsAuthZone(false, scope, lease.Value);
                }

                _log.Write(dhcpEP, "DHCP Server successfully deactivated scope: " + scope.Name);

                return true;
            }
            catch (Exception ex)
            {
                _log.Write(dhcpEP, "DHCP Server failed to deactivate scope: " + scope.Name + "\r\n" + ex.ToString());

                if (throwException)
                    throw;
            }

            return false;
        }

        private async Task LoadScopeAsync(Scope scope, bool waitForInterface)
        {
            foreach (KeyValuePair<string, Scope> entry in _scopes)
            {
                Scope existingScope = entry.Value;

                if (existingScope.IsAddressInRange(scope.StartingAddress) || existingScope.IsAddressInRange(scope.EndingAddress))
                    throw new DhcpServerException("Scope with overlapping range already exists: " + existingScope.StartingAddress.ToString() + "-" + existingScope.EndingAddress.ToString());
            }

            if (!_scopes.TryAdd(scope.Name, scope))
                throw new DhcpServerException("Scope with same name already exists.");

            if (scope.Enabled)
            {
                if (!await ActivateScopeAsync(scope, waitForInterface))
                    scope.SetEnabled(false);
            }

            _log.Write("DHCP Server successfully loaded scope: " + scope.Name);
        }

        private void UnloadScope(Scope scope)
        {
            if (scope.Enabled)
                DeactivateScope(scope);

            if (_scopes.TryRemove(scope.Name, out Scope removedScope))
            {
                removedScope.Dispose();

                _log.Write("DHCP Server successfully unloaded scope: " + scope.Name);
            }
        }

        private void LoadAllScopeFiles()
        {
            string[] scopeFiles = Directory.GetFiles(_scopesFolder, "*.scope");

            foreach (string scopeFile in scopeFiles)
                _ = LoadScopeFileAsync(scopeFile);

            _lastModifiedScopesSavedOn = DateTime.UtcNow;
        }

        private async Task LoadScopeFileAsync(string scopeFile)
        {
            //load scope file async to allow waiting for interface to come up
            try
            {
                using (FileStream fS = new FileStream(scopeFile, FileMode.Open, FileAccess.Read))
                {
                    await LoadScopeAsync(new Scope(fS, _log, this), true);
                }
            }
            catch (Exception ex)
            {
                _log.Write("DHCP Server failed to load scope file: " + scopeFile + "\r\n" + ex.ToString());
            }
        }

        private void SaveScopeFile(Scope scope)
        {
            string scopeFile = Path.Combine(_scopesFolder, scope.Name + ".scope");

            try
            {
                using (MemoryStream mS = new MemoryStream())
                {
                    //serialize scope
                    scope.WriteTo(mS);

                    //write config
                    mS.Position = 0;

                    using (FileStream fS = new FileStream(scopeFile, FileMode.Create, FileAccess.Write))
                    {
                        mS.CopyTo(fS);
                    }
                }

                _log.Write("DHCP Server successfully saved scope file: " + scopeFile);
            }
            catch (Exception ex)
            {
                _log.Write("DHCP Server failed to save scope file: " + scopeFile + "\r\n" + ex.ToString());
            }
        }

        private void DeleteScopeFile(string scopeName)
        {
            string scopeFile = Path.Combine(_scopesFolder, scopeName + ".scope");

            try
            {
                File.Delete(scopeFile);

                _log.Write("DHCP Server successfully deleted scope file: " + scopeFile);
            }
            catch (Exception ex)
            {
                _log.Write("DHCP Server failed to delete scope file: " + scopeFile + "\r\n" + ex.ToString());
            }
        }

        private void SaveModifiedScopes()
        {
            DateTime currentDateTime = DateTime.UtcNow;

            foreach (KeyValuePair<string, Scope> scope in _scopes)
            {
                if (scope.Value.LastModified > _lastModifiedScopesSavedOn)
                    SaveScopeFile(scope.Value);
            }

            _lastModifiedScopesSavedOn = currentDateTime;
        }

        private void StartMaintenanceTimer()
        {
            if (_maintenanceTimer == null)
            {
                _maintenanceTimer = new Timer(delegate (object state)
                {
                    try
                    {
                        foreach (KeyValuePair<string, Scope> scope in _scopes)
                        {
                            scope.Value.RemoveExpiredOffers();

                            List<Lease> expiredLeases = scope.Value.RemoveExpiredLeases();
                            if (expiredLeases.Count > 0)
                            {
                                _log.Write("DHCP Server removed " + expiredLeases.Count + " lease(s) from scope: " + scope.Value.Name);

                                foreach (Lease expiredLease in expiredLeases)
                                    UpdateDnsAuthZone(false, scope.Value, expiredLease);
                            }
                        }

                        SaveModifiedScopes();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                    finally
                    {
                        if (!_disposed)
                            _maintenanceTimer.Change(MAINTENANCE_TIMER_INTERVAL, Timeout.Infinite);
                    }
                }, null, Timeout.Infinite, Timeout.Infinite);
            }

            _maintenanceTimer.Change(MAINTENANCE_TIMER_INTERVAL, Timeout.Infinite);
        }

        private void StopMaintenanceTimer()
        {
            _maintenanceTimer.Change(Timeout.Infinite, Timeout.Infinite);
        }

        #endregion

        #region public

        public void Start()
        {
            if (_disposed)
                ObjectDisposedException.ThrowIf(_disposed, this);

            if (_state != ServiceState.Stopped)
                throw new InvalidOperationException("DHCP Server is already running.");

            _state = ServiceState.Starting;

            LoadAllScopeFiles();
            StartMaintenanceTimer();

            _state = ServiceState.Running;
        }

        public void Stop()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            StopMaintenanceTimer();

            SaveModifiedScopes();

            foreach (KeyValuePair<string, Scope> scope in _scopes)
                UnloadScope(scope.Value);

            _udpListeners.Clear();

            _state = ServiceState.Stopped;
        }

        public async Task AddScopeAsync(Scope scope)
        {
            await LoadScopeAsync(scope, false);
            SaveScopeFile(scope);
        }

        public Scope GetScope(string name)
        {
            if (_scopes.TryGetValue(name, out Scope scope))
                return scope;

            return null;
        }

        public void RenameScope(string oldName, string newName)
        {
            Scope.ValidateScopeName(newName);

            if (!_scopes.TryGetValue(oldName, out Scope scope))
                throw new DhcpServerException("Scope with name '" + oldName + "' does not exists.");

            if (!_scopes.TryAdd(newName, scope))
                throw new DhcpServerException("Scope with name '" + newName + "' already exists.");

            scope.Name = newName;
            _scopes.TryRemove(oldName, out _);

            SaveScopeFile(scope);
            DeleteScopeFile(oldName);
        }

        public void DeleteScope(string name)
        {
            if (_scopes.TryGetValue(name, out Scope scope))
            {
                UnloadScope(scope);
                DeleteScopeFile(scope.Name);
            }
        }

        public async Task<bool> EnableScopeAsync(string name, bool throwException = false)
        {
            if (_scopes.TryGetValue(name, out Scope scope))
            {
                if (!scope.Enabled && await ActivateScopeAsync(scope, false, throwException))
                {
                    scope.SetEnabled(true);
                    SaveScopeFile(scope);

                    return true;
                }
            }

            return false;
        }

        public bool DisableScope(string name, bool throwException = false)
        {
            if (_scopes.TryGetValue(name, out Scope scope))
            {
                if (scope.Enabled && DeactivateScope(scope, throwException))
                {
                    scope.SetEnabled(false);
                    SaveScopeFile(scope);

                    return true;
                }
            }

            return false;
        }

        public void SaveScope(string name)
        {
            if (_scopes.TryGetValue(name, out Scope scope))
                SaveScopeFile(scope);
        }

        public IDictionary<string, string> GetAddressHostNameMap()
        {
            Dictionary<string, string> map = new Dictionary<string, string>();

            foreach (KeyValuePair<string, Scope> scope in _scopes)
            {
                foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in scope.Value.Leases)
                {
                    if (!string.IsNullOrEmpty(lease.Value.HostName))
                        map.Add(lease.Value.Address.ToString(), lease.Value.HostName);
                }
            }

            return map;
        }

        #endregion

        #region properties

        public IReadOnlyDictionary<string, Scope> Scopes
        { get { return _scopes; } }

        public DnsServer DnsServer
        {
            get { return _dnsServer; }
            set { _dnsServer = value; }
        }

        internal AuthManager AuthManager
        {
            get { return _authManager; }
            set { _authManager = value; }
        }

        #endregion

        class UdpListener
        {
            #region private

            readonly Socket _socket;
            volatile int _scopeCount;

            #endregion

            #region constructor

            public UdpListener(Socket socket)
            {
                _socket = socket;
            }

            #endregion

            #region public

            public void IncrementScopeCount()
            {
                Interlocked.Increment(ref _scopeCount);
            }

            public void DecrementScopeCount()
            {
                Interlocked.Decrement(ref _scopeCount);
            }

            #endregion

            #region properties

            public Socket Socket
            { get { return _socket; } }

            public int ScopeCount
            { get { return _scopeCount; } }

            #endregion
        }
    }
}
