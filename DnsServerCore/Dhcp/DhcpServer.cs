/*
Technitium DNS Server
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using DnsServerCore.Dns.ZoneManagers;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dhcp
{
    //Dynamic Host Configuration Protocol
    //https://tools.ietf.org/html/rfc2131

    //DHCP Options and BOOTP Vendor Extensions
    //https://tools.ietf.org/html/rfc2132

    //Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4)
    //https://tools.ietf.org/html/rfc3396

    //Client Fully Qualified Domain Name(FQDN) Option
    //https://tools.ietf.org/html/rfc4702

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
        LogManager _log;

        readonly ConcurrentDictionary<IPAddress, UdpListener> _udpListeners = new ConcurrentDictionary<IPAddress, UdpListener>();

        readonly ConcurrentDictionary<string, Scope> _scopes = new ConcurrentDictionary<string, Scope>();

        AuthZoneManager _authZoneManager;

        volatile ServiceState _state = ServiceState.Stopped;

        readonly IPEndPoint _dhcpDefaultEP = new IPEndPoint(IPAddress.Any, 67);

        Timer _maintenanceTimer;
        const int MAINTENANCE_TIMER_INTERVAL = 10000;

        DateTime _lastModifiedScopesSavedOn;

        #endregion

        #region constructor

        public DhcpServer(string scopesFolder, LogManager log = null)
        {
            _scopesFolder = scopesFolder;
            _log = log;

            if (!Directory.Exists(_scopesFolder))
            {
                Directory.CreateDirectory(_scopesFolder);

                //create default scope
                Scope scope = new Scope("Default", false, IPAddress.Parse("192.168.1.1"), IPAddress.Parse("192.168.1.254"), IPAddress.Parse("255.255.255.0"));
                scope.Exclusions = new Exclusion[] { new Exclusion(IPAddress.Parse("192.168.1.1"), IPAddress.Parse("192.168.1.10")) };
                scope.RouterAddress = IPAddress.Parse("192.168.1.1");
                scope.UseThisDnsServer = true;
                scope.DomainName = "local";
                scope.LeaseTimeDays = 7;

                SaveScopeFile(scope);
            }
        }

        #endregion

        #region IDisposable

        private bool _disposed = false;

        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                Stop();

                if (_maintenanceTimer != null)
                    _maintenanceTimer.Dispose();

                SaveModifiedScopes();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private void ReadUdpRequestAsync(object parameter)
        {
            Socket udpListener = parameter as Socket;
            EndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);
            byte[] recvBuffer = new byte[576];
            int bytesRecv;

            try
            {
                bool processOnlyUnicastMessages = !(udpListener.LocalEndPoint as IPEndPoint).Address.Equals(IPAddress.Any); //only 0.0.0.0 ip should process broadcast to avoid duplicate offers on Windows

                while (true)
                {
                    SocketFlags flags = SocketFlags.None;
                    IPPacketInformation ipPacketInformation;

                    try
                    {
                        bytesRecv = udpListener.ReceiveMessageFrom(recvBuffer, 0, recvBuffer.Length, ref flags, ref remoteEP, out ipPacketInformation);
                    }
                    catch (SocketException ex)
                    {
                        switch (ex.SocketErrorCode)
                        {
                            case SocketError.ConnectionReset:
                            case SocketError.HostUnreachable:
                            case SocketError.MessageSize:
                            case SocketError.NetworkReset:
                                bytesRecv = 0;
                                break;

                            default:
                                throw;
                        }
                    }

                    if (bytesRecv > 0)
                    {
                        if (processOnlyUnicastMessages && ipPacketInformation.Address.Equals(IPAddress.Broadcast))
                            continue;

                        switch ((remoteEP as IPEndPoint).Port)
                        {
                            case 67:
                            case 68:
                                try
                                {
                                    DhcpMessage request = new DhcpMessage(new MemoryStream(recvBuffer, 0, bytesRecv, false));
                                    _ = ProcessDhcpRequestAsync(request, remoteEP as IPEndPoint, ipPacketInformation, udpListener);
                                }
                                catch (Exception ex)
                                {
                                    LogManager log = _log;
                                    if (log != null)
                                        log.Write(remoteEP as IPEndPoint, ex);
                                }

                                break;
                        }
                    }
                }
            }
            catch (ObjectDisposedException)
            {
                //socket disposed
            }
            catch (SocketException ex)
            {
                switch (ex.SocketErrorCode)
                {
                    case SocketError.Interrupted:
                        break; //server stopping

                    default:
                        LogManager log = _log;
                        if (log != null)
                            log.Write(remoteEP as IPEndPoint, ex);

                        throw;
                }
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                LogManager log = _log;
                if (log != null)
                    log.Write(remoteEP as IPEndPoint, ex);

                throw;
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
                        await udpListener.SendToAsync(sendBuffer, 0, (int)sendBufferStream.Position, new IPEndPoint(request.RelayAgentIpAddress, 67));
                    }
                    else if (!request.ClientIpAddress.Equals(IPAddress.Any))
                    {
                        //client is already configured and renewing lease so send unicast response on port 68
                        await udpListener.SendToAsync(sendBuffer, 0, (int)sendBufferStream.Position, new IPEndPoint(request.ClientIpAddress, 68));
                    }
                    else
                    {
                        Socket udpSocket;

                        //send response as broadcast on port 68 on appropriate interface bound socket
                        if (_udpListeners.TryGetValue(response.NextServerIpAddress, out UdpListener listener))
                            udpSocket = listener.Socket; //found scope specific socket
                        else
                            udpSocket = udpListener; //no appropriate socket found so use default socket

                        await udpSocket.SendToAsync(sendBuffer, 0, (int)sendBufferStream.Position, new IPEndPoint(IPAddress.Broadcast, 68), SocketFlags.DontRoute); //no routing for broadcast
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

                LogManager log = _log;
                if (log != null)
                    log.Write(remoteEP, ex);
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

                        if (scope.OfferDelayTime > 0)
                            await Task.Delay(scope.OfferDelayTime); //delay sending offer

                        Lease offer = scope.GetOffer(request);
                        if (offer == null)
                            return null; //no offer available, do nothing

                        List<DhcpOption> options = scope.GetOptions(request, scope.InterfaceAddress);
                        if (options == null)
                            return null;

                        //log ip offer
                        LogManager log = _log;
                        if (log != null)
                            log.Write(remoteEP, "DHCP Server offered IP address [" + offer.Address.ToString() + "] to " + request.GetClientFullIdentifier() + ".");

                        return new DhcpMessage(request, offer.Address, scope.InterfaceAddress, options);
                    }

                case DhcpMessageType.Request:
                    {
                        //request ip address lease or extend existing lease
                        Scope scope = FindScope(request, remoteEP.Address, ipPacketInformation);
                        if (scope == null)
                            return null; //no scope available; do nothing

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
                                    return new DhcpMessage(request, IPAddress.Any, scope.InterfaceAddress, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                                }

                                if (!request.ClientIpAddress.Equals(leaseOffer.Address))
                                {
                                    //client ip is incorrect
                                    //send nak
                                    return new DhcpMessage(request, IPAddress.Any, scope.InterfaceAddress, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
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
                                    return new DhcpMessage(request, IPAddress.Any, scope.InterfaceAddress, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                                }

                                if (!request.RequestedIpAddress.Address.Equals(leaseOffer.Address))
                                {
                                    //the client's notion of its IP address is not correct - RFC 2131
                                    //send nak
                                    return new DhcpMessage(request, IPAddress.Any, scope.InterfaceAddress, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                                }
                            }
                        }
                        else
                        {
                            //selecting offer

                            if (request.RequestedIpAddress == null)
                                return null; //client MUST include this option; do nothing

                            if (!request.ServerIdentifier.Address.Equals(scope.InterfaceAddress))
                                return null; //offer declined by client; do nothing

                            leaseOffer = scope.GetExistingLeaseOrOffer(request);
                            if (leaseOffer == null)
                            {
                                //no existing lease or offer available for client
                                //send nak
                                return new DhcpMessage(request, IPAddress.Any, scope.InterfaceAddress, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                            }

                            if (!request.RequestedIpAddress.Address.Equals(leaseOffer.Address))
                            {
                                //requested ip is incorrect
                                //send nak
                                return new DhcpMessage(request, IPAddress.Any, scope.InterfaceAddress, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(scope.InterfaceAddress), DhcpOption.CreateEndOption() });
                            }
                        }

                        List<DhcpOption> options = scope.GetOptions(request, scope.InterfaceAddress);
                        if (options == null)
                            return null;

                        scope.CommitLease(leaseOffer);

                        //log ip lease
                        LogManager log = _log;
                        if (log != null)
                            log.Write(remoteEP, "DHCP Server leased IP address [" + leaseOffer.Address.ToString() + "] to " + request.GetClientFullIdentifier() + ".");

                        //update hostname in reserved leases
                        if (request.HostName != null)
                        {
                            Lease reservedLease = scope.GetReservedLease(leaseOffer.ClientIdentifier);
                            if (reservedLease != null)
                                reservedLease.SetHostName(request.HostName.HostName);
                        }

                        if (string.IsNullOrWhiteSpace(scope.DomainName))
                        {
                            //update lease hostname
                            leaseOffer.SetHostName(request.HostName?.HostName);
                        }
                        else
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
                                if (request.HostName != null)
                                    clientDomainName = request.HostName.HostName.Replace(' ', '-') + "." + scope.DomainName;
                            }

                            if (!string.IsNullOrWhiteSpace(clientDomainName))
                            {
                                leaseOffer.SetHostName(clientDomainName.ToLower());
                                UpdateDnsAuthZone(true, scope, leaseOffer);
                            }
                        }

                        return new DhcpMessage(request, leaseOffer.Address, scope.InterfaceAddress, options);
                    }

                case DhcpMessageType.Decline:
                    {
                        //ip address is already in use as detected by client via ARP

                        if ((request.ServerIdentifier == null) || (request.RequestedIpAddress == null))
                            return null; //client MUST include these option; do nothing

                        Scope scope = FindScope(request, remoteEP.Address, ipPacketInformation);
                        if (scope == null)
                            return null; //no scope available; do nothing

                        if (!request.ServerIdentifier.Address.Equals(scope.InterfaceAddress))
                            return null; //request not for this server; do nothing

                        Lease lease = scope.GetExistingLeaseOrOffer(request);
                        if (lease == null)
                            return null; //no existing lease or offer available for client; do nothing

                        if (!lease.Address.Equals(request.RequestedIpAddress.Address))
                            return null; //the client's notion of its IP address is not correct; do nothing

                        //remove lease since the IP address is used by someone else
                        scope.ReleaseLease(lease);

                        //log issue
                        LogManager log = _log;
                        if (log != null)
                            log.Write(remoteEP, "DHCP Server received DECLINE message: " + lease.GetClientFullIdentifier() + " detected that IP address [" + lease.Address + "] is already in use.");

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

                        if (!request.ServerIdentifier.Address.Equals(scope.InterfaceAddress))
                            return null; //request not for this server; do nothing

                        Lease lease = scope.GetExistingLeaseOrOffer(request);
                        if (lease == null)
                            return null; //no existing lease or offer available for client; do nothing

                        if (!lease.Address.Equals(request.ClientIpAddress))
                            return null; //the client's notion of its IP address is not correct; do nothing

                        //release lease
                        scope.ReleaseLease(lease);

                        //log ip lease release
                        LogManager log = _log;
                        if (log != null)
                            log.Write(remoteEP, "DHCP Server released IP address [" + lease.Address.ToString() + "] that was leased to " + lease.GetClientFullIdentifier() + ".");

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

                        //log inform
                        LogManager log = _log;
                        if (log != null)
                            log.Write(remoteEP, "DHCP Server received INFORM message from " + request.GetClientFullIdentifier() + ".");

                        List<DhcpOption> options = scope.GetOptions(request, scope.InterfaceAddress);
                        if (options == null)
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
                                if (request.HostName != null)
                                    clientDomainName = request.HostName.HostName.Replace(' ', '-') + "." + scope.DomainName;
                            }

                            if (!string.IsNullOrWhiteSpace(clientDomainName))
                                UpdateDnsAuthZone(true, scope, clientDomainName, request.ClientIpAddress);
                        }

                        return new DhcpMessage(request, IPAddress.Any, scope.InterfaceAddress, options);
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

                    foreach (Scope scope in _scopes.Values)
                    {
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
                    if (!remoteAddress.Equals(request.ClientIpAddress))
                        return null; //client ip must match udp src addr

                    //unicast request
                    foreach (Scope scope in _scopes.Values)
                    {
                        if (scope.Enabled && scope.IsAddressInRange(remoteAddress))
                            return scope;
                    }

                    return null;
                }
            }
            else
            {
                //relay agent unicast
                Scope foundScope = null;

                foreach (Scope scope in _scopes.Values)
                {
                    if (scope.Enabled && scope.InterfaceAddress.Equals(IPAddress.Any))
                    {
                        if (scope.GetReservedLease(request) != null)
                            return scope; //found reserved lease on this scope

                        if (!request.ClientIpAddress.Equals(IPAddress.Any) && scope.IsAddressInRange(request.ClientIpAddress))
                            foundScope = scope; //client IP address is in scope range
                        else if ((foundScope == null) && scope.IsAddressInRange(request.RelayAgentIpAddress))
                            foundScope = scope; //relay agent IP address is in scope range
                    }
                }

                return foundScope;
            }
        }

        private void UpdateDnsAuthZone(bool add, Scope scope, Lease lease)
        {
            UpdateDnsAuthZone(add, scope, lease.HostName, lease.Address);
        }

        private void UpdateDnsAuthZone(bool add, Scope scope, string domain, IPAddress address)
        {
            if (_authZoneManager == null)
                return;

            if (string.IsNullOrWhiteSpace(scope.DomainName))
                return;

            if (string.IsNullOrWhiteSpace(domain))
                return;

            if (!DnsClient.IsDomainNameValid(domain))
                return;

            try
            {
                if (add)
                {
                    //update forward zone
                    _authZoneManager.CreatePrimaryZone(scope.DomainName, _authZoneManager.ServerDomain, false);
                    _authZoneManager.SetRecords(domain, DnsResourceRecordType.A, scope.DnsTtl, new DnsResourceRecordData[] { new DnsARecord(address) });

                    //update reverse zone
                    _authZoneManager.CreatePrimaryZone(Zone.GetReverseZone(address, scope.SubnetMask), _authZoneManager.ServerDomain, false);
                    _authZoneManager.SetRecords(Zone.GetReverseZone(address, 32), DnsResourceRecordType.PTR, scope.DnsTtl, new DnsResourceRecordData[] { new DnsPTRRecord(domain) });
                }
                else
                {
                    //remove from forward zone
                    _authZoneManager.DeleteRecords(domain, DnsResourceRecordType.A);

                    //remove from reverse zone
                    _authZoneManager.DeleteRecords(Zone.GetReverseZone(address, 32), DnsResourceRecordType.PTR);
                }
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write(ex);
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
                    Thread thread = new Thread(ReadUdpRequestAsync);
                    thread.Name = "DHCP Read Request: " + dhcpEP.ToString();
                    thread.IsBackground = true;
                    thread.Start(udpSocket);

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
                        //issue: https://github.com/dotnet/runtime/issues/37873

                        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                        {
                            listener.Socket.Dispose();
                        }
                        else
                        {
                            ThreadPool.QueueUserWorkItem(delegate (object state)
                            {
                                listener.Socket.Dispose();
                            });
                        }

                        return true;
                    }
                }
            }

            return false;
        }

        private async Task<bool> ActivateScopeAsync(Scope scope, bool waitForInterface)
        {
            IPEndPoint dhcpEP = null;

            try
            {
                //find this dns server address in case the network config has changed
                if (scope.UseThisDnsServer)
                    scope.FindThisDnsServerAddress();

                //find scope interface for binding socket
                if (waitForInterface)
                {
                    //retry for 30 seconds for interface to come up
                    int tries = 0;
                    while (true)
                    {
                        if (scope.FindInterface())
                            break;

                        if (++tries >= 30)
                            throw new DhcpServerException("DHCP Server requires static IP address to work correctly but no network interface was found to have any static IP address configured.");

                        await Task.Delay(1000);
                    }
                }
                else
                {
                    if (!scope.FindInterface())
                        throw new DhcpServerException("DHCP Server requires static IP address to work correctly but no network interface was found to have any static IP address configured.");
                }

                IPAddress interfaceAddress = scope.InterfaceAddress;
                dhcpEP = new IPEndPoint(interfaceAddress, 67);

                if (!interfaceAddress.Equals(IPAddress.Any))
                    BindUdpListener(dhcpEP);

                try
                {
                    BindUdpListener(_dhcpDefaultEP);
                }
                catch
                {
                    if (!interfaceAddress.Equals(IPAddress.Any))
                        UnbindUdpListener(dhcpEP);

                    throw;
                }

                if (_authZoneManager != null)
                {
                    //update valid leases into dns
                    DateTime utcNow = DateTime.UtcNow;

                    foreach (Lease lease in scope.Leases)
                        UpdateDnsAuthZone(utcNow < lease.LeaseExpires, scope, lease); //lease valid
                }

                LogManager log = _log;
                if (log != null)
                    log.Write(dhcpEP, "DHCP Server successfully activated scope: " + scope.Name);

                return true;
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write(dhcpEP, "DHCP Server failed to activate scope: " + scope.Name + "\r\n" + ex.ToString());
            }

            return false;
        }

        private bool DeactivateScope(Scope scope)
        {
            IPEndPoint dhcpEP = null;

            try
            {
                IPAddress interfaceAddress = scope.InterfaceAddress;
                dhcpEP = new IPEndPoint(interfaceAddress, 67);

                if (!interfaceAddress.Equals(IPAddress.Any))
                    UnbindUdpListener(dhcpEP);

                UnbindUdpListener(_dhcpDefaultEP);

                if (_authZoneManager != null)
                {
                    //remove all leases from dns
                    foreach (Lease lease in scope.Leases)
                        UpdateDnsAuthZone(false, scope, lease);
                }

                LogManager log = _log;
                if (log != null)
                    log.Write(dhcpEP, "DHCP Server successfully deactivated scope: " + scope.Name);

                return true;
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write(dhcpEP, "DHCP Server failed to deactivate scope: " + scope.Name + "\r\n" + ex.ToString());
            }

            return false;
        }

        private async Task LoadScopeAsync(Scope scope, bool waitForInterface)
        {
            foreach (Scope existingScope in _scopes.Values)
            {
                if (existingScope.IsAddressInRange(scope.StartingAddress) || existingScope.IsAddressInRange(scope.EndingAddress))
                    throw new DhcpServerException("Scope with overlapping range already exists.");
            }

            if (!_scopes.TryAdd(scope.Name, scope))
                throw new DhcpServerException("Scope with same name already exists.");

            if (scope.Enabled)
            {
                if (!await ActivateScopeAsync(scope, waitForInterface))
                    scope.SetEnabled(false);
            }

            LogManager log = _log;
            if (log != null)
                log.Write("DHCP Server successfully loaded scope: " + scope.Name);
        }

        private void UnloadScope(Scope scope)
        {
            if (scope.Enabled)
                DeactivateScope(scope);

            if (_scopes.TryRemove(scope.Name, out _))
            {
                LogManager log = _log;
                if (log != null)
                    log.Write("DHCP Server successfully unloaded scope: " + scope.Name);
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
                    await LoadScopeAsync(new Scope(new BinaryReader(fS)), true);
                }

                LogManager log = _log;
                if (log != null)
                    log.Write("DHCP Server successfully loaded scope file: " + scopeFile);
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write("DHCP Server failed to load scope file: " + scopeFile + "\r\n" + ex.ToString());
            }
        }

        private void SaveScopeFile(Scope scope)
        {
            string scopeFile = Path.Combine(_scopesFolder, scope.Name + ".scope");

            try
            {
                using (FileStream fS = new FileStream(scopeFile, FileMode.Create, FileAccess.Write))
                {
                    scope.WriteTo(new BinaryWriter(fS));
                }

                LogManager log = _log;
                if (log != null)
                    log.Write("DHCP Server successfully saved scope file: " + scopeFile);
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write("DHCP Server failed to save scope file: " + scopeFile + "\r\n" + ex.ToString());
            }
        }

        private void DeleteScopeFile(string scopeName)
        {
            string scopeFile = Path.Combine(_scopesFolder, scopeName + ".scope");

            try
            {
                File.Delete(scopeFile);

                LogManager log = _log;
                if (log != null)
                    log.Write("DHCP Server successfully deleted scope file: " + scopeFile);
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write("DHCP Server failed to delete scope file: " + scopeFile + "\r\n" + ex.ToString());
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

                            foreach (Lease expiredLease in expiredLeases)
                                UpdateDnsAuthZone(false, scope.Value, expiredLease);
                        }

                        SaveModifiedScopes();
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
                throw new ObjectDisposedException("DhcpServer");

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

        public async Task<bool> EnableScopeAsync(string name)
        {
            if (_scopes.TryGetValue(name, out Scope scope))
            {
                if (!scope.Enabled && await ActivateScopeAsync(scope, false))
                {
                    scope.SetEnabled(true);
                    SaveScopeFile(scope);

                    return true;
                }
            }

            return false;
        }

        public bool DisableScope(string name)
        {
            if (_scopes.TryGetValue(name, out Scope scope))
            {
                if (scope.Enabled && DeactivateScope(scope))
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

        public IDictionary<string, string> GetAddressClientMap()
        {
            Dictionary<string, string> map = new Dictionary<string, string>();

            foreach (KeyValuePair<string, Scope> scope in _scopes)
            {
                foreach (Lease lease in scope.Value.Leases)
                {
                    if (!string.IsNullOrEmpty(lease.HostName))
                        map.Add(lease.Address.ToString(), lease.HostName);
                }
            }

            return map;
        }

        #endregion

        #region properties

        public ICollection<Scope> Scopes
        { get { return _scopes.Values; } }

        public AuthZoneManager AuthZoneManager
        {
            get { return _authZoneManager; }
            set { _authZoneManager = value; }
        }

        public LogManager LogManager
        {
            get { return _log; }
            set { _log = value; }
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
