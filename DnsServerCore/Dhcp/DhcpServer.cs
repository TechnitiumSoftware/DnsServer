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
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
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

    public class DhcpServer : IDisposable
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

        readonly string _configFolder;

        readonly ConcurrentDictionary<IPAddress, Socket> _udpListeners = new ConcurrentDictionary<IPAddress, Socket>();
        readonly List<Thread> _listenerThreads = new List<Thread>();

        readonly ConcurrentDictionary<string, Scope> _scopes = new ConcurrentDictionary<string, Scope>();

        string _serverDomain = Environment.MachineName;
        AuthZoneManager _authZoneManager;
        LogManager _log;

        int _activeScopeCount = 0;
        readonly object _activeScopeLock = new object();

        volatile ServiceState _state = ServiceState.Stopped;

        readonly IPEndPoint _dhcpDefaultEP = new IPEndPoint(IPAddress.Any, 67);

        Timer _maintenanceTimer;
        const int MAINTENANCE_TIMER_INTERVAL = 10000;

        DateTime _lastModifiedScopesSavedOn;

        #endregion

        #region constructor

        public DhcpServer(string configFolder)
        {
            _configFolder = configFolder;

            if (!Directory.Exists(_configFolder))
            {
                Directory.CreateDirectory(_configFolder);

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

        protected virtual void Dispose(bool disposing)
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
                                    ThreadPool.QueueUserWorkItem(ProcessUdpRequestAsync, new object[] { udpListener, remoteEP, ipPacketInformation, new DhcpMessage(new MemoryStream(recvBuffer, 0, bytesRecv, false)) });
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

        private void ProcessUdpRequestAsync(object parameter)
        {
            object[] parameters = parameter as object[];

            Socket udpListener = parameters[0] as Socket;
            EndPoint remoteEP = parameters[1] as EndPoint;
            IPPacketInformation ipPacketInformation = (IPPacketInformation)parameters[2];
            DhcpMessage request = parameters[3] as DhcpMessage;

            try
            {
                DhcpMessage response = ProcessDhcpMessage(request, remoteEP as IPEndPoint, ipPacketInformation);

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
                        udpListener.SendTo(sendBuffer, 0, (int)sendBufferStream.Position, SocketFlags.None, new IPEndPoint(request.RelayAgentIpAddress, 67));
                    }
                    else if (!request.ClientIpAddress.Equals(IPAddress.Any))
                    {
                        //client is already configured and renewing lease so send unicast response on port 68
                        udpListener.SendTo(sendBuffer, 0, (int)sendBufferStream.Position, SocketFlags.None, new IPEndPoint(request.ClientIpAddress, 68));
                    }
                    else
                    {
                        //send response as broadcast on port 68 on appropriate interface bound socket
                        if (!_udpListeners.TryGetValue(response.NextServerIpAddress, out Socket udpSocket))
                            udpSocket = udpListener; //no appropriate socket found so use default socket

                        udpSocket.SendTo(sendBuffer, 0, (int)sendBufferStream.Position, SocketFlags.DontRoute, new IPEndPoint(IPAddress.Broadcast, 68)); //no routing for broadcast
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
                    log.Write(remoteEP as IPEndPoint, ex);
            }
        }

        private DhcpMessage ProcessDhcpMessage(DhcpMessage request, IPEndPoint remoteEP, IPPacketInformation ipPacketInformation)
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
                            Thread.Sleep(scope.OfferDelayTime); //delay sending offer

                        Lease offer = scope.GetOffer(request);
                        if (offer == null)
                            return null; //no offer available, do nothing

                        List<DhcpOption> options = scope.GetOptions(request, scope.InterfaceAddress);
                        if (options == null)
                            return null;

                        //log ip offer
                        LogManager log = _log;
                        if (log != null)
                            log.Write(remoteEP as IPEndPoint, "DHCP Server offered IP address [" + offer.Address.ToString() + "] to " + request.GetClientFullIdentifier() + ".");

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
                            log.Write(remoteEP as IPEndPoint, "DHCP Server leased IP address [" + leaseOffer.Address.ToString() + "] to " + request.GetClientFullIdentifier() + ".");

                        //update hostname in reserved leases
                        if ((request.HostName != null) && (scope.ReservedLeases != null))
                        {
                            foreach (Lease reservedLease in scope.ReservedLeases)
                            {
                                if (reservedLease.ClientIdentifier.Equals(leaseOffer.ClientIdentifier))
                                {
                                    reservedLease.SetHostName(request.HostName.HostName);
                                    break;
                                }
                            }
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
                            log.Write(remoteEP as IPEndPoint, "DHCP Server received DECLINE message: " + lease.GetClientFullIdentifier() + " detected that IP address [" + lease.Address + "] is already in use.");

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
                            log.Write(remoteEP as IPEndPoint, "DHCP Server released IP address [" + lease.Address.ToString() + "] that was leased to " + lease.GetClientFullIdentifier() + ".");

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

                        List<DhcpOption> options = scope.GetOptions(request, scope.InterfaceAddress);
                        if (options == null)
                            return null;

                        //log inform
                        LogManager log = _log;
                        if (log != null)
                            log.Write(remoteEP as IPEndPoint, "DHCP Server received INFORM message from " + request.GetClientFullIdentifier() + ".");

                        return new DhcpMessage(request, IPAddress.Any, scope.InterfaceAddress, options);
                    }

                default:
                    return null;
            }
        }

        private Scope FindScope(DhcpMessage request, IPAddress remoteAddress, IPPacketInformation ipPacketInformation)
        {
            bool broadcast;

            if (request.RelayAgentIpAddress.Equals(IPAddress.Any))
            {
                //no relay agent
                if (request.ClientIpAddress.Equals(IPAddress.Any))
                {
                    if (!ipPacketInformation.Address.Equals(IPAddress.Broadcast))
                        return null; //message destination address must be broadcast address

                    broadcast = true; //broadcast request
                }
                else
                {
                    if (!remoteAddress.Equals(request.ClientIpAddress))
                        return null; //client ip must match udp src addr

                    broadcast = false; //unicast request
                }
            }
            else
            {
                //relay agent unicast

                if (!remoteAddress.Equals(request.RelayAgentIpAddress))
                    return null; //relay ip must match udp src addr

                broadcast = false; //unicast request
            }

            if (broadcast)
            {
                foreach (KeyValuePair<string, Scope> scope in _scopes)
                {
                    if (scope.Value.Enabled && (scope.Value.InterfaceIndex == ipPacketInformation.Interface))
                        return scope.Value;
                }
            }
            else
            {
                foreach (KeyValuePair<string, Scope> scope in _scopes)
                {
                    if (scope.Value.Enabled && (scope.Value.IsAddressInRange(remoteAddress)))
                        return scope.Value;
                }
            }

            return null;
        }

        private void UpdateDnsAuthZone(bool add, Scope scope, Lease lease)
        {
            if (_authZoneManager == null)
                return;

            if (string.IsNullOrWhiteSpace(scope.DomainName))
                return;

            if (string.IsNullOrWhiteSpace(lease.HostName))
                return;

            if (!DnsClient.IsDomainNameValid(lease.HostName))
                return;

            if (add)
            {
                //update forward zone
                _authZoneManager.CreatePrimaryZone(scope.DomainName, _serverDomain, false);
                _authZoneManager.SetRecords(lease.HostName, DnsResourceRecordType.A, scope.DnsTtl, new DnsResourceRecordData[] { new DnsARecord(lease.Address) });

                //update reverse zone
                _authZoneManager.CreatePrimaryZone(scope.ReverseZone, _serverDomain, false);
                _authZoneManager.SetRecords(Scope.GetReverseZone(lease.Address, 32), DnsResourceRecordType.PTR, scope.DnsTtl, new DnsResourceRecordData[] { new DnsPTRRecord(lease.HostName) });
            }
            else
            {
                //remove from forward zone
                _authZoneManager.DeleteRecords(lease.HostName, DnsResourceRecordType.A);

                //remove from reverse zone
                _authZoneManager.DeleteRecords(Scope.GetReverseZone(lease.Address, 32), DnsResourceRecordType.PTR);
            }
        }

        private void BindUdpListener(IPEndPoint dhcpEP)
        {
            Socket udpListener = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            try
            {
                #region this code ignores ICMP port unreachable responses which creates SocketException in ReceiveFrom()

                if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                {
                    const uint IOC_IN = 0x80000000;
                    const uint IOC_VENDOR = 0x18000000;
                    const uint SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

                    udpListener.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { Convert.ToByte(false) }, null);
                }

                #endregion

                //bind to interface address
                if (Environment.OSVersion.Platform == PlatformID.Unix)
                    udpListener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1); //to allow binding to same port with different addresses

                udpListener.EnableBroadcast = true;
                udpListener.ExclusiveAddressUse = false;

                udpListener.Bind(dhcpEP);

                if (!_udpListeners.TryAdd(dhcpEP.Address, udpListener))
                    throw new DhcpServerException("Udp listener already exists for IP address: " + dhcpEP.Address);

                //start reading dhcp packets
                Thread listenerThread = new Thread(ReadUdpRequestAsync);
                listenerThread.IsBackground = true;
                listenerThread.Start(udpListener);

                lock (_listenerThreads)
                {
                    _listenerThreads.Add(listenerThread);
                }
            }
            catch
            {
                udpListener.Dispose();
                throw;
            }
        }

        private bool UnbindUdpListener(IPEndPoint dhcpEP)
        {
            if (_udpListeners.TryRemove(dhcpEP.Address, out Socket socket))
            {
                socket.Dispose();
                return true;
            }

            return false;
        }

        private bool ActivateScope(Scope scope)
        {
            IPEndPoint dhcpEP = null;

            try
            {
                //find this dns server address in case the network config has changed
                if (scope.UseThisDnsServer)
                    scope.FindThisDnsServerAddress();

                //find scope interface for binding socket
                scope.FindInterface();

                IPAddress interfaceAddress = scope.InterfaceAddress;
                dhcpEP = new IPEndPoint(interfaceAddress, 67);

                if (!interfaceAddress.Equals(IPAddress.Any))
                    BindUdpListener(dhcpEP);

                lock (_activeScopeLock)
                {
                    if (_activeScopeCount < 1)
                    {
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
                    }

                    _activeScopeCount++;
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

                lock (_activeScopeLock)
                {
                    _activeScopeCount--;

                    if (_activeScopeCount < 1)
                    {
                        _activeScopeCount = 0;
                        UnbindUdpListener(_dhcpDefaultEP);
                    }
                }

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

        private void LoadScope(Scope scope)
        {
            foreach (KeyValuePair<string, Scope> existingScope in _scopes)
            {
                if (existingScope.Value.Equals(scope))
                    throw new DhcpServerException("Scope with same range already exists.");
            }

            if (!_scopes.TryAdd(scope.Name, scope))
                throw new DhcpServerException("Scope with same name already exists.");

            if (scope.Enabled)
            {
                if (!ActivateScope(scope))
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
            string[] scopeFiles = Directory.GetFiles(_configFolder, "*.scope");

            foreach (string scopeFile in scopeFiles)
                LoadScopeFile(scopeFile);

            _lastModifiedScopesSavedOn = DateTime.UtcNow;
        }

        private void LoadScopeFile(string scopeFile)
        {
            try
            {
                using (FileStream fS = new FileStream(scopeFile, FileMode.Open, FileAccess.Read))
                {
                    LoadScope(new Scope(new BinaryReader(fS)));
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
            string scopeFile = Path.Combine(_configFolder, scope.Name + ".scope");

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
            string scopeFile = Path.Combine(_configFolder, scopeName + ".scope");

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

            _listenerThreads.Clear();
            _udpListeners.Clear();

            _state = ServiceState.Stopped;
        }

        public void AddScope(Scope scope)
        {
            LoadScope(scope);
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

        public bool EnableScope(string name)
        {
            if (_scopes.TryGetValue(name, out Scope scope))
            {
                if (!scope.Enabled && ActivateScope(scope))
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

        public string ServerDomain
        {
            get { return _serverDomain; }
            set { _serverDomain = value; }
        }

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
    }
}
