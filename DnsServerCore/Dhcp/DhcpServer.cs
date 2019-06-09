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
using System.Threading;

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

        readonly List<Socket> _udpListeners = new List<Socket>();
        readonly List<Thread> _listenerThreads = new List<Thread>();

        readonly List<Scope> _scopes = new List<Scope>();

        LogManager _log;

        volatile ServiceState _state = ServiceState.Stopped;

        #endregion

        #region constructor

        public DhcpServer()
        { }

        public DhcpServer(ICollection<Scope> scopes)
        {
            _scopes.AddRange(scopes);
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

                if (_log != null)
                    _log.Dispose();
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
                while (true)
                {
                    remoteEP = new IPEndPoint(IPAddress.Any, 0);

                    try
                    {
                        bytesRecv = udpListener.ReceiveFrom(recvBuffer, ref remoteEP);
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
                        switch ((remoteEP as IPEndPoint).Port)
                        {
                            case 67:
                            case 68:
                                try
                                {
                                    ThreadPool.QueueUserWorkItem(ProcessUdpRequestAsync, new object[] { udpListener, remoteEP, new DhcpMessage(new MemoryStream(recvBuffer, 0, bytesRecv, false)) });
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
            DhcpMessage request = parameters[2] as DhcpMessage;

            try
            {
                DhcpMessage response = ProcessDhcpMessage(request, remoteEP as IPEndPoint, udpListener.LocalEndPoint as IPEndPoint);

                //send response
                if (response != null)
                {
                    byte[] sendBuffer = new byte[512];
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
                        //send response as broadcast on port 68
                        udpListener.SendTo(sendBuffer, 0, (int)sendBufferStream.Position, SocketFlags.None, new IPEndPoint(IPAddress.Broadcast, 68));
                    }
                }
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

        private DhcpMessage ProcessDhcpMessage(DhcpMessage request, IPEndPoint remoteEP, IPEndPoint interfaceEP)
        {
            if (request.OpCode != DhcpMessageOpCode.BootRequest)
                return null;

            switch (request.DhcpMessageType?.Type)
            {
                case DhcpMessageType.Discover:
                    {
                        Scope scope = FindScope(request, remoteEP.Address, interfaceEP.Address);
                        if (scope == null)
                            return null; //no scope available; do nothing

                        if (scope.DelayTime > 0)
                            Thread.Sleep(scope.DelayTime * 1000); //delay sending offer

                        Lease offer = scope.GetOffer(request);
                        if (offer == null)
                            throw new DhcpServerException("DHCP Server failed to offer address: address unavailable.");

                        List<DhcpOption> options = scope.GetOptions(request, interfaceEP.Address);
                        if (options == null)
                            return null;

                        return new DhcpMessage(request, offer.Address, interfaceEP.Address, options);
                    }

                case DhcpMessageType.Request:
                    {
                        //request ip address lease or extend existing lease
                        Scope scope;
                        Lease leaseOffer;

                        if (request.ServerIdentifier == null)
                        {
                            if (request.RequestedIpAddress == null)
                            {
                                //renewing or rebinding

                                if (request.ClientIpAddress.Equals(IPAddress.Any))
                                    return null; //client must set IP address in ciaddr; do nothing

                                scope = FindScope(request, remoteEP.Address, interfaceEP.Address);
                                if (scope == null)
                                {
                                    //no scope available; do nothing
                                    return null;
                                }

                                leaseOffer = scope.GetExistingLeaseOrOffer(request);
                                if (leaseOffer == null)
                                {
                                    //no existing lease or offer available for client
                                    //send nak
                                    return new DhcpMessage(request, IPAddress.Any, interfaceEP.Address, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(interfaceEP.Address), DhcpOption.CreateEndOption() });
                                }

                                if (!request.ClientIpAddress.Equals(leaseOffer.Address))
                                {
                                    //client ip is incorrect
                                    //send nak
                                    return new DhcpMessage(request, IPAddress.Any, interfaceEP.Address, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(interfaceEP.Address), DhcpOption.CreateEndOption() });
                                }
                            }
                            else
                            {
                                //init-reboot
                                scope = FindScope(request, remoteEP.Address, interfaceEP.Address);
                                if (scope == null)
                                {
                                    //no scope available; do nothing
                                    return null;
                                }

                                leaseOffer = scope.GetExistingLeaseOrOffer(request);
                                if (leaseOffer == null)
                                {
                                    //no existing lease or offer available for client
                                    //send nak
                                    return new DhcpMessage(request, IPAddress.Any, interfaceEP.Address, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(interfaceEP.Address), DhcpOption.CreateEndOption() });
                                }

                                if (!request.RequestedIpAddress.Address.Equals(leaseOffer.Address))
                                {
                                    //the client's notion of its IP address is not correct - RFC 2131
                                    //send nak
                                    return new DhcpMessage(request, IPAddress.Any, interfaceEP.Address, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(interfaceEP.Address), DhcpOption.CreateEndOption() });
                                }
                            }
                        }
                        else
                        {
                            //selecting offer

                            if (request.RequestedIpAddress == null)
                                return null; //client MUST include this option; do nothing

                            if (!request.ServerIdentifier.Address.Equals(interfaceEP.Address))
                                return null; //offer declined by client; do nothing

                            scope = FindScope(request, remoteEP.Address, interfaceEP.Address);
                            if (scope == null)
                            {
                                //no scope available
                                //send nak
                                return new DhcpMessage(request, IPAddress.Any, interfaceEP.Address, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(interfaceEP.Address), DhcpOption.CreateEndOption() });
                            }

                            leaseOffer = scope.GetExistingLeaseOrOffer(request);
                            if (leaseOffer == null)
                            {
                                //no existing lease or offer available for client
                                //send nak
                                return new DhcpMessage(request, IPAddress.Any, interfaceEP.Address, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(interfaceEP.Address), DhcpOption.CreateEndOption() });
                            }

                            if (!request.RequestedIpAddress.Address.Equals(leaseOffer.Address))
                            {
                                //requested ip is incorrect
                                //send nak
                                return new DhcpMessage(request, IPAddress.Any, interfaceEP.Address, new DhcpOption[] { new DhcpMessageTypeOption(DhcpMessageType.Nak), new ServerIdentifierOption(interfaceEP.Address), DhcpOption.CreateEndOption() });
                            }
                        }

                        List<DhcpOption> options = scope.GetOptions(request, interfaceEP.Address);
                        if (options == null)
                            return null;

                        scope.CommitLease(leaseOffer);

                        //log ip lease
                        LogManager log = _log;
                        if (log != null)
                            log.Write(remoteEP as IPEndPoint, "DHCP Server leased IP address [" + leaseOffer.Address.ToString() + "] to " + request.GetClientFullIdentifier() + ".");

                        return new DhcpMessage(request, leaseOffer.Address, interfaceEP.Address, options);
                    }

                case DhcpMessageType.Decline:
                    {
                        //ip address is already in use as detected by client via ARP

                        if ((request.ServerIdentifier == null) || (request.RequestedIpAddress == null))
                            return null; //client MUST include these option; do nothing

                        if (!request.ServerIdentifier.Address.Equals(interfaceEP.Address))
                            return null; //request not for this server; do nothing

                        Scope scope = FindScope(request, remoteEP.Address, interfaceEP.Address);
                        if (scope == null)
                            return null; //no scope available; do nothing

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
                            log.Write(remoteEP as IPEndPoint, "DHCP Server received DECLINE message: " + request.GetClientFullIdentifier() + " detected that IP address [" + lease.Address + "] is already in use.");

                        return null;
                    }

                case DhcpMessageType.Release:
                    {
                        //cancel ip address lease

                        if (request.ServerIdentifier == null)
                            return null; //client MUST include this option; do nothing

                        if (!request.ServerIdentifier.Address.Equals(interfaceEP.Address))
                            return null; //request not for this server; do nothing

                        Scope scope = FindScope(request, remoteEP.Address, interfaceEP.Address);
                        if (scope == null)
                            return null; //no scope available; do nothing

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
                            log.Write(remoteEP as IPEndPoint, "DHCP Server released IP address [" + lease.Address.ToString() + "] that was leased to " + request.GetClientFullIdentifier() + ".");

                        //do nothing
                        return null;
                    }

                case DhcpMessageType.Inform:
                    {
                        //need only local config; already has ip address assigned externally/manually

                        Scope scope = FindScope(request, remoteEP.Address, interfaceEP.Address);
                        if (scope == null)
                            return null; //no scope available; do nothing

                        List<DhcpOption> options = scope.GetOptions(request, interfaceEP.Address);
                        if (options == null)
                            return null;

                        return new DhcpMessage(request, IPAddress.Any, interfaceEP.Address, options);
                    }

                default:
                    return null;
            }
        }

        private Scope FindScope(DhcpMessage request, IPAddress remoteAddress, IPAddress interfaceAddress)
        {
            IPAddress address;

            if (request.RelayAgentIpAddress.Equals(IPAddress.Any))
            {
                //no relay agent
                if (request.ClientIpAddress.Equals(IPAddress.Any))
                {
                    address = interfaceAddress; //broadcast request
                }
                else
                {
                    if (!remoteAddress.Equals(request.ClientIpAddress))
                        return null; //client ip must match udp src addr

                    address = request.ClientIpAddress; //unicast request
                }
            }
            else
            {
                //relay agent unicast

                if (!remoteAddress.Equals(request.RelayAgentIpAddress))
                    return null; //relay ip must match udp src addr

                address = request.RelayAgentIpAddress;
            }

            lock (_scopes)
            {
                foreach (Scope scope in _scopes)
                {
                    if (scope.InterfaceAddress.Equals(interfaceAddress) && scope.IsAddressInRange(address))
                        return scope;
                }
            }

            return null;
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
                udpListener.EnableBroadcast = true;
                udpListener.Bind(dhcpEP);

                lock (_udpListeners)
                {
                    _udpListeners.Add(udpListener);
                }

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

        #endregion

        #region public

        public void Start()
        {
            if (_disposed)
                throw new ObjectDisposedException("DhcpServer");

            if (_state != ServiceState.Stopped)
                throw new InvalidOperationException("DHCP Server is already running.");

            _state = ServiceState.Starting;

            IPEndPoint dhcpEP = new IPEndPoint(IPAddress.Any, 67);

            try
            {
                BindUdpListener(dhcpEP);

                LogManager log = _log;
                if (log != null)
                    log.Write(dhcpEP, "DHCP Server was bound successfully.");
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write(dhcpEP, "DHCP Server failed bind.\r\n" + ex.ToString());
            }

            lock (_scopes)
            {
                foreach (Scope scope in _scopes)
                {
                    if (scope.Enabled)
                        ActivateScope(scope);
                }
            }

            _state = ServiceState.Running;
        }

        public void Stop()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            lock (_udpListeners)
            {
                foreach (Socket udpListener in _udpListeners)
                    udpListener.Dispose();
            }

            _listenerThreads.Clear();
            _udpListeners.Clear();

            lock (_scopes)
            {
                foreach (Scope scope in _scopes)
                    scope.Dispose();
            }

            _state = ServiceState.Stopped;
        }

        public Scope[] GetScopes()
        {
            lock (_scopes)
            {
                return _scopes.ToArray();
            }
        }

        public void AddScope(Scope scope)
        {
            lock (_scopes)
            {
                foreach (Scope existingScope in _scopes)
                {
                    if (existingScope.Equals(scope))
                        return;
                }

                scope.LogManager = _log;

                if (scope.Enabled)
                    ActivateScope(scope);

                _scopes.Add(scope);
            }
        }

        public void RemoveScope(Scope scope)
        {
            lock (_scopes)
            {
                DeactivateScope(scope);
                _scopes.Remove(scope);
            }
        }

        public void ActivateScope(Scope scope)
        {
            if (scope.IsActive)
                return;

            IPAddress interfaceAddress = scope.InterfaceAddress;
            IPEndPoint dhcpEP = new IPEndPoint(interfaceAddress, 67);

            if (interfaceAddress.Equals(IPAddress.Any))
            {
                scope.SetActive(true);

                LogManager log = _log;
                if (log != null)
                    log.Write(dhcpEP, "DHCP Server successfully activated scope '" + scope.Name + "'");
            }
            else
            {
                try
                {
                    BindUdpListener(dhcpEP);
                    scope.SetActive(true);

                    LogManager log = _log;
                    if (log != null)
                        log.Write(dhcpEP, "DHCP Server successfully activated scope '" + scope.Name + "'");
                }
                catch (Exception ex)
                {
                    LogManager log = _log;
                    if (log != null)
                        log.Write(dhcpEP, "DHCP Server failed to activate scope '" + scope.Name + "'.\r\n" + ex.ToString());
                }
            }
        }

        public void DeactivateScope(Scope scope)
        {
            if (!scope.IsActive)
                return;

            IPAddress interfaceAddress = scope.InterfaceAddress;
            IPEndPoint dhcpEP = new IPEndPoint(interfaceAddress, 67);

            if (interfaceAddress.Equals(IPAddress.Any))
            {
                scope.SetActive(false);

                LogManager log = _log;
                if (log != null)
                    log.Write(dhcpEP, "DHCP Server successfully deactivated scope '" + scope.Name + "'");
            }
            else
            {
                lock (_udpListeners)
                {
                    foreach (Socket udpListener in _udpListeners)
                    {
                        if (dhcpEP.Equals(udpListener.LocalEndPoint))
                        {
                            try
                            {
                                udpListener.Dispose();
                                scope.SetActive(false);

                                LogManager log = _log;
                                if (log != null)
                                    log.Write(dhcpEP, "DHCP Server successfully deactivated scope '" + scope.Name + "'");
                            }
                            catch (Exception ex)
                            {
                                LogManager log = _log;
                                if (log != null)
                                    log.Write(dhcpEP, "DHCP Server failed to deactivated scope '" + scope.Name + "'.\r\n" + ex.ToString());
                            }

                            return;
                        }
                    }
                }
            }
        }

        #endregion

        #region properties

        public LogManager LogManager
        {
            get { return _log; }
            set { _log = value; }
        }

        #endregion
    }
}
