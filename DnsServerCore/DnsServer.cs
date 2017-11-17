/*
Technitium DNS Server
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore
{
    public class DnsServer
    {
        #region enum

        enum ServiceState
        {
            Stopped = 0,
            Running = 1,
            Stopping = 2
        }

        #endregion

        #region variables

        const int TCP_SOCKET_SEND_TIMEOUT = 30000;
        const int TCP_SOCKET_RECV_TIMEOUT = 60000;

        readonly IPEndPoint _localEP;

        Socket _udpListener;
        Thread _udpListenerThread;

        Socket _tcpListener;
        Thread _tcpListenerThread;

        readonly Zone _authoritativeZoneRoot = new Zone(true);
        readonly Zone _cacheZoneRoot = new Zone(false);

        readonly IDnsCache _dnsCache;

        bool _allowRecursion = false;
        NameServerAddress[] _forwarders;
        bool _preferIPv6 = false;
        int _retries = 2;

        volatile ServiceState _state = ServiceState.Stopped;

        #endregion

        #region constructor

        public DnsServer()
            : this(new IPEndPoint(IPAddress.IPv6Any, 53))
        { }

        public DnsServer(IPAddress localIP)
            : this(new IPEndPoint(localIP, 53))
        { }

        public DnsServer(IPEndPoint localEP)
        {
            _localEP = localEP;
            _dnsCache = new DnsCache(_cacheZoneRoot);

            //set min threads since the default value is too small
            {
                int minWorker, minIOC;
                ThreadPool.GetMinThreads(out minWorker, out minIOC);

                minWorker = Environment.ProcessorCount * 32;
                ThreadPool.SetMinThreads(minWorker, minIOC);
            }
        }

        #endregion

        #region private

        private void ReadUdpQueryPacketsAsync(object parameter)
        {
            #region this code ignores ICMP port unreachable responses which creates SocketException in ReceiveFrom()

            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                const uint IOC_IN = 0x80000000;
                const uint IOC_VENDOR = 0x18000000;
                const uint SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

                _udpListener.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { Convert.ToByte(false) }, null);
            }

            #endregion

            FixMemoryStream recvBufferStream = new FixMemoryStream(128);
            int bytesRecv;

            try
            {
                while (true)
                {
                    EndPoint remoteEP;

                    if (_udpListener.AddressFamily == AddressFamily.InterNetwork)
                        remoteEP = new IPEndPoint(IPAddress.Any, 0);
                    else
                        remoteEP = new IPEndPoint(IPAddress.IPv6Any, 0);

                    try
                    {
                        bytesRecv = _udpListener.ReceiveFrom(recvBufferStream.Buffer, ref remoteEP);
                    }
                    catch (SocketException ex)
                    {
                        switch (ex.SocketErrorCode)
                        {
                            case SocketError.ConnectionReset:
                            case SocketError.HostUnreachable:
                                bytesRecv = 0;
                                break;

                            default:
                                throw;
                        }
                    }

                    if (bytesRecv > 0)
                    {
                        recvBufferStream.Position = 0;
                        recvBufferStream.SetLength(bytesRecv);

                        try
                        {
                            ThreadPool.QueueUserWorkItem(ProcessUdpRequestAsync, new object[] { remoteEP, new DnsDatagram(recvBufferStream) });
                        }
                        catch
                        { }
                    }
                }
            }
            catch
            {
                if (_state == ServiceState.Running)
                    throw;
            }
        }

        private void ProcessUdpRequestAsync(object parameter)
        {
            object[] parameters = parameter as object[];

            EndPoint remoteEP = parameters[0] as EndPoint;
            DnsDatagram request = parameters[1] as DnsDatagram;

            try
            {
                DnsDatagram response = ProcessQuery(request);

                //send response
                if (response != null)
                {
                    FixMemoryStream sendBufferStream = new FixMemoryStream(512);

                    try
                    {
                        response.WriteTo(sendBufferStream);
                    }
                    catch (EndOfStreamException)
                    {
                        DnsHeader header = response.Header;
                        response = new DnsDatagram(new DnsHeader(header.Identifier, true, header.OPCODE, header.AuthoritativeAnswer, true, header.RecursionDesired, header.RecursionAvailable, header.AuthenticData, header.CheckingDisabled, header.RCODE, header.QDCOUNT, 0, 0, 0), response.Question, null, null, null);

                        sendBufferStream.Position = 0;
                        response.WriteTo(sendBufferStream);
                    }

                    //send dns datagram
                    _udpListener.SendTo(sendBufferStream.Buffer, 0, (int)sendBufferStream.Position, SocketFlags.None, remoteEP);
                }
            }
            catch
            { }
        }

        private void AcceptTcpConnectionAsync(object parameter)
        {
            try
            {
                while (true)
                {
                    Socket socket = _tcpListener.Accept();

                    socket.NoDelay = true;
                    socket.SendTimeout = TCP_SOCKET_SEND_TIMEOUT;
                    socket.ReceiveTimeout = TCP_SOCKET_RECV_TIMEOUT;

                    ThreadPool.QueueUserWorkItem(ProcessTcpRequestAsync, socket);
                }
            }
            catch
            {
                if (_state == ServiceState.Running)
                    throw;
            }
        }

        private void ProcessTcpRequestAsync(object parameter)
        {
            Socket tcpSocket = parameter as Socket;

            try
            {
                FixMemoryStream recvBufferStream = new FixMemoryStream(128);
                MemoryStream sendBufferStream = new MemoryStream(512);
                int bytesRecv;

                while (true)
                {
                    //read dns datagram length
                    bytesRecv = tcpSocket.Receive(recvBufferStream.Buffer, 0, 2, SocketFlags.None);
                    if (bytesRecv < 1)
                        throw new SocketException();

                    Array.Reverse(recvBufferStream.Buffer, 0, 2);
                    short length = BitConverter.ToInt16(recvBufferStream.Buffer, 0);

                    //read dns datagram
                    int offset = 0;
                    while (offset < length)
                    {
                        bytesRecv = tcpSocket.Receive(recvBufferStream.Buffer, offset, length, SocketFlags.None);
                        if (bytesRecv < 1)
                            throw new SocketException();

                        offset += bytesRecv;
                    }

                    bytesRecv = length;

                    if (bytesRecv > 0)
                    {
                        recvBufferStream.Position = 0;
                        recvBufferStream.SetLength(bytesRecv);

                        DnsDatagram response = ProcessQuery(new DnsDatagram(recvBufferStream));

                        //send response
                        if (response != null)
                        {
                            //write dns datagram
                            sendBufferStream.Position = 0;
                            response.WriteTo(sendBufferStream);

                            //prepare final buffer
                            byte[] lengthBytes = BitConverter.GetBytes(Convert.ToInt16(sendBufferStream.Position));
                            byte[] buffer = new byte[sendBufferStream.Position + 2];

                            //copy datagram length
                            buffer[0] = lengthBytes[1];
                            buffer[1] = lengthBytes[0];

                            //copy datagram
                            sendBufferStream.Position = 0;
                            sendBufferStream.Read(buffer, 2, buffer.Length - 2);

                            //send dns datagram
                            tcpSocket.Send(buffer, 0, buffer.Length, SocketFlags.None);
                        }
                    }
                }
            }
            catch
            { }
            finally
            {
                if (tcpSocket != null)
                    tcpSocket.Dispose();
            }
        }

        private DnsDatagram ProcessQuery(DnsDatagram request)
        {
            if (request.Header.IsResponse)
                return null;

            switch (request.Header.OPCODE)
            {
                case DnsOpcode.StandardQuery:
                    if (request.Question.Length != 1)
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, _allowRecursion, false, false, DnsResponseCode.Refused, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);

                    try
                    {
                        DnsDatagram authoritativeResponse = ProcessAuthoritativeQuery(request);

                        if ((authoritativeResponse.Header.RCODE != DnsResponseCode.Refused) || !request.Header.RecursionDesired || !_allowRecursion)
                            return authoritativeResponse;

                        return ProcessRecursiveQuery(request);
                    }
                    catch
                    {
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, _allowRecursion, false, false, DnsResponseCode.ServerFailure, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
                    }

                default:
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, request.Header.OPCODE, false, false, request.Header.RecursionDesired, _allowRecursion, false, false, DnsResponseCode.Refused, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
            }
        }

        public DnsDatagram ProcessAuthoritativeQuery(DnsDatagram request)
        {
            DnsDatagram response = _authoritativeZoneRoot.Query(request);

            if ((response.Header.RCODE == DnsResponseCode.NoError) && (response.Answer.Length > 0))
            {
                DnsResourceRecordType questionType = request.Question[0].Type;
                DnsResourceRecord lastRR = response.Answer[response.Answer.Length - 1];

                if ((lastRR.Type != questionType) && (lastRR.Type == DnsResourceRecordType.CNAME) && (questionType != DnsResourceRecordType.ANY))
                {
                    List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                    responseAnswer.AddRange(response.Answer);

                    DnsDatagram lastResponse;

                    while (true)
                    {
                        DnsDatagram cnameRequest = new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, questionType, DnsClass.IN) }, null, null, null);

                        lastResponse = _authoritativeZoneRoot.Query(cnameRequest);

                        if (lastResponse.Header.RCODE == DnsResponseCode.Refused)
                        {
                            if (!cnameRequest.Header.RecursionDesired || !_allowRecursion)
                                break;

                            lastResponse = ProcessRecursiveQuery(cnameRequest);
                        }

                        if ((lastResponse.Header.RCODE != DnsResponseCode.NoError) || (lastResponse.Answer.Length == 0))
                            break;

                        responseAnswer.AddRange(lastResponse.Answer);

                        lastRR = lastResponse.Answer[lastResponse.Answer.Length - 1];

                        if (lastRR.Type != DnsResourceRecordType.CNAME)
                            break;
                    }

                    DnsResponseCode rcode;
                    DnsResourceRecord[] authority;

                    if (lastResponse.Header.RCODE == DnsResponseCode.Refused)
                    {
                        rcode = DnsResponseCode.NoError;
                        authority = new DnsResourceRecord[] { };
                    }
                    else
                    {
                        rcode = lastResponse.Header.RCODE;

                        if ((lastResponse.Authority.Length > 0) && (lastResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                            authority = lastResponse.Authority;
                        else
                            authority = new DnsResourceRecord[] { };
                    }

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, lastResponse.Header.AuthoritativeAnswer, false, request.Header.RecursionDesired, _allowRecursion, false, false, rcode, 1, Convert.ToUInt16(responseAnswer.Count), Convert.ToUInt16(authority.Length), 0), request.Question, responseAnswer.ToArray(), authority, new DnsResourceRecord[] { });
                }
            }

            return response;
        }

        public DnsDatagram ProcessRecursiveQuery(DnsDatagram request)
        {
            DnsDatagram response = DnsClient.ResolveViaNameServers(request.Question[0], _forwarders, _dnsCache, null, _preferIPv6, false, _retries);

            DnsResourceRecord[] authority;

            if ((response.Header.RCODE == DnsResponseCode.NoError) && (response.Answer.Length > 0))
            {
                DnsResourceRecordType questionType = request.Question[0].Type;
                DnsResourceRecord lastRR = response.Answer[response.Answer.Length - 1];

                if ((lastRR.Type != questionType) && (lastRR.Type == DnsResourceRecordType.CNAME) && (questionType != DnsResourceRecordType.ANY))
                {
                    List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                    responseAnswer.AddRange(response.Answer);

                    DnsDatagram lastResponse;

                    while (true)
                    {
                        lastResponse = DnsClient.ResolveViaNameServers((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, questionType, _forwarders, _dnsCache, null, _preferIPv6, false, _retries);

                        if ((lastResponse.Header.RCODE != DnsResponseCode.NoError) || (lastResponse.Answer.Length == 0))
                            break;

                        responseAnswer.AddRange(lastResponse.Answer);

                        lastRR = lastResponse.Answer[lastResponse.Answer.Length - 1];

                        if (lastRR.Type == questionType)
                            break;

                        if (lastRR.Type != DnsResourceRecordType.CNAME)
                            throw new DnsServerException("Invalid response received from Dns server.");
                    }

                    if ((lastResponse.Authority.Length > 0) && (lastResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                        authority = lastResponse.Authority;
                    else
                        authority = new DnsResourceRecord[] { };

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, lastResponse.Header.RCODE, 1, Convert.ToUInt16(responseAnswer.Count), Convert.ToUInt16(authority.Length), 0), request.Question, responseAnswer.ToArray(), authority, new DnsResourceRecord[] { });
                }
            }

            if ((response.Authority.Length > 0) && (response.Authority[0].Type == DnsResourceRecordType.SOA))
                authority = response.Authority;
            else
                authority = new DnsResourceRecord[] { };

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, response.Header.RCODE, 1, Convert.ToUInt16(response.Answer.Length), Convert.ToUInt16(authority.Length), 0), request.Question, response.Answer, authority, new DnsResourceRecord[] { });
        }

        #endregion

        #region public

        public void Start()
        {
            if (_state != ServiceState.Stopped)
                return;

            _udpListener = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            _udpListener.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
            _udpListener.Bind(_localEP);

            _tcpListener = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            _tcpListener.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
            _tcpListener.Bind(_localEP);
            _tcpListener.Listen(10);

            //start reading query packets
            _udpListenerThread = new Thread(ReadUdpQueryPacketsAsync);
            _udpListenerThread.IsBackground = true;
            _udpListenerThread.Start();

            _tcpListenerThread = new Thread(AcceptTcpConnectionAsync);
            _tcpListenerThread.IsBackground = true;
            _tcpListenerThread.Start();

            _state = ServiceState.Running;
        }

        public void Stop()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            _udpListener.Dispose();
            _tcpListener.Dispose();

            _state = ServiceState.Stopped;
        }

        #endregion

        #region properties

        public IPEndPoint LocalEP
        { get { return _localEP; } }

        public Zone AuthoritativeZoneRoot
        { get { return _authoritativeZoneRoot; } }

        public Zone CacheZoneRoot
        { get { return _cacheZoneRoot; } }

        public bool AllowRecursion
        {
            get { return _allowRecursion; }
            set { _allowRecursion = value; }
        }

        public NameServerAddress[] Forwarders
        {
            get { return _forwarders; }
            set { _forwarders = value; }
        }

        public bool PreferIPv6
        {
            get { return _preferIPv6; }
            set { _preferIPv6 = value; }
        }

        public int Retries
        {
            get { return _retries; }
            set { _retries = value; }
        }

        #endregion

        class DnsCache : IDnsCache
        {
            #region variables

            readonly Zone _cacheZoneRoot;

            #endregion

            #region constructor

            public DnsCache(Zone cacheZoneRoot)
            {
                _cacheZoneRoot = cacheZoneRoot;
            }

            #endregion

            #region public

            public DnsDatagram Query(DnsDatagram request)
            {
                return _cacheZoneRoot.Query(request);
            }

            public void CacheResponse(DnsDatagram response)
            {
                _cacheZoneRoot.CacheResponse(response);
            }

            #endregion
        }
    }
}
