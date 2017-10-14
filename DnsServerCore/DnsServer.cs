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
    public class DnsServer : IDisposable
    {
        #region variables

        const int TCP_SOCKET_SEND_TIMEOUT = 30000;
        const int TCP_SOCKET_RECV_TIMEOUT = 60000;

        readonly IPEndPoint _localEP;

        readonly Socket _udpListener;
        readonly Thread _udpListenerThread;

        readonly Socket _tcpListener;
        readonly Thread _tcpListenerThread;

        readonly Zone _authoritativeZoneRoot = new Zone(true);
        readonly Zone _cacheZoneRoot = new Zone(false);

        readonly IDnsCache _dnsCache;

        bool _allowRecursion = false;
        NameServerAddress[] _forwarders;
        bool _preferIPv6 = false;
        int _retries = 2;

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
        }

        #endregion

        #region IDisposable Support

        bool _disposed = false;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    if (_udpListener != null)
                        _udpListener.Dispose();

                    if (_tcpListener != null)
                        _tcpListener.Dispose();
                }

                _disposed = true;
            }
        }

        #endregion

        #region private

        private void ReadUdpQueryPacketsAsync(object parameter)
        {
            EndPoint remoteEP;
            FixMemoryStream recvBufferStream = new FixMemoryStream(128);
            FixMemoryStream sendBufferStream = new FixMemoryStream(512);
            int bytesRecv;

            if (_udpListener.AddressFamily == AddressFamily.InterNetwork)
                remoteEP = new IPEndPoint(IPAddress.Any, 0);
            else
                remoteEP = new IPEndPoint(IPAddress.IPv6Any, 0);

            #region this code ignores ICMP port unreachable responses which creates SocketException in ReceiveFrom()

            const uint IOC_IN = 0x80000000;
            const uint IOC_VENDOR = 0x18000000;
            const uint SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

            _udpListener.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { Convert.ToByte(false) }, null);

            #endregion

            while (true)
            {
                bytesRecv = _udpListener.ReceiveFrom(recvBufferStream.Buffer, ref remoteEP);

                if (bytesRecv > 0)
                {
                    recvBufferStream.Position = 0;
                    recvBufferStream.SetLength(bytesRecv);

                    IPEndPoint remoteNodeEP = remoteEP as IPEndPoint;

                    try
                    {
                        DnsDatagram response = ProcessQuery(recvBufferStream);

                        //send response
                        if (response != null)
                        {
                            try
                            {
                                sendBufferStream.Position = 0;
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
            }
        }

        private void AcceptTcpConnectionAsync(object parameter)
        {
            while (true)
            {
                Socket socket = _tcpListener.Accept();

                socket.NoDelay = true;
                socket.SendTimeout = TCP_SOCKET_SEND_TIMEOUT;
                socket.ReceiveTimeout = TCP_SOCKET_RECV_TIMEOUT;

                ThreadPool.QueueUserWorkItem(ReadTcpQueryPacketsAsync, socket);
            }
        }

        private void ReadTcpQueryPacketsAsync(object parameter)
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

                        DnsDatagram response = ProcessQuery(recvBufferStream);

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

        private DnsDatagram ProcessQuery(Stream s)
        {
            DnsDatagram request;

            try
            {
                request = new DnsDatagram(s);
            }
            catch
            {
                return null;
            }

            if (request.Header.IsResponse)
                return null;

            switch (request.Header.OPCODE)
            {
                case DnsOpcode.StandardQuery:
                    if (request.Question.Length != 1)
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, request.Header.OPCODE, false, false, request.Header.RecursionDesired, _allowRecursion, false, false, DnsResponseCode.Refused, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);

                    try
                    {
                        DnsDatagram authoritativeResponse = _authoritativeZoneRoot.Query(request);

                        if ((authoritativeResponse.Header.AuthoritativeAnswer) || !request.Header.RecursionDesired || !_allowRecursion)
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

        public DnsDatagram ProcessRecursiveQuery(DnsDatagram request)
        {
            DnsDatagram response = DnsClient.ResolveViaNameServers(_forwarders, request.Question[0], _dnsCache, null, _preferIPv6, false, _retries);

            if ((response.Header.RCODE == DnsResponseCode.NoError) && (response.Answer.Length > 0))
            {
                if ((response.Answer[0].Type == DnsResourceRecordType.CNAME) && (request.Question[0].Type != DnsResourceRecordType.CNAME) && (request.Question[0].Type != DnsResourceRecordType.ANY))
                {
                    DnsResourceRecord cnameRR = response.Answer[0];

                    List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                    responseAnswer.Add(cnameRR);

                    while (true)
                    {
                        DnsDatagram cnameResponse = DnsClient.ResolveViaNameServers(_forwarders, (cnameRR.RDATA as DnsCNAMERecord).CNAMEDomainName, request.Question[0].Type, _dnsCache, null, _preferIPv6, false, _retries);

                        if (cnameResponse.Header.RCODE != DnsResponseCode.NoError)
                            break;

                        if (cnameResponse.Answer.Length == 0)
                            break;

                        responseAnswer.AddRange(cnameResponse.Answer);

                        if (cnameResponse.Answer[0].Type != DnsResourceRecordType.CNAME)
                            break;

                        cnameRR = cnameResponse.Answer[0];
                    }

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.NoError, 1, Convert.ToUInt16(responseAnswer.Count), 0, 0), request.Question, responseAnswer.ToArray(), new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
                }
            }

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.NoError, 1, Convert.ToUInt16(response.Answer.Length), 0, 0), request.Question, response.Answer, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
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
