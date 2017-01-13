/*
Technitium Library
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
using TechnitiumLibrary.Net;

namespace DnsServerCore
{
    public class DnsServer : IDisposable
    {
        #region variables

        const int BUFFER_MAX_SIZE = 65535;
        const int TCP_SOCKET_SEND_TIMEOUT = 30000;
        const int TCP_SOCKET_RECV_TIMEOUT = 60000;

        Socket _udpListener;
        Thread _udpListenerThread;

        Socket _tcpListener;
        Thread _tcpListenerThread;

        Zone _authoritativeZoneRoot = new Zone(true);
        Zone _cacheZoneRoot = new Zone(false);

        bool _allowRecursion;
        NameServerAddress[] _forwarders;
        bool _enableIPv6 = false;

        #endregion

        #region constructor

        public DnsServer()
            : this(new IPEndPoint(IPAddress.IPv6Any, 53))
        { }

        public DnsServer(IPAddress localIP, int port = 53)
            : this(new IPEndPoint(localIP, port))
        { }

        public DnsServer(IPEndPoint localEP)
        {
            _udpListener = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            _udpListener.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
            _udpListener.Bind(localEP);

            _tcpListener = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            _tcpListener.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
            _tcpListener.Bind(localEP);
            _tcpListener.Listen(10);

            //start reading query packets
            _udpListenerThread = new Thread(ReadUdpQueryPacketsAsync);
            _udpListenerThread.IsBackground = true;
            _udpListenerThread.Start(_udpListener);

            _tcpListenerThread = new Thread(AcceptTcpConnectionAsync);
            _tcpListenerThread.IsBackground = true;
            _tcpListenerThread.Start(_tcpListener);
        }

        #endregion

        #region IDisposable Support

        bool _disposed = false;

        ~DnsServer()
        {
            Dispose(false);
        }

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
            Socket udpListener = parameter as Socket;

            EndPoint remoteEP;
            FixMemoryStream recvBufferStream = new FixMemoryStream(BUFFER_MAX_SIZE);
            FixMemoryStream sendBufferStream = new FixMemoryStream(BUFFER_MAX_SIZE);
            int bytesRecv;

            if (udpListener.AddressFamily == AddressFamily.InterNetwork)
                remoteEP = new IPEndPoint(IPAddress.Any, 0);
            else
                remoteEP = new IPEndPoint(IPAddress.IPv6Any, 0);

            while (true)
            {
                bytesRecv = udpListener.ReceiveFrom(recvBufferStream.Buffer, ref remoteEP);

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
                            sendBufferStream.Position = 0;
                            response.WriteTo(sendBufferStream);
                            udpListener.SendTo(sendBufferStream.Buffer, 0, (int)sendBufferStream.Position, SocketFlags.None, remoteEP);
                        }
                    }
                    catch
                    { }
                }
            }
        }

        private void AcceptTcpConnectionAsync(object parameter)
        {
            Socket tcpListener = parameter as Socket;

            while (true)
            {
                Socket socket = tcpListener.Accept();

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
                FixMemoryStream recvBufferStream = new FixMemoryStream(BUFFER_MAX_SIZE);
                FixMemoryStream sendBufferStream = new FixMemoryStream(BUFFER_MAX_SIZE);
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
                            //write dns datagram from 3rd position
                            sendBufferStream.Position = 2;
                            response.WriteTo(sendBufferStream);

                            //write dns datagram length at beginning
                            byte[] lengthBytes = BitConverter.GetBytes(Convert.ToInt16(sendBufferStream.Position - 2));
                            sendBufferStream.Buffer[0] = lengthBytes[1];
                            sendBufferStream.Buffer[1] = lengthBytes[0];

                            //send dns datagram
                            tcpSocket.Send(sendBufferStream.Buffer, 0, (int)sendBufferStream.Position, SocketFlags.None);
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
                    try
                    {
                        DnsDatagram authoritativeResponse = Zone.Query(_authoritativeZoneRoot, request, _enableIPv6);

                        if ((authoritativeResponse.Header.RCODE != DnsResponseCode.Refused) || !request.Header.RecursionDesired || !_allowRecursion)
                            return authoritativeResponse;

                        return RecursiveQuery(request);
                    }
                    catch
                    {
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, _allowRecursion, false, false, DnsResponseCode.ServerFailure, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
                    }

                default:
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, request.Header.OPCODE, false, false, request.Header.RecursionDesired, _allowRecursion, false, false, DnsResponseCode.Refused, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
            }
        }

        public DnsDatagram RecursiveQuery(DnsDatagram request)
        {
            DnsDatagram originalRequest = request;
            List<DnsDatagram> responses = new List<DnsDatagram>(1);

            while (true)
            {
                DnsDatagram response = Resolve(request);
                responses.Add(response);

                if (response.Header.RCODE != DnsResponseCode.NoError)
                    break;

                if (response.Answer.Length == 0)
                    break;

                List<DnsQuestionRecord> newQuestions = new List<DnsQuestionRecord>();

                foreach (DnsQuestionRecord question in request.Question)
                {
                    for (int i = 0; i < response.Answer.Length; i++)
                    {
                        DnsResourceRecord answerRecord = response.Answer[i];

                        if ((answerRecord.Type == DnsResourceRecordType.CNAME) && question.Name.Equals(answerRecord.Name, StringComparison.CurrentCultureIgnoreCase))
                        {
                            string cnameDomain = (answerRecord.RDATA as DnsCNAMERecord).CNAMEDomainName;
                            bool containsAnswer = false;

                            for (int j = i + 1; j < response.Answer.Length; j++)
                            {
                                DnsResourceRecord answer = response.Answer[j];

                                if ((answer.Type == question.Type) && cnameDomain.Equals(answer.Name, StringComparison.CurrentCultureIgnoreCase))
                                {
                                    containsAnswer = true;
                                    break;
                                }
                            }

                            if (!containsAnswer)
                                newQuestions.Add(new DnsQuestionRecord((answerRecord.RDATA as DnsCNAMERecord).CNAMEDomainName, question.Type, question.Class));

                            break;
                        }
                    }
                }

                if (newQuestions.Count == 0)
                    break;

                request = new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, Convert.ToUInt16(newQuestions.Count), 0, 0, 0), newQuestions.ToArray(), null, null, null);
            }

            return MergeResponseAnswers(originalRequest, responses);
        }

        private DnsDatagram Resolve(DnsDatagram request)
        {
            DnsDatagram cacheResponse = Zone.Query(_cacheZoneRoot, request, _enableIPv6);

            if (cacheResponse.Header.RCODE != DnsResponseCode.Refused)
                return cacheResponse;

            List<DnsDatagram> responses = new List<DnsDatagram>();

            foreach (DnsQuestionRecord questionRecord in request.Question)
            {
                NameServerAddress[] nameServers = NameServerAddress.GetNameServersFromResponse(cacheResponse, _enableIPv6);

                if (nameServers.Length == 0)
                {
                    if (_enableIPv6)
                        nameServers = DnsClient.ROOT_NAME_SERVERS_IPv6;
                    else
                        nameServers = DnsClient.ROOT_NAME_SERVERS_IPv4;
                }

                int hopCount = 0;
                bool working = true;

                while (working && ((hopCount++) < 64))
                {
                    DnsClient client = new DnsClient(nameServers, _enableIPv6, false);

                    DnsDatagram response = client.Resolve(questionRecord);

                    Zone.CacheResponse(_cacheZoneRoot, response);

                    switch (response.Header.RCODE)
                    {
                        case DnsResponseCode.NoError:
                            if ((response.Answer.Length > 0) || (response.Authority.Length == 0))
                            {
                                responses.Add(response);
                                working = false;
                            }
                            else
                            {
                                nameServers = NameServerAddress.GetNameServersFromResponse(response, _enableIPv6);

                                if (nameServers.Length == 0)
                                {
                                    responses.Add(response);
                                    working = false;
                                }
                            }
                            break;

                        default:
                            responses.Add(response);
                            working = false;
                            break;
                    }
                }
            }

            return MergeResponseAnswers(request, responses);
        }

        private DnsDatagram MergeResponseAnswers(DnsDatagram request, List<DnsDatagram> responses)
        {
            switch (responses.Count)
            {
                case 0:
                    return null;

                case 1:
                    DnsDatagram responseReceived = responses[0];

                    if (responseReceived.Answer.Length == 0)
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, request.Header.OPCODE, false, false, true, true, false, false, responseReceived.Header.RCODE, request.Header.QDCOUNT, responseReceived.Header.ANCOUNT, responseReceived.Header.NSCOUNT, 0), request.Question, responseReceived.Answer, responseReceived.Authority, null);
                    else
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, request.Header.OPCODE, false, false, true, true, false, false, responseReceived.Header.RCODE, request.Header.QDCOUNT, responseReceived.Header.ANCOUNT, 0, 0), request.Question, responseReceived.Answer, null, null);

                default:
                    List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                    List<DnsResourceRecord> responseAuthority = new List<DnsResourceRecord>();

                    foreach (DnsDatagram response in responses)
                    {
                        responseAnswer.AddRange(response.Answer);

                        if ((response.Answer.Length == 0) && (response.Authority != null))
                            responseAuthority.AddRange(response.Authority);
                    }

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, request.Header.OPCODE, false, false, true, true, false, false, responses[0].Header.RCODE, request.Header.QDCOUNT, Convert.ToUInt16(responseAnswer.Count), Convert.ToUInt16(responseAuthority.Count), 0), request.Question, responseAnswer.ToArray(), responseAuthority.ToArray(), null);
            }
        }

        #endregion

        #region properties

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

        public bool EnableIPv6
        {
            get { return _enableIPv6; }
            set { _enableIPv6 = value; }
        }
        #endregion
    }

    public class DnsServerException : Exception
    {
        #region constructors

        public DnsServerException()
            : base()
        { }

        public DnsServerException(string message)
            : base(message)
        { }

        public DnsServerException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected DnsServerException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }

}
