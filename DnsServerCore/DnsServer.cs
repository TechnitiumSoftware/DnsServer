/*
Technitium DNS Server
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

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

        const int UDP_LISTENER_THREAD_COUNT = 3;
        const int TCP_SOCKET_SEND_TIMEOUT = 30000;
        const int TCP_SOCKET_RECV_TIMEOUT = 120000;

        readonly IPEndPoint _localEP;

        Socket _udpListener;
        Thread[] _udpListenerThreads;

        Socket _tcpListener;
        Thread _tcpListenerThread;

        readonly Zone _authoritativeZoneRoot = new Zone(true);
        readonly Zone _cacheZoneRoot = new Zone(false);
        readonly Zone _allowedZoneRoot = new Zone(true);
        Zone _blockedZoneRoot = new Zone(true);

        readonly IDnsCache _dnsCache;

        bool _allowRecursion = false;
        bool _allowRecursionOnlyForPrivateNetworks = false;
        NetProxy _proxy;
        NameServerAddress[] _forwarders;
        DnsClientProtocol _forwarderProtocol = DnsClientProtocol.Udp;
        DnsClientProtocol _recursiveResolveProtocol = DnsClientProtocol.Udp;
        bool _preferIPv6 = false;
        int _retries = 3;
        int _timeout = 2000;
        int _maxStackCount = 10;
        LogManager _log;
        LogManager _queryLog;
        StatsManager _stats;

        readonly ConcurrentDictionary<DnsQuestionRecord, object> _recursiveQueryLocks = new ConcurrentDictionary<DnsQuestionRecord, object>();

        volatile ServiceState _state = ServiceState.Stopped;

        #endregion

        #region constructor

        static DnsServer()
        {
            //set min threads since the default value is too small
            {
                int minWorker = Environment.ProcessorCount * 64;
                int minIOC = Environment.ProcessorCount * 64;

                ThreadPool.SetMinThreads(minWorker, minIOC);
            }

            if (ServicePointManager.DefaultConnectionLimit < 512)
                ServicePointManager.DefaultConnectionLimit = 512; //concurrent http request limit required when using DNS-over-HTTPS
        }

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
        }

        #endregion

        #region private

        private void ReadUdpRequestAsync(object parameter)
        {
            EndPoint remoteEP;
            byte[] recvBuffer = new byte[512];
            int bytesRecv;

            if (_udpListener.AddressFamily == AddressFamily.InterNetwork)
                remoteEP = new IPEndPoint(IPAddress.Any, 0);
            else
                remoteEP = new IPEndPoint(IPAddress.IPv6Any, 0);

            try
            {
                while (true)
                {
                    try
                    {
                        bytesRecv = _udpListener.ReceiveFrom(recvBuffer, ref remoteEP);
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
                        try
                        {
                            ThreadPool.QueueUserWorkItem(ProcessUdpRequestAsync, new object[] { remoteEP, new DnsDatagram(new MemoryStream(recvBuffer, 0, bytesRecv, false)) });
                        }
                        catch (Exception ex)
                        {
                            LogManager log = _log;
                            if (log != null)
                                log.Write(remoteEP as IPEndPoint, ex);
                        }
                    }
                }
            }
            catch (ThreadAbortException)
            {
                //server stopping
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write(remoteEP as IPEndPoint, ex);

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
                DnsDatagram response = ProcessQuery(request, remoteEP);

                //send response
                if (response != null)
                {
                    byte[] sendBuffer = new byte[512];
                    MemoryStream sendBufferStream = new MemoryStream(sendBuffer);

                    try
                    {
                        response.WriteTo(sendBufferStream);
                    }
                    catch (NotSupportedException)
                    {
                        DnsHeader header = response.Header;
                        response = new DnsDatagram(new DnsHeader(header.Identifier, true, header.OPCODE, header.AuthoritativeAnswer, true, header.RecursionDesired, header.RecursionAvailable, header.AuthenticData, header.CheckingDisabled, header.RCODE, header.QDCOUNT, 0, 0, 0), response.Question, null, null, null);

                        sendBufferStream.Position = 0;
                        response.WriteTo(sendBufferStream);
                    }

                    //send dns datagram
                    _udpListener.SendTo(sendBuffer, 0, (int)sendBufferStream.Position, SocketFlags.None, remoteEP);

                    LogManager queryLog = _queryLog;
                    if (queryLog != null)
                        queryLog.Write(remoteEP as IPEndPoint, false, request, response);

                    StatsManager stats = _stats;
                    if (stats != null)
                        stats.Update(response, (remoteEP as IPEndPoint).Address);
                }
            }
            catch (Exception ex)
            {
                LogManager queryLog = _queryLog;
                if (queryLog != null)
                    queryLog.Write(remoteEP as IPEndPoint, false, request, null);

                LogManager log = _log;
                if (log != null)
                    log.Write(remoteEP as IPEndPoint, ex);
            }
        }

        private void AcceptTcpConnectionAsync(object parameter)
        {
            try
            {
                while (true)
                {
                    Socket socket = _tcpListener.Accept();

                    socket.SendTimeout = TCP_SOCKET_SEND_TIMEOUT;
                    socket.ReceiveTimeout = TCP_SOCKET_RECV_TIMEOUT;

                    ThreadPool.QueueUserWorkItem(ReadTcpRequestAsync, socket);
                }
            }
            catch (ThreadAbortException)
            {
                //server stopping
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write(_localEP, ex);

                if (_state == ServiceState.Running)
                    throw;
            }
        }

        private void ReadTcpRequestAsync(object parameter)
        {
            Socket tcpSocket = parameter as Socket;
            DnsDatagram request = null;

            try
            {
                NetworkStream tcpStream = new NetworkStream(tcpSocket);
                OffsetStream recvDatagramStream = new OffsetStream(tcpStream, 0, 0);
                MemoryStream sendBufferStream = new MemoryStream(64);
                ushort length;

                while (true)
                {
                    request = null;

                    //read dns datagram length
                    byte[] lengthBuffer = tcpStream.ReadBytes(2);
                    Array.Reverse(lengthBuffer, 0, 2);
                    length = BitConverter.ToUInt16(lengthBuffer, 0);

                    //read dns datagram
                    recvDatagramStream.Reset(0, length, 0);
                    request = new DnsDatagram(recvDatagramStream);

                    //process request async
                    ThreadPool.QueueUserWorkItem(ProcessTcpRequestAsync, new object[] { request, tcpSocket, tcpStream, sendBufferStream });
                }
            }
            catch (IOException)
            {
                //ignore IO exceptions
            }
            catch (Exception ex)
            {
                LogManager queryLog = _queryLog;
                if ((queryLog != null) && (request != null))
                    queryLog.Write(tcpSocket.RemoteEndPoint as IPEndPoint, true, request, null);

                LogManager log = _log;
                if (log != null)
                    log.Write(tcpSocket.RemoteEndPoint as IPEndPoint, ex);
            }
            finally
            {
                if (tcpSocket != null)
                    tcpSocket.Dispose();
            }
        }

        private void ProcessTcpRequestAsync(object parameter)
        {
            object[] parameters = parameter as object[];

            DnsDatagram request = parameters[0] as DnsDatagram;
            Socket tcpSocket = parameters[1] as Socket;
            NetworkStream tcpStream = parameters[2] as NetworkStream;
            MemoryStream sendBufferStream = parameters[3] as MemoryStream;

            try
            {
                DnsDatagram response = ProcessQuery(request, tcpSocket.RemoteEndPoint);

                //send response
                if (response != null)
                {
                    lock (tcpSocket)
                    {
                        //write dns datagram
                        sendBufferStream.Position = 0;
                        response.WriteTo(sendBufferStream);

                        //write dns datagram length
                        ushort length = Convert.ToUInt16(sendBufferStream.Position);
                        byte[] lengthBuffer = BitConverter.GetBytes(length);
                        Array.Reverse(lengthBuffer, 0, 2);
                        tcpStream.Write(lengthBuffer);

                        //send dns datagram
                        sendBufferStream.Position = 0;
                        sendBufferStream.CopyTo(tcpStream, 512, length);

                        tcpStream.Flush();
                    }

                    LogManager queryLog = _queryLog;
                    if (queryLog != null)
                        queryLog.Write(tcpSocket.RemoteEndPoint as IPEndPoint, true, request, response);

                    StatsManager stats = _stats;
                    if (stats != null)
                        stats.Update(response, (tcpSocket.RemoteEndPoint as IPEndPoint).Address);
                }
            }
            catch (IOException)
            {
                //ignore IO exceptions
            }
            catch (Exception ex)
            {
                LogManager queryLog = _queryLog;
                if ((queryLog != null) && (request != null))
                    queryLog.Write(tcpSocket.RemoteEndPoint as IPEndPoint, true, request, null);

                LogManager log = _log;
                if (log != null)
                    log.Write(tcpSocket.RemoteEndPoint as IPEndPoint, ex);
            }
        }

        private bool IsRecursionAllowed(EndPoint remoteEP)
        {
            if (!_allowRecursion)
                return false;

            if (_allowRecursionOnlyForPrivateNetworks)
            {
                switch (remoteEP.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                    case AddressFamily.InterNetworkV6:
                        return NetUtilities.IsPrivateIP((remoteEP as IPEndPoint).Address);

                    default:
                        return false;
                }
            }

            return true;
        }

        private DnsDatagram ProcessQuery(DnsDatagram request, EndPoint remoteEP)
        {
            if (request.Header.IsResponse)
                return null;

            bool isRecursionAllowed = IsRecursionAllowed(remoteEP);

            switch (request.Header.OPCODE)
            {
                case DnsOpcode.StandardQuery:
                    if ((request.Question.Length != 1) || (request.Question[0].Class != DnsClass.IN))
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);

                    switch (request.Question[0].Type)
                    {
                        case DnsResourceRecordType.IXFR:
                        case DnsResourceRecordType.AXFR:
                        case DnsResourceRecordType.MAILB:
                        case DnsResourceRecordType.MAILA:
                            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
                    }

                    try
                    {
                        //query authoritative zone
                        DnsDatagram authoritativeResponse = ProcessAuthoritativeQuery(request, isRecursionAllowed);

                        if ((authoritativeResponse.Header.RCODE != DnsResponseCode.Refused) || !request.Header.RecursionDesired || !isRecursionAllowed)
                            return authoritativeResponse;

                        //query blocked zone
                        DnsDatagram blockedResponse = _blockedZoneRoot.Query(request);

                        if (blockedResponse.Header.RCODE != DnsResponseCode.Refused)
                        {
                            //query allowed zone
                            DnsDatagram allowedResponse = _allowedZoneRoot.Query(request);

                            if (allowedResponse.Header.RCODE == DnsResponseCode.Refused)
                            {
                                //request domain not in allowed zone

                                if (blockedResponse.Header.RCODE == DnsResponseCode.NameError)
                                {
                                    DnsResourceRecord[] answer;
                                    DnsResourceRecord[] authority;

                                    switch (blockedResponse.Question[0].Type)
                                    {
                                        case DnsResourceRecordType.A:
                                            answer = new DnsResourceRecord[] { new DnsResourceRecord(blockedResponse.Question[0].Name, DnsResourceRecordType.A, blockedResponse.Question[0].Class, 60, new DnsARecord(IPAddress.Any)) };
                                            authority = new DnsResourceRecord[] { };
                                            break;

                                        case DnsResourceRecordType.AAAA:
                                            answer = new DnsResourceRecord[] { new DnsResourceRecord(blockedResponse.Question[0].Name, DnsResourceRecordType.AAAA, blockedResponse.Question[0].Class, 60, new DnsAAAARecord(IPAddress.IPv6Any)) };
                                            authority = new DnsResourceRecord[] { };
                                            break;

                                        default:
                                            answer = blockedResponse.Answer;
                                            authority = blockedResponse.Authority;
                                            break;
                                    }

                                    blockedResponse = new DnsDatagram(new DnsHeader(blockedResponse.Header.Identifier, true, blockedResponse.Header.OPCODE, false, false, blockedResponse.Header.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, blockedResponse.Header.QDCOUNT, (ushort)answer.Length, (ushort)authority.Length, 0), blockedResponse.Question, answer, authority, null);
                                }

                                //return blocked response
                                blockedResponse.Tag = "blocked";
                                return blockedResponse;
                            }
                        }

                        //do recursive query
                        return ProcessRecursiveQuery(request);
                    }
                    catch (Exception ex)
                    {
                        LogManager log = _log;
                        if (log != null)
                            log.Write(remoteEP as IPEndPoint, ex);

                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.ServerFailure, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
                    }

                default:
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, request.Header.OPCODE, false, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
            }
        }

        private DnsDatagram ProcessAuthoritativeQuery(DnsDatagram request, bool isRecursionAllowed)
        {
            DnsDatagram response = _authoritativeZoneRoot.Query(request);
            response.Tag = "cacheHit";

            if (response.Header.RCODE == DnsResponseCode.NoError)
            {
                if (response.Answer.Length > 0)
                {
                    DnsResourceRecordType questionType = request.Question[0].Type;
                    DnsResourceRecord lastRR = response.Answer[response.Answer.Length - 1];

                    if ((lastRR.Type != questionType) && (lastRR.Type == DnsResourceRecordType.CNAME) && (questionType != DnsResourceRecordType.ANY))
                    {
                        List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                        responseAnswer.AddRange(response.Answer);

                        DnsDatagram lastResponse;
                        bool cacheHit = (response.Tag == "cacheHit");

                        while (true)
                        {
                            DnsDatagram cnameRequest = new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, questionType, DnsClass.IN) }, null, null, null);

                            lastResponse = _authoritativeZoneRoot.Query(cnameRequest);

                            if (lastResponse.Header.RCODE == DnsResponseCode.Refused)
                            {
                                if (!cnameRequest.Header.RecursionDesired || !isRecursionAllowed)
                                    break;

                                lastResponse = ProcessRecursiveQuery(cnameRequest);
                                cacheHit &= (lastResponse.Tag == "cacheHit");
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
                        DnsResourceRecord[] additional;

                        if (lastResponse.Header.RCODE == DnsResponseCode.Refused)
                        {
                            rcode = DnsResponseCode.NoError;
                            authority = new DnsResourceRecord[] { };
                            additional = new DnsResourceRecord[] { };
                        }
                        else
                        {
                            rcode = lastResponse.Header.RCODE;

                            if (lastResponse.Header.AuthoritativeAnswer)
                            {
                                authority = lastResponse.Authority;
                                additional = lastResponse.Additional;
                            }
                            else
                            {
                                if ((lastResponse.Authority.Length > 0) && (lastResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                                    authority = lastResponse.Authority;
                                else
                                    authority = new DnsResourceRecord[] { };

                                additional = new DnsResourceRecord[] { };
                            }
                        }

                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, lastResponse.Header.AuthoritativeAnswer, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, rcode, 1, (ushort)responseAnswer.Count, (ushort)authority.Length, (ushort)additional.Length), request.Question, responseAnswer.ToArray(), authority, additional) { Tag = (cacheHit ? "cacheHit" : null) };
                    }
                }
                else if ((response.Authority.Length > 0) && (response.Authority[0].Type == DnsResourceRecordType.NS) && isRecursionAllowed)
                {
                    if (_forwarders != null)
                        return ProcessRecursiveQuery(request); //do recursive resolution using forwarders

                    //do recursive resolution using response authority name servers
                    NameServerAddress[] nameServers = NameServerAddress.GetNameServersFromResponse(response, _preferIPv6, false);

                    return ProcessRecursiveQuery(request, nameServers);
                }
            }

            return response;
        }

        private DnsDatagram ProcessRecursiveQuery(DnsDatagram request, NameServerAddress[] viaNameServers = null)
        {
            DnsDatagram response = RecursiveResolve(request, viaNameServers);

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
                    bool cacheHit = (response.Tag == "cacheHit");

                    while (true)
                    {
                        DnsQuestionRecord question;

                        if (questionType == DnsResourceRecordType.PTR)
                            question = new DnsQuestionRecord(IPAddress.Parse((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName), DnsClass.IN);
                        else
                            question = new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, questionType, DnsClass.IN);

                        lastResponse = RecursiveResolve(question, _forwarders);
                        cacheHit &= (lastResponse.Tag == "cacheHit");

                        if ((lastResponse.Header.RCODE != DnsResponseCode.NoError) || (lastResponse.Answer.Length == 0))
                            break;

                        responseAnswer.AddRange(lastResponse.Answer);

                        lastRR = lastResponse.Answer[lastResponse.Answer.Length - 1];

                        if (lastRR.Type == questionType)
                            break;

                        if (lastRR.Type != DnsResourceRecordType.CNAME)
                            throw new DnsServerException("Invalid response received from DNS server.");
                    }

                    if ((lastResponse.Authority.Length > 0) && (lastResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                        authority = lastResponse.Authority;
                    else
                        authority = new DnsResourceRecord[] { };

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, lastResponse.Header.RCODE, 1, (ushort)responseAnswer.Count, (ushort)authority.Length, 0), request.Question, responseAnswer.ToArray(), authority, new DnsResourceRecord[] { }) { Tag = (cacheHit ? "cacheHit" : null) };
                }
            }

            if ((response.Authority.Length > 0) && (response.Authority[0].Type == DnsResourceRecordType.SOA))
                authority = response.Authority;
            else
                authority = new DnsResourceRecord[] { };

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, response.Header.RCODE, 1, (ushort)response.Answer.Length, (ushort)authority.Length, 0), request.Question, response.Answer, authority, new DnsResourceRecord[] { }) { Tag = response.Tag };
        }

        private DnsDatagram RecursiveResolve(DnsQuestionRecord questionRecord, NameServerAddress[] viaNameServers)
        {
            return RecursiveResolve(new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { questionRecord }, null, null, null), viaNameServers);
        }

        private DnsDatagram RecursiveResolve(DnsDatagram request, NameServerAddress[] viaNameServers)
        {
            //query cache zone to see if answer available
            {
                DnsDatagram cacheResponse = _cacheZoneRoot.Query(request);

                if (cacheResponse.Header.RCODE != DnsResponseCode.Refused)
                {
                    if ((cacheResponse.Answer.Length > 0) || ((cacheResponse.Authority.Length == 0) || (cacheResponse.Authority[0].Type == DnsResourceRecordType.SOA)))
                    {
                        cacheResponse.Tag = "cacheHit";
                        return cacheResponse;
                    }
                }
            }

            //recursion with locking
            {
                object newLockObj = new object();
                object actualLockObj = _recursiveQueryLocks.GetOrAdd(request.Question[0], newLockObj);

                if (!actualLockObj.Equals(newLockObj))
                {
                    //question already being recursively resolved by another thread, wait till timeout or pulse signal
                    lock (actualLockObj)
                    {
                        Monitor.Wait(actualLockObj, _timeout);
                    }

                    //query cache zone again to see if answer available
                    {
                        DnsDatagram cacheResponse = _cacheZoneRoot.Query(request);

                        if (cacheResponse.Header.RCODE != DnsResponseCode.Refused)
                        {
                            if ((cacheResponse.Answer.Length > 0) || ((cacheResponse.Authority.Length == 0) || (cacheResponse.Authority[0].Type == DnsResourceRecordType.SOA)))
                            {
                                cacheResponse.Tag = "cacheHit";
                                return cacheResponse;
                            }
                        }
                    }

                    //no response available in cache so respond with server failure
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.ServerFailure, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
                }
            }

            //select protocol
            DnsClientProtocol protocol;

            if (_forwarders == null)
            {
                protocol = _recursiveResolveProtocol;
            }
            else
            {
                viaNameServers = _forwarders; //forwarder has higher weightage
                protocol = _forwarderProtocol;
            }

            try
            {
                return DnsClient.ResolveViaNameServers(request.Question[0], viaNameServers, _dnsCache, _proxy, _preferIPv6, protocol, _retries, _maxStackCount, _timeout, _recursiveResolveProtocol);
            }
            finally
            {
                //remove question lock
                if (_recursiveQueryLocks.TryRemove(request.Question[0], out object lockObj))
                {
                    //pulse all waiting threads
                    lock (lockObj)
                    {
                        Monitor.PulseAll(lockObj);
                    }
                }
            }
        }

        #endregion

        #region public

        public void Start()
        {
            if (_state != ServiceState.Stopped)
                return;

            _udpListener = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            _udpListener.DualMode = true;
            _udpListener.Bind(_localEP);

            #region this code ignores ICMP port unreachable responses which creates SocketException in ReceiveFrom()

            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                const uint IOC_IN = 0x80000000;
                const uint IOC_VENDOR = 0x18000000;
                const uint SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

                _udpListener.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { Convert.ToByte(false) }, null);
            }

            #endregion

            _tcpListener = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            _tcpListener.DualMode = true;
            _tcpListener.Bind(_localEP);
            _tcpListener.Listen(100);

            //start reading query packets
            _udpListenerThreads = new Thread[UDP_LISTENER_THREAD_COUNT];

            for (int i = 0; i < UDP_LISTENER_THREAD_COUNT; i++)
            {
                _udpListenerThreads[i] = new Thread(ReadUdpRequestAsync);
                _udpListenerThreads[i].IsBackground = true;
                _udpListenerThreads[i].Start();
            }

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

            for (int i = 0; i < UDP_LISTENER_THREAD_COUNT; i++)
            {
                try
                {
                    _udpListenerThreads[i].Abort();
                }
                catch (PlatformNotSupportedException)
                { }
            }


            try
            {
                _tcpListenerThread.Abort();
            }
            catch (PlatformNotSupportedException)
            { }

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

        public Zone AllowedZoneRoot
        { get { return _allowedZoneRoot; } }

        public Zone BlockedZoneRoot
        {
            get { return _blockedZoneRoot; }
            set
            {
                if (value == null)
                    throw new ArgumentNullException();

                if (!value.IsAuthoritative)
                    throw new ArgumentException("Blocked zone must be authoritative.");

                _blockedZoneRoot = value;
            }
        }

        internal IDnsCache Cache
        { get { return _dnsCache; } }

        public bool AllowRecursion
        {
            get { return _allowRecursion; }
            set { _allowRecursion = value; }
        }

        public bool AllowRecursionOnlyForPrivateNetworks
        {
            get { return _allowRecursionOnlyForPrivateNetworks; }
            set { _allowRecursionOnlyForPrivateNetworks = value; }
        }

        public NetProxy Proxy
        {
            get { return _proxy; }
            set { _proxy = value; }
        }

        public NameServerAddress[] Forwarders
        {
            get { return _forwarders; }
            set { _forwarders = value; }
        }

        public DnsClientProtocol ForwarderProtocol
        {
            get { return _forwarderProtocol; }
            set { _forwarderProtocol = value; }
        }

        public DnsClientProtocol RecursiveResolveProtocol
        {
            get { return _recursiveResolveProtocol; }
            set { _recursiveResolveProtocol = value; }
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

        public int Timeout
        {
            get { return _timeout; }
            set { _timeout = value; }
        }

        public int MaxStackCount
        {
            get { return _maxStackCount; }
            set { _maxStackCount = value; }
        }

        public LogManager LogManager
        {
            get { return _log; }
            set { _log = value; }
        }

        public LogManager QueryLogManager
        {
            get { return _queryLog; }
            set { _queryLog = value; }
        }

        public StatsManager StatsManager
        {
            get { return _stats; }
            set { _stats = value; }
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
