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

using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    public class DnsServer : IDisposable
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

        const int LISTENER_THREAD_COUNT = 3;

        IPAddress[] _localIPs;

        List<Socket> _udpListeners = new List<Socket>();
        List<Socket> _tcpListeners = new List<Socket>();
        List<Socket> _httpListeners = new List<Socket>();
        List<Socket> _tlsListeners = new List<Socket>();
        List<Socket> _httpsListeners = new List<Socket>();
        List<Thread> _listenerThreads = new List<Thread>();

        bool _enableDnsOverHttp = false;
        bool _enableDnsOverTls = false;
        bool _enableDnsOverHttps = false;
        bool _isDnsOverHttpsEnabled;
        X509Certificate2 _certificate;

        readonly Zone _authoritativeZoneRoot = new Zone(true);
        readonly Zone _cacheZoneRoot = new Zone(false) { ServeStaleTtl = 7 * 24 * 60 * 60 }; //7 days serve stale ttl as per draft-ietf-dnsop-serve-stale-04
        readonly Zone _allowedZoneRoot = new Zone(true);
        Zone _blockedZoneRoot = new Zone(true);

        readonly IDnsCache _dnsCache;

        bool _allowRecursion = false;
        bool _allowRecursionOnlyForPrivateNetworks = false;
        NetProxy _proxy;
        NameServerAddress[] _forwarders;
        DnsTransportProtocol _forwarderProtocol = DnsTransportProtocol.Udp;
        DnsTransportProtocol _recursiveResolveProtocol = DnsTransportProtocol.Udp;
        bool _preferIPv6 = false;
        int _retries = 2;
        int _timeout = 2000;
        int _maxStackCount = 10;
        LogManager _log;
        LogManager _queryLog;
        StatsManager _stats;

        int _tcpSendTimeout = 10000;
        int _tcpReceiveTimeout = 10000;

        readonly ConcurrentDictionary<DnsQuestionRecord, RecursiveQueryLock> _recursiveQueryLocks = new ConcurrentDictionary<DnsQuestionRecord, RecursiveQueryLock>(Environment.ProcessorCount * 64, Environment.ProcessorCount * 32);

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

            if (ServicePointManager.DefaultConnectionLimit < 10)
                ServicePointManager.DefaultConnectionLimit = 10; //concurrent http request limit required when using DNS-over-HTTPS forwarders
        }

        public DnsServer()
            : this(new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any })
        { }

        public DnsServer(IPAddress localIP)
            : this(new IPAddress[] { localIP })
        { }

        public DnsServer(IPAddress[] localIPs)
        {
            _localIPs = localIPs;
            _dnsCache = new DnsCache(_cacheZoneRoot);
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

                if (_queryLog != null)
                    _queryLog.Dispose();

                if (_stats != null)
                    _stats.Dispose();
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
            EndPoint remoteEP;
            byte[] recvBuffer = new byte[512];
            int bytesRecv;

            if (udpListener.AddressFamily == AddressFamily.InterNetwork)
                remoteEP = new IPEndPoint(IPAddress.Any, 0);
            else
                remoteEP = new IPEndPoint(IPAddress.IPv6Any, 0);

            try
            {
                while (true)
                {
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
                        try
                        {
                            ThreadPool.QueueUserWorkItem(ProcessUdpRequestAsync, new object[] { udpListener, remoteEP, new DnsDatagram(new MemoryStream(recvBuffer, 0, bytesRecv, false)) });
                        }
                        catch (Exception ex)
                        {
                            LogManager log = _log;
                            if (log != null)
                                log.Write(remoteEP as IPEndPoint, DnsTransportProtocol.Udp, ex);
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
                    log.Write(remoteEP as IPEndPoint, DnsTransportProtocol.Udp, ex);

                throw;
            }
        }

        private void ProcessUdpRequestAsync(object parameter)
        {
            object[] parameters = parameter as object[];

            Socket udpListener = parameters[0] as Socket;
            EndPoint remoteEP = parameters[1] as EndPoint;
            DnsDatagram request = parameters[2] as DnsDatagram;

            try
            {
                DnsDatagram response = ProcessQuery(request, remoteEP, DnsTransportProtocol.Udp);

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
                    udpListener.SendTo(sendBuffer, 0, (int)sendBufferStream.Position, SocketFlags.None, remoteEP);

                    LogManager queryLog = _queryLog;
                    if (queryLog != null)
                        queryLog.Write(remoteEP as IPEndPoint, DnsTransportProtocol.Udp, request, response);

                    StatsManager stats = _stats;
                    if (stats != null)
                        stats.Update(response, (remoteEP as IPEndPoint).Address);
                }
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                LogManager queryLog = _queryLog;
                if (queryLog != null)
                    queryLog.Write(remoteEP as IPEndPoint, DnsTransportProtocol.Udp, request, null);

                LogManager log = _log;
                if (log != null)
                    log.Write(remoteEP as IPEndPoint, DnsTransportProtocol.Udp, ex);
            }
        }

        private void AcceptConnectionAsync(object parameter)
        {
            object[] parameters = parameter as object[];

            Socket tcpListener = parameters[0] as Socket;
            DnsTransportProtocol protocol = (DnsTransportProtocol)parameters[1];

            bool usingHttps = true;
            if (parameters.Length > 2)
                usingHttps = (bool)parameters[2];

            IPEndPoint localEP = tcpListener.LocalEndPoint as IPEndPoint;

            try
            {
                tcpListener.SendTimeout = _tcpSendTimeout;
                tcpListener.ReceiveTimeout = _tcpReceiveTimeout;
                tcpListener.SendBufferSize = 2048;
                tcpListener.ReceiveBufferSize = 512;
                tcpListener.NoDelay = true;

                while (true)
                {
                    Socket socket = tcpListener.Accept();

                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        EndPoint remoteEP = null;

                        try
                        {
                            remoteEP = socket.RemoteEndPoint;

                            switch (protocol)
                            {
                                case DnsTransportProtocol.Tcp:
                                    ReadStreamRequest(new NetworkStream(socket), remoteEP, protocol);
                                    break;

                                case DnsTransportProtocol.Tls:
                                    SslStream tlsStream = new SslStream(new NetworkStream(socket));
                                    tlsStream.AuthenticateAsServer(_certificate);

                                    ReadStreamRequest(tlsStream, remoteEP, protocol);
                                    break;

                                case DnsTransportProtocol.Https:
                                    Stream stream = new NetworkStream(socket);

                                    if (usingHttps)
                                    {
                                        SslStream httpsStream = new SslStream(stream);
                                        httpsStream.AuthenticateAsServer(_certificate);

                                        stream = httpsStream;
                                    }
                                    else if (!NetUtilities.IsPrivateIP((remoteEP as IPEndPoint).Address))
                                    {
                                        //intentionally blocking public IP addresses from using DNS-over-HTTP (without TLS)
                                        //this feature is intended to be used with an SSL terminated reverse proxy like nginx on private network
                                        return;
                                    }

                                    ProcessDoHRequest(stream, remoteEP, !usingHttps);
                                    break;
                            }
                        }
                        catch (IOException)
                        {
                            //ignore IO exceptions
                        }
                        catch (Exception ex)
                        {
                            LogManager log = _log;
                            if (log != null)
                                log.Write(remoteEP as IPEndPoint, protocol, ex);
                        }
                        finally
                        {
                            if (socket != null)
                                socket.Dispose();
                        }
                    });
                }
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                LogManager log = _log;
                if (log != null)
                    log.Write(localEP, protocol, ex);

                throw;
            }
        }

        private void ReadStreamRequest(Stream stream, EndPoint remoteEP, DnsTransportProtocol protocol)
        {
            DnsDatagram request = null;

            try
            {
                OffsetStream recvDatagramStream = new OffsetStream(stream, 0, 0);
                Stream writeBufferedStream = new WriteBufferedStream(stream, 2048);
                MemoryStream writeBuffer = new MemoryStream(64);
                byte[] lengthBuffer = new byte[2];
                ushort length;

                while (true)
                {
                    request = null;

                    //read dns datagram length
                    stream.ReadBytes(lengthBuffer, 0, 2);
                    Array.Reverse(lengthBuffer, 0, 2);
                    length = BitConverter.ToUInt16(lengthBuffer, 0);

                    //read dns datagram
                    recvDatagramStream.Reset(0, length, 0);
                    request = new DnsDatagram(recvDatagramStream);

                    //process request async
                    ThreadPool.QueueUserWorkItem(ProcessStreamRequestAsync, new object[] { writeBufferedStream, writeBuffer, remoteEP, request, protocol });
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
                    queryLog.Write(remoteEP as IPEndPoint, protocol, request, null);

                LogManager log = _log;
                if (log != null)
                    log.Write(remoteEP as IPEndPoint, protocol, ex);
            }
        }

        private void ProcessStreamRequestAsync(object parameter)
        {
            object[] parameters = parameter as object[];

            Stream stream = parameters[0] as Stream;
            MemoryStream writeBuffer = parameters[1] as MemoryStream;
            EndPoint remoteEP = parameters[2] as EndPoint;
            DnsDatagram request = parameters[3] as DnsDatagram;
            DnsTransportProtocol protocol = (DnsTransportProtocol)parameters[4];

            try
            {
                DnsDatagram response = ProcessQuery(request, remoteEP, protocol);

                //send response
                if (response != null)
                {
                    lock (stream)
                    {
                        //write dns datagram
                        writeBuffer.Position = 0;
                        response.WriteTo(writeBuffer);

                        //write dns datagram length
                        ushort length = Convert.ToUInt16(writeBuffer.Position);
                        byte[] lengthBuffer = BitConverter.GetBytes(length);
                        Array.Reverse(lengthBuffer, 0, 2);
                        stream.Write(lengthBuffer);

                        //send dns datagram
                        writeBuffer.Position = 0;
                        writeBuffer.CopyTo(stream, 512, length);

                        stream.Flush();
                    }

                    LogManager queryLog = _queryLog;
                    if (queryLog != null)
                        queryLog.Write(remoteEP as IPEndPoint, protocol, request, response);

                    StatsManager stats = _stats;
                    if (stats != null)
                        stats.Update(response, (remoteEP as IPEndPoint).Address);
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
                    queryLog.Write(remoteEP as IPEndPoint, protocol, request, null);

                LogManager log = _log;
                if (log != null)
                    log.Write(remoteEP as IPEndPoint, protocol, ex);
            }
        }

        private void ProcessDoHRequest(Stream stream, EndPoint remoteEP, bool usingReverseProxy)
        {
            DnsDatagram dnsRequest = null;
            DnsTransportProtocol dnsProtocol = DnsTransportProtocol.Https;

            try
            {
                while (true)
                {
                    string requestMethod;
                    string requestPath;
                    NameValueCollection requestQueryString = new NameValueCollection();
                    string requestProtocol;
                    WebHeaderCollection requestHeaders = new WebHeaderCollection();

                    #region parse http request

                    using (MemoryStream mS = new MemoryStream())
                    {
                        //read http request header into memory stream
                        int byteRead;
                        int crlfCount = 0;

                        while (true)
                        {
                            byteRead = stream.ReadByte();
                            switch (byteRead)
                            {
                                case '\r':
                                case '\n':
                                    crlfCount++;
                                    break;

                                case -1:
                                    throw new EndOfStreamException();

                                default:
                                    crlfCount = 0;
                                    break;
                            }

                            mS.WriteByte((byte)byteRead);

                            if (crlfCount == 4)
                                break; //http request completed
                        }

                        mS.Position = 0;
                        StreamReader sR = new StreamReader(mS);

                        string[] requestParts = sR.ReadLine().Split(new char[] { ' ' }, 3);

                        if (requestParts.Length != 3)
                            throw new InvalidDataException("Invalid HTTP request.");

                        requestMethod = requestParts[0];
                        string pathAndQueryString = requestParts[1];
                        requestProtocol = requestParts[2];

                        string[] requestPathAndQueryParts = pathAndQueryString.Split(new char[] { '?' }, 2);

                        requestPath = requestPathAndQueryParts[0];

                        string queryString = null;
                        if (requestPathAndQueryParts.Length > 1)
                            queryString = requestPathAndQueryParts[1];

                        if (!string.IsNullOrEmpty(queryString))
                        {
                            foreach (string item in queryString.Split(new char[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                string[] itemParts = item.Split(new char[] { '=' }, 2);

                                string name = itemParts[0];
                                string value = null;

                                if (itemParts.Length > 1)
                                    value = itemParts[1];

                                requestQueryString.Add(name, value);
                            }
                        }

                        while (true)
                        {
                            string line = sR.ReadLine();
                            if (string.IsNullOrEmpty(line))
                                break;

                            string[] parts = line.Split(new char[] { ':' }, 2);
                            if (parts.Length != 2)
                                throw new InvalidDataException("Invalid HTTP request.");

                            requestHeaders.Add(parts[0], parts[1]);
                        }
                    }

                    #endregion

                    if (usingReverseProxy)
                    {
                        string xRealIp = requestHeaders["X-Real-IP"];
                        string xForwardedFor = requestHeaders["X-Forwarded-For"];

                        if (!string.IsNullOrEmpty(xRealIp))
                        {
                            //get the real IP address of the requesting client from X-Real-IP header set in nginx proxy_pass block
                            remoteEP = new IPEndPoint(IPAddress.Parse(xRealIp), 0);
                        }
                        else if (!string.IsNullOrEmpty(xForwardedFor))
                        {
                            //get the real IP address of the requesting client from X-Forwarded-For header set in nginx proxy_pass block
                            string[] xForwardedForParts = xForwardedFor.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                            remoteEP = new IPEndPoint(IPAddress.Parse(xForwardedForParts[0]), 0);
                        }
                    }

                    string requestConnection = requestHeaders[HttpRequestHeader.Connection];
                    if (string.IsNullOrEmpty(requestConnection))
                        requestConnection = "close";

                    switch (requestPath)
                    {
                        case "/dns-query":
                            DnsTransportProtocol protocol = DnsTransportProtocol.Udp;

                            string strRequestAcceptTypes = requestHeaders[HttpRequestHeader.Accept];
                            if (!string.IsNullOrEmpty(strRequestAcceptTypes))
                            {
                                protocol = DnsTransportProtocol.Udp;

                                foreach (string acceptType in strRequestAcceptTypes.Split(','))
                                {
                                    if (acceptType == "application/dns-message")
                                    {
                                        protocol = DnsTransportProtocol.Https;
                                        break;
                                    }
                                    else if (acceptType == "application/dns-json")
                                    {
                                        protocol = DnsTransportProtocol.HttpsJson;
                                        dnsProtocol = DnsTransportProtocol.HttpsJson;
                                        break;
                                    }
                                }
                            }

                            switch (protocol)
                            {
                                case DnsTransportProtocol.Https:
                                    #region https wire format
                                    {
                                        switch (requestMethod)
                                        {
                                            case "GET":
                                                string strRequest = requestQueryString["dns"];
                                                if (string.IsNullOrEmpty(strRequest))
                                                    throw new ArgumentNullException("dns");

                                                //convert from base64url to base64
                                                strRequest = strRequest.Replace('-', '+');
                                                strRequest = strRequest.Replace('_', '/');

                                                //add padding
                                                int x = strRequest.Length % 4;
                                                if (x > 0)
                                                    strRequest = strRequest.PadRight(strRequest.Length - x + 4, '=');

                                                dnsRequest = new DnsDatagram(new MemoryStream(Convert.FromBase64String(strRequest)));
                                                break;

                                            case "POST":
                                                string strContentType = requestHeaders[HttpRequestHeader.ContentType];
                                                if (strContentType != "application/dns-message")
                                                    throw new NotSupportedException("DNS request type not supported: " + strContentType);

                                                dnsRequest = new DnsDatagram(stream);
                                                break;

                                            default:
                                                throw new NotSupportedException("DoH request type not supported.");
                                        }

                                        DnsDatagram dnsResponse = ProcessQuery(dnsRequest, remoteEP, protocol);
                                        if (dnsResponse != null)
                                        {
                                            using (MemoryStream mS = new MemoryStream())
                                            {
                                                dnsResponse.WriteTo(mS);

                                                byte[] buffer = mS.ToArray();
                                                Send200(stream, "application/dns-message", buffer);
                                            }

                                            LogManager queryLog = _queryLog;
                                            if (queryLog != null)
                                                queryLog.Write(remoteEP as IPEndPoint, protocol, dnsRequest, dnsResponse);

                                            StatsManager stats = _stats;
                                            if (stats != null)
                                                stats.Update(dnsResponse, (remoteEP as IPEndPoint).Address);
                                        }
                                    }
                                    #endregion
                                    break;

                                case DnsTransportProtocol.HttpsJson:
                                    #region https json format
                                    {
                                        string strName = requestQueryString["name"];
                                        if (string.IsNullOrEmpty(strName))
                                            throw new ArgumentNullException("name");

                                        string strType = requestQueryString["type"];
                                        if (string.IsNullOrEmpty(strType))
                                            strType = "1";

                                        dnsRequest = new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { new DnsQuestionRecord(strName, (DnsResourceRecordType)int.Parse(strType), DnsClass.IN) }, null, null, null);

                                        DnsDatagram dnsResponse = ProcessQuery(dnsRequest, remoteEP, protocol);
                                        if (dnsResponse != null)
                                        {
                                            using (MemoryStream mS = new MemoryStream())
                                            {
                                                JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                                                dnsResponse.WriteTo(jsonWriter);
                                                jsonWriter.Flush();

                                                byte[] buffer = mS.ToArray();
                                                Send200(stream, "application/dns-json; charset=utf-8", buffer);
                                            }

                                            LogManager queryLog = _queryLog;
                                            if (queryLog != null)
                                                queryLog.Write(remoteEP as IPEndPoint, protocol, dnsRequest, dnsResponse);

                                            StatsManager stats = _stats;
                                            if (stats != null)
                                                stats.Update(dnsResponse, (remoteEP as IPEndPoint).Address);
                                        }
                                    }
                                    #endregion
                                    break;

                                default:
                                    Send406(stream, "Only application/dns-message and application/dns-json types are accepted.");
                                    return;
                            }

                            if (requestConnection.Equals("close", StringComparison.CurrentCultureIgnoreCase))
                                break;
                            break;

                        case "/.well-known/doh-servers-associated/":
                            using (MemoryStream mS = new MemoryStream())
                            {
                                JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS, Encoding.UTF8));
                                jsonWriter.WriteStartObject();

                                jsonWriter.WritePropertyName("associated-resolvers");
                                jsonWriter.WriteStartArray();

                                if (_enableDnsOverHttp || _enableDnsOverHttps)
                                    jsonWriter.WriteValue("https://" + _authoritativeZoneRoot.ServerDomain + "/dns-query{?dns}");

                                jsonWriter.WriteEndArray();

                                jsonWriter.WriteEndObject();
                                jsonWriter.Flush();

                                Send200(stream, "application/json", mS.ToArray());
                            }

                            break;

                        default:
                            Send404(stream);
                            break;
                    }
                }
            }
            catch (IOException)
            {
                //ignore IO exceptions
            }
            catch (Exception ex)
            {
                LogManager queryLog = _queryLog;
                if ((queryLog != null) && (dnsRequest != null))
                    queryLog.Write(remoteEP as IPEndPoint, dnsProtocol, dnsRequest, null);

                LogManager log = _log;
                if (log != null)
                    log.Write(remoteEP as IPEndPoint, dnsProtocol, ex);
            }
        }

        private static void Send404(Stream outputStream)
        {
            byte[] bufferContent = Encoding.UTF8.GetBytes("<h1>404 Not Found</h1>");
            byte[] bufferHeader = Encoding.UTF8.GetBytes("HTTP/1.1 404 Not Found\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + bufferContent.Length + "\r\nX-Robots-Tag: noindex, nofollow\r\n\r\n");

            using (MemoryStream mS = new MemoryStream())
            {
                mS.Write(bufferHeader, 0, bufferHeader.Length);
                mS.Write(bufferContent, 0, bufferContent.Length);

                byte[] buffer = mS.ToArray();
                outputStream.Write(buffer, 0, buffer.Length);
            }
        }

        private static void Send406(Stream outputStream, string message)
        {
            byte[] bufferContent = Encoding.UTF8.GetBytes("<h1>406 Not Acceptable</h1><p>" + message + "</p>");
            byte[] bufferHeader = Encoding.UTF8.GetBytes("HTTP/1.1 406 Not Acceptable\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + bufferContent.Length + "\r\nX-Robots-Tag: noindex, nofollow\r\n\r\n");

            using (MemoryStream mS = new MemoryStream())
            {
                mS.Write(bufferHeader, 0, bufferHeader.Length);
                mS.Write(bufferContent, 0, bufferContent.Length);

                byte[] buffer = mS.ToArray();
                outputStream.Write(buffer, 0, buffer.Length);
            }
        }

        private static void Send200(Stream outputStream, string contentType, byte[] bufferContent)
        {
            byte[] bufferHeader = Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nContent-Type: " + contentType + "\r\nContent-Length: " + bufferContent.Length + "\r\nX-Robots-Tag: noindex, nofollow\r\n\r\n");

            using (MemoryStream mS = new MemoryStream())
            {
                mS.Write(bufferHeader, 0, bufferHeader.Length);
                mS.Write(bufferContent, 0, bufferContent.Length);

                byte[] buffer = mS.ToArray();
                outputStream.Write(buffer, 0, buffer.Length);
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

        internal DnsDatagram ProcessQuery(DnsDatagram request, EndPoint remoteEP, DnsTransportProtocol protocol)
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
                            log.Write(remoteEP as IPEndPoint, protocol, ex);

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
                        //resolve cname record
                        List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                        responseAnswer.AddRange(response.Answer);

                        DnsDatagram lastResponse;
                        bool cacheHit = ("cacheHit".Equals(response.Tag));

                        while (true)
                        {
                            DnsDatagram cnameRequest = new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, questionType, DnsClass.IN) }, null, null, null);

                            //query authoritative zone first
                            lastResponse = _authoritativeZoneRoot.Query(cnameRequest);

                            if (lastResponse.Header.RCODE == DnsResponseCode.Refused)
                            {
                                //not found in auth zone
                                if (!isRecursionAllowed || !cnameRequest.Header.RecursionDesired)
                                    break; //break since no recursion allowed/desired

                                //do recursion
                                lastResponse = ProcessRecursiveQuery(cnameRequest);
                                cacheHit &= ("cacheHit".Equals(lastResponse.Tag));
                            }
                            else if ((lastResponse.Header.RCODE == DnsResponseCode.NoError) && (lastResponse.Answer.Length == 0) && (lastResponse.Authority.Length > 0) && (lastResponse.Authority[0].Type == DnsResourceRecordType.NS))
                            {
                                //found delegated zone
                                if (!isRecursionAllowed || !cnameRequest.Header.RecursionDesired)
                                    break; //break since no recursion allowed/desired

                                //do recursive resolution using delegated authority name servers
                                NameServerAddress[] nameServers = NameServerAddress.GetNameServersFromResponse(lastResponse, _preferIPv6);

                                lastResponse = ProcessRecursiveQuery(cnameRequest, nameServers);
                                cacheHit &= ("cacheHit".Equals(lastResponse.Tag));
                            }

                            //check last response
                            if ((lastResponse.Header.RCODE != DnsResponseCode.NoError) || (lastResponse.Answer.Length == 0))
                                break; //cannot proceed to resolve cname further

                            responseAnswer.AddRange(lastResponse.Answer);

                            lastRR = lastResponse.Answer[lastResponse.Answer.Length - 1];

                            if (lastRR.Type != DnsResourceRecordType.CNAME)
                                break; //cname was resolved
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
                    //do recursive resolution using response authority name servers
                    NameServerAddress[] nameServers = NameServerAddress.GetNameServersFromResponse(response, _preferIPv6);

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
                    bool cacheHit = ("cacheHit".Equals(response.Tag));

                    while (true)
                    {
                        DnsQuestionRecord question;

                        if (questionType == DnsResourceRecordType.PTR)
                            question = new DnsQuestionRecord(IPAddress.Parse((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName), DnsClass.IN);
                        else
                            question = new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, questionType, DnsClass.IN);

                        lastResponse = RecursiveResolve(new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { question }, null, null, null), null);
                        cacheHit &= ("cacheHit".Equals(lastResponse.Tag));

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

        private DnsDatagram RecursiveResolve(DnsDatagram request, NameServerAddress[] viaNameServers)
        {
            //query cache zone to see if answer available
            {
                DnsDatagram cacheResponse = QueryCache(request, false);
                if (cacheResponse != null)
                    return cacheResponse;
            }

            //recursion with locking
            RecursiveQueryLock newLockObj = new RecursiveQueryLock();
            RecursiveQueryLock actualLockObj = _recursiveQueryLocks.GetOrAdd(request.Question[0], newLockObj);

            if (actualLockObj.Equals(newLockObj))
            {
                //got lock so question not being resolved; do recursive resolution in worker thread
                ThreadPool.QueueUserWorkItem(delegate (object state)
                {
                    //select protocol
                    DnsTransportProtocol protocol;

                    if ((viaNameServers == null) && (_forwarders != null))
                    {
                        viaNameServers = _forwarders;
                        protocol = _forwarderProtocol;
                    }
                    else
                    {
                        protocol = _recursiveResolveProtocol;
                    }

                    DnsDatagram response = null;

                    try
                    {
                        //recursive resolve and update cache
                        response = DnsClient.RecursiveResolve(request.Question[0], viaNameServers, _dnsCache, _proxy, _preferIPv6, protocol, _retries, _timeout, _recursiveResolveProtocol, _maxStackCount);
                    }
                    catch (Exception ex)
                    {
                        LogManager log = _log;
                        if (log != null)
                        {
                            string nameServers = null;

                            if (viaNameServers != null)
                            {
                                foreach (NameServerAddress nameServer in viaNameServers)
                                {
                                    if (nameServers == null)
                                        nameServers = nameServer.ToString();
                                    else
                                        nameServers += ", " + nameServer.ToString();
                                }
                            }

                            log.Write("DNS Server recursive resolution failed for QNAME: " + request.Question[0].Name + "; QTYPE: " + request.Question[0].Type.ToString() + "; QCLASS: " + request.Question[0].Class.ToString() + (nameServers == null ? "" : "; Name Servers: " + nameServers) + ";\r\n" + ex.ToString());
                        }

                        //fetch stale record and reset expiry
                        {
                            DnsDatagram cacheResponse = QueryCache(request, true);
                            if (cacheResponse != null)
                            {
                                foreach (DnsResourceRecord record in cacheResponse.Answer)
                                {
                                    if (record.IsStale)
                                        record.ResetExpiry(30); //reset expiry by 30 seconds so that resolver tries again only after 30 seconds as per draft-ietf-dnsop-serve-stale-04
                                }

                                response = cacheResponse;
                            }
                        }
                    }
                    finally
                    {
                        //remove question lock
                        if (_recursiveQueryLocks.TryRemove(request.Question[0], out RecursiveQueryLock lockObj))
                        {
                            //pulse all waiting threads
                            lock (lockObj)
                            {
                                lockObj.SetComplete(response);
                                Monitor.PulseAll(lockObj);
                            }
                        }
                    }
                });
            }

            //request is being recursively resolved by worker thread

            bool timeout = false;

            //wait till short timeout or pulse signal
            lock (actualLockObj)
            {
                if (!actualLockObj.Complete)
                    timeout = !Monitor.Wait(actualLockObj, _timeout - 200); //1.8 sec wait with default client timeout as 2 sec as per draft-ietf-dnsop-serve-stale-04
            }

            if (timeout)
            {
                //query cache zone to return stale answer (if available) as per draft-ietf-dnsop-serve-stale-04
                {
                    DnsDatagram cacheResponse = QueryCache(request, true);
                    if (cacheResponse != null)
                        return cacheResponse;
                }

                //wait till timeout or pulse signal for some more time before responding as ServerFailure
                //this is required since, quickly returning ServerFailure results in clients giving up lookup attempt early causing DNS error messages in web browsers
                timeout = false;

                lock (actualLockObj)
                {
                    if (!actualLockObj.Complete)
                        timeout = !Monitor.Wait(actualLockObj, _timeout + 200);
                }

                if (!timeout)
                {
                    if (actualLockObj.Response != null)
                        return actualLockObj.Response;
                }
            }
            else
            {
                if (actualLockObj.Response != null)
                    return actualLockObj.Response;
            }

            //no response available in cache so respond with ServerFailure
            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.ServerFailure, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
        }

        private DnsDatagram QueryCache(DnsDatagram request, bool serveStale)
        {
            DnsDatagram cacheResponse = _cacheZoneRoot.Query(request, serveStale);

            if (cacheResponse.Header.RCODE != DnsResponseCode.Refused)
            {
                if ((cacheResponse.Answer.Length > 0) || (cacheResponse.Authority.Length == 0) || (cacheResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                {
                    cacheResponse.Tag = "cacheHit";

                    return cacheResponse;
                }
            }

            return null;
        }

        #endregion

        #region public

        public void Start()
        {
            if (_disposed)
                throw new ObjectDisposedException("DnsServer");

            if (_state != ServiceState.Stopped)
                throw new InvalidOperationException("DNS Server is already running.");

            _state = ServiceState.Starting;

            //bind on all local end points
            for (int i = 0; i < _localIPs.Length; i++)
            {
                IPEndPoint dnsEP = new IPEndPoint(_localIPs[i], 53);

                Socket udpListener = new Socket(dnsEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

                #region this code ignores ICMP port unreachable responses which creates SocketException in ReceiveFrom()

                if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                {
                    const uint IOC_IN = 0x80000000;
                    const uint IOC_VENDOR = 0x18000000;
                    const uint SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

                    udpListener.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { Convert.ToByte(false) }, null);
                }

                #endregion

                try
                {
                    udpListener.Bind(dnsEP);

                    _udpListeners.Add(udpListener);

                    LogManager log = _log;
                    if (log != null)
                        log.Write(dnsEP, DnsTransportProtocol.Udp, "DNS Server was bound successfully.");
                }
                catch (Exception ex)
                {
                    LogManager log = _log;
                    if (log != null)
                        log.Write(dnsEP, DnsTransportProtocol.Udp, ex);

                    udpListener.Dispose();
                }

                Socket tcpListener = new Socket(dnsEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    tcpListener.Bind(dnsEP);
                    tcpListener.Listen(100);

                    _tcpListeners.Add(tcpListener);

                    LogManager log = _log;
                    if (log != null)
                        log.Write(dnsEP, DnsTransportProtocol.Tcp, "DNS Server was bound successfully.");
                }
                catch (Exception ex)
                {
                    LogManager log = _log;
                    if (log != null)
                        log.Write(dnsEP, DnsTransportProtocol.Tcp, ex);

                    tcpListener.Dispose();
                }

                if (_enableDnsOverHttp)
                {
                    IPEndPoint httpEP = new IPEndPoint(_localIPs[i], 8053);
                    Socket httpListener = new Socket(httpEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                    try
                    {
                        httpListener.Bind(httpEP);
                        httpListener.Listen(100);

                        _httpListeners.Add(httpListener);

                        _isDnsOverHttpsEnabled = true;

                        LogManager log = _log;
                        if (log != null)
                            log.Write(httpEP, DnsTransportProtocol.Https, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        LogManager log = _log;
                        if (log != null)
                            log.Write(httpEP, DnsTransportProtocol.Https, ex);

                        httpListener.Dispose();
                    }
                }

                if (_enableDnsOverTls && (_certificate != null))
                {
                    IPEndPoint tlsEP = new IPEndPoint(_localIPs[i], 853);
                    Socket tlsListener = new Socket(tlsEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                    try
                    {
                        tlsListener.Bind(tlsEP);
                        tlsListener.Listen(100);

                        _tlsListeners.Add(tlsListener);

                        LogManager log = _log;
                        if (log != null)
                            log.Write(tlsEP, DnsTransportProtocol.Tls, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        LogManager log = _log;
                        if (log != null)
                            log.Write(tlsEP, DnsTransportProtocol.Tls, ex);

                        tlsListener.Dispose();
                    }
                }

                if (_enableDnsOverHttps && (_certificate != null))
                {
                    IPEndPoint httpsEP = new IPEndPoint(_localIPs[i], 443);
                    Socket httpsListener = new Socket(httpsEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                    try
                    {
                        httpsListener.Bind(httpsEP);
                        httpsListener.Listen(100);

                        _httpsListeners.Add(httpsListener);

                        _isDnsOverHttpsEnabled = true;

                        LogManager log = _log;
                        if (log != null)
                            log.Write(httpsEP, DnsTransportProtocol.Https, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        LogManager log = _log;
                        if (log != null)
                            log.Write(httpsEP, DnsTransportProtocol.Https, ex);

                        httpsListener.Dispose();
                    }
                }
            }

            if (_isDnsOverHttpsEnabled)
            {
                string serverDomain = _authoritativeZoneRoot.ServerDomain;

                _authoritativeZoneRoot.SetRecords("resolver-associated-doh.arpa", DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord(serverDomain, "hostmaster." + serverDomain, uint.Parse(DateTime.UtcNow.ToString("yyyyMMddHH")), 28800, 7200, 604800, 600) });
                _authoritativeZoneRoot.SetRecords("resolver-associated-doh.arpa", DnsResourceRecordType.NS, 14400, new DnsResourceRecordData[] { new DnsNSRecord(serverDomain) });
                _authoritativeZoneRoot.SetRecords("resolver-associated-doh.arpa", DnsResourceRecordType.TXT, 60, new DnsResourceRecordData[] { new DnsTXTRecord("https://" + serverDomain + "/dns-query{?dns}") });

                _authoritativeZoneRoot.SetRecords("resolver-addresses.arpa", DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord(serverDomain, "hostmaster." + serverDomain, uint.Parse(DateTime.UtcNow.ToString("yyyyMMddHH")), 28800, 7200, 604800, 600) });
                _authoritativeZoneRoot.SetRecords("resolver-addresses.arpa", DnsResourceRecordType.NS, 14400, new DnsResourceRecordData[] { new DnsNSRecord(serverDomain) });
                _authoritativeZoneRoot.SetRecords("resolver-addresses.arpa", DnsResourceRecordType.CNAME, 60, new DnsResourceRecordData[] { new DnsCNAMERecord(serverDomain) });
            }

            //start reading query packets
            foreach (Socket udpListener in _udpListeners)
            {
                for (int i = 0; i < LISTENER_THREAD_COUNT; i++)
                {
                    Thread listenerThread = new Thread(ReadUdpRequestAsync);
                    listenerThread.IsBackground = true;
                    listenerThread.Start(udpListener);

                    _listenerThreads.Add(listenerThread);
                }
            }

            foreach (Socket tcpListener in _tcpListeners)
            {
                for (int i = 0; i < LISTENER_THREAD_COUNT; i++)
                {
                    Thread listenerThread = new Thread(AcceptConnectionAsync);
                    listenerThread.IsBackground = true;
                    listenerThread.Start(new object[] { tcpListener, DnsTransportProtocol.Tcp });

                    _listenerThreads.Add(listenerThread);
                }
            }

            foreach (Socket httpListener in _httpListeners)
            {
                for (int i = 0; i < LISTENER_THREAD_COUNT; i++)
                {
                    Thread listenerThread = new Thread(AcceptConnectionAsync);
                    listenerThread.IsBackground = true;
                    listenerThread.Start(new object[] { httpListener, DnsTransportProtocol.Https, false });

                    _listenerThreads.Add(listenerThread);
                }
            }

            foreach (Socket tlsListener in _tlsListeners)
            {
                for (int i = 0; i < LISTENER_THREAD_COUNT; i++)
                {
                    Thread listenerThread = new Thread(AcceptConnectionAsync);
                    listenerThread.IsBackground = true;
                    listenerThread.Start(new object[] { tlsListener, DnsTransportProtocol.Tls });

                    _listenerThreads.Add(listenerThread);
                }
            }

            foreach (Socket httpsListener in _httpsListeners)
            {
                for (int i = 0; i < LISTENER_THREAD_COUNT; i++)
                {
                    Thread listenerThread = new Thread(AcceptConnectionAsync);
                    listenerThread.IsBackground = true;
                    listenerThread.Start(new object[] { httpsListener, DnsTransportProtocol.Https });

                    _listenerThreads.Add(listenerThread);
                }
            }

            _state = ServiceState.Running;
        }

        public void Stop()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            foreach (Socket udpListener in _udpListeners)
                udpListener.Dispose();

            foreach (Socket tcpListener in _tcpListeners)
                tcpListener.Dispose();

            foreach (Socket httpListener in _httpListeners)
                httpListener.Dispose();

            foreach (Socket tlsListener in _tlsListeners)
                tlsListener.Dispose();

            foreach (Socket httpsListener in _httpsListeners)
                httpsListener.Dispose();

            _listenerThreads.Clear();
            _udpListeners.Clear();
            _tcpListeners.Clear();
            _httpListeners.Clear();
            _tlsListeners.Clear();
            _httpsListeners.Clear();

            _state = ServiceState.Stopped;
        }

        #endregion

        #region properties

        public IPAddress[] LocalAddresses
        {
            get { return _localIPs; }
            set { _localIPs = value; }
        }

        public string ServerDomain
        {
            get { return _authoritativeZoneRoot.ServerDomain; }
            set
            {
                _authoritativeZoneRoot.ServerDomain = value;
                _allowedZoneRoot.ServerDomain = value;
                _blockedZoneRoot.ServerDomain = value;

                if (_isDnsOverHttpsEnabled)
                {
                    _authoritativeZoneRoot.SetRecords("resolver-associated-doh.arpa", DnsResourceRecordType.TXT, 60, new DnsResourceRecordData[] { new DnsTXTRecord("https://" + value + "/dns-query{?dns}") });
                    _authoritativeZoneRoot.SetRecords("resolver-addresses.arpa", DnsResourceRecordType.CNAME, 60, new DnsResourceRecordData[] { new DnsCNAMERecord(value) });
                }
            }
        }

        public bool EnableDnsOverHttp
        {
            get { return _enableDnsOverHttp; }
            set { _enableDnsOverHttp = value; }
        }

        public bool EnableDnsOverTls
        {
            get { return _enableDnsOverTls; }
            set { _enableDnsOverTls = value; }
        }

        public bool EnableDnsOverHttps
        {
            get { return _enableDnsOverHttps; }
            set { _enableDnsOverHttps = value; }
        }

        public bool IsDnsOverHttpsEnabled
        { get { return _isDnsOverHttpsEnabled; } }

        public X509Certificate2 Certificate
        {
            get { return _certificate; }
            set
            {
                if (!value.HasPrivateKey)
                    throw new ArgumentException("Tls certificate does not contain private key.");

                _certificate = value;
            }
        }

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
                _blockedZoneRoot.ServerDomain = _authoritativeZoneRoot.ServerDomain;
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

        public DnsTransportProtocol ForwarderProtocol
        {
            get { return _forwarderProtocol; }
            set { _forwarderProtocol = value; }
        }

        public DnsTransportProtocol RecursiveResolveProtocol
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
            set
            {
                if (value > 0)
                    _retries = value;
            }
        }

        public int Timeout
        {
            get { return _timeout; }
            set
            {
                if (value >= 2000)
                    _timeout = value;
            }
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

        public int TcpSendTimeout
        {
            get { return _tcpSendTimeout; }
            set { _tcpSendTimeout = value; }
        }

        public int TcpReceiveTimeout
        {
            get { return _tcpReceiveTimeout; }
            set { _tcpReceiveTimeout = value; }
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

        class RecursiveQueryLock
        {
            #region variables

            bool _complete;
            DnsDatagram _response;

            #endregion

            #region public

            public void SetComplete(DnsDatagram response)
            {
                if (!_complete)
                {
                    _complete = true;
                    _response = response;
                }
            }

            #endregion

            #region properties

            public bool Complete
            { get { return _complete; } }

            public DnsDatagram Response
            { get { return _response; } }

            #endregion
        }
    }
}
