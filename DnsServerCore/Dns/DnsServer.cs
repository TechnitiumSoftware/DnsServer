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
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore.Dns
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
        const int MAX_HOPS = 16;

        IPAddress[] _localAddresses;

        readonly List<Socket> _udpListeners = new List<Socket>();
        readonly List<Socket> _tcpListeners = new List<Socket>();
        readonly List<Socket> _httpListeners = new List<Socket>();
        readonly List<Socket> _tlsListeners = new List<Socket>();
        readonly List<Socket> _httpsListeners = new List<Socket>();
        readonly List<Thread> _listenerThreads = new List<Thread>();

        bool _enableDnsOverHttp = false;
        bool _enableDnsOverTls = false;
        bool _enableDnsOverHttps = false;
        bool _isDnsOverHttpsEnabled;
        X509Certificate2 _certificate;

        readonly Zone _authoritativeZoneRoot = new Zone(true);
        readonly Zone _cacheZoneRoot = new Zone(false);
        readonly Zone _allowedZoneRoot = new Zone(true);
        Zone _blockedZoneRoot = new Zone(true);

        readonly DnsCache _dnsCache;

        bool _allowRecursion = false;
        bool _allowRecursionOnlyForPrivateNetworks = false;
        NetProxy _proxy;
        NameServerAddress[] _forwarders;
        DnsTransportProtocol _forwarderProtocol = DnsTransportProtocol.Udp;
        bool _preferIPv6 = false;
        int _retries = 2;
        int _timeout = 2000;
        int _maxStackCount = 10;
        int _cachePrefetchEligibility = 2;
        int _cachePrefetchTrigger = 9;
        int _cachePrefetchSampleIntervalInMinutes = 5;
        int _cachePrefetchSampleEligibilityHitsPerHour = 30;
        LogManager _log;
        LogManager _queryLog;
        StatsManager _stats;

        int _tcpSendTimeout = 10000;
        int _tcpReceiveTimeout = 10000;

        Timer _cachePrefetchSamplingTimer;
        readonly object _cachePrefetchSamplingTimerLock = new object();

        Timer _cachePrefetchRefreshTimer;
        readonly object _cachePrefetchRefreshTimerLock = new object();
        const int CACHE_PREFETCH_REFRESH_TIMER_INITIAL_INTEVAL = 60000;
        DateTime _cachePrefetchSamplingTimerTriggersOn;
        DnsQuestionRecord[] _cachePrefetchSampleList;

        Timer _cacheMaintenanceTimer;
        const int CACHE_MAINTENANCE_TIMER_INITIAL_INTEVAL = 60 * 60 * 1000;
        const int CACHE_MAINTENANCE_TIMER_PERIODIC_INTERVAL = 60 * 60 * 1000;

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
            _localAddresses = localIPs;
            _dnsCache = new ResolverDnsCache(_cacheZoneRoot);
        }

        #endregion

        #region IDisposable

        private bool _disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
                Stop();

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
                DnsDatagram response = ProcessQuery(request, remoteEP, IsRecursionAllowed(remoteEP), DnsTransportProtocol.Udp);

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
                DnsDatagram response = ProcessQuery(request, remoteEP, IsRecursionAllowed(remoteEP), protocol);

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

                        if (!string.IsNullOrEmpty(xRealIp))
                        {
                            //get the real IP address of the requesting client from X-Real-IP header set in nginx proxy_pass block
                            remoteEP = new IPEndPoint(IPAddress.Parse(xRealIp), 0);
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

                                        DnsDatagram dnsResponse = ProcessQuery(dnsRequest, remoteEP, IsRecursionAllowed(remoteEP), protocol);
                                        if (dnsResponse != null)
                                        {
                                            using (MemoryStream mS = new MemoryStream())
                                            {
                                                dnsResponse.WriteTo(mS);

                                                byte[] buffer = mS.ToArray();
                                                SendContent(stream, "application/dns-message", buffer);
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

                                        DnsDatagram dnsResponse = ProcessQuery(dnsRequest, remoteEP, IsRecursionAllowed(remoteEP), protocol);
                                        if (dnsResponse != null)
                                        {
                                            using (MemoryStream mS = new MemoryStream())
                                            {
                                                JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                                                dnsResponse.WriteTo(jsonWriter);
                                                jsonWriter.Flush();

                                                byte[] buffer = mS.ToArray();
                                                SendContent(stream, "application/dns-json; charset=utf-8", buffer);
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
                                    SendError(stream, 406, "Only application/dns-message and application/dns-json types are accepted.");
                                    break;
                            }

                            if (requestConnection.Equals("close", StringComparison.OrdinalIgnoreCase))
                                return;

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

                                SendContent(stream, "application/json", mS.ToArray());
                            }

                            break;

                        default:
                            SendError(stream, 404);
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

                SendError(stream, ex);
            }
        }

        private static void SendContent(Stream outputStream, string contentType, byte[] bufferContent)
        {
            byte[] bufferHeader = Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nContent-Type: " + contentType + "\r\nContent-Length: " + bufferContent.Length + "\r\nX-Robots-Tag: noindex, nofollow\r\n\r\n");

            outputStream.Write(bufferHeader, 0, bufferHeader.Length);
            outputStream.Write(bufferContent, 0, bufferContent.Length);
            outputStream.Flush();
        }

        private static void SendError(Stream outputStream, Exception ex)
        {
            SendError(outputStream, 500, ex.ToString());
        }

        private static void SendError(Stream outputStream, int statusCode, string message = null)
        {
            try
            {
                string statusString = statusCode + " " + GetStatusString((HttpStatusCode)statusCode);
                byte[] bufferContent = Encoding.UTF8.GetBytes("<html><head><title>" + statusString + "</title></head><body><h1>" + statusString + "</h1>" + (message == null ? "" : "<p>" + message + "</p>") + "</body></html>");
                byte[] bufferHeader = Encoding.UTF8.GetBytes("HTTP/1.1 " + statusString + "\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + bufferContent.Length + "\r\nX-Robots-Tag: noindex, nofollow\r\n\r\n");

                outputStream.Write(bufferHeader, 0, bufferHeader.Length);
                outputStream.Write(bufferContent, 0, bufferContent.Length);
                outputStream.Flush();
            }
            catch
            { }
        }

        internal static string GetStatusString(HttpStatusCode statusCode)
        {
            StringBuilder sb = new StringBuilder();

            foreach (char c in statusCode.ToString().ToCharArray())
            {
                if (char.IsUpper(c) && sb.Length > 0)
                    sb.Append(' ');

                sb.Append(c);
            }

            return sb.ToString();
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

        internal DnsDatagram ProcessQuery(DnsDatagram request, EndPoint remoteEP, bool isRecursionAllowed, DnsTransportProtocol protocol)
        {
            if (request.Header.IsResponse)
                return null;

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
                            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NotImplemented, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
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
            response.Tag = "authHit";

            if (response.Header.RCODE == DnsResponseCode.NoError)
            {
                if (response.Answer.Length > 0)
                {
                    DnsResourceRecordType questionType = request.Question[0].Type;
                    DnsClass questionClass = request.Question[0].Class;
                    DnsResourceRecord lastRR = response.Answer[response.Answer.Length - 1];

                    if ((lastRR.Type != questionType) && (lastRR.Type == DnsResourceRecordType.CNAME) && (questionType != DnsResourceRecordType.ANY))
                    {
                        //resolve cname record
                        List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                        responseAnswer.AddRange(response.Answer);

                        DnsDatagram lastResponse;

                        while (true)
                        {
                            DnsDatagram cnameRequest = new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, questionType, questionClass) }, null, null, null);

                            //query authoritative zone first
                            lastResponse = _authoritativeZoneRoot.Query(cnameRequest);

                            if (lastResponse.Header.RCODE == DnsResponseCode.Refused)
                            {
                                //not found in auth zone
                                if (!isRecursionAllowed || !cnameRequest.Header.RecursionDesired)
                                    break; //break since no recursion allowed/desired

                                //do recursion
                                lastResponse = ProcessRecursiveQuery(cnameRequest);
                            }
                            else if ((lastResponse.Header.RCODE == DnsResponseCode.NoError) && (lastResponse.Answer.Length == 0) && (lastResponse.Authority.Length > 0) && (lastResponse.Authority[0].Type == DnsResourceRecordType.NS))
                            {
                                //found delegated zone
                                if (!isRecursionAllowed || !cnameRequest.Header.RecursionDesired)
                                    break; //break since no recursion allowed/desired

                                //do recursive resolution using delegated authority name servers
                                NameServerAddress[] nameServers = NameServerAddress.GetNameServersFromResponse(lastResponse, _preferIPv6, false);

                                lastResponse = ProcessRecursiveQuery(cnameRequest, nameServers);
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

                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, lastResponse.Header.AuthoritativeAnswer, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, rcode, 1, (ushort)responseAnswer.Count, (ushort)authority.Length, (ushort)additional.Length), request.Question, responseAnswer.ToArray(), authority, additional) { Tag = response.Tag };
                    }
                }
                else if ((response.Authority.Length > 0) && (response.Authority[0].Type == DnsResourceRecordType.NS) && isRecursionAllowed)
                {
                    //do recursive resolution using response authority name servers
                    NameServerAddress[] nameServers = NameServerAddress.GetNameServersFromResponse(response, _preferIPv6, false);

                    return ProcessRecursiveQuery(request, nameServers);
                }
            }

            return response;
        }

        private DnsDatagram ProcessRecursiveQuery(DnsDatagram request, NameServerAddress[] viaNameServers = null, bool cacheRefreshOperation = false)
        {
            DnsDatagram response = RecursiveResolve(request, viaNameServers, false, cacheRefreshOperation);

            DnsResourceRecord[] authority;
            DnsResourceRecord[] additional;

            if (response.Answer.Length > 0)
            {
                DnsResourceRecordType questionType = request.Question[0].Type;
                DnsClass questionClass = request.Question[0].Class;
                DnsResourceRecord lastRR = response.Answer[response.Answer.Length - 1];

                if ((lastRR.Type != questionType) && (lastRR.Type == DnsResourceRecordType.CNAME) && (questionType != DnsResourceRecordType.ANY))
                {
                    List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                    responseAnswer.AddRange(response.Answer);

                    DnsDatagram lastResponse;
                    int queryCount = 0;

                    while (true)
                    {
                        DnsQuestionRecord question = new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, questionType, questionClass);

                        lastResponse = RecursiveResolve(new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { question }, null, null, null), null, false, cacheRefreshOperation);

                        //reset response tag to null for correct stats classification as recursive query
                        if (lastResponse.Tag == null)
                            response.Tag = null;

                        if (lastResponse.Answer.Length == 0)
                            break;

                        responseAnswer.AddRange(lastResponse.Answer);

                        lastRR = lastResponse.Answer[lastResponse.Answer.Length - 1];

                        if (lastRR.Type == questionType)
                            break;

                        if (lastRR.Type != DnsResourceRecordType.CNAME)
                            throw new DnsServerException("Invalid response received from DNS server.");

                        queryCount++;
                        if (queryCount > MAX_HOPS)
                            throw new DnsServerException("Recursive resolution exceeded max hops.");
                    }

                    if ((lastResponse.Authority.Length > 0) && (lastResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                        authority = lastResponse.Authority;
                    else
                        authority = new DnsResourceRecord[] { };

                    if ((response.Additional.Length > 0) && (request.Question[0].Type == DnsResourceRecordType.MX))
                        additional = response.Additional;
                    else
                        additional = new DnsResourceRecord[] { };

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, lastResponse.Header.RCODE, 1, (ushort)responseAnswer.Count, (ushort)authority.Length, (ushort)additional.Length), request.Question, responseAnswer.ToArray(), authority, additional) { Tag = response.Tag };
                }
            }

            if ((response.Authority.Length > 0) && (response.Authority[0].Type == DnsResourceRecordType.SOA))
                authority = response.Authority;
            else
                authority = new DnsResourceRecord[] { };

            if ((response.Additional.Length > 0) && (request.Question[0].Type == DnsResourceRecordType.MX))
                additional = response.Additional;
            else
                additional = new DnsResourceRecord[] { };

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, response.Header.RCODE, 1, (ushort)response.Answer.Length, (ushort)authority.Length, (ushort)additional.Length), request.Question, response.Answer, authority, additional) { Tag = response.Tag };
        }

        private DnsDatagram RecursiveResolve(DnsDatagram request, NameServerAddress[] viaNameServers, bool cachePrefetchOperation, bool cacheRefreshOperation)
        {
            if (!cachePrefetchOperation && !cacheRefreshOperation)
            {
                //query cache zone to see if answer available
                DnsDatagram cacheResponse = QueryCache(request, false);
                if (cacheResponse != null)
                {
                    if (_cachePrefetchTrigger > 0)
                    {
                        //inspect response TTL values to decide if prefetch trigger is needed
                        foreach (DnsResourceRecord answer in cacheResponse.Answer)
                        {
                            if ((answer.OriginalTtlValue > _cachePrefetchEligibility) && (answer.TtlValue < _cachePrefetchTrigger))
                            {
                                //trigger prefetch in worker thread
                                ThreadPool.QueueUserWorkItem(delegate (object state)
                                {
                                    try
                                    {
                                        RecursiveResolve(request, viaNameServers, true, false);
                                    }
                                    catch (Exception ex)
                                    {
                                        LogManager log = _log;
                                        if (log != null)
                                            log.Write(ex);
                                    }
                                });

                                break;
                            }
                        }
                    }

                    return cacheResponse;
                }
            }

            //recursion with locking
            RecursiveQueryLock newLockObj = new RecursiveQueryLock();
            RecursiveQueryLock actualLockObj = _recursiveQueryLocks.GetOrAdd(request.Question[0], newLockObj);

            if (actualLockObj.Equals(newLockObj))
            {
                //got lock so question not being resolved; do recursive resolution in worker thread
                ThreadPool.QueueUserWorkItem(delegate (object state)
                {
                    DnsDatagram response = null;

                    try
                    {
                        if ((viaNameServers == null) && (_forwarders != null))
                        {
                            //use forwarders

                            if (_proxy == null)
                            {
                                //recursive resolve name server when proxy is null else let proxy resolve it
                                foreach (NameServerAddress nameServerAddress in _forwarders)
                                {
                                    if (nameServerAddress.IsIPEndPointStale) //refresh forwarder IPEndPoint if stale
                                        nameServerAddress.RecursiveResolveIPAddress(_dnsCache, null, _preferIPv6, _retries, _timeout);
                                }
                            }

                            //query forwarders and update cache
                            DnsClient dnsClient = new DnsClient(_forwarders);

                            dnsClient.Proxy = _proxy;
                            dnsClient.PreferIPv6 = _preferIPv6;
                            dnsClient.Protocol = _forwarderProtocol;
                            dnsClient.Retries = _retries;
                            dnsClient.Timeout = _timeout;

                            response = dnsClient.Resolve(request.Question[0]);

                            _dnsCache.CacheResponse(response);
                        }
                        else
                        {
                            //recursive resolve and update cache
                            response = DnsClient.RecursiveResolve(request.Question[0], viaNameServers, (cachePrefetchOperation || cacheRefreshOperation ? new ResolverPrefetchDnsCache(_cacheZoneRoot, request.Question[0]) : _dnsCache), _proxy, _preferIPv6, _retries, _timeout, false, _maxStackCount);
                        }
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

            if (cachePrefetchOperation)
                return null; //return null as prefetch worker thread does not need valid response and thus does not need to wait

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

        private DnsQuestionRecord GetCacheRefreshNeededQuery(DnsQuestionRecord question, int trigger)
        {
            int queryCount = 0;

            while (true)
            {
                DnsDatagram cacheResponse = QueryCache(new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { question }, null, null, null), false);
                if (cacheResponse == null)
                    return question; //cache expired so refresh question

                if (cacheResponse.Answer.Length == 0)
                    return null; //dont refresh empty responses

                //inspect response TTL values to decide if refresh is needed
                foreach (DnsResourceRecord answer in cacheResponse.Answer)
                {
                    if ((answer.OriginalTtlValue > _cachePrefetchEligibility) && (answer.TtlValue < trigger))
                        return question; //TTL eligible and less than trigger so refresh question
                }

                DnsResourceRecord lastRR = cacheResponse.Answer[cacheResponse.Answer.Length - 1];

                if (lastRR.Type == question.Type)
                    return null; //answer was resolved

                if (lastRR.Type != DnsResourceRecordType.CNAME)
                    return null; //invalid response so ignore question

                queryCount++;
                if (queryCount > MAX_HOPS)
                    return null; //too many hops so ignore question

                //follow CNAME chain to inspect TTL further
                question = new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, question.Type, question.Class);
            }
        }

        private bool CacheRefreshNeeded(DnsQuestionRecord question, int trigger)
        {
            DnsDatagram cacheResponse = QueryCache(new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { question }, null, null, null), false);
            if (cacheResponse == null)
                return true; //cache expired so refresh needed

            if (cacheResponse.Answer.Length == 0)
                return false; //dont refresh empty responses

            //inspect response TTL values to decide if refresh is needed
            foreach (DnsResourceRecord answer in cacheResponse.Answer)
            {
                if ((answer.OriginalTtlValue > _cachePrefetchEligibility) && (answer.TtlValue < trigger))
                    return true; //TTL eligible less than trigger so refresh
            }

            return false; //no need to refresh for this query
        }

        private void CachePrefetchSamplingAsync(object state)
        {
            try
            {
                StatsManager stats = _stats;
                if (stats != null)
                {
                    List<KeyValuePair<DnsQuestionRecord, int>> eligibleQueries = stats.GetLastHourEligibleQueries(_cachePrefetchSampleEligibilityHitsPerHour);
                    List<DnsQuestionRecord> cacheRefreshSampleList = new List<DnsQuestionRecord>();
                    int cacheRefreshTrigger = (_cachePrefetchSampleIntervalInMinutes + 1) * 60;

                    foreach (KeyValuePair<DnsQuestionRecord, int> query in eligibleQueries)
                    {
                        if (_authoritativeZoneRoot.ZoneExistsAndEnabled(query.Key.Name))
                            continue; //no cache refresh for zone that is hosted and enabled

                        if (query.Key.Type == DnsResourceRecordType.ANY)
                            continue; //dont refresh ANY queries

                        DnsQuestionRecord refreshQuery = GetCacheRefreshNeededQuery(query.Key, cacheRefreshTrigger);
                        if (refreshQuery != null)
                            cacheRefreshSampleList.Add(refreshQuery);
                    }

                    _cachePrefetchSampleList = cacheRefreshSampleList.ToArray();
                }
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write(ex);
            }
            finally
            {
                lock (_cachePrefetchSamplingTimerLock)
                {
                    if (_cachePrefetchSamplingTimer != null)
                    {
                        _cachePrefetchSamplingTimer.Change(_cachePrefetchSampleIntervalInMinutes * 60 * 1000, System.Threading.Timeout.Infinite);
                        _cachePrefetchSamplingTimerTriggersOn = DateTime.UtcNow.AddMinutes(_cachePrefetchSampleIntervalInMinutes);
                    }
                }
            }
        }

        private void CachePrefetchRefreshAsync(object state)
        {
            try
            {
                DnsQuestionRecord[] cacheRefreshSampleList = _cachePrefetchSampleList;
                if (cacheRefreshSampleList != null)
                {
                    for (int i = 0; i < cacheRefreshSampleList.Length; i++)
                    {
                        DnsQuestionRecord sampleQuestion = cacheRefreshSampleList[i];
                        if (sampleQuestion == null)
                            continue;

                        if (!CacheRefreshNeeded(sampleQuestion, _cachePrefetchTrigger + 2))
                            continue;

                        int sampleQuestionIndex = i;

                        ThreadPool.QueueUserWorkItem(delegate (object state2)
                        {
                            try
                            {
                                //refresh cache
                                DnsDatagram response = ProcessRecursiveQuery(new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { sampleQuestion }, null, null, null), null, true);

                                bool removeFromSampleList = true;
                                DateTime utcNow = DateTime.UtcNow;

                                foreach (DnsResourceRecord answer in response.Answer)
                                {
                                    if ((answer.OriginalTtlValue > _cachePrefetchEligibility) && (utcNow.AddSeconds(answer.TtlValue) < _cachePrefetchSamplingTimerTriggersOn))
                                    {
                                        //answer expires before next sampling so dont remove from list to allow refreshing it
                                        removeFromSampleList = false;
                                        break;
                                    }
                                }

                                if (removeFromSampleList)
                                    cacheRefreshSampleList[sampleQuestionIndex] = null;
                            }
                            catch (Exception ex)
                            {
                                LogManager log = _log;
                                if (log != null)
                                    log.Write(ex);
                            }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write(ex);
            }
            finally
            {
                lock (_cachePrefetchRefreshTimerLock)
                {
                    if (_cachePrefetchRefreshTimer != null)
                        _cachePrefetchRefreshTimer.Change((_cachePrefetchTrigger + 1) * 1000, System.Threading.Timeout.Infinite);
                }
            }
        }

        private void CacheMaintenanceAsync(object state)
        {
            try
            {
                _cacheZoneRoot.RemoveExpiredCachedRecords();
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log != null)
                    log.Write(ex);
            }
        }

        private void ResetPrefetchTimers()
        {
            if (_cachePrefetchTrigger == 0)
            {
                lock (_cachePrefetchSamplingTimerLock)
                {
                    if (_cachePrefetchSamplingTimer != null)
                        _cachePrefetchSamplingTimer.Change(System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
                }

                lock (_cachePrefetchRefreshTimerLock)
                {
                    if (_cachePrefetchRefreshTimer != null)
                        _cachePrefetchRefreshTimer.Change(System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
                }
            }
            else if (_state == ServiceState.Running)
            {
                lock (_cachePrefetchSamplingTimerLock)
                {
                    if (_cachePrefetchSamplingTimer != null)
                    {
                        _cachePrefetchSamplingTimer.Change(_cachePrefetchSampleIntervalInMinutes * 60 * 1000, System.Threading.Timeout.Infinite);
                        _cachePrefetchSamplingTimerTriggersOn = DateTime.UtcNow.AddMinutes(_cachePrefetchSampleIntervalInMinutes);
                    }
                }

                lock (_cachePrefetchRefreshTimerLock)
                {
                    if (_cachePrefetchRefreshTimer != null)
                        _cachePrefetchRefreshTimer.Change(CACHE_PREFETCH_REFRESH_TIMER_INITIAL_INTEVAL, System.Threading.Timeout.Infinite);
                }
            }

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
            for (int i = 0; i < _localAddresses.Length; i++)
            {
                IPEndPoint dnsEP = new IPEndPoint(_localAddresses[i], 53);

                Socket udpListener = null;

                try
                {
                    udpListener = new Socket(dnsEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

                    #region this code ignores ICMP port unreachable responses which creates SocketException in ReceiveFrom()

                    if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                    {
                        const uint IOC_IN = 0x80000000;
                        const uint IOC_VENDOR = 0x18000000;
                        const uint SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

                        udpListener.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { Convert.ToByte(false) }, null);
                    }

                    #endregion

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
                        log.Write(dnsEP, DnsTransportProtocol.Udp, "DNS Server failed to bind.\r\n" + ex.ToString());

                    if (udpListener != null)
                        udpListener.Dispose();
                }

                Socket tcpListener = null;

                try
                {
                    tcpListener = new Socket(dnsEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

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
                        log.Write(dnsEP, DnsTransportProtocol.Tcp, "DNS Server failed to bind.\r\n" + ex.ToString());

                    if (tcpListener != null)
                        tcpListener.Dispose();
                }

                if (_enableDnsOverHttp)
                {
                    IPEndPoint httpEP = new IPEndPoint(_localAddresses[i], 8053);
                    Socket httpListener = null;

                    try
                    {
                        httpListener = new Socket(httpEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

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
                            log.Write(httpEP, DnsTransportProtocol.Https, "DNS Server failed to bind.\r\n" + ex.ToString());

                        if (httpListener != null)
                            httpListener.Dispose();
                    }
                }

                if (_enableDnsOverTls && (_certificate != null))
                {
                    IPEndPoint tlsEP = new IPEndPoint(_localAddresses[i], 853);
                    Socket tlsListener = null;

                    try
                    {
                        tlsListener = new Socket(tlsEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

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
                            log.Write(tlsEP, DnsTransportProtocol.Tls, "DNS Server failed to bind.\r\n" + ex.ToString());

                        if (tlsListener != null)
                            tlsListener.Dispose();
                    }
                }

                if (_enableDnsOverHttps && (_certificate != null))
                {
                    IPEndPoint httpsEP = new IPEndPoint(_localAddresses[i], 443);
                    Socket httpsListener = null;

                    try
                    {
                        httpsListener = new Socket(httpsEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

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
                            log.Write(httpsEP, DnsTransportProtocol.Https, "DNS Server failed to bind.\r\n" + ex.ToString());

                        if (httpsListener != null)
                            httpsListener.Dispose();
                    }
                }
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

            _cachePrefetchSamplingTimer = new Timer(CachePrefetchSamplingAsync, null, System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
            _cachePrefetchRefreshTimer = new Timer(CachePrefetchRefreshAsync, null, System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
            _cacheMaintenanceTimer = new Timer(CacheMaintenanceAsync, null, CACHE_MAINTENANCE_TIMER_INITIAL_INTEVAL, CACHE_MAINTENANCE_TIMER_PERIODIC_INTERVAL);

            _state = ServiceState.Running;

            ResetPrefetchTimers();
        }

        public void Stop()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            lock (_cachePrefetchSamplingTimerLock)
            {
                if (_cachePrefetchSamplingTimer != null)
                {
                    _cachePrefetchSamplingTimer.Dispose();
                    _cachePrefetchSamplingTimer = null;
                }
            }

            lock (_cachePrefetchRefreshTimerLock)
            {
                if (_cachePrefetchRefreshTimer != null)
                {
                    _cachePrefetchRefreshTimer.Dispose();
                    _cachePrefetchRefreshTimer = null;
                }
            }

            if (_cacheMaintenanceTimer != null)
            {
                _cacheMaintenanceTimer.Dispose();
                _cacheMaintenanceTimer = null;
            }

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

        public DnsDatagram DirectQuery(DnsQuestionRecord question, int timeout = 2000)
        {
            object timeoutLock = new object();
            DnsDatagram response = null;

            lock (timeoutLock)
            {
                ThreadPool.QueueUserWorkItem(delegate (object state)
                {
                    try
                    {
                        response = ProcessQuery(new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { question }, null, null, null), new IPEndPoint(IPAddress.Any, 0), true, DnsTransportProtocol.Tcp);

                        lock (timeoutLock)
                        {
                            Monitor.Pulse(timeoutLock);
                        }
                    }
                    catch
                    { }
                });

                Monitor.Wait(timeoutLock, timeout);
                return response;
            }
        }

        #endregion

        #region properties

        public IPAddress[] LocalAddresses
        {
            get { return _localAddresses; }
            set { _localAddresses = value; }
        }

        public string ServerDomain
        {
            get { return _authoritativeZoneRoot.ServerDomain; }
            set
            {
                _authoritativeZoneRoot.ServerDomain = value;
                _allowedZoneRoot.ServerDomain = value;
                _blockedZoneRoot.ServerDomain = value;
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

        internal DnsCache Cache
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

        public int CachePrefetchEligibility
        {
            get { return _cachePrefetchEligibility; }
            set
            {
                if (value < 2)
                    throw new ArgumentOutOfRangeException("CachePrefetchEligibility", "Valid value is greater that or equal to 2.");

                _cachePrefetchEligibility = value;
            }
        }

        public int CachePrefetchTrigger
        {
            get { return _cachePrefetchTrigger; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException("CachePrefetchTrigger", "Valid value is greater that or equal to 0.");

                if (_cachePrefetchTrigger != value)
                {
                    _cachePrefetchTrigger = value;
                    ResetPrefetchTimers();
                }
            }
        }

        public int CachePrefetchSampleIntervalInMinutes
        {
            get { return _cachePrefetchSampleIntervalInMinutes; }
            set
            {
                if ((value < 1) || (value > 60))
                    throw new ArgumentOutOfRangeException("CacheRefreshSampleIntervalInMinutes", "Valid range is between 1 and 60 minutes.");

                if (_cachePrefetchSampleIntervalInMinutes != value)
                {
                    _cachePrefetchSampleIntervalInMinutes = value;
                    ResetPrefetchTimers();
                }
            }
        }

        public int CachePrefetchSampleEligibilityHitsPerHour
        {
            get { return _cachePrefetchSampleEligibilityHitsPerHour; }
            set
            {
                if (value < 1)
                    throw new ArgumentOutOfRangeException("CachePrefetchSampleEligibilityHitsPerHour", "Valid value is greater than or equal to 1.");

                _cachePrefetchSampleEligibilityHitsPerHour = value;
            }
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
    }
}
