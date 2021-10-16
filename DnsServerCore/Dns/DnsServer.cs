/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.ApplicationCommon;
using DnsServerCore.Dns.Applications;
using DnsServerCore.Dns.ZoneManagers;
using DnsServerCore.Dns.Zones;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore.Dns
{
    public enum DnsServerRecursion : byte
    {
        Deny = 0,
        Allow = 1,
        AllowOnlyForPrivateNetworks = 2,
        UseSpecifiedNetworks = 3
    }

    public enum DnsServerBlockingType : byte
    {
        AnyAddress = 0,
        NxDomain = 1,
        CustomAddress = 2
    }

    public sealed class DnsServer : IDisposable, IDnsClient
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

        internal const int MAX_CNAME_HOPS = 16;
        const int SERVE_STALE_WAIT_TIME = 1800;

        static readonly IPEndPoint IPENDPOINT_ANY_0 = new IPEndPoint(IPAddress.Any, 0);

        string _serverDomain;
        readonly string _configFolder;
        readonly string _dohwwwFolder;
        IReadOnlyList<IPEndPoint> _localEndPoints;
        LogManager _log;

        NameServerAddress _thisServer;

        readonly List<Socket> _udpListeners = new List<Socket>();
        readonly List<Socket> _tcpListeners = new List<Socket>();
        readonly List<Socket> _httpListeners = new List<Socket>();
        readonly List<Socket> _tlsListeners = new List<Socket>();
        readonly List<Socket> _httpsListeners = new List<Socket>();

        bool _enableDnsOverHttp;
        bool _enableDnsOverTls;
        bool _enableDnsOverHttps;
        bool _isDnsOverHttpsEnabled;
        X509Certificate2 _certificate;
        IReadOnlyDictionary<string, TsigKey> _tsigKeys;

        readonly AuthZoneManager _authZoneManager;
        readonly AllowedZoneManager _allowedZoneManager;
        readonly BlockedZoneManager _blockedZoneManager;
        readonly BlockListZoneManager _blockListZoneManager;
        readonly CacheZoneManager _cacheZoneManager;
        readonly DnsApplicationManager _dnsApplicationManager;

        readonly ResolverDnsCache _dnsCache;

        readonly IReadOnlyCollection<DnsARecord> _aRecords = new DnsARecord[] { new DnsARecord(IPAddress.Any) };
        readonly IReadOnlyCollection<DnsAAAARecord> _aaaaRecords = new DnsAAAARecord[] { new DnsAAAARecord(IPAddress.IPv6Any) };

        DnsServerRecursion _recursion;
        IReadOnlyCollection<NetworkAddress> _recursionDeniedNetworks;
        IReadOnlyCollection<NetworkAddress> _recursionAllowedNetworks;
        NetProxy _proxy;
        IReadOnlyList<NameServerAddress> _forwarders;
        bool _preferIPv6;
        bool _randomizeName;
        bool _qnameMinimization;
        bool _nsRevalidation;
        int _qpmLimitRequests = 0;
        int _qpmLimitErrors = 0;
        int _qpmLimitSampleMinutes = 5;
        int _qpmLimitIPv4PrefixLength = 24;
        int _qpmLimitIPv6PrefixLength = 56;
        int _forwarderRetries = 3;
        int _resolverRetries = 5;
        int _forwarderTimeout = 4000;
        int _resolverTimeout = 4000;
        int _clientTimeout = 4000;
        int _forwarderConcurrency = 2;
        int _resolverMaxStackCount = 16;
        bool _serveStale = true;
        int _cachePrefetchEligibility = 2;
        int _cachePrefetchTrigger = 9;
        int _cachePrefetchSampleIntervalInMinutes = 5;
        int _cachePrefetchSampleEligibilityHitsPerHour = 30;
        bool _enableBlocking = true;
        bool _allowTxtBlockingReport = true;
        DnsServerBlockingType _blockingType = DnsServerBlockingType.AnyAddress;
        IReadOnlyCollection<DnsARecord> _customBlockingARecords = Array.Empty<DnsARecord>();
        IReadOnlyCollection<DnsAAAARecord> _customBlockingAAAARecords = Array.Empty<DnsAAAARecord>();
        LogManager _queryLog;
        readonly StatsManager _stats;

        int _tcpSendTimeout = 10000;
        int _tcpReceiveTimeout = 10000;

        Timer _cachePrefetchSamplingTimer;
        readonly object _cachePrefetchSamplingTimerLock = new object();
        const int CACHE_PREFETCH_SAMPLING_TIMER_INITIAL_INTEVAL = 5000;

        Timer _cachePrefetchRefreshTimer;
        readonly object _cachePrefetchRefreshTimerLock = new object();
        const int CACHE_PREFETCH_REFRESH_TIMER_INITIAL_INTEVAL = 10000;
        DateTime _cachePrefetchSamplingTimerTriggersOn;
        IList<CacheRefreshSample> _cacheRefreshSampleList;

        Timer _cacheMaintenanceTimer;
        readonly object _cacheMaintenanceTimerLock = new object();
        const int CACHE_MAINTENANCE_TIMER_INITIAL_INTEVAL = 5 * 60 * 1000;
        const int CACHE_MAINTENANCE_TIMER_PERIODIC_INTERVAL = 5 * 60 * 1000;

        Timer _qpmLimitSamplingTimer;
        readonly object _qpmLimitSamplingTimerLock = new object();
        const int QPM_LIMIT_SAMPLING_TIMER_INTERVAL = 10000;
        IReadOnlyDictionary<IPAddress, int> _qpmLimitClientSubnetStats;
        IReadOnlyDictionary<IPAddress, int> _qpmLimitErrorClientSubnetStats;

        readonly IndependentTaskScheduler _resolverTaskScheduler = new IndependentTaskScheduler(ThreadPriority.AboveNormal);
        readonly DomainTree<Task<DnsDatagram>> _resolverTasks = new DomainTree<Task<DnsDatagram>>();

        volatile ServiceState _state = ServiceState.Stopped;

        #endregion

        #region constructor

        static DnsServer()
        {
            //set min threads since the default value is too small
            {
                ThreadPool.GetMinThreads(out int minWorker, out int minIOC);

                int minThreads = Environment.ProcessorCount * 256;

                if (minWorker < minThreads)
                    minWorker = minThreads;

                if (minIOC < minThreads)
                    minIOC = minThreads;

                ThreadPool.SetMinThreads(minWorker, minIOC);
            }

            if (ServicePointManager.DefaultConnectionLimit < 10)
                ServicePointManager.DefaultConnectionLimit = 10; //concurrent http request limit required when using DNS-over-HTTPS forwarders
        }

        public DnsServer(string serverDomain, string configFolder, string dohwwwFolder, LogManager log = null)
            : this(serverDomain, configFolder, dohwwwFolder, new IPEndPoint[] { new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53) }, log)
        { }

        public DnsServer(string serverDomain, string configFolder, string dohwwwFolder, IPEndPoint localEndPoint, LogManager log = null)
            : this(serverDomain, configFolder, dohwwwFolder, new IPEndPoint[] { localEndPoint }, log)
        { }

        public DnsServer(string serverDomain, string configFolder, string dohwwwFolder, IReadOnlyList<IPEndPoint> localEndPoints, LogManager log = null)
        {
            _serverDomain = serverDomain;
            _configFolder = configFolder;
            _dohwwwFolder = dohwwwFolder;
            _localEndPoints = localEndPoints;
            _log = log;

            _authZoneManager = new AuthZoneManager(this);
            _allowedZoneManager = new AllowedZoneManager(this);
            _blockedZoneManager = new BlockedZoneManager(this);
            _blockListZoneManager = new BlockListZoneManager(this);
            _cacheZoneManager = new CacheZoneManager(this);
            _dnsApplicationManager = new DnsApplicationManager(this);

            _dnsCache = new ResolverDnsCache(_dnsApplicationManager, _authZoneManager, _cacheZoneManager);

            //init stats
            _stats = new StatsManager(this);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                Stop();

                if (_authZoneManager is not null)
                    _authZoneManager.Dispose();

                if (_dnsApplicationManager is not null)
                    _dnsApplicationManager.Dispose();

                if (_stats is not null)
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

        private async Task ReadUdpRequestAsync(Socket udpListener)
        {
            const int BUFFER_SIZE = 512;
            byte[] recvBuffer = new byte[BUFFER_SIZE];
            using MemoryStream recvBufferStream = new MemoryStream(recvBuffer);

            try
            {
                EndPoint epAny;

                switch (udpListener.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        epAny = new IPEndPoint(IPAddress.Any, 0);
                        break;

                    case AddressFamily.InterNetworkV6:
                        epAny = new IPEndPoint(IPAddress.IPv6Any, 0);
                        break;

                    default:
                        throw new NotSupportedException("AddressFamily not supported.");
                }

                SocketReceiveFromResult result;

                while (true)
                {
                    recvBufferStream.SetLength(BUFFER_SIZE); //resetting length before using buffer

                    try
                    {
                        result = await udpListener.ReceiveFromAsync(recvBuffer, SocketFlags.None, epAny);
                    }
                    catch (SocketException ex)
                    {
                        switch (ex.SocketErrorCode)
                        {
                            case SocketError.ConnectionReset:
                            case SocketError.HostUnreachable:
                            case SocketError.MessageSize:
                            case SocketError.NetworkReset:
                                result = default;
                                break;

                            default:
                                throw;
                        }
                    }

                    if (result.ReceivedBytes > 0)
                    {
                        if (result.RemoteEndPoint is not IPEndPoint remoteEP)
                            continue;

                        if (IsQpmLimitCrossed(remoteEP))
                            continue;

                        try
                        {
                            recvBufferStream.Position = 0;
                            recvBufferStream.SetLength(result.ReceivedBytes);

                            DnsDatagram request = DnsDatagram.ReadFrom(recvBufferStream);

                            _ = ProcessUdpRequestAsync(udpListener, remoteEP, request);
                        }
                        catch (EndOfStreamException)
                        {
                            //ignore incomplete udp datagrams
                        }
                        catch (Exception ex)
                        {
                            LogManager log = _log;
                            if (log is not null)
                                log.Write(remoteEP, DnsTransportProtocol.Udp, ex);
                        }
                    }
                }
            }
            catch (ObjectDisposedException)
            {
                //server stopping
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                LogManager log = _log;
                if (log is not null)
                    log.Write(ex);
            }
        }

        private async Task ProcessUdpRequestAsync(Socket udpListener, IPEndPoint remoteEP, DnsDatagram request)
        {
            try
            {
                DnsDatagram response = await PreProcessQueryAsync(request, remoteEP, DnsTransportProtocol.Udp, IsRecursionAllowed(remoteEP));
                if (response is null)
                    return; //drop request

                //send response
                byte[] sendBuffer = new byte[512];
                using (MemoryStream sendBufferStream = new MemoryStream(sendBuffer))
                {
                    try
                    {
                        response.WriteTo(sendBufferStream);
                    }
                    catch (NotSupportedException)
                    {
                        if (response.IsSigned)
                        {
                            //rfc8945 section 5.3
                            response = new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, true, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, DnsResponseCode.NoError, response.Question, null, null, new DnsResourceRecord[] { response.Additional[response.Additional.Count - 1] }) { Tag = DnsServerResponseType.Authoritative };
                        }
                        else
                        {
                            if (response.Question[0].Type == DnsResourceRecordType.IXFR)
                                response = new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, false, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, response.RCODE, response.Question, new DnsResourceRecord[] { response.Answer[0] }) { Tag = DnsServerResponseType.Authoritative }; //truncate response
                            else
                                response = new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, true, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, response.RCODE, response.Question) { Tag = DnsServerResponseType.Authoritative };
                        }

                        sendBufferStream.Position = 0;
                        response.WriteTo(sendBufferStream);
                    }

                    //send dns datagram async
                    await udpListener.SendToAsync(new ArraySegment<byte>(sendBuffer, 0, (int)sendBufferStream.Position), SocketFlags.None, remoteEP);
                }

                LogManager queryLog = _queryLog;
                if (queryLog is not null)
                    queryLog.Write(remoteEP, DnsTransportProtocol.Udp, request, response);

                _stats.QueueUpdate(request, remoteEP, DnsTransportProtocol.Udp, response);
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                LogManager queryLog = _queryLog;
                if (queryLog is not null)
                    queryLog.Write(remoteEP, DnsTransportProtocol.Udp, request, null);

                LogManager log = _log;
                if (log is not null)
                    log.Write(remoteEP, DnsTransportProtocol.Udp, ex);
            }
        }

        private async Task AcceptConnectionAsync(Socket tcpListener, DnsTransportProtocol protocol, bool usingHttps)
        {
            IPEndPoint localEP = tcpListener.LocalEndPoint as IPEndPoint;

            try
            {
                tcpListener.SendTimeout = _tcpSendTimeout;
                tcpListener.ReceiveTimeout = _tcpReceiveTimeout;
                tcpListener.NoDelay = true;

                while (true)
                {
                    Socket socket = await tcpListener.AcceptAsync();

                    _ = ProcessConnectionAsync(socket, protocol, usingHttps);
                }
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.OperationAborted)
                    return; //server stopping

                LogManager log = _log;
                if (log is not null)
                    log.Write(localEP, protocol, ex);
            }
            catch (ObjectDisposedException)
            {
                //server stopped
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                LogManager log = _log;
                if (log is not null)
                    log.Write(localEP, protocol, ex);
            }
        }

        private async Task ProcessConnectionAsync(Socket socket, DnsTransportProtocol protocol, bool usingHttps)
        {
            IPEndPoint remoteEP = null;

            try
            {
                remoteEP = socket.RemoteEndPoint as IPEndPoint;

                switch (protocol)
                {
                    case DnsTransportProtocol.Tcp:
                        await ReadStreamRequestAsync(new NetworkStream(socket), _tcpReceiveTimeout, remoteEP, protocol);
                        break;

                    case DnsTransportProtocol.Tls:
                        SslStream tlsStream = new SslStream(new NetworkStream(socket));
                        await tlsStream.AuthenticateAsServerAsync(_certificate);

                        await ReadStreamRequestAsync(tlsStream, _tcpReceiveTimeout, remoteEP, protocol);
                        break;

                    case DnsTransportProtocol.Https:
                        Stream stream = new NetworkStream(socket);

                        if (usingHttps)
                        {
                            SslStream httpsStream = new SslStream(stream);
                            await httpsStream.AuthenticateAsServerAsync(_certificate);

                            stream = httpsStream;
                        }

                        await ProcessDoHRequestAsync(stream, _tcpReceiveTimeout, remoteEP, usingHttps);
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
                if (log is not null)
                    log.Write(remoteEP, protocol, ex);
            }
            finally
            {
                if (socket is not null)
                    socket.Dispose();
            }
        }

        private async Task ReadStreamRequestAsync(Stream stream, int receiveTimeout, IPEndPoint remoteEP, DnsTransportProtocol protocol)
        {
            try
            {
                using MemoryStream readBuffer = new MemoryStream(64);
                using MemoryStream writeBuffer = new MemoryStream(4096);
                using SemaphoreSlim writeSemaphore = new SemaphoreSlim(1, 1);

                while (true)
                {
                    if (IsQpmLimitCrossed(remoteEP))
                        break;

                    DnsDatagram request;

                    //read dns datagram with timeout
                    using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
                    {
                        Task<DnsDatagram> task = DnsDatagram.ReadFromTcpAsync(stream, readBuffer, cancellationTokenSource.Token);

                        if (await Task.WhenAny(task, Task.Delay(receiveTimeout, cancellationTokenSource.Token)) != task)
                        {
                            //read timed out
                            await stream.DisposeAsync();
                            return;
                        }

                        cancellationTokenSource.Cancel(); //cancel delay task

                        request = await task;
                    }

                    //process request async
                    _ = ProcessStreamRequestAsync(stream, writeBuffer, writeSemaphore, remoteEP, request, protocol);
                }
            }
            catch (ObjectDisposedException)
            {
                //ignore
            }
            catch (IOException)
            {
                //ignore IO exceptions
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log is not null)
                    log.Write(remoteEP, protocol, ex);
            }
        }

        private async Task ProcessStreamRequestAsync(Stream stream, MemoryStream writeBuffer, SemaphoreSlim writeSemaphore, IPEndPoint remoteEP, DnsDatagram request, DnsTransportProtocol protocol)
        {
            try
            {
                DnsDatagram response = await PreProcessQueryAsync(request, remoteEP, protocol, IsRecursionAllowed(remoteEP));
                if (response is null)
                {
                    await stream.DisposeAsync();
                    return; //drop request
                }

                //send response
                await writeSemaphore.WaitAsync();
                try
                {
                    //send dns datagram
                    await response.WriteToTcpAsync(stream, writeBuffer);
                    await stream.FlushAsync();
                }
                finally
                {
                    writeSemaphore.Release();
                }

                LogManager queryLog = _queryLog;
                if (queryLog is not null)
                    queryLog.Write(remoteEP, protocol, request, response);

                _stats.QueueUpdate(request, remoteEP, protocol, response);
            }
            catch (IOException)
            {
                //ignore IO exceptions
            }
            catch (Exception ex)
            {
                LogManager queryLog = _queryLog;
                if ((queryLog is not null) && (request is not null))
                    queryLog.Write(remoteEP, protocol, request, null);

                LogManager log = _log;
                if (log is not null)
                    log.Write(remoteEP, protocol, ex);
            }
        }

        private async Task ProcessDoHRequestAsync(Stream stream, int receiveTimeout, IPEndPoint remoteEP, bool usingHttps)
        {
            DnsDatagram dnsRequest = null;
            DnsTransportProtocol dnsProtocol = DnsTransportProtocol.Https;

            try
            {
                while (true)
                {
                    bool isSocketRemoteIpPrivate = NetUtilities.IsPrivateIP(remoteEP.Address);
                    HttpRequest httpRequest;

                    if (usingHttps || !isSocketRemoteIpPrivate)
                    {
                        //is HTTPS request or is over public IP
                        if (IsQpmLimitCrossed(remoteEP))
                            break;

                        httpRequest = await HttpRequest.ReadRequestAsync(stream, 512).WithTimeout(receiveTimeout);
                        if (httpRequest is null)
                            return; //connection closed gracefully by client
                    }
                    else
                    {
                        //is HTTP request (probably via reverse proxy) and is over private IP
                        httpRequest = await HttpRequest.ReadRequestAsync(stream, 512).WithTimeout(receiveTimeout);
                        if (httpRequest is null)
                            return; //connection closed gracefully by client

                        string xRealIp = httpRequest.Headers["X-Real-IP"];
                        if (IPAddress.TryParse(xRealIp, out IPAddress address))
                        {
                            //get the real IP address of the requesting client from X-Real-IP header set in nginx proxy_pass block
                            remoteEP = new IPEndPoint(address, 0);
                        }

                        if (IsQpmLimitCrossed(remoteEP))
                            break;
                    }

                    string requestConnection = httpRequest.Headers[HttpRequestHeader.Connection];
                    if (string.IsNullOrEmpty(requestConnection))
                        requestConnection = "close";

                    switch (httpRequest.RequestPath)
                    {
                        case "/dns-query":
                            if (!usingHttps && !isSocketRemoteIpPrivate)
                            {
                                //intentionally blocking public IP addresses from using DNS-over-HTTP (without TLS)
                                //this feature is intended to be used with an SSL terminated reverse proxy like nginx on private network
                                await SendErrorAsync(stream, "close", 403, "DNS-over-HTTPS (DoH) queries are supported only on HTTPS.");
                                return;
                            }

                            DnsTransportProtocol protocol = DnsTransportProtocol.Udp;

                            string strRequestAcceptTypes = httpRequest.Headers[HttpRequestHeader.Accept];
                            if (string.IsNullOrEmpty(strRequestAcceptTypes))
                            {
                                string strContentType = httpRequest.Headers[HttpRequestHeader.ContentType];
                                if (strContentType == "application/dns-message")
                                    protocol = DnsTransportProtocol.Https;
                            }
                            else
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
                                        switch (httpRequest.HttpMethod)
                                        {
                                            case "GET":
                                                string strRequest = httpRequest.QueryString["dns"];
                                                if (string.IsNullOrEmpty(strRequest))
                                                    throw new DnsServerException("Missing query string parameter: dns");

                                                //convert from base64url to base64
                                                strRequest = strRequest.Replace('-', '+');
                                                strRequest = strRequest.Replace('_', '/');

                                                //add padding
                                                int x = strRequest.Length % 4;
                                                if (x > 0)
                                                    strRequest = strRequest.PadRight(strRequest.Length - x + 4, '=');

                                                using (MemoryStream mS = new MemoryStream(Convert.FromBase64String(strRequest)))
                                                {
                                                    dnsRequest = DnsDatagram.ReadFrom(mS);
                                                }

                                                break;

                                            case "POST":
                                                string strContentType = httpRequest.Headers[HttpRequestHeader.ContentType];
                                                if (string.IsNullOrEmpty(strContentType))
                                                    throw new DnsServerException("Missing Content-Type header.");

                                                if (strContentType != "application/dns-message")
                                                    throw new NotSupportedException("DNS request type not supported: " + strContentType);

                                                using (MemoryStream mS = new MemoryStream(32))
                                                {
                                                    await httpRequest.InputStream.CopyToAsync(mS, 32);

                                                    mS.Position = 0;
                                                    dnsRequest = DnsDatagram.ReadFrom(mS);
                                                }

                                                break;

                                            default:
                                                throw new NotSupportedException("DoH request type not supported.");
                                        }

                                        DnsDatagram dnsResponse = await PreProcessQueryAsync(dnsRequest, remoteEP, protocol, IsRecursionAllowed(remoteEP));
                                        if (dnsResponse is null)
                                            return; //drop request

                                        using (MemoryStream mS = new MemoryStream(512))
                                        {
                                            dnsResponse.WriteTo(mS);

                                            mS.Position = 0;
                                            await SendContentAsync(stream, requestConnection, "application/dns-message", mS);
                                        }

                                        LogManager queryLog = _queryLog;
                                        if (queryLog is not null)
                                            queryLog.Write(remoteEP, protocol, dnsRequest, dnsResponse);

                                        _stats.QueueUpdate(dnsRequest, remoteEP, protocol, dnsResponse);
                                    }
                                    #endregion
                                    break;

                                case DnsTransportProtocol.HttpsJson:
                                    #region https json format
                                    {
                                        string strName = httpRequest.QueryString["name"];
                                        if (string.IsNullOrEmpty(strName))
                                            throw new DnsServerException("Missing query string parameter: name");

                                        string strType = httpRequest.QueryString["type"];
                                        if (string.IsNullOrEmpty(strType))
                                            strType = "1";

                                        dnsRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(strName, (DnsResourceRecordType)int.Parse(strType), DnsClass.IN) });

                                        DnsDatagram dnsResponse = await PreProcessQueryAsync(dnsRequest, remoteEP, protocol, IsRecursionAllowed(remoteEP));
                                        if (dnsResponse is null)
                                            return; //drop request

                                        using (MemoryStream mS = new MemoryStream(512))
                                        {
                                            JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                                            dnsResponse.WriteToJson(jsonWriter);
                                            jsonWriter.Flush();

                                            mS.Position = 0;
                                            await SendContentAsync(stream, requestConnection, "application/dns-json; charset=utf-8", mS);
                                        }

                                        LogManager queryLog = _queryLog;
                                        if (queryLog is not null)
                                            queryLog.Write(remoteEP, protocol, dnsRequest, dnsResponse);

                                        _stats.QueueUpdate(dnsRequest, remoteEP, protocol, dnsResponse);
                                    }
                                    #endregion
                                    break;

                                default:
                                    await RedirectAsync(stream, httpRequest.Protocol, requestConnection, "https://" + httpRequest.Headers[HttpRequestHeader.Host]);
                                    break;
                            }

                            if (requestConnection.Equals("close", StringComparison.OrdinalIgnoreCase))
                                return;

                            break;

                        default:
                            string path = httpRequest.RequestPath;

                            if (!path.StartsWith("/") || path.Contains("/../") || path.Contains("/.../"))
                            {
                                await SendErrorAsync(stream, requestConnection, 404);
                                break;
                            }

                            if (path == "/")
                                path = "/index.html";

                            path = Path.GetFullPath(_dohwwwFolder + path.Replace('/', Path.DirectorySeparatorChar));

                            if (!path.StartsWith(_dohwwwFolder) || !File.Exists(path))
                            {
                                await SendErrorAsync(stream, requestConnection, 404);
                                break;
                            }

                            await SendFileAsync(stream, requestConnection, path);
                            break;
                    }
                }
            }
            catch (TimeoutException)
            {
                //ignore timeout exception
            }
            catch (IOException)
            {
                //ignore IO exceptions
            }
            catch (Exception ex)
            {
                LogManager queryLog = _queryLog;
                if ((queryLog is not null) && (dnsRequest is not null))
                    queryLog.Write(remoteEP, dnsProtocol, dnsRequest, null);

                LogManager log = _log;
                if (log is not null)
                    log.Write(remoteEP, dnsProtocol, ex);

                await SendErrorAsync(stream, "close", ex);
            }
        }

        private static async Task SendContentAsync(Stream outputStream, string connection, string contentType, Stream content)
        {
            byte[] bufferHeader = Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nContent-Type: " + contentType + "\r\nContent-Length: " + content.Length + "\r\nX-Robots-Tag: noindex, nofollow\r\nConnection: " + connection + "\r\n\r\n");

            await outputStream.WriteAsync(bufferHeader);
            await content.CopyToAsync(outputStream);
            await outputStream.FlushAsync();
        }

        private static Task SendErrorAsync(Stream outputStream, string connection, Exception ex)
        {
            return SendErrorAsync(outputStream, connection, 500, ex.ToString());
        }

        private static async Task SendErrorAsync(Stream outputStream, string connection, int statusCode, string message = null)
        {
            try
            {
                string statusString = statusCode + " " + GetHttpStatusString((HttpStatusCode)statusCode);
                byte[] bufferContent = Encoding.UTF8.GetBytes("<html><head><title>" + statusString + "</title></head><body><h1>" + statusString + "</h1>" + (message is null ? "" : "<p>" + message + "</p>") + "</body></html>");
                byte[] bufferHeader = Encoding.UTF8.GetBytes("HTTP/1.1 " + statusString + "\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + bufferContent.Length + "\r\nX-Robots-Tag: noindex, nofollow\r\nConnection: " + connection + "\r\n\r\n");

                await outputStream.WriteAsync(bufferHeader);
                await outputStream.WriteAsync(bufferContent);
                await outputStream.FlushAsync();
            }
            catch
            { }
        }

        private static async Task RedirectAsync(Stream outputStream, string protocol, string connection, string location)
        {
            try
            {
                string statusString = "302 Found";
                byte[] bufferContent = Encoding.UTF8.GetBytes("<html><head><title>" + statusString + "</title></head><body><h1>" + statusString + "</h1><p>Location: <a href=\"" + location + "\">" + location + "</a></p></body></html>");
                byte[] bufferHeader = Encoding.UTF8.GetBytes(protocol + " " + statusString + "\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nLocation: " + location + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + bufferContent.Length + "\r\nX-Robots-Tag: noindex, nofollow\r\nConnection: " + connection + "\r\n\r\n");

                await outputStream.WriteAsync(bufferHeader);
                await outputStream.WriteAsync(bufferContent);
                await outputStream.FlushAsync();
            }
            catch
            { }
        }

        private static async Task SendFileAsync(Stream outputStream, string connection, string filePath)
        {
            using (FileStream fS = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                byte[] bufferHeader = Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nContent-Type: " + WebUtilities.GetContentType(filePath).MediaType + "\r\nContent-Length: " + fS.Length + "\r\nCache-Control: private, max-age=300\r\nX-Robots-Tag: noindex, nofollow\r\nConnection: " + connection + "\r\n\r\n");

                await outputStream.WriteAsync(bufferHeader);
                await fS.CopyToAsync(outputStream);
                await outputStream.FlushAsync();
            }
        }

        internal static string GetHttpStatusString(HttpStatusCode statusCode)
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

        private bool IsRecursionAllowed(IPEndPoint remoteEP)
        {
            switch (_recursion)
            {
                case DnsServerRecursion.Allow:
                    return true;

                case DnsServerRecursion.AllowOnlyForPrivateNetworks:
                    switch (remoteEP.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                        case AddressFamily.InterNetworkV6:
                            return NetUtilities.IsPrivateIP(remoteEP.Address);

                        default:
                            return false;
                    }

                case DnsServerRecursion.UseSpecifiedNetworks:
                    IPAddress address = remoteEP.Address;

                    if (_recursionDeniedNetworks is not null)
                    {
                        foreach (NetworkAddress deniedNetworkAddress in _recursionDeniedNetworks)
                        {
                            if (deniedNetworkAddress.Contains(address))
                                return false;
                        }
                    }

                    if (_recursionAllowedNetworks is not null)
                    {
                        foreach (NetworkAddress allowedNetworkAddress in _recursionAllowedNetworks)
                        {
                            if (allowedNetworkAddress.Contains(address))
                                return true;
                        }
                    }

                    if (IPAddress.IsLoopback(address))
                        return true;

                    return false;

                default:
                    return false;
            }
        }

        private async Task<DnsDatagram> PreProcessQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            foreach (IDnsRequestController requestController in _dnsApplicationManager.DnsRequestControllers)
            {
                DnsRequestControllerAction action = await requestController.GetRequestActionAsync(request, remoteEP, protocol);
                switch (action)
                {
                    case DnsRequestControllerAction.DropSilently:
                        return null; //drop request

                    case DnsRequestControllerAction.DropWithRefused:
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative }; //drop request with refused
                }
            }

            if (request.ParsingException is not null)
            {
                //format error
                if (!(request.ParsingException is IOException))
                {
                    LogManager log = _log;
                    if (log is not null)
                        log.Write(remoteEP, protocol, request.ParsingException);
                }

                //format error response
                return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };
            }

            if (request.IsSigned)
            {
                if (!request.VerifySignedRequest(_tsigKeys, out DnsDatagram unsignedRequest, out DnsDatagram errorResponse))
                {
                    LogManager log = _log;
                    if (log is not null)
                        log.Write(remoteEP, protocol, "DNS Server received a request that failed TSIG signature verification (RCODE: " + errorResponse.RCODE + "; TSIG Error: " + errorResponse.TsigError + ")");

                    errorResponse.Tag = DnsServerResponseType.Authoritative;
                    return errorResponse;
                }

                DnsDatagram unsignedResponse = await ProcessQueryAsync(unsignedRequest, remoteEP, protocol, isRecursionAllowed, false, request.TsigKeyName);
                return unsignedResponse.SignResponse(request, _tsigKeys);
            }

            return await ProcessQueryAsync(request, remoteEP, protocol, isRecursionAllowed, false, null);
        }

        private async Task<DnsDatagram> ProcessQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers, string tsigAuthenticatedKeyName)
        {
            if (request.IsResponse)
                return null; //drop response datagram to avoid loops in rare scenarios

            switch (request.OPCODE)
            {
                case DnsOpcode.StandardQuery:
                    if (request.Question.Count != 1)
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                    if (request.Question[0].Class != DnsClass.IN)
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };

                    try
                    {
                        DnsQuestionRecord question = request.Question[0];

                        switch (question.Type)
                        {
                            case DnsResourceRecordType.AXFR:
                                if (protocol == DnsTransportProtocol.Udp)
                                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                                return await ProcessZoneTransferQueryAsync(request, remoteEP, protocol, tsigAuthenticatedKeyName);

                            case DnsResourceRecordType.IXFR:
                                return await ProcessZoneTransferQueryAsync(request, remoteEP, protocol, tsigAuthenticatedKeyName);

                            case DnsResourceRecordType.FWD:
                            case DnsResourceRecordType.APP:
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };
                        }

                        //query authoritative zone
                        DnsDatagram response = await ProcessAuthoritativeQueryAsync(request, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers);
                        if (response is not null)
                        {
                            if ((question.Type == DnsResourceRecordType.ANY) && (protocol == DnsTransportProtocol.Udp)) //force TCP for ANY request
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, true, request.RecursionDesired, isRecursionAllowed, false, false, response.RCODE, request.Question) { Tag = DnsServerResponseType.Authoritative };

                            return response;
                        }

                        if (!request.RecursionDesired || !isRecursionAllowed)
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };

                        //do recursive query
                        if ((question.Type == DnsResourceRecordType.ANY) && (protocol == DnsTransportProtocol.Udp)) //force TCP for ANY request
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, true, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                        return await ProcessRecursiveQueryAsync(request, remoteEP, protocol, null, false);
                    }
                    catch (InvalidDomainNameException)
                    {
                        //format error response
                        return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };
                    }
                    catch (Exception ex)
                    {
                        LogManager log = _log;
                        if (log is not null)
                            log.Write(remoteEP, protocol, ex);

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.ServerFailure, request.Question) { Tag = DnsServerResponseType.Authoritative };
                    }

                case DnsOpcode.Notify:
                    return await ProcessNotifyQueryAsync(request, remoteEP, protocol);

                default:
                    return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NotImplemented, request.Question) { Tag = DnsServerResponseType.Authoritative };
            }
        }

        private async Task<DnsDatagram> ProcessNotifyQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol)
        {
            AuthZoneInfo authZoneInfo = _authZoneManager.GetAuthZoneInfo(request.Question[0].Name);
            if ((authZoneInfo is null) || (authZoneInfo.Type != AuthZoneType.Secondary) || authZoneInfo.Disabled)
                return new DnsDatagram(request.Identifier, true, DnsOpcode.Notify, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };

            IPAddress remoteAddress = remoteEP.Address;
            bool remoteVerified = false;

            IReadOnlyList<NameServerAddress> primaryNameServers = await authZoneInfo.GetPrimaryNameServerAddressesAsync(this);

            foreach (NameServerAddress primaryNameServer in primaryNameServers)
            {
                if (primaryNameServer.IPEndPoint.Address.Equals(remoteAddress))
                {
                    remoteVerified = true;
                    break;
                }
            }

            if (!remoteVerified)
                return new DnsDatagram(request.Identifier, true, DnsOpcode.Notify, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };

            LogManager log = _log;
            if (log is not null)
                log.Write(remoteEP, protocol, "DNS Server received NOTIFY for zone: " + (authZoneInfo.Name == "" ? "<root>" : authZoneInfo.Name));

            if ((request.Answer.Count > 0) && (request.Answer[0].Type == DnsResourceRecordType.SOA))
            {
                IReadOnlyList<DnsResourceRecord> localSoaRecords = authZoneInfo.GetRecords(DnsResourceRecordType.SOA);

                if (!DnsSOARecord.IsZoneUpdateAvailable((localSoaRecords[0].RDATA as DnsSOARecord).Serial, (request.Answer[0].RDATA as DnsSOARecord).Serial))
                {
                    //no update was available
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.Notify, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question) { Tag = DnsServerResponseType.Authoritative };
                }
            }

            authZoneInfo.TriggerRefresh();
            return new DnsDatagram(request.Identifier, true, DnsOpcode.Notify, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question) { Tag = DnsServerResponseType.Authoritative };
        }

        private async Task<DnsDatagram> ProcessZoneTransferQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, string tsigAuthenticatedKeyName)
        {
            LogManager log = _log;

            AuthZoneInfo authZoneInfo = _authZoneManager.GetAuthZoneInfo(request.Question[0].Name);
            if ((authZoneInfo is null) || authZoneInfo.Disabled || authZoneInfo.IsExpired)
            {
                if (log is not null)
                    log.Write(remoteEP, protocol, "DNS Server refused a zone transfer request due to zone not found, zone disabled, or zone expired reasons for zone: " + (authZoneInfo.Name == "" ? "<root>" : authZoneInfo.Name));

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };
            }

            switch (authZoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Secondary:
                    break;

                default:
                    if (log is not null)
                        log.Write(remoteEP, protocol, "DNS Server refused a zone transfer request since the DNS server is not authoritative for zone: " + (authZoneInfo.Name == "" ? "<root>" : authZoneInfo.Name));

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };
            }

            bool isZoneTransferAllowed = false;

            switch (authZoneInfo.ZoneTransfer)
            {
                case AuthZoneTransfer.Allow:
                    isZoneTransferAllowed = true;
                    break;

                case AuthZoneTransfer.AllowOnlyZoneNameServers:
                    {
                        IPAddress remoteAddress = remoteEP.Address;

                        if (IPAddress.IsLoopback(remoteAddress))
                        {
                            isZoneTransferAllowed = true;
                            break;
                        }

                        IReadOnlyList<NameServerAddress> secondaryNameServers = await authZoneInfo.GetSecondaryNameServerAddressesAsync(this);

                        foreach (NameServerAddress secondaryNameServer in secondaryNameServers)
                        {
                            if (secondaryNameServer.IPEndPoint.Address.Equals(remoteAddress))
                            {
                                isZoneTransferAllowed = true;
                                break;
                            }
                        }
                    }
                    break;

                case AuthZoneTransfer.AllowOnlySpecifiedNameServers:
                    {
                        IPAddress remoteAddress = remoteEP.Address;

                        if (IPAddress.IsLoopback(remoteAddress))
                        {
                            isZoneTransferAllowed = true;
                            break;
                        }

                        IReadOnlyCollection<IPAddress> specifiedNameServers = authZoneInfo.ZoneTransferNameServers;
                        if (specifiedNameServers is not null)
                        {
                            foreach (IPAddress specifiedNameServer in specifiedNameServers)
                            {
                                if (specifiedNameServer.Equals(remoteAddress))
                                {
                                    isZoneTransferAllowed = true;
                                    break;
                                }
                            }
                        }
                    }
                    break;
            }

            if (!isZoneTransferAllowed)
            {
                if (log is not null)
                    log.Write(remoteEP, protocol, "DNS Server refused a zone transfer request since the request IP address is not allowed by the zone: " + (authZoneInfo.Name == "" ? "<root>" : authZoneInfo.Name));

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };
            }

            if ((authZoneInfo.TsigKeyNames is not null) && (authZoneInfo.TsigKeyNames.Count > 0))
            {
                if ((tsigAuthenticatedKeyName is null) || !authZoneInfo.TsigKeyNames.ContainsKey(tsigAuthenticatedKeyName.ToLower()))
                {
                    if (log is not null)
                        log.Write(remoteEP, protocol, "DNS Server refused a zone transfer request since the request is missing TSIG auth required by the zone: " + (authZoneInfo.Name == "" ? "<root>" : authZoneInfo.Name));

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };
                }
            }

            if (log is not null)
                log.Write(remoteEP, protocol, "DNS Server received zone transfer request for zone: " + (authZoneInfo.Name == "" ? "<root>" : authZoneInfo.Name));

            IReadOnlyList<DnsResourceRecord> xfrRecords;

            if (request.Question[0].Type == DnsResourceRecordType.IXFR)
            {
                if ((request.Authority.Count == 1) && (request.Authority[0].Type == DnsResourceRecordType.SOA))
                    xfrRecords = _authZoneManager.QueryIncrementalZoneTransferRecords(request.Question[0].Name, request.Authority[0]);
                else
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };
            }
            else
            {
                xfrRecords = _authZoneManager.QueryZoneTransferRecords(request.Question[0].Name);
            }

            DnsDatagram xfrResponse = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, xfrRecords) { Tag = DnsServerResponseType.Authoritative };
            xfrResponse = xfrResponse.Split();

            return xfrResponse;
        }

        private async Task<DnsDatagram> ProcessAuthoritativeQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers)
        {
            DnsDatagram response = null;

            if (!skipDnsAppAuthoritativeRequestHandlers)
            {
                foreach (IDnsAuthoritativeRequestHandler requestHandler in _dnsApplicationManager.DnsAuthoritativeRequestHandlers)
                {
                    response = await requestHandler.ProcessRequestAsync(request, remoteEP, protocol, isRecursionAllowed);
                    if (response is not null)
                    {
                        if (response.Tag is null)
                            response.Tag = DnsServerResponseType.Authoritative;

                        break;
                    }
                }
            }

            if (response is null)
            {
                response = _authZoneManager.Query(request, isRecursionAllowed);
                if (response is null)
                    return null;

                response.Tag = DnsServerResponseType.Authoritative;
            }

            bool reprocessResponse;
            do
            {
                reprocessResponse = false;

                if (response.RCODE == DnsResponseCode.NoError)
                {
                    if (response.Answer.Count > 0)
                    {
                        DnsResourceRecordType questionType = request.Question[0].Type;
                        DnsResourceRecord lastRR = response.Answer[response.Answer.Count - 1];

                        if ((lastRR.Type != questionType) && (questionType != DnsResourceRecordType.ANY))
                        {
                            switch (lastRR.Type)
                            {
                                case DnsResourceRecordType.CNAME:
                                    return await ProcessCNAMEAsync(request, remoteEP, response, isRecursionAllowed, protocol, false);

                                case DnsResourceRecordType.ANAME:
                                    return await ProcessANAMEAsync(request, remoteEP, response, isRecursionAllowed, protocol);
                            }
                        }
                    }
                    else if (response.Authority.Count > 0)
                    {
                        switch (response.Authority[0].Type)
                        {
                            case DnsResourceRecordType.NS:
                                if (request.RecursionDesired && isRecursionAllowed)
                                {
                                    //do forced recursive resolution using empty forwarders; name servers will be provided via ResolverDnsCache
                                    return await ProcessRecursiveQueryAsync(request, remoteEP, protocol, Array.Empty<NameServerAddress>(), false);
                                }

                                break;

                            case DnsResourceRecordType.FWD:
                                if ((response.Authority.Count == 1) && (response.Authority[0].RDATA as DnsForwarderRecord).Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                                {
                                    //do conditional forwarding via "this-server" 
                                    return await ProcessRecursiveQueryAsync(request, remoteEP, protocol, null, false);
                                }
                                else
                                {
                                    //do conditional forwarding
                                    List<NameServerAddress> forwarders = new List<NameServerAddress>(response.Authority.Count);

                                    foreach (DnsResourceRecord rr in response.Authority)
                                    {
                                        if (rr.Type == DnsResourceRecordType.FWD)
                                        {
                                            DnsForwarderRecord fwd = rr.RDATA as DnsForwarderRecord;

                                            if (!fwd.Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                                                forwarders.Add(fwd.NameServer);
                                        }
                                    }

                                    return await ProcessRecursiveQueryAsync(request, remoteEP, protocol, forwarders, false);
                                }

                            case DnsResourceRecordType.APP:
                                response = await ProcessAPPAsync(request, remoteEP, response, isRecursionAllowed, protocol);
                                reprocessResponse = true;
                                break;
                        }
                    }
                }
            }
            while (reprocessResponse);

            return response;
        }

        private async Task<DnsDatagram> ProcessAPPAsync(DnsDatagram request, IPEndPoint remoteEP, DnsDatagram response, bool isRecursionAllowed, DnsTransportProtocol protocol)
        {
            DnsResourceRecord appResourceRecord = response.Authority[0];
            DnsApplicationRecord appRecord = appResourceRecord.RDATA as DnsApplicationRecord;

            if (_dnsApplicationManager.Applications.TryGetValue(appRecord.AppName, out DnsApplication application))
            {
                if (application.DnsAppRecordRequestHandlers.TryGetValue(appRecord.ClassPath, out IDnsAppRecordRequestHandler appRecordRequestHandler))
                {
                    AuthZoneInfo zoneInfo = _authZoneManager.GetAuthZoneInfo(appResourceRecord.Name);

                    DnsDatagram appResponse = await appRecordRequestHandler.ProcessRequestAsync(request, remoteEP, protocol, isRecursionAllowed, zoneInfo.Name, appResourceRecord.TtlValue, appRecord.Data);
                    if (appResponse is null)
                    {
                        //return no error response with SOA
                        IReadOnlyList<DnsResourceRecord> authority = zoneInfo.GetRecords(DnsResourceRecordType.SOA);

                        return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, null, authority) { Tag = DnsServerResponseType.Authoritative };
                    }
                    else
                    {
                        if (appResponse.AuthoritativeAnswer)
                            appResponse.Tag = DnsServerResponseType.Authoritative;

                        return appResponse; //return app response
                    }
                }
                else
                {
                    LogManager log = _log;
                    if (log is not null)
                        log.Write(remoteEP, protocol, "DNS request handler '" + appRecord.ClassPath + "' was not found in the application '" + appRecord.AppName + "': " + appResourceRecord.Name);
                }
            }
            else
            {
                LogManager log = _log;
                if (log is not null)
                    log.Write(remoteEP, protocol, "DNS application '" + appRecord.AppName + "' was not found: " + appResourceRecord.Name);
            }

            //return server failure response with SOA
            {
                AuthZoneInfo zoneInfo = _authZoneManager.GetAuthZoneInfo(request.Question[0].Name);
                IReadOnlyList<DnsResourceRecord> authority = zoneInfo.GetRecords(DnsResourceRecordType.SOA);

                return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.ServerFailure, request.Question, null, authority) { Tag = DnsServerResponseType.Authoritative };
            }
        }

        private async Task<DnsDatagram> ProcessCNAMEAsync(DnsDatagram request, IPEndPoint remoteEP, DnsDatagram response, bool isRecursionAllowed, DnsTransportProtocol protocol, bool cacheRefreshOperation)
        {
            List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
            responseAnswer.AddRange(response.Answer);

            DnsDatagram lastResponse = response;
            bool isAuthoritativeAnswer = response.AuthoritativeAnswer;
            string lastDomain = (response.Answer[response.Answer.Count - 1].RDATA as DnsCNAMERecord).Domain;
            DnsDatagram newResponse;

            int queryCount = 0;
            do
            {
                DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(lastDomain, request.Question[0].Type, request.Question[0].Class) });

                //query authoritative zone first
                newResponse = _authZoneManager.Query(newRequest, isRecursionAllowed);
                if (newResponse is null)
                {
                    //not found in auth zone
                    if (newRequest.RecursionDesired && isRecursionAllowed)
                    {
                        //do recursion
                        newResponse = await RecursiveResolveAsync(newRequest, null, false, cacheRefreshOperation);
                        isAuthoritativeAnswer = false;
                    }
                    else
                    {
                        //break since no recursion allowed/desired
                        break;
                    }
                }
                else if ((newResponse.Answer.Count > 0) && (newResponse.Answer[newResponse.Answer.Count - 1].Type == DnsResourceRecordType.ANAME))
                {
                    newResponse = await ProcessANAMEAsync(request, remoteEP, newResponse, isRecursionAllowed, protocol);
                }
                else if ((newResponse.Answer.Count == 0) && (newResponse.Authority.Count > 0))
                {
                    //found delegated/forwarded zone
                    switch (newResponse.Authority[0].Type)
                    {
                        case DnsResourceRecordType.NS:
                            if (newRequest.RecursionDesired && isRecursionAllowed)
                            {
                                //do forced recursive resolution using empty forwarders; name servers will be provided via ResolveDnsCache
                                newResponse = await RecursiveResolveAsync(newRequest, Array.Empty<NameServerAddress>(), false, false);
                                isAuthoritativeAnswer = false;
                            }

                            break;

                        case DnsResourceRecordType.FWD:
                            if ((newResponse.Authority.Count == 1) && (newResponse.Authority[0].RDATA as DnsForwarderRecord).Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                            {
                                //do conditional forwarding via "this-server" 
                                newResponse = await RecursiveResolveAsync(newRequest, null, false, false);
                                isAuthoritativeAnswer = false;
                            }
                            else
                            {
                                //do conditional forwarding
                                List<NameServerAddress> forwarders = new List<NameServerAddress>(newResponse.Authority.Count);

                                foreach (DnsResourceRecord rr in newResponse.Authority)
                                {
                                    if (rr.Type == DnsResourceRecordType.FWD)
                                    {
                                        DnsForwarderRecord fwd = rr.RDATA as DnsForwarderRecord;

                                        if (!fwd.Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                                            forwarders.Add(fwd.NameServer);
                                    }
                                }

                                if (forwarders.Count < 1)
                                    forwarders = null;

                                newResponse = await RecursiveResolveAsync(newRequest, forwarders, false, false);
                                isAuthoritativeAnswer = false;
                            }

                            break;

                        case DnsResourceRecordType.APP:
                            newResponse = await ProcessAPPAsync(newRequest, remoteEP, newResponse, isRecursionAllowed, protocol);
                            break;
                    }
                }

                //check last response
                if (newResponse.Answer.Count == 0)
                    break; //cannot proceed to resolve further

                responseAnswer.AddRange(newResponse.Answer);

                DnsResourceRecord lastRR = newResponse.Answer[newResponse.Answer.Count - 1];

                if (lastRR.Type != DnsResourceRecordType.CNAME)
                    break; //cname was resolved

                lastResponse = newResponse;
                lastDomain = (lastRR.RDATA as DnsCNAMERecord).Domain;
            }
            while (++queryCount < MAX_CNAME_HOPS);

            DnsResponseCode rcode;
            IReadOnlyList<DnsResourceRecord> authority = null;
            IReadOnlyList<DnsResourceRecord> additional = null;

            if (newResponse is null)
            {
                //no recursion available
                rcode = DnsResponseCode.NoError;

                authority = lastResponse.Authority;
                additional = lastResponse.Additional;
            }
            else
            {
                rcode = newResponse.RCODE;

                if (isAuthoritativeAnswer)
                {
                    authority = newResponse.Authority;
                    additional = newResponse.Additional;
                }
                else
                {
                    if (newResponse.Authority.Count > 0)
                    {
                        if (newResponse.Authority[0].Type == DnsResourceRecordType.SOA)
                            authority = newResponse.Authority;
                    }
                    else
                    {
                        switch (request.Question[0].Type)
                        {
                            case DnsResourceRecordType.NS:
                            case DnsResourceRecordType.MX:
                            case DnsResourceRecordType.SRV:
                                additional = newResponse.Additional;
                                break;
                        }
                    }
                }
            }

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, isAuthoritativeAnswer, false, request.RecursionDesired, isRecursionAllowed, false, false, rcode, request.Question, responseAnswer, authority, additional) { Tag = response.Tag };
        }

        private async Task<DnsDatagram> ProcessANAMEAsync(DnsDatagram request, IPEndPoint remoteEP, DnsDatagram response, bool isRecursionAllowed, DnsTransportProtocol protocol)
        {
            Queue<Task<IReadOnlyList<DnsResourceRecord>>> resolveQueue = new Queue<Task<IReadOnlyList<DnsResourceRecord>>>();

            async Task<IReadOnlyList<DnsResourceRecord>> ResolveANAMEAsync(DnsResourceRecord anameRR, int queryCount = 0)
            {
                string lastDomain = (anameRR.RDATA as DnsANAMERecord).Domain;

                do
                {
                    DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(lastDomain, request.Question[0].Type, request.Question[0].Class) });

                    //query authoritative zone first
                    DnsDatagram newResponse = _authZoneManager.Query(newRequest, isRecursionAllowed);
                    if (newResponse is null)
                    {
                        //not found in auth zone; do recursion
                        newResponse = await RecursiveResolveAsync(newRequest, null, false, false);
                    }
                    else if ((newResponse.Answer.Count == 0) && (newResponse.Authority.Count > 0))
                    {
                        //found delegated/forwarded zone
                        switch (newResponse.Authority[0].Type)
                        {
                            case DnsResourceRecordType.NS:
                                //do forced recursive resolution using empty forwarders; name servers will be provided via ResolverDnsCache
                                newResponse = await RecursiveResolveAsync(newRequest, Array.Empty<NameServerAddress>(), false, false);
                                break;

                            case DnsResourceRecordType.FWD:
                                if ((newResponse.Authority.Count == 1) && (newResponse.Authority[0].RDATA as DnsForwarderRecord).Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                                {
                                    //do conditional forwarding via "this-server" 
                                    newResponse = await RecursiveResolveAsync(newRequest, null, false, false);
                                }
                                else
                                {
                                    //do conditional forwarding
                                    List<NameServerAddress> forwarders = new List<NameServerAddress>(newResponse.Authority.Count);

                                    foreach (DnsResourceRecord rr in newResponse.Authority)
                                    {
                                        if (rr.Type == DnsResourceRecordType.FWD)
                                        {
                                            DnsForwarderRecord fwd = rr.RDATA as DnsForwarderRecord;

                                            if (!fwd.Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                                                forwarders.Add(fwd.NameServer);
                                        }
                                    }

                                    if (forwarders.Count < 1)
                                        forwarders = null;

                                    newResponse = await RecursiveResolveAsync(newRequest, forwarders, false, false);
                                }

                                break;

                            case DnsResourceRecordType.APP:
                                newResponse = await ProcessAPPAsync(newRequest, remoteEP, newResponse, isRecursionAllowed, protocol);
                                break;
                        }
                    }

                    //check new response
                    if (newResponse.Answer.Count == 0)
                        return Array.Empty<DnsResourceRecord>(); //cannot proceed to resolve further

                    DnsResourceRecordType questionType = request.Question[0].Type;
                    DnsResourceRecord lastRR = newResponse.Answer[newResponse.Answer.Count - 1];
                    if (lastRR.Type == questionType)
                    {
                        //found final answer
                        List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                        foreach (DnsResourceRecord answer in newResponse.Answer)
                        {
                            if (answer.Type != questionType)
                                continue;

                            if (anameRR.TtlValue < answer.TtlValue)
                                answers.Add(new DnsResourceRecord(anameRR.Name, answer.Type, answer.Class, anameRR.TtlValue, answer.RDATA));
                            else
                                answers.Add(new DnsResourceRecord(anameRR.Name, answer.Type, answer.Class, answer.TtlValue, answer.RDATA));
                        }

                        return answers;
                    }

                    if (lastRR.Type == DnsResourceRecordType.ANAME)
                    {
                        if (newResponse.Answer.Count == 1)
                        {
                            lastDomain = (lastRR.RDATA as DnsANAMERecord).Domain;
                        }
                        else
                        {
                            //resolve multiple ANAME records async
                            queryCount++; //increment since one query was done already

                            foreach (DnsResourceRecord newAnswer in newResponse.Answer)
                                resolveQueue.Enqueue(ResolveANAMEAsync(newAnswer, queryCount));

                            return Array.Empty<DnsResourceRecord>();
                        }
                    }
                    else if (lastRR.Type == DnsResourceRecordType.CNAME)
                    {
                        lastDomain = (lastRR.RDATA as DnsCNAMERecord).Domain;
                    }
                    else
                    {
                        //aname/cname was resolved, but no answer found
                        return Array.Empty<DnsResourceRecord>();
                    }
                }
                while (++queryCount < MAX_CNAME_HOPS);

                //max hops limit crossed
                return Array.Empty<DnsResourceRecord>();
            }

            List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord answer in response.Answer)
            {
                if (answer.Type == DnsResourceRecordType.ANAME)
                {
                    resolveQueue.Enqueue(ResolveANAMEAsync(answer));
                }
                else
                {
                    if (resolveQueue.Count == 0)
                        responseAnswer.Add(answer);
                }
            }

            while (resolveQueue.Count > 0)
                responseAnswer.AddRange(await resolveQueue.Dequeue());

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, responseAnswer.Count > 0 ? DnsResponseCode.NoError : DnsResponseCode.ServerFailure, request.Question, responseAnswer, response.Authority, response.Additional) { Tag = response.Tag };
        }

        private DnsDatagram ProcessBlockedQuery(DnsDatagram request)
        {
            DnsDatagram response = null;

            if (_blockedZoneManager.TotalZonesBlocked > 0)
                response = _blockedZoneManager.Query(request);

            if (response is null)
            {
                //domain not blocked in blocked zone
                if (_blockListZoneManager.TotalZonesBlocked > 0)
                {
                    response = _blockListZoneManager.Query(request); //check in block list zone
                    if (response is not null)
                    {
                        //domain is blocked in block list zone
                        response.Tag = DnsServerResponseType.Blocked;
                        return response;
                    }
                }

                //domain not blocked in block list zone
                return null;
            }
            else
            {
                //domain is blocked in blocked zone
                DnsQuestionRecord question = request.Question[0];

                if (_allowTxtBlockingReport && (question.Type == DnsResourceRecordType.TXT))
                {
                    //return meta data
                    string blockedDomain;

                    if ((response.Authority.Count > 0) && (response.Authority[0].Type == DnsResourceRecordType.SOA))
                        blockedDomain = response.Authority[0].Name;
                    else
                        blockedDomain = question.Name;

                    IReadOnlyList<DnsResourceRecord> answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("source=blocked-zone; domain=" + blockedDomain)) };

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answer) { Tag = DnsServerResponseType.Blocked };
                }
                else
                {
                    IReadOnlyCollection<DnsARecord> aRecords;
                    IReadOnlyCollection<DnsAAAARecord> aaaaRecords;

                    switch (_blockingType)
                    {
                        case DnsServerBlockingType.AnyAddress:
                            aRecords = _aRecords;
                            aaaaRecords = _aaaaRecords;
                            break;

                        case DnsServerBlockingType.CustomAddress:
                            aRecords = _customBlockingARecords;
                            aaaaRecords = _customBlockingAAAARecords;
                            break;

                        case DnsServerBlockingType.NxDomain:
                            string blockedDomain;

                            if ((response.Authority.Count > 0) && (response.Authority[0].Type == DnsResourceRecordType.SOA))
                                blockedDomain = response.Authority[0].Name;
                            else
                                blockedDomain = question.Name;

                            string parentDomain = BlockListZoneManager.GetParentZone(blockedDomain);
                            if (parentDomain is null)
                                parentDomain = string.Empty;

                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NxDomain, request.Question, null, new DnsResourceRecord[] { new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, 60, _blockedZoneManager.DnsSOARecord) }) { Tag = DnsServerResponseType.Blocked };

                        default:
                            throw new InvalidOperationException();
                    }

                    IReadOnlyList<DnsResourceRecord> answer = null;
                    IReadOnlyList<DnsResourceRecord> authority = null;

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.A:
                            {
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(aRecords.Count);

                                foreach (DnsARecord record in aRecords)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, 60, record));

                                answer = rrList;
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            {
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(aaaaRecords.Count);

                                foreach (DnsAAAARecord record in aaaaRecords)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, 60, record));

                                answer = rrList;
                            }
                            break;

                        case DnsResourceRecordType.NS:
                            answer = response.Answer;
                            authority = response.Authority;
                            break;

                        default:
                            authority = response.Authority;
                            break;
                    }

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answer, authority) { Tag = DnsServerResponseType.Blocked };
                }
            }
        }

        private async Task<DnsDatagram> ProcessRecursiveQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, IReadOnlyList<NameServerAddress> viaForwarders, bool cacheRefreshOperation)
        {
            bool inAllowedZone;

            if (cacheRefreshOperation)
            {
                //cache refresh operation should be able to refresh all the records in cache
                //this is since a blocked CNAME record could still be used by an allowed domain name and so must resolve
                inAllowedZone = true;
            }
            else if (!_enableBlocking)
            {
                inAllowedZone = true;
            }
            else
            {
                inAllowedZone = (_allowedZoneManager.TotalZonesAllowed > 0) && (_allowedZoneManager.Query(request) is not null);
                if (!inAllowedZone)
                {
                    //check in blocked zone and block list zone
                    DnsDatagram blockedResponse = ProcessBlockedQuery(request);
                    if (blockedResponse is not null)
                        return blockedResponse;
                }
            }

            DnsDatagram response = await RecursiveResolveAsync(request, viaForwarders, false, cacheRefreshOperation);

            if (response.Answer.Count > 0)
            {
                DnsResourceRecordType questionType = request.Question[0].Type;
                DnsResourceRecord lastRR = response.Answer[response.Answer.Count - 1];

                if ((lastRR.Type != questionType) && (lastRR.Type == DnsResourceRecordType.CNAME) && (questionType != DnsResourceRecordType.ANY))
                    response = await ProcessCNAMEAsync(request, remoteEP, response, true, protocol, cacheRefreshOperation);

                if (!inAllowedZone)
                {
                    //check for CNAME cloaking
                    for (int i = 0; i < response.Answer.Count; i++)
                    {
                        DnsResourceRecord record = response.Answer[i];

                        if (record.Type != DnsResourceRecordType.CNAME)
                            break; //no further CNAME records exists

                        DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord((record.RDATA as DnsCNAMERecord).Domain, request.Question[0].Type, request.Question[0].Class) });

                        //check allowed zone
                        inAllowedZone = (_allowedZoneManager.TotalZonesAllowed > 0) && (_allowedZoneManager.Query(newRequest) is not null);
                        if (inAllowedZone)
                            break; //CNAME is in allowed zone

                        //check blocked zone and block list zone
                        DnsDatagram lastResponse = ProcessBlockedQuery(newRequest);
                        if (lastResponse is not null)
                        {
                            //found cname cloaking
                            List<DnsResourceRecord> answer = new List<DnsResourceRecord>();

                            //copy current and previous CNAME records
                            for (int j = 0; j <= i; j++)
                                answer.Add(response.Answer[j]);

                            //copy last response answers
                            answer.AddRange(lastResponse.Answer);

                            IReadOnlyList<DnsResourceRecord> authority = null;
                            IReadOnlyList<DnsResourceRecord> additional = null;

                            if (lastResponse.Authority.Count > 0)
                            {
                                if (lastResponse.Authority[0].Type == DnsResourceRecordType.SOA)
                                    authority = lastResponse.Authority;
                            }
                            else
                            {
                                switch (questionType)
                                {
                                    case DnsResourceRecordType.NS:
                                    case DnsResourceRecordType.MX:
                                    case DnsResourceRecordType.SRV:
                                        additional = lastResponse.Additional;
                                        break;
                                }
                            }

                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.NoError, request.Question, answer, authority, additional) { Tag = lastResponse.Tag };
                        }
                    }
                }
            }

            //return response
            {
                IReadOnlyList<DnsResourceRecord> authority = null;
                IReadOnlyList<DnsResourceRecord> additional = null;

                if (response.Authority.Count > 0)
                {
                    if (response.Authority[0].Type == DnsResourceRecordType.SOA)
                        authority = response.Authority;
                }
                else
                {
                    switch (request.Question[0].Type)
                    {
                        case DnsResourceRecordType.NS:
                        case DnsResourceRecordType.MX:
                        case DnsResourceRecordType.SRV:
                            additional = response.Additional;
                            break;
                    }
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, response.RCODE, request.Question, response.Answer, authority, additional) { Tag = response.Tag };
            }
        }

        private async Task<DnsDatagram> RecursiveResolveAsync(DnsDatagram request, IReadOnlyList<NameServerAddress> viaForwarders, bool cachePrefetchOperation, bool cacheRefreshOperation)
        {
            if (!cachePrefetchOperation && !cacheRefreshOperation)
            {
                //query cache zone to see if answer available
                DnsDatagram cacheResponse = QueryCache(request, false);
                if (cacheResponse is not null)
                {
                    if (_cachePrefetchTrigger > 0)
                    {
                        //inspect response TTL values to decide if prefetch trigger is needed
                        foreach (DnsResourceRecord answer in cacheResponse.Answer)
                        {
                            if ((answer.OriginalTtlValue >= _cachePrefetchEligibility) && (answer.TtlValue <= _cachePrefetchTrigger))
                            {
                                //trigger prefetch async
                                _ = PrefetchCacheAsync(request, viaForwarders);
                                break;
                            }
                        }
                    }

                    return cacheResponse;
                }
            }

            //recursion with locking
            TaskCompletionSource<DnsDatagram> resolverTaskCompletionSource = new TaskCompletionSource<DnsDatagram>();
            Task<DnsDatagram> resolverTask = _resolverTasks.GetOrAdd(GetResolverQueryKey(request.Question[0]), resolverTaskCompletionSource.Task);

            if (resolverTask.Equals(resolverTaskCompletionSource.Task))
            {
                //got new resolver task added so question is not being resolved; do recursive resolution in another task on resolver thread pool
                _ = Task.Factory.StartNew(delegate ()
                {
                    return RecursiveResolveAsync(request, viaForwarders, cachePrefetchOperation, cacheRefreshOperation, resolverTaskCompletionSource);
                }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _resolverTaskScheduler);
            }

            //request is being recursively resolved by another thread

            if (cachePrefetchOperation)
                return null; //return null as prefetch worker thread does not need valid response and thus does not need to wait

            DateTime resolverWaitStartTime = DateTime.UtcNow;

            //wait till short timeout for response
            if (await Task.WhenAny(resolverTask, Task.Delay(SERVE_STALE_WAIT_TIME)) == resolverTask) //1.8 sec wait as per draft-ietf-dnsop-serve-stale-04
            {
                //resolver signaled
                DnsDatagram response = await resolverTask;

                if (response is not null)
                    return response;

                //resolver had exception and no stale record was found
            }
            else
            {
                //wait timed out

                if (_serveStale)
                {
                    //query cache zone to return stale answer (if available) as per draft-ietf-dnsop-serve-stale-04
                    DnsDatagram staleResponse = QueryCache(request, true);
                    if (staleResponse is not null)
                        return staleResponse;
                }

                //wait till full timeout before responding as ServerFailure
                int timeout = Convert.ToInt32(_clientTimeout - (DateTime.UtcNow - resolverWaitStartTime).TotalMilliseconds);
                if (timeout > 0)
                {
                    if (await Task.WhenAny(resolverTask, Task.Delay(timeout)) == resolverTask)
                    {
                        //resolver signaled
                        DnsDatagram response = await resolverTask;

                        if (response is not null)
                            return response;
                    }

                    //no response available from resolver or resolver had exception and no stale record was found
                }
            }

            //no response available; respond with ServerFailure
            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.ServerFailure, request.Question);
        }

        private async Task RecursiveResolveAsync(DnsDatagram request, IReadOnlyList<NameServerAddress> viaForwarders, bool cachePrefetchOperation, bool cacheRefreshOperation, TaskCompletionSource<DnsDatagram> taskCompletionSource)
        {
            IReadOnlyList<NameServerAddress> forwarders;

            if (viaForwarders is null)
                forwarders = _forwarders; //use default forwarders
            else
                forwarders = viaForwarders; //use provided forwarders

            DnsQuestionRecord question = request.Question[0];

            try
            {
                DnsDatagram response;

                if ((forwarders is not null) && (forwarders.Count > 0))
                {
                    //use forwarders
                    if (_proxy is null)
                    {
                        //recursive resolve name server when proxy is null else let proxy resolve it
                        foreach (NameServerAddress nameServerAddress in forwarders)
                        {
                            if (nameServerAddress.IsIPEndPointStale) //refresh forwarder IPEndPoint if stale
                                await nameServerAddress.RecursiveResolveIPAddressAsync(_dnsCache, null, _preferIPv6, _randomizeName, _qnameMinimization, _resolverRetries, _resolverTimeout);
                        }
                    }

                    //query forwarders and update cache
                    DnsClient dnsClient = new DnsClient(forwarders);

                    dnsClient.Proxy = _proxy;
                    dnsClient.PreferIPv6 = _preferIPv6;
                    dnsClient.RandomizeName = _randomizeName;
                    dnsClient.Retries = _forwarderRetries;
                    dnsClient.Timeout = _forwarderTimeout;
                    dnsClient.Concurrency = _forwarderConcurrency;

                    response = await dnsClient.ResolveAsync(question);

                    if (viaForwarders is not null)
                        response = SanitizeConditionalForwarderResponseAnswer(response);

                    response = SanitizeForwarderResponseAuthority(response);

                    _cacheZoneManager.CacheResponse(response);
                }
                else
                {
                    //recursive resolve and update cache
                    IDnsCache dnsCache;

                    if (cachePrefetchOperation || cacheRefreshOperation)
                        dnsCache = new ResolverPrefetchDnsCache(_dnsApplicationManager, _authZoneManager, _cacheZoneManager, question);
                    else
                        dnsCache = _dnsCache;

                    response = await DnsClient.RecursiveResolveAsync(question, dnsCache, _proxy, _preferIPv6, _randomizeName, _qnameMinimization, _nsRevalidation, _resolverRetries, _resolverTimeout, _resolverMaxStackCount);
                }

                switch (response.RCODE)
                {
                    case DnsResponseCode.NoError:
                    case DnsResponseCode.NxDomain:
                    case DnsResponseCode.YXDomain:
                        taskCompletionSource.SetResult(response);
                        break;

                    default:
                        throw new DnsServerException("DNS Server received a response with RCODE=" + response.RCODE.ToString() + " from: " + response.Metadata.NameServer);
                }
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log is not null)
                {
                    string strForwarders = null;

                    if (forwarders is not null)
                    {
                        foreach (NameServerAddress nameServer in forwarders)
                        {
                            if (strForwarders is null)
                                strForwarders = nameServer.ToString();
                            else
                                strForwarders += ", " + nameServer.ToString();
                        }
                    }

                    log.Write("DNS Server failed to resolve the request with QNAME: " + question.Name + "; QTYPE: " + question.Type.ToString() + "; QCLASS: " + question.Class.ToString() + (strForwarders is null ? "" : "; Forwarders: " + strForwarders) + ";\r\n" + ex.ToString());
                }

                if (_serveStale)
                {
                    //fetch stale record
                    DnsDatagram staleResponse = QueryCache(request, true);
                    if (staleResponse is null)
                    {
                        //no stale record was found; signal null response to release waiting tasks
                        taskCompletionSource.SetResult(null);
                    }
                    else
                    {
                        //signal stale response
                        taskCompletionSource.SetResult(staleResponse);
                    }
                }
                else
                {
                    //signal null response to release waiting tasks
                    taskCompletionSource.SetResult(null);
                }
            }
            finally
            {
                _resolverTasks.TryRemove(GetResolverQueryKey(question), out _);
            }
        }

        private static DnsDatagram SanitizeConditionalForwarderResponseAnswer(DnsDatagram response)
        {
            string qName = response.Question[0].Name;

            for (int i = 0; i < response.Answer.Count; i++)
            {
                DnsResourceRecord answer = response.Answer[i];

                if (answer.Name.Equals(qName, StringComparison.OrdinalIgnoreCase))
                {
                    switch (answer.Type)
                    {
                        case DnsResourceRecordType.CNAME:
                            if (i < response.Answer.Count - 1)
                            {
                                //do not follow CNAME for conditional forwarder response
                                //truncate answer upto current RR
                                List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(i + 1);

                                for (int j = 0; j <= i; j++)
                                    newAnswers.Add(response.Answer[j]);

                                return response.Clone(newAnswers, null);
                            }
                            break;
                    }
                }
                else if ((answer.Type == DnsResourceRecordType.DNAME) && qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                {
                    //found DNAME, continue next
                }
                else
                {
                    //name mismatch
                    //truncate answer upto previous RR

                    List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(i);

                    for (int j = 0; j < i; j++)
                        newAnswers.Add(response.Answer[j]);

                    return response.Clone(newAnswers, null);
                }
            }

            return response;
        }

        private static DnsDatagram SanitizeForwarderResponseAuthority(DnsDatagram response)
        {
            if ((response.Authority.Count > 0) && (response.Authority[0].Type != DnsResourceRecordType.SOA))
                return response.Clone(null, Array.Empty<DnsResourceRecord>());

            return response;
        }

        private static string GetResolverQueryKey(DnsQuestionRecord question)
        {
            if (string.IsNullOrEmpty(question.Name))
                return question.Type + "." + question.Class;

            return question.Name + "." + question.Type + "." + question.Class;
        }

        private DnsDatagram QueryCache(DnsDatagram request, bool serveStaleAndResetExpiry)
        {
            DnsDatagram cacheResponse = _cacheZoneManager.Query(request, serveStaleAndResetExpiry);
            if (cacheResponse is not null)
            {
                if ((cacheResponse.RCODE != DnsResponseCode.NoError) || (cacheResponse.Answer.Count > 0) || (cacheResponse.Authority.Count == 0) || (cacheResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                {
                    cacheResponse.Tag = DnsServerResponseType.Cached;

                    return cacheResponse;
                }
            }

            return null;
        }

        private async Task PrefetchCacheAsync(DnsDatagram request, IReadOnlyList<NameServerAddress> viaForwarders)
        {
            try
            {
                await RecursiveResolveAsync(request, viaForwarders, true, false);
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log is not null)
                    log.Write(ex);
            }
        }

        private async Task RefreshCacheAsync(IList<CacheRefreshSample> cacheRefreshSampleList, CacheRefreshSample sample, int sampleQuestionIndex)
        {
            try
            {
                //refresh cache
                DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { sample.SampleQuestion });
                DnsDatagram response = await ProcessRecursiveQueryAsync(request, IPENDPOINT_ANY_0, DnsTransportProtocol.Udp, sample.ViaForwarders, true);

                bool addBackToSampleList = false;
                DateTime utcNow = DateTime.UtcNow;

                foreach (DnsResourceRecord answer in response.Answer)
                {
                    if ((answer.OriginalTtlValue >= _cachePrefetchEligibility) && (utcNow.AddSeconds(answer.TtlValue) < _cachePrefetchSamplingTimerTriggersOn))
                    {
                        //answer expires before next sampling so add back to the list to allow refreshing it
                        addBackToSampleList = true;
                        break;
                    }
                }

                if (addBackToSampleList)
                    cacheRefreshSampleList[sampleQuestionIndex] = sample; //put back into sample list to allow refreshing it again
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log is not null)
                    log.Write(ex);

                cacheRefreshSampleList[sampleQuestionIndex] = sample; //put back into sample list to allow refreshing it again
            }
        }

        private DnsQuestionRecord GetCacheRefreshNeededQuery(DnsQuestionRecord question, int trigger)
        {
            int queryCount = 0;

            while (true)
            {
                DnsDatagram cacheResponse = QueryCache(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }), false);
                if (cacheResponse is null)
                    return question; //cache expired so refresh question

                if (cacheResponse.Answer.Count == 0)
                    return null; //dont refresh empty responses

                //inspect response TTL values to decide if refresh is needed
                foreach (DnsResourceRecord answer in cacheResponse.Answer)
                {
                    if ((answer.OriginalTtlValue >= _cachePrefetchEligibility) && (answer.TtlValue <= trigger))
                        return question; //TTL eligible and less than trigger so refresh question
                }

                DnsResourceRecord lastRR = cacheResponse.Answer[cacheResponse.Answer.Count - 1];

                if (lastRR.Type == question.Type)
                    return null; //answer was resolved

                if (lastRR.Type != DnsResourceRecordType.CNAME)
                    return null; //invalid response so ignore question

                queryCount++;
                if (queryCount >= MAX_CNAME_HOPS)
                    return null; //too many hops so ignore question

                //follow CNAME chain to inspect TTL further
                question = new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).Domain, question.Type, question.Class);
            }
        }

        private bool IsCacheRefreshNeeded(DnsQuestionRecord question, int trigger)
        {
            DnsDatagram cacheResponse = QueryCache(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }), false);
            if (cacheResponse is null)
                return true; //cache expired so refresh needed

            if (cacheResponse.Answer.Count == 0)
                return false; //dont refresh empty responses

            //inspect response TTL values to decide if refresh is needed
            foreach (DnsResourceRecord answer in cacheResponse.Answer)
            {
                if ((answer.OriginalTtlValue >= _cachePrefetchEligibility) && (answer.TtlValue <= trigger))
                    return true; //TTL eligible less than trigger so refresh
            }

            return false; //no need to refresh for this query
        }

        private void CachePrefetchSamplingTimerCallback(object state)
        {
            try
            {
                List<KeyValuePair<DnsQuestionRecord, int>> eligibleQueries = _stats.GetLastHourEligibleQueries(_cachePrefetchSampleEligibilityHitsPerHour);
                List<CacheRefreshSample> cacheRefreshSampleList = new List<CacheRefreshSample>(eligibleQueries.Count);
                int cacheRefreshTrigger = (_cachePrefetchSampleIntervalInMinutes + 1) * 60;

                foreach (KeyValuePair<DnsQuestionRecord, int> eligibleQuery in eligibleQueries)
                {
                    DnsQuestionRecord eligibleQuerySample = eligibleQuery.Key;

                    if (eligibleQuerySample.Type == DnsResourceRecordType.ANY)
                        continue; //dont refresh type ANY queries

                    DnsQuestionRecord refreshQuery = null;
                    IReadOnlyList<NameServerAddress> viaForwarders = null;

                    //query auth zone for refresh query
                    int queryCount = 0;
                    bool reQueryAuthZone;
                    do
                    {
                        reQueryAuthZone = false;

                        DnsDatagram response = _authZoneManager.Query(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { eligibleQuerySample }), true);
                        if (response is null)
                        {
                            //zone not hosted; do refresh
                            refreshQuery = GetCacheRefreshNeededQuery(eligibleQuerySample, cacheRefreshTrigger);
                        }
                        else
                        {
                            //zone is hosted; check further
                            if (response.Answer.Count > 0)
                            {
                                DnsResourceRecord lastRecord = response.Answer[response.Answer.Count - 1];

                                if ((lastRecord.Type == DnsResourceRecordType.CNAME) && (eligibleQuerySample.Type != DnsResourceRecordType.CNAME))
                                {
                                    eligibleQuerySample = new DnsQuestionRecord((lastRecord.RDATA as DnsCNAMERecord).Domain, eligibleQuerySample.Type, eligibleQuerySample.Class);
                                    reQueryAuthZone = true;
                                }
                            }
                            else if (response.Authority.Count > 0)
                            {
                                switch (response.Authority[0].Type)
                                {
                                    case DnsResourceRecordType.NS: //zone is delegated
                                        refreshQuery = GetCacheRefreshNeededQuery(eligibleQuerySample, cacheRefreshTrigger);
                                        viaForwarders = Array.Empty<NameServerAddress>(); //do forced recursive resolution using empty forwarders
                                        break;

                                    case DnsResourceRecordType.FWD: //zone is conditional forwarder
                                        refreshQuery = GetCacheRefreshNeededQuery(eligibleQuerySample, cacheRefreshTrigger);

                                        if ((response.Authority.Count == 1) && (response.Authority[0].RDATA as DnsForwarderRecord).Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                                        {
                                            //do conditional forwarding via "this-server"
                                        }
                                        else
                                        {
                                            //do conditional forwarding
                                            List<NameServerAddress> forwarders = new List<NameServerAddress>(response.Authority.Count);

                                            foreach (DnsResourceRecord rr in response.Authority)
                                            {
                                                if (rr.Type == DnsResourceRecordType.FWD)
                                                {
                                                    DnsForwarderRecord fwd = rr.RDATA as DnsForwarderRecord;

                                                    if (!fwd.Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                                                        forwarders.Add(fwd.NameServer);
                                                }
                                            }

                                            if (forwarders.Count > 0)
                                                viaForwarders = forwarders;
                                        }
                                        break;
                                }
                            }
                        }
                    }
                    while (reQueryAuthZone && (++queryCount < MAX_CNAME_HOPS));

                    if (refreshQuery is not null)
                        cacheRefreshSampleList.Add(new CacheRefreshSample(refreshQuery, viaForwarders));
                }

                _cacheRefreshSampleList = cacheRefreshSampleList;
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log is not null)
                    log.Write(ex);
            }
            finally
            {
                lock (_cachePrefetchSamplingTimerLock)
                {
                    if (_cachePrefetchSamplingTimer is not null)
                    {
                        _cachePrefetchSamplingTimer.Change(_cachePrefetchSampleIntervalInMinutes * 60 * 1000, Timeout.Infinite);
                        _cachePrefetchSamplingTimerTriggersOn = DateTime.UtcNow.AddMinutes(_cachePrefetchSampleIntervalInMinutes);
                    }
                }
            }
        }

        private void CachePrefetchRefreshTimerCallback(object state)
        {
            try
            {
                IList<CacheRefreshSample> cacheRefreshSampleList = _cacheRefreshSampleList;
                if (cacheRefreshSampleList is not null)
                {
                    for (int i = 0; i < cacheRefreshSampleList.Count; i++)
                    {
                        CacheRefreshSample sample = cacheRefreshSampleList[i];
                        if (sample is null)
                            continue;

                        if (!IsCacheRefreshNeeded(sample.SampleQuestion, _cachePrefetchTrigger + 1))
                            continue;

                        cacheRefreshSampleList[i] = null; //remove from sample list to avoid concurrent refresh attempt

                        int sampleQuestionIndex = i;
                        _ = Task.Run(delegate () { return RefreshCacheAsync(cacheRefreshSampleList, sample, sampleQuestionIndex); }); //run task in threadpool since its long running
                    }
                }
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log is not null)
                    log.Write(ex);
            }
            finally
            {
                lock (_cachePrefetchRefreshTimerLock)
                {
                    if (_cachePrefetchRefreshTimer is not null)
                        _cachePrefetchRefreshTimer.Change((_cachePrefetchTrigger + 1) * 1000, Timeout.Infinite);
                }
            }
        }

        private void CacheMaintenanceTimerCallback(object state)
        {
            try
            {
                _cacheZoneManager.RemoveExpiredRecords();
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log is not null)
                    log.Write(ex);
            }
            finally
            {
                lock (_cacheMaintenanceTimerLock)
                {
                    if (_cacheMaintenanceTimer is not null)
                        _cacheMaintenanceTimer.Change(CACHE_MAINTENANCE_TIMER_PERIODIC_INTERVAL, Timeout.Infinite);
                }
            }
        }

        private void ResetPrefetchTimers()
        {
            if ((_cachePrefetchTrigger == 0) || (_recursion == DnsServerRecursion.Deny))
            {
                lock (_cachePrefetchSamplingTimerLock)
                {
                    if (_cachePrefetchSamplingTimer is not null)
                        _cachePrefetchSamplingTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }

                lock (_cachePrefetchRefreshTimerLock)
                {
                    if (_cachePrefetchRefreshTimer is not null)
                        _cachePrefetchRefreshTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
            else if (_state == ServiceState.Running)
            {
                lock (_cachePrefetchSamplingTimerLock)
                {
                    if (_cachePrefetchSamplingTimer is not null)
                    {
                        _cachePrefetchSamplingTimer.Change(CACHE_PREFETCH_SAMPLING_TIMER_INITIAL_INTEVAL, Timeout.Infinite);
                        _cachePrefetchSamplingTimerTriggersOn = DateTime.UtcNow.AddMilliseconds(CACHE_PREFETCH_SAMPLING_TIMER_INITIAL_INTEVAL);
                    }
                }

                lock (_cachePrefetchRefreshTimerLock)
                {
                    if (_cachePrefetchRefreshTimer is not null)
                        _cachePrefetchRefreshTimer.Change(CACHE_PREFETCH_REFRESH_TIMER_INITIAL_INTEVAL, Timeout.Infinite);
                }
            }
        }

        private bool IsQpmLimitCrossed(IPEndPoint remoteEP)
        {
            if ((_qpmLimitRequests < 1) && (_qpmLimitErrors < 1))
                return false;

            IPAddress remoteIP = remoteEP.Address;

            if (IPAddress.IsLoopback(remoteIP))
                return false;

            IPAddress remoteSubnet;

            switch (remoteIP.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    remoteSubnet = remoteIP.GetNetworkAddress(_qpmLimitIPv4PrefixLength);
                    break;

                case AddressFamily.InterNetworkV6:
                    remoteSubnet = remoteIP.GetNetworkAddress(_qpmLimitIPv6PrefixLength);
                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            if ((_qpmLimitErrors > 0) && (_qpmLimitErrorClientSubnetStats is not null) && _qpmLimitErrorClientSubnetStats.TryGetValue(remoteSubnet, out int errorCountPerSample))
            {
                int averageErrorCountPerMinute = errorCountPerSample / _qpmLimitSampleMinutes;
                if (averageErrorCountPerMinute >= _qpmLimitErrors)
                    return true;
            }

            if ((_qpmLimitRequests > 0) && (_qpmLimitClientSubnetStats is not null) && _qpmLimitClientSubnetStats.TryGetValue(remoteSubnet, out int countPerSample))
            {
                int averageCountPerMinute = countPerSample / _qpmLimitSampleMinutes;
                if (averageCountPerMinute >= _qpmLimitRequests)
                    return true;
            }

            return false;
        }

        private void QpmLimitSamplingTimerCallback(object state)
        {
            try
            {
                _stats.GetLatestClientSubnetStats(_qpmLimitSampleMinutes, _qpmLimitIPv4PrefixLength, _qpmLimitIPv6PrefixLength, out _qpmLimitClientSubnetStats, out _qpmLimitErrorClientSubnetStats);
            }
            catch (Exception ex)
            {
                LogManager log = _log;
                if (log is not null)
                    log.Write(ex);
            }
            finally
            {
                lock (_qpmLimitSamplingTimerLock)
                {
                    if (_qpmLimitSamplingTimer is not null)
                        _qpmLimitSamplingTimer.Change(QPM_LIMIT_SAMPLING_TIMER_INTERVAL, Timeout.Infinite);
                }
            }
        }

        private void ResetQpsLimitTimer()
        {
            if ((_qpmLimitRequests < 1) && (_qpmLimitErrors < 1))
            {
                lock (_qpmLimitSamplingTimerLock)
                {
                    if (_qpmLimitSamplingTimer is not null)
                        _qpmLimitSamplingTimer.Change(Timeout.Infinite, Timeout.Infinite);

                    _qpmLimitClientSubnetStats = null;
                    _qpmLimitErrorClientSubnetStats = null;
                }
            }
            else if (_state == ServiceState.Running)
            {
                lock (_qpmLimitSamplingTimerLock)
                {
                    if (_qpmLimitSamplingTimer is not null)
                        _qpmLimitSamplingTimer.Change(0, Timeout.Infinite);
                }
            }
        }

        private void UpdateThisServer()
        {
            if ((_localEndPoints is null) || (_localEndPoints.Count == 0))
            {
                _thisServer = new NameServerAddress(_serverDomain, IPAddress.Loopback);
            }
            else
            {
                foreach (IPEndPoint localEndPoint in _localEndPoints)
                {
                    if (localEndPoint.Address.Equals(IPAddress.Any))
                    {
                        _thisServer = new NameServerAddress(_serverDomain, new IPEndPoint(IPAddress.Loopback, localEndPoint.Port));
                        return;
                    }

                    if (localEndPoint.Address.Equals(IPAddress.IPv6Any))
                    {
                        _thisServer = new NameServerAddress(_serverDomain, new IPEndPoint(IPAddress.IPv6Loopback, localEndPoint.Port));
                        return;
                    }
                }

                _thisServer = new NameServerAddress(_serverDomain, _localEndPoints[0]);
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
            foreach (IPEndPoint localEP in _localEndPoints)
            {
                Socket udpListener = null;

                try
                {
                    udpListener = new Socket(localEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

                    #region this code ignores ICMP port unreachable responses which creates SocketException in ReceiveFrom()

                    if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                    {
                        const uint IOC_IN = 0x80000000;
                        const uint IOC_VENDOR = 0x18000000;
                        const uint SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

                        udpListener.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { Convert.ToByte(false) }, null);
                    }

                    #endregion

                    udpListener.ReceiveBufferSize = 64 * 1024;
                    udpListener.SendBufferSize = 64 * 1024;

                    udpListener.Bind(localEP);

                    _udpListeners.Add(udpListener);

                    LogManager log = _log;
                    if (log is not null)
                        log.Write(localEP, DnsTransportProtocol.Udp, "DNS Server was bound successfully.");
                }
                catch (Exception ex)
                {
                    LogManager log = _log;
                    if (log is not null)
                        log.Write(localEP, DnsTransportProtocol.Udp, "DNS Server failed to bind.\r\n" + ex.ToString());

                    if (udpListener is not null)
                        udpListener.Dispose();
                }

                Socket tcpListener = null;

                try
                {
                    tcpListener = new Socket(localEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                    tcpListener.Bind(localEP);
                    tcpListener.Listen(100);

                    _tcpListeners.Add(tcpListener);

                    LogManager log = _log;
                    if (log is not null)
                        log.Write(localEP, DnsTransportProtocol.Tcp, "DNS Server was bound successfully.");
                }
                catch (Exception ex)
                {
                    LogManager log = _log;
                    if (log is not null)
                        log.Write(localEP, DnsTransportProtocol.Tcp, "DNS Server failed to bind.\r\n" + ex.ToString());

                    if (tcpListener is not null)
                        tcpListener.Dispose();
                }

                if (_enableDnsOverHttp)
                {
                    IPEndPoint httpEP = new IPEndPoint(localEP.Address, 8053);
                    Socket httpListener = null;

                    try
                    {
                        httpListener = new Socket(httpEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        httpListener.Bind(httpEP);
                        httpListener.Listen(100);

                        _httpListeners.Add(httpListener);

                        _isDnsOverHttpsEnabled = true;

                        LogManager log = _log;
                        if (log is not null)
                            log.Write(httpEP, "Http", "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        LogManager log = _log;
                        if (log is not null)
                            log.Write(httpEP, "Http", "DNS Server failed to bind.\r\n" + ex.ToString());

                        if (httpListener is not null)
                            httpListener.Dispose();
                    }
                }

                if (_enableDnsOverTls && (_certificate is not null))
                {
                    IPEndPoint tlsEP = new IPEndPoint(localEP.Address, 853);
                    Socket tlsListener = null;

                    try
                    {
                        tlsListener = new Socket(tlsEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        tlsListener.Bind(tlsEP);
                        tlsListener.Listen(100);

                        _tlsListeners.Add(tlsListener);

                        LogManager log = _log;
                        if (log is not null)
                            log.Write(tlsEP, DnsTransportProtocol.Tls, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        LogManager log = _log;
                        if (log is not null)
                            log.Write(tlsEP, DnsTransportProtocol.Tls, "DNS Server failed to bind.\r\n" + ex.ToString());

                        if (tlsListener is not null)
                            tlsListener.Dispose();
                    }
                }

                if (_enableDnsOverHttps)
                {
                    //bind to http port 80 for certbot webroot support
                    {
                        IPEndPoint httpEP = new IPEndPoint(localEP.Address, 80);
                        Socket httpListener = null;

                        try
                        {
                            httpListener = new Socket(httpEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                            httpListener.Bind(httpEP);
                            httpListener.Listen(100);

                            _httpListeners.Add(httpListener);

                            LogManager log = _log;
                            if (log is not null)
                                log.Write(httpEP, "Http", "DNS Server was bound successfully.");
                        }
                        catch (Exception ex)
                        {
                            LogManager log = _log;
                            if (log is not null)
                                log.Write(httpEP, "Http", "DNS Server failed to bind.\r\n" + ex.ToString());

                            if (httpListener is not null)
                                httpListener.Dispose();
                        }
                    }

                    //bind to https port 443
                    if (_certificate is not null)
                    {
                        IPEndPoint httpsEP = new IPEndPoint(localEP.Address, 443);
                        Socket httpsListener = null;

                        try
                        {
                            httpsListener = new Socket(httpsEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                            httpsListener.Bind(httpsEP);
                            httpsListener.Listen(100);

                            _httpsListeners.Add(httpsListener);

                            _isDnsOverHttpsEnabled = true;

                            LogManager log = _log;
                            if (log is not null)
                                log.Write(httpsEP, DnsTransportProtocol.Https, "DNS Server was bound successfully.");
                        }
                        catch (Exception ex)
                        {
                            LogManager log = _log;
                            if (log is not null)
                                log.Write(httpsEP, DnsTransportProtocol.Https, "DNS Server failed to bind.\r\n" + ex.ToString());

                            if (httpsListener is not null)
                                httpsListener.Dispose();
                        }
                    }
                }
            }

            //start reading query packets
            int listenerTaskCount = Math.Max(1, Environment.ProcessorCount);

            foreach (Socket udpListener in _udpListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return ReadUdpRequestAsync(udpListener);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
                }
            }

            foreach (Socket tcpListener in _tcpListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(tcpListener, DnsTransportProtocol.Tcp, false);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
                }
            }

            foreach (Socket httpListener in _httpListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(httpListener, DnsTransportProtocol.Https, false);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
                }
            }

            foreach (Socket tlsListener in _tlsListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(tlsListener, DnsTransportProtocol.Tls, false);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
                }
            }

            foreach (Socket httpsListener in _httpsListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(httpsListener, DnsTransportProtocol.Https, true);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
                }
            }

            _cachePrefetchSamplingTimer = new Timer(CachePrefetchSamplingTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
            _cachePrefetchRefreshTimer = new Timer(CachePrefetchRefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
            _cacheMaintenanceTimer = new Timer(CacheMaintenanceTimerCallback, null, CACHE_MAINTENANCE_TIMER_INITIAL_INTEVAL, Timeout.Infinite);
            _qpmLimitSamplingTimer = new Timer(QpmLimitSamplingTimerCallback, null, Timeout.Infinite, Timeout.Infinite);

            _state = ServiceState.Running;

            UpdateThisServer();
            ResetPrefetchTimers();
            ResetQpsLimitTimer();
        }

        public void Stop()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            lock (_cachePrefetchSamplingTimerLock)
            {
                if (_cachePrefetchSamplingTimer is not null)
                {
                    _cachePrefetchSamplingTimer.Dispose();
                    _cachePrefetchSamplingTimer = null;
                }
            }

            lock (_cachePrefetchRefreshTimerLock)
            {
                if (_cachePrefetchRefreshTimer is not null)
                {
                    _cachePrefetchRefreshTimer.Dispose();
                    _cachePrefetchRefreshTimer = null;
                }
            }

            lock (_cacheMaintenanceTimerLock)
            {
                if (_cacheMaintenanceTimer is not null)
                {
                    _cacheMaintenanceTimer.Dispose();
                    _cacheMaintenanceTimer = null;
                }
            }

            lock (_qpmLimitSamplingTimerLock)
            {
                if (_qpmLimitSamplingTimer is not null)
                {
                    _qpmLimitSamplingTimer.Dispose();
                    _qpmLimitSamplingTimer = null;
                }
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

            _udpListeners.Clear();
            _tcpListeners.Clear();
            _httpListeners.Clear();
            _tlsListeners.Clear();
            _httpsListeners.Clear();

            _state = ServiceState.Stopped;
        }

        public Task<DnsDatagram> DirectQueryAsync(DnsQuestionRecord question, bool skipDnsAppAuthoritativeRequestHandlers = false)
        {
            return ProcessQueryAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }), IPENDPOINT_ANY_0, DnsTransportProtocol.Tcp, true, skipDnsAppAuthoritativeRequestHandlers, null);
        }

        Task<DnsDatagram> IDnsClient.ResolveAsync(DnsQuestionRecord question)
        {
            return DirectQueryAsync(question);
        }

        #endregion

        #region properties

        public string ServerDomain
        {
            get { return _serverDomain; }
            set
            {
                if (!_serverDomain.Equals(value))
                {
                    _serverDomain = value.ToLower();

                    _authZoneManager.ServerDomain = _serverDomain;
                    _allowedZoneManager.ServerDomain = _serverDomain;
                    _blockedZoneManager.ServerDomain = _serverDomain;
                    _blockListZoneManager.ServerDomain = _serverDomain;

                    UpdateThisServer();
                }
            }
        }

        public string ConfigFolder
        { get { return _configFolder; } }

        public IReadOnlyList<IPEndPoint> LocalEndPoints
        {
            get { return _localEndPoints; }
            set { _localEndPoints = value; }
        }

        public NameServerAddress ThisServer
        { get { return _thisServer; } }

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

        public IReadOnlyDictionary<string, TsigKey> TsigKeys
        {
            get { return _tsigKeys; }
            set { _tsigKeys = value; }
        }

        public AuthZoneManager AuthZoneManager
        { get { return _authZoneManager; } }

        public AllowedZoneManager AllowedZoneManager
        { get { return _allowedZoneManager; } }

        public BlockedZoneManager BlockedZoneManager
        { get { return _blockedZoneManager; } }

        public BlockListZoneManager BlockListZoneManager
        { get { return _blockListZoneManager; } }

        public CacheZoneManager CacheZoneManager
        { get { return _cacheZoneManager; } }

        public DnsApplicationManager DnsApplicationManager
        { get { return _dnsApplicationManager; } }

        public IDnsCache DnsCache
        { get { return _dnsCache; } }

        public DnsServerRecursion Recursion
        {
            get { return _recursion; }
            set
            {
                if (_recursion != value)
                {
                    if ((_recursion == DnsServerRecursion.Deny) || (value == DnsServerRecursion.Deny))
                    {
                        _recursion = value;
                        ResetPrefetchTimers();
                    }
                    else
                    {
                        _recursion = value;
                    }
                }
            }
        }

        public IReadOnlyCollection<NetworkAddress> RecursionDeniedNetworks
        {
            get { return _recursionDeniedNetworks; }
            set
            {
                if ((value is not null) && (value.Count > byte.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(RecursionDeniedNetworks), "Networks cannot be more than 255.");

                _recursionDeniedNetworks = value;
            }
        }

        public IReadOnlyCollection<NetworkAddress> RecursionAllowedNetworks
        {
            get { return _recursionAllowedNetworks; }
            set
            {
                if ((value is not null) && (value.Count > byte.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(RecursionAllowedNetworks), "Networks cannot be more than 255.");

                _recursionAllowedNetworks = value;
            }
        }

        public NetProxy Proxy
        {
            get { return _proxy; }
            set { _proxy = value; }
        }

        public IReadOnlyList<NameServerAddress> Forwarders
        {
            get { return _forwarders; }
            set { _forwarders = value; }
        }

        public bool PreferIPv6
        {
            get { return _preferIPv6; }
            set { _preferIPv6 = value; }
        }

        public bool RandomizeName
        {
            get { return _randomizeName; }
            set { _randomizeName = value; }
        }

        public bool QnameMinimization
        {
            get { return _qnameMinimization; }
            set { _qnameMinimization = value; }
        }

        public bool NsRevalidation
        {
            get { return _nsRevalidation; }
            set { _nsRevalidation = value; }
        }

        public int QpmLimitRequests
        {
            get { return _qpmLimitRequests; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(QpmLimitRequests), "Value cannot be less than 0.");

                if (_qpmLimitRequests != value)
                {
                    if ((_qpmLimitRequests == 0) || (value == 0))
                    {
                        _qpmLimitRequests = value;
                        ResetQpsLimitTimer();
                    }
                    else
                    {
                        _qpmLimitRequests = value;
                    }
                }
            }
        }

        public int QpmLimitErrors
        {
            get { return _qpmLimitErrors; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(QpmLimitErrors), "Value cannot be less than 0.");

                if (_qpmLimitErrors != value)
                {
                    if ((_qpmLimitErrors == 0) || (value == 0))
                    {
                        _qpmLimitErrors = value;
                        ResetQpsLimitTimer();
                    }
                    else
                    {
                        _qpmLimitErrors = value;
                    }
                }
            }
        }

        public int QpmLimitSampleMinutes
        {
            get { return _qpmLimitSampleMinutes; }
            set
            {
                if ((value < 1) || (value > 60))
                    throw new ArgumentOutOfRangeException(nameof(QpmLimitSampleMinutes), "Valid range is between 1 and 60 minutes.");

                _qpmLimitSampleMinutes = value;
            }
        }

        public int QpmLimitIPv4PrefixLength
        {
            get { return _qpmLimitIPv4PrefixLength; }
            set
            {
                if ((value < 0) || (value > 32))
                    throw new ArgumentOutOfRangeException(nameof(QpmLimitIPv4PrefixLength), "Valid range is between 0 and 32.");

                _qpmLimitIPv4PrefixLength = value;
            }
        }

        public int QpmLimitIPv6PrefixLength
        {
            get { return _qpmLimitIPv6PrefixLength; }
            set
            {
                if ((value < 0) || (value > 64))
                    throw new ArgumentOutOfRangeException(nameof(QpmLimitIPv6PrefixLength), "Valid range is between 0 and 64.");

                _qpmLimitIPv6PrefixLength = value;
            }
        }

        public int ForwarderRetries
        {
            get { return _forwarderRetries; }
            set
            {
                if (value > 0)
                    _forwarderRetries = value;
            }
        }

        public int ResolverRetries
        {
            get { return _resolverRetries; }
            set
            {
                if (value > 0)
                    _resolverRetries = value;
            }
        }

        public int ForwarderTimeout
        {
            get { return _forwarderTimeout; }
            set
            {
                if (value >= 2000)
                    _forwarderTimeout = value;
            }
        }

        public int ResolverTimeout
        {
            get { return _resolverTimeout; }
            set
            {
                if (value >= 2000)
                    _resolverTimeout = value;
            }
        }

        public int ClientTimeout
        {
            get { return _clientTimeout; }
            set
            {
                if (value >= 2000)
                    _clientTimeout = value;
            }
        }

        public int ForwarderConcurrency
        {
            get { return _forwarderConcurrency; }
            set { _forwarderConcurrency = value; }
        }

        public int ResolverMaxStackCount
        {
            get { return _resolverMaxStackCount; }
            set { _resolverMaxStackCount = value; }
        }

        public bool ServeStale
        {
            get { return _serveStale; }
            set { _serveStale = value; }
        }

        public int CachePrefetchEligibility
        {
            get { return _cachePrefetchEligibility; }
            set
            {
                if (value < 2)
                    throw new ArgumentOutOfRangeException(nameof(CachePrefetchEligibility), "Valid value is greater that or equal to 2.");

                _cachePrefetchEligibility = value;
            }
        }

        public int CachePrefetchTrigger
        {
            get { return _cachePrefetchTrigger; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(CachePrefetchTrigger), "Valid value is greater that or equal to 0.");

                if (_cachePrefetchTrigger != value)
                {
                    if ((_cachePrefetchTrigger == 0) || (value == 0))
                    {
                        _cachePrefetchTrigger = value;
                        ResetPrefetchTimers();
                    }
                    else
                    {
                        _cachePrefetchTrigger = value;
                    }
                }
            }
        }

        public int CachePrefetchSampleIntervalInMinutes
        {
            get { return _cachePrefetchSampleIntervalInMinutes; }
            set
            {
                if ((value < 1) || (value > 60))
                    throw new ArgumentOutOfRangeException(nameof(CachePrefetchSampleIntervalInMinutes), "Valid range is between 1 and 60 minutes.");

                _cachePrefetchSampleIntervalInMinutes = value;
            }
        }

        public int CachePrefetchSampleEligibilityHitsPerHour
        {
            get { return _cachePrefetchSampleEligibilityHitsPerHour; }
            set
            {
                if (value < 1)
                    throw new ArgumentOutOfRangeException(nameof(CachePrefetchSampleEligibilityHitsPerHour), "Valid value is greater than or equal to 1.");

                _cachePrefetchSampleEligibilityHitsPerHour = value;
            }
        }

        public bool EnableBlocking
        {
            get { return _enableBlocking; }
            set { _enableBlocking = value; }
        }

        public bool AllowTxtBlockingReport
        {
            get { return _allowTxtBlockingReport; }
            set { _allowTxtBlockingReport = value; }
        }

        public DnsServerBlockingType BlockingType
        {
            get { return _blockingType; }
            set { _blockingType = value; }
        }

        public IReadOnlyCollection<DnsARecord> CustomBlockingARecords
        {
            get { return _customBlockingARecords; }
            set
            {
                if (value is null)
                    value = Array.Empty<DnsARecord>();

                _customBlockingARecords = value;
            }
        }

        public IReadOnlyCollection<DnsAAAARecord> CustomBlockingAAAARecords
        {
            get { return _customBlockingAAAARecords; }
            set
            {
                if (value is null)
                    value = Array.Empty<DnsAAAARecord>();

                _customBlockingAAAARecords = value;
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
        { get { return _stats; } }

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

        class CacheRefreshSample
        {
            public CacheRefreshSample(DnsQuestionRecord sampleQuestion, IReadOnlyList<NameServerAddress> viaForwarders)
            {
                SampleQuestion = sampleQuestion;
                ViaForwarders = viaForwarders;
            }

            public DnsQuestionRecord SampleQuestion { get; }

            public IReadOnlyList<NameServerAddress> ViaForwarders { get; }
        }
    }
}
