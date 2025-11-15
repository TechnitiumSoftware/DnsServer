/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Trees;
using DnsServerCore.Dns.ZoneManagers;
using DnsServerCore.Dns.Zones;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ClientConnection;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;
using TechnitiumLibrary.Net.ProxyProtocol;

namespace DnsServerCore.Dns
{
#pragma warning disable CA2252 // This API requires opting into preview features
#pragma warning disable CA1416 // Validate platform compatibility

    public enum DnsServerRecursion : byte
    {
        Deny = 0,
        Allow = 1,
        AllowOnlyForPrivateNetworks = 2,
        UseSpecifiedNetworkACL = 3
    }

    public enum DnsServerBlockingType : byte
    {
        AnyAddress = 0,
        NxDomain = 1,
        CustomAddress = 2
    }

    public sealed class DnsServer : IAsyncDisposable, IDisposable, IDnsClient
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

        readonly static char[] commaSeparator = new char[] { ',' };

        internal const int MAX_CNAME_HOPS = 16;
        internal const int SERVE_STALE_MAX_WAIT_TIME = 1800; //max time to wait before serve stale [RFC 8767]
        const int SERVE_STALE_TIME_DIFFERENCE = 200; //200ms before client timeout [RFC 8767]
        internal const int RECURSIVE_RESOLUTION_TIMEOUT = 60000; //max time that can be spent per recursive resolution task

        static readonly IPEndPoint IPENDPOINT_ANY_0 = new IPEndPoint(IPAddress.Any, 0);
        static readonly IReadOnlyCollection<DnsARecordData> _aRecords = [new DnsARecordData(IPAddress.Any)];
        static readonly IReadOnlyCollection<DnsAAAARecordData> _aaaaRecords = [new DnsAAAARecordData(IPAddress.IPv6Any)];
        static readonly List<SslApplicationProtocol> _doqApplicationProtocols = new List<SslApplicationProtocol>() { new SslApplicationProtocol("doq") };

        string _serverDomain;
        readonly string _configFolder;
        readonly string _dohwwwFolder;
        IReadOnlyList<IPEndPoint> _localEndPoints;
        readonly LogManager _log;

        MailAddress _responsiblePerson;
        MailAddress _defaultResponsiblePerson;

        NameServerAddress _thisServer;

        readonly List<Socket> _udpListeners = new List<Socket>();
        readonly List<Socket> _udpProxyListeners = new List<Socket>();
        readonly List<Socket> _tcpListeners = new List<Socket>();
        readonly List<Socket> _tcpProxyListeners = new List<Socket>();
        readonly List<Socket> _tlsListeners = new List<Socket>();
        readonly List<QuicListener> _quicListeners = new List<QuicListener>();

        WebApplication _dohWebService;

        readonly AuthZoneManager _authZoneManager;
        readonly AllowedZoneManager _allowedZoneManager;
        readonly BlockedZoneManager _blockedZoneManager;
        readonly BlockListZoneManager _blockListZoneManager;
        readonly CacheZoneManager _cacheZoneManager;
        readonly DnsApplicationManager _dnsApplicationManager;

        readonly ResolverDnsCache _dnsCache;
        readonly ResolverDnsCache _dnsCacheSkipDnsApps; //to prevent request reaching apps again
        readonly StatsManager _statsManager;

        IReadOnlyCollection<NetworkAddress> _zoneTransferAllowedNetworks;
        IReadOnlyCollection<NetworkAddress> _notifyAllowedNetworks;
        bool _preferIPv6;
        bool _enableUdpSocketPool;
        ushort _udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE;
        bool _dnssecValidation = true;

        bool _eDnsClientSubnet;
        byte _eDnsClientSubnetIPv4PrefixLength = 24;
        byte _eDnsClientSubnetIPv6PrefixLength = 56;
        NetworkAddress _eDnsClientSubnetIpv4Override;
        NetworkAddress _eDnsClientSubnetIpv6Override;

        //ipv4 prefix: udp, tcp
        IReadOnlyDictionary<int, (int, int)> _qpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>()
        {
            { 32, (600, 600) },
            { 24, (6000, 6000) }
        };

        //ipv6 prefix: udp, tcp
        IReadOnlyDictionary<int, (int, int)> _qpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>()
        {
            { 128, (600, 600) },
            { 64, (1200, 1200) },
            { 56, (6000, 6000) }
        };

        int _qpmLimitSampleMinutes = 5;
        int _qpmLimitUdpTruncationPercentage = 50; //percentage of requests that are responded with TC when QPM limit exceeds for UDP (Slip)
        IReadOnlyCollection<NetworkAddress> _qpmLimitBypassList;

        int _clientTimeout = 2000;
        int _tcpSendTimeout = 10000;
        int _tcpReceiveTimeout = 10000;
        int _quicIdleTimeout = 60000;
        int _quicMaxInboundStreams = 100;
        int _listenBacklog = 100;

        bool _enableDnsOverUdpProxy;
        bool _enableDnsOverTcpProxy;
        bool _enableDnsOverHttp;
        bool _enableDnsOverTls;
        bool _enableDnsOverHttps;
        bool _enableDnsOverHttp3;
        bool _enableDnsOverQuic;
        IReadOnlyCollection<NetworkAccessControl> _reverseProxyNetworkACL;
        int _dnsOverUdpProxyPort = 538;
        int _dnsOverTcpProxyPort = 538;
        int _dnsOverHttpPort = 80;
        int _dnsOverTlsPort = 853;
        int _dnsOverHttpsPort = 443;
        int _dnsOverQuicPort = 853;
        string _dnsTlsCertificatePath;
        string _dnsTlsCertificatePassword;
        string _dnsOverHttpRealIpHeader = "X-Real-IP";

        Timer _tlsCertificateUpdateTimer;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

        DateTime _dnsTlsCertificateLastModifiedOn;
        SslServerAuthenticationOptions _dotSslServerAuthenticationOptions;
        SslServerAuthenticationOptions _doqSslServerAuthenticationOptions;
        SslServerAuthenticationOptions _dohSslServerAuthenticationOptions;

        IReadOnlyDictionary<string, TsigKey> _tsigKeys;

        DnsServerRecursion _recursion;
        IReadOnlyCollection<NetworkAccessControl> _recursionNetworkACL;

        bool _randomizeName;
        bool _qnameMinimization;

        int _resolverRetries = 2;
        int _resolverTimeout = 1500;
        int _resolverConcurrency = 2;
        int _resolverMaxStackCount = 16;

        bool _saveCacheToDisk = true;
        bool _serveStale = true;
        int _serveStaleMaxWaitTime = SERVE_STALE_MAX_WAIT_TIME;
        int _cachePrefetchEligibility = 2;
        int _cachePrefetchTrigger = 9;
        int _cachePrefetchSampleIntervalMinutes = 5;
        int _cachePrefetchSampleEligibilityHitsPerHour = 30;

        bool _enableBlocking = true;
        bool _allowTxtBlockingReport = true;
        IReadOnlyCollection<NetworkAddress> _blockingBypassList;
        DnsServerBlockingType _blockingType = DnsServerBlockingType.NxDomain;
        uint _blockingAnswerTtl = 30;
        IReadOnlyCollection<DnsARecordData> _customBlockingARecords = [];
        IReadOnlyCollection<DnsAAAARecordData> _customBlockingAAAARecords = [];

        NetProxy _proxy;
        IReadOnlyList<NameServerAddress> _forwarders;
        bool _concurrentForwarding = true;
        int _forwarderRetries = 3;
        int _forwarderTimeout = 2000;
        int _forwarderConcurrency = 2;

        LogManager _resolverLog;
        LogManager _queryLog;

        Timer _cachePrefetchSamplingTimer;
        readonly object _cachePrefetchSamplingTimerLock = new object();
        const int CACHE_PREFETCH_SAMPLING_TIMER_INITIAL_INTEVAL = 5000;

        Timer _cachePrefetchRefreshTimer;
        readonly object _cachePrefetchRefreshTimerLock = new object();
        const int CACHE_PREFETCH_REFRESH_TIMER_INTEVAL = 10000;
        IList<CacheRefreshSample> _cacheRefreshSampleList;

        Timer _qpmLimitSamplingTimer;
        readonly object _qpmLimitSamplingTimerLock = new object();
        const int QPM_LIMIT_SAMPLING_TIMER_INTERVAL = 10000;
        IReadOnlyDictionary<NetworkAddress, ValueTuple<long, long>> _qpmLimitClientSubnetStats;

        readonly IndependentTaskScheduler _queryTaskScheduler = new IndependentTaskScheduler(threadName: "QueryThreadPool");

        TaskPool _resolverTaskPool;
        readonly IndependentTaskScheduler _resolverTaskScheduler = new IndependentTaskScheduler(priority: ThreadPriority.AboveNormal, threadName: "ResolverThreadPool");
        readonly ConcurrentDictionary<string, Task<RecursiveResolveResponse>> _resolverTasks = new ConcurrentDictionary<string, Task<RecursiveResolveResponse>>(-1, 1000);

        volatile ServiceState _state = ServiceState.Stopped;

        readonly object _saveLock = new object();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        static DnsServer()
        {
            //set min threads since the default value is too small
            {
                ThreadPool.GetMinThreads(out int minWorker, out int minIOC);

                int minThreads = Environment.ProcessorCount * 16;

                if (minWorker < minThreads)
                    minWorker = minThreads;

                if (minIOC < minThreads)
                    minIOC = minThreads;

                ThreadPool.SetMinThreads(minWorker, minIOC);
            }
        }

        public DnsServer(string configFolder, string dohwwwFolder, LogManager log, string serverDomain = null)
            : this(configFolder, dohwwwFolder, [new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53)], log, serverDomain)
        { }

        public DnsServer(string configFolder, string dohwwwFolder, IPEndPoint localEndPoint, LogManager log, string serverDomain = null)
            : this(configFolder, dohwwwFolder, [localEndPoint], log, serverDomain)
        { }

        public DnsServer(string configFolder, string dohwwwFolder, IReadOnlyList<IPEndPoint> localEndPoints, LogManager log, string serverDomain = null)
        {
            if (string.IsNullOrEmpty(serverDomain))
                serverDomain = Environment.MachineName.ToLowerInvariant();

            if (!DnsClient.IsDomainNameValid(serverDomain) || IPAddress.TryParse(serverDomain, out _))
                serverDomain = "dns-server-1"; //use this name instead since machine name is not a valid domain name

            _serverDomain = serverDomain;
            _configFolder = configFolder;
            _dohwwwFolder = dohwwwFolder;
            LocalEndPoints = localEndPoints;
            _log = log;

            ReconfigureResolverTaskPool(100);

            _authZoneManager = new AuthZoneManager(this);
            _allowedZoneManager = new AllowedZoneManager(this);
            _blockedZoneManager = new BlockedZoneManager(this);
            _blockListZoneManager = new BlockListZoneManager(this);
            _cacheZoneManager = new CacheZoneManager(this);
            _dnsApplicationManager = new DnsApplicationManager(this);

            _dnsCache = new ResolverDnsCache(this, false);
            _dnsCacheSkipDnsApps = new ResolverDnsCache(this, true); //to prevent request reaching apps again

            //init stats
            _statsManager = new StatsManager(this);

            //load dns cache async
            if (_saveCacheToDisk)
            {
                ThreadPool.QueueUserWorkItem(delegate (object state)
                {
                    try
                    {
                        _cacheZoneManager.LoadCacheZoneFile();
                    }
                    catch (Exception ex)
                    {
                        _log.Write("Failed to fully load DNS Cache from disk\r\n" + ex.ToString());
                    }
                });
            }

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveConfigFileInternal();
                            _pendingSave = false;
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);

                            //set timer to retry again
                            _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                        }
                    }
                }
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
                return;

            await StopAsync();

            StopTlsCertificateUpdateTimer();

            _authZoneManager?.Dispose();
            _cacheZoneManager?.Dispose();

            _allowedZoneManager?.Dispose();
            _blockedZoneManager?.Dispose();
            _blockListZoneManager?.Dispose();

            _dnsApplicationManager?.Dispose();

            _statsManager?.Dispose();

            _resolverTaskPool?.Dispose();

            _queryTaskScheduler?.Dispose();
            _resolverTaskScheduler?.Dispose();

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave)
                {
                    try
                    {
                        SaveConfigFileInternal();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            if (_saveCacheToDisk)
            {
                try
                {
                    _cacheZoneManager?.SaveCacheZoneFile();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        public void Dispose()
        {
            DisposeAsync().Sync();
        }

        #endregion

        #region config

        public void LoadConfigFile()
        {
            string dnsConfigFile = Path.Combine(_configFolder, "dns.config");

            try
            {
                using (FileStream fS = new FileStream(dnsConfigFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS, false);
                }

                _log.Write("DNS Server config file was loaded: " + dnsConfigFile);
            }
            catch (FileNotFoundException)
            {
                //general
                string serverDomain = Environment.GetEnvironmentVariable("DNS_SERVER_DOMAIN");
                if (!string.IsNullOrEmpty(serverDomain))
                    ServerDomain = serverDomain;

                _dnsApplicationManager.EnableAutomaticUpdate = true;

                string strPreferIPv6 = Environment.GetEnvironmentVariable("DNS_SERVER_PREFER_IPV6");
                if (!string.IsNullOrEmpty(strPreferIPv6))
                    PreferIPv6 = bool.Parse(strPreferIPv6);

                DnssecValidation = true;

                EnableUdpSocketPool = Environment.OSVersion.Platform == PlatformID.Win32NT;

                //optional protocols
                string strDnsOverHttp = Environment.GetEnvironmentVariable("DNS_SERVER_OPTIONAL_PROTOCOL_DNS_OVER_HTTP");
                if (!string.IsNullOrEmpty(strDnsOverHttp))
                    EnableDnsOverHttp = bool.Parse(strDnsOverHttp);

                //recursion
                string strRecursion = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION");
                if (!string.IsNullOrEmpty(strRecursion))
                    Recursion = Enum.Parse<DnsServerRecursion>(strRecursion, true);
                else
                    Recursion = DnsServerRecursion.AllowOnlyForPrivateNetworks; //default for security reasons

                string strRecursionNetworkACL = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION_NETWORK_ACL");
                if (!string.IsNullOrEmpty(strRecursionNetworkACL))
                {
                    RecursionNetworkACL = strRecursionNetworkACL.Split(NetworkAccessControl.Parse, ',');
                }
                else
                {
                    NetworkAddress[] recursionDeniedNetworks = null;
                    NetworkAddress[] recursionAllowedNetworks = null;

                    string strRecursionDeniedNetworks = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION_DENIED_NETWORKS");
                    if (!string.IsNullOrEmpty(strRecursionDeniedNetworks))
                        recursionDeniedNetworks = strRecursionDeniedNetworks.Split(NetworkAddress.Parse, ',');

                    string strRecursionAllowedNetworks = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION_ALLOWED_NETWORKS");
                    if (!string.IsNullOrEmpty(strRecursionAllowedNetworks))
                        recursionAllowedNetworks = strRecursionAllowedNetworks.Split(NetworkAddress.Parse, ',');

                    RecursionNetworkACL = AuthZoneInfo.ConvertDenyAllowToACL(recursionDeniedNetworks, recursionAllowedNetworks);
                }

                RandomizeName = false; //default false to allow resolving from bad name servers
                QnameMinimization = true; //default true to enable privacy feature

                //cache
                _cacheZoneManager.MaximumEntries = 10000;

                //blocking
                string strEnableBlocking = Environment.GetEnvironmentVariable("DNS_SERVER_ENABLE_BLOCKING");
                if (!string.IsNullOrEmpty(strEnableBlocking))
                    EnableBlocking = bool.Parse(strEnableBlocking);

                string strAllowTxtBlockingReport = Environment.GetEnvironmentVariable("DNS_SERVER_ALLOW_TXT_BLOCKING_REPORT");
                if (!string.IsNullOrEmpty(strAllowTxtBlockingReport))
                    AllowTxtBlockingReport = bool.Parse(strAllowTxtBlockingReport);

                string strBlockListUrls = Environment.GetEnvironmentVariable("DNS_SERVER_BLOCK_LIST_URLS");
                if (!string.IsNullOrEmpty(strBlockListUrls))
                    _blockListZoneManager.BlockListUrls = strBlockListUrls.Split(commaSeparator, StringSplitOptions.RemoveEmptyEntries);

                //proxy & forwarders
                string strForwarders = Environment.GetEnvironmentVariable("DNS_SERVER_FORWARDERS");
                if (!string.IsNullOrEmpty(strForwarders))
                {
                    DnsTransportProtocol forwarderProtocol;

                    string strForwarderProtocol = Environment.GetEnvironmentVariable("DNS_SERVER_FORWARDER_PROTOCOL");
                    if (string.IsNullOrEmpty(strForwarderProtocol))
                    {
                        forwarderProtocol = DnsTransportProtocol.Udp;
                    }
                    else
                    {
                        forwarderProtocol = Enum.Parse<DnsTransportProtocol>(strForwarderProtocol, true);
                        if (forwarderProtocol == DnsTransportProtocol.HttpsJson)
                            forwarderProtocol = DnsTransportProtocol.Https;
                    }

                    Forwarders = strForwarders.Split(delegate (string value)
                    {
                        NameServerAddress forwarder = NameServerAddress.Parse(value);

                        if (forwarder.Protocol != forwarderProtocol)
                            forwarder = forwarder.ChangeProtocol(forwarderProtocol);

                        return forwarder;
                    }, ',');
                }

                //logging
                ResolverLogManager = _log;

                string strUseLocalTime = Environment.GetEnvironmentVariable("DNS_SERVER_LOG_USING_LOCAL_TIME");
                if (!string.IsNullOrEmpty(strUseLocalTime))
                    _log.UseLocalTime = bool.Parse(strUseLocalTime);

                _statsManager.EnableInMemoryStats = false;
                _statsManager.MaxStatFileDays = 365;

                SaveConfigFileInternal();
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading DNS config file: " + dnsConfigFile + "\r\n" + ex.ToString());
                _log.Write("Note: You may try deleting the DNS config file to fix this issue. However, you will lose DNS settings but, other data wont be affected.");
            }
        }

        public void LoadConfig(Stream s, bool isConfigTransfer)
        {
            lock (_saveLock)
            {
                ReadConfigFrom(s, isConfigTransfer);

                //save config file
                SaveConfigFileInternal();

                if (_pendingSave)
                {
                    _pendingSave = false;
                    _saveTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
        }

        internal void SaveConfigFileInternal()
        {
            string configFile = Path.Combine(_configFolder, "dns.config");

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize config
                WriteConfigTo(mS);

                //write config
                mS.Position = 0;

                using (FileStream fS = new FileStream(configFile, FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _log.Write("DNS Server config file was saved: " + configFile);
        }

        public void SaveConfigFile()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void ReadConfigFrom(Stream s, bool isConfigTransfer)
        {
            BinaryReader bR = new BinaryReader(s);

            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DC") //format
                throw new InvalidDataException("DNS Server config file format is invalid.");

            int version = bR.ReadByte();
            if (version < 1)
                throw new InvalidDataException("DNS Server config version not supported.");

            //general
            string serverDomain = bR.ReadShortString();
            if (!isConfigTransfer)
            {
                try
                {
                    ServerDomain = serverDomain;
                }
                catch
                {
                    //server domain failed validation
                    _serverDomain = serverDomain;
                }
            }

            {
                IPEndPoint[] localEndPoints;

                int count = bR.ReadByte();
                if (count > 0)
                {
                    IPEndPoint[] localEPs = new IPEndPoint[count];

                    for (int i = 0; i < count; i++)
                        localEPs[i] = (IPEndPoint)EndPointExtensions.ReadFrom(bR);

                    localEndPoints = localEPs;
                }
                else
                {
                    localEndPoints = [new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53)];
                }

                if (!isConfigTransfer)
                    _localEndPoints = localEndPoints;
            }

            NetworkAddress[] ipv4SourceAddresses = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
            if (!isConfigTransfer)
                DnsClientConnection.IPv4SourceAddresses = ipv4SourceAddresses;

            NetworkAddress[] ipv6SourceAddresses = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
            if (!isConfigTransfer)
                DnsClientConnection.IPv6SourceAddresses = ipv6SourceAddresses;

            _authZoneManager.DefaultRecordTtl = bR.ReadUInt32();

            string rp = bR.ReadString();
            if (rp.Length == 0)
                _responsiblePerson = null;
            else
                _responsiblePerson = new MailAddress(rp);

            _authZoneManager.UseSoaSerialDateScheme = bR.ReadBoolean();
            _authZoneManager.MinSoaRefresh = bR.ReadUInt32();
            _authZoneManager.MinSoaRetry = bR.ReadUInt32();

            _zoneTransferAllowedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
            _notifyAllowedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);

            _dnsApplicationManager.EnableAutomaticUpdate = bR.ReadBoolean();

            bool preferIPv6 = bR.ReadBoolean();
            if (!isConfigTransfer)
                _preferIPv6 = preferIPv6;

            {
                bool enableUdpSocketPool = bR.ReadBoolean();
                if (!isConfigTransfer)
                    _enableUdpSocketPool = enableUdpSocketPool;

                int count = bR.ReadUInt16();
                ushort[] socketPoolExcludedPorts = new ushort[count];

                for (int i = 0; i < count; i++)
                    socketPoolExcludedPorts[i] = bR.ReadUInt16();

                if (!isConfigTransfer)
                    UdpClientConnection.SocketPoolExcludedPorts = socketPoolExcludedPorts;
            }

            _udpPayloadSize = bR.ReadUInt16();
            _dnssecValidation = bR.ReadBoolean();

            _eDnsClientSubnet = bR.ReadBoolean();
            _eDnsClientSubnetIPv4PrefixLength = bR.ReadByte();
            _eDnsClientSubnetIPv6PrefixLength = bR.ReadByte();

            if (bR.ReadBoolean())
                _eDnsClientSubnetIpv4Override = NetworkAddress.ReadFrom(bR);
            else
                _eDnsClientSubnetIpv4Override = null;

            if (bR.ReadBoolean())
                _eDnsClientSubnetIpv6Override = NetworkAddress.ReadFrom(bR);
            else
                _eDnsClientSubnetIpv6Override = null;

            {
                int count = bR.ReadByte();
                Dictionary<int, (int, int)> qpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>(count);

                for (int i = 0; i < count; i++)
                    qpmPrefixLimitsIPv4.Add(bR.ReadInt32(), (bR.ReadInt32(), bR.ReadInt32()));

                _qpmPrefixLimitsIPv4 = qpmPrefixLimitsIPv4;
            }

            {
                int count = bR.ReadByte();
                Dictionary<int, (int, int)> qpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>(count);

                for (int i = 0; i < count; i++)
                    qpmPrefixLimitsIPv6.Add(bR.ReadInt32(), (bR.ReadInt32(), bR.ReadInt32()));

                _qpmPrefixLimitsIPv6 = qpmPrefixLimitsIPv6;
            }

            _qpmLimitSampleMinutes = bR.ReadInt32();
            _qpmLimitUdpTruncationPercentage = bR.ReadInt32();

            _qpmLimitBypassList = AuthZoneInfo.ReadNetworkAddressesFrom(bR);

            _clientTimeout = bR.ReadInt32();
            _tcpSendTimeout = bR.ReadInt32();
            _tcpReceiveTimeout = bR.ReadInt32();
            _quicIdleTimeout = bR.ReadInt32();
            _quicMaxInboundStreams = bR.ReadInt32();
            _listenBacklog = bR.ReadInt32();
            MaxConcurrentResolutionsPerCore = bR.ReadUInt16();

            //optional protocols
            bool enableDnsOverUdpProxy = bR.ReadBoolean();
            if (!isConfigTransfer)
                _enableDnsOverUdpProxy = enableDnsOverUdpProxy;

            bool enableDnsOverTcpProxy = bR.ReadBoolean();
            if (!isConfigTransfer)
                _enableDnsOverTcpProxy = enableDnsOverTcpProxy;

            bool enableDnsOverHttp = bR.ReadBoolean();
            if (!isConfigTransfer)
                _enableDnsOverHttp = enableDnsOverHttp;

            bool enableDnsOverTls = bR.ReadBoolean();
            if (!isConfigTransfer)
                _enableDnsOverTls = enableDnsOverTls;

            bool enableDnsOverHttps = bR.ReadBoolean();
            if (!isConfigTransfer)
                _enableDnsOverHttps = enableDnsOverHttps;

            bool enableDnsOverHttp3 = bR.ReadBoolean();
            if (!isConfigTransfer)
                _enableDnsOverHttp3 = enableDnsOverHttp3;

            bool enableDnsOverQuic = bR.ReadBoolean();
            if (!isConfigTransfer)
                _enableDnsOverQuic = enableDnsOverQuic;

            int dnsOverUdpProxyPort = bR.ReadInt32();
            if (!isConfigTransfer)
                _dnsOverUdpProxyPort = dnsOverUdpProxyPort;

            int dnsOverTcpProxyPort = bR.ReadInt32();
            if (!isConfigTransfer)
                _dnsOverTcpProxyPort = dnsOverTcpProxyPort;

            int dnsOverHttpPort = bR.ReadInt32();
            if (!isConfigTransfer)
                _dnsOverHttpPort = dnsOverHttpPort;

            int dnsOverTlsPort = bR.ReadInt32();
            if (!isConfigTransfer)
                _dnsOverTlsPort = dnsOverTlsPort;

            int dnsOverHttpsPort = bR.ReadInt32();
            if (!isConfigTransfer)
                _dnsOverHttpsPort = dnsOverHttpsPort;

            int dnsOverQuicPort = bR.ReadInt32();
            if (!isConfigTransfer)
                _dnsOverQuicPort = dnsOverQuicPort;

            NetworkAccessControl[] reverseProxyNetworkACL = AuthZoneInfo.ReadNetworkACLFrom(bR);
            if (!isConfigTransfer)
                _reverseProxyNetworkACL = reverseProxyNetworkACL;

            string dnsTlsCertificatePath = bR.ReadShortString();
            string dnsTlsCertificatePassword = bR.ReadShortString();

            if (!isConfigTransfer)
            {
                _dnsTlsCertificatePath = dnsTlsCertificatePath;
                _dnsTlsCertificatePassword = dnsTlsCertificatePassword;

                if (_dnsTlsCertificatePath.Length == 0)
                    _dnsTlsCertificatePath = null;

                if (_dnsTlsCertificatePath is null)
                {
                    StopTlsCertificateUpdateTimer();
                }
                else
                {
                    string dnsTlsCertificateAbsolutePath = ConvertToAbsolutePath(_dnsTlsCertificatePath);

                    try
                    {
                        LoadDnsTlsCertificate(dnsTlsCertificateAbsolutePath, _dnsTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading DNS Server TLS certificate: " + dnsTlsCertificateAbsolutePath + "\r\n" + ex.ToString());
                    }

                    StartTlsCertificateUpdateTimer();
                }
            }

            string dnsOverHttpRealIpHeader = bR.ReadShortString();
            if (!isConfigTransfer)
                _dnsOverHttpRealIpHeader = dnsOverHttpRealIpHeader;

            //tsig
            {
                int count = bR.ReadByte();
                Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(count);

                for (int i = 0; i < count; i++)
                {
                    string keyName = bR.ReadShortString();
                    string sharedSecret = bR.ReadShortString();
                    TsigAlgorithm algorithm = (TsigAlgorithm)bR.ReadByte();

                    tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, algorithm));
                }

                _tsigKeys = tsigKeys;
            }

            //recursion
            _recursion = (DnsServerRecursion)bR.ReadByte();
            _recursionNetworkACL = AuthZoneInfo.ReadNetworkACLFrom(bR);

            _randomizeName = bR.ReadBoolean();
            _qnameMinimization = bR.ReadBoolean();

            _resolverRetries = bR.ReadInt32();
            _resolverTimeout = bR.ReadInt32();
            _resolverConcurrency = bR.ReadInt32();
            _resolverMaxStackCount = bR.ReadInt32();

            //cache
            bool saveCacheToDisk = bR.ReadBoolean();
            if (!isConfigTransfer)
                _saveCacheToDisk = saveCacheToDisk;

            bool serveStale = bR.ReadBoolean();
            if (!isConfigTransfer)
                _serveStale = serveStale;

            uint serveStaleTtl = bR.ReadUInt32();
            if (!isConfigTransfer)
                _cacheZoneManager.ServeStaleTtl = serveStaleTtl;

            uint serveStaleAnswerTtl = bR.ReadUInt32();
            if (!isConfigTransfer)
                _cacheZoneManager.ServeStaleAnswerTtl = serveStaleAnswerTtl;

            uint serveStaleResetTtl = bR.ReadUInt32();
            if (!isConfigTransfer)
                _cacheZoneManager.ServeStaleResetTtl = serveStaleResetTtl;

            int serveStaleMaxWaitTime = bR.ReadInt32();
            if (!isConfigTransfer)
                _serveStaleMaxWaitTime = serveStaleMaxWaitTime;

            long cacheMaximumEntries = bR.ReadInt64();
            if (!isConfigTransfer)
                _cacheZoneManager.MaximumEntries = cacheMaximumEntries;

            uint minimumRecordTtl = bR.ReadUInt32();
            if (!isConfigTransfer)
                _cacheZoneManager.MinimumRecordTtl = minimumRecordTtl;

            uint maximumRecordTtl = bR.ReadUInt32();
            if (!isConfigTransfer)
                _cacheZoneManager.MaximumRecordTtl = maximumRecordTtl;

            uint negativeRecordTtl = bR.ReadUInt32();
            if (!isConfigTransfer)
                _cacheZoneManager.NegativeRecordTtl = negativeRecordTtl;

            uint failureRecordTtl = bR.ReadUInt32();
            if (!isConfigTransfer)
                _cacheZoneManager.FailureRecordTtl = failureRecordTtl;

            int cachePrefetchEligibility = bR.ReadInt32();
            if (!isConfigTransfer)
                _cachePrefetchEligibility = cachePrefetchEligibility;

            int cachePrefetchTrigger = bR.ReadInt32();
            if (!isConfigTransfer)
                _cachePrefetchTrigger = cachePrefetchTrigger;

            int cachePrefetchSampleIntervalMinutes = bR.ReadInt32();
            if (!isConfigTransfer)
                _cachePrefetchSampleIntervalMinutes = cachePrefetchSampleIntervalMinutes;

            int cachePrefetchSampleEligibilityHitsPerHour = bR.ReadInt32();
            if (!isConfigTransfer)
                _cachePrefetchSampleEligibilityHitsPerHour = cachePrefetchSampleEligibilityHitsPerHour;

            //blocking
            _enableBlocking = bR.ReadBoolean();
            _allowTxtBlockingReport = bR.ReadBoolean();

            _blockingBypassList = AuthZoneInfo.ReadNetworkAddressesFrom(bR);

            _blockingType = (DnsServerBlockingType)bR.ReadByte();

            {
                //read custom blocking addresses
                List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

                int count = bR.ReadByte();
                if (count > 0)
                {
                    for (int i = 0; i < count; i++)
                    {
                        IPAddress customAddress = IPAddressExtensions.ReadFrom(bR);

                        switch (customAddress.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                dnsARecords.Add(new DnsARecordData(customAddress));
                                break;

                            case AddressFamily.InterNetworkV6:
                                dnsAAAARecords.Add(new DnsAAAARecordData(customAddress));
                                break;
                        }
                    }
                }

                _customBlockingARecords = dnsARecords;
                _customBlockingAAAARecords = dnsAAAARecords;
            }

            _blockingAnswerTtl = bR.ReadUInt32();

            //proxy & forwarders
            NetProxyType proxyType = (NetProxyType)bR.ReadByte();
            if (proxyType != NetProxyType.None)
            {
                string address = bR.ReadShortString();
                int port = bR.ReadInt32();
                NetworkCredential credential = null;

                if (bR.ReadBoolean()) //credential set
                    credential = new NetworkCredential(bR.ReadShortString(), bR.ReadShortString());

                _proxy = NetProxy.CreateProxy(proxyType, address, port, credential);

                int count = bR.ReadByte();
                List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(count);

                for (int i = 0; i < count; i++)
                    bypassList.Add(new NetProxyBypassItem(bR.ReadShortString()));

                _proxy.BypassList = bypassList;
            }
            else
            {
                _proxy = null;
            }

            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    NameServerAddress[] forwarders = new NameServerAddress[count];

                    for (int i = 0; i < count; i++)
                    {
                        forwarders[i] = new NameServerAddress(bR);

                        if (forwarders[i].Protocol == DnsTransportProtocol.HttpsJson)
                            forwarders[i] = forwarders[i].ChangeProtocol(DnsTransportProtocol.Https);
                    }

                    _forwarders = forwarders;
                }
                else
                {
                    _forwarders = null;
                }
            }

            _concurrentForwarding = bR.ReadBoolean();
            _forwarderRetries = bR.ReadInt32();
            _forwarderTimeout = bR.ReadInt32();
            _forwarderConcurrency = bR.ReadInt32();

            //logging
            bool ignoreResolverLogs = bR.ReadBoolean(); //ignore resolver logs
            if (!isConfigTransfer)
            {
                if (ignoreResolverLogs)
                    _resolverLog = null;
                else
                    _resolverLog = _log;
            }

            bool logQueries = bR.ReadBoolean(); //log all queries
            if (!isConfigTransfer)
            {
                if (logQueries)
                    _queryLog = _log;
                else
                    _queryLog = null;
            }

            bool enableInMemoryStats = bR.ReadBoolean();
            if (!isConfigTransfer)
                _statsManager.EnableInMemoryStats = enableInMemoryStats;

            int maxStatFileDays = bR.ReadInt32();
            if (!isConfigTransfer)
                _statsManager.MaxStatFileDays = maxStatFileDays;
        }

        private void WriteConfigTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("DC")); //format
            bW.Write((byte)1); //version

            //general
            bW.WriteShortString(_serverDomain);

            {
                bW.Write(Convert.ToByte(_localEndPoints.Count));

                foreach (IPEndPoint localEP in _localEndPoints)
                    localEP.WriteTo(bW);
            }

            AuthZoneInfo.WriteNetworkAddressesTo(DnsClientConnection.IPv4SourceAddresses, bW);
            AuthZoneInfo.WriteNetworkAddressesTo(DnsClientConnection.IPv6SourceAddresses, bW);

            bW.Write(_authZoneManager.DefaultRecordTtl);

            if (_responsiblePerson is null)
                bW.WriteShortString("");
            else
                bW.WriteShortString(_responsiblePerson.Address);

            bW.Write(_authZoneManager.UseSoaSerialDateScheme);
            bW.Write(_authZoneManager.MinSoaRefresh);
            bW.Write(_authZoneManager.MinSoaRetry);

            AuthZoneInfo.WriteNetworkAddressesTo(_zoneTransferAllowedNetworks, bW);
            AuthZoneInfo.WriteNetworkAddressesTo(_notifyAllowedNetworks, bW);

            bW.Write(_dnsApplicationManager.EnableAutomaticUpdate);

            bW.Write(_preferIPv6);
            bW.Write(_enableUdpSocketPool);

            ushort[] socketPoolExcludedPorts = UdpClientConnection.SocketPoolExcludedPorts;
            if (socketPoolExcludedPorts is null)
            {
                bW.Write(ushort.MinValue);
            }
            else
            {
                bW.Write(Convert.ToUInt16(socketPoolExcludedPorts.Length));

                foreach (ushort excludedPort in socketPoolExcludedPorts)
                    bW.Write(excludedPort);
            }

            bW.Write(_udpPayloadSize);
            bW.Write(_dnssecValidation);

            bW.Write(_eDnsClientSubnet);
            bW.Write(_eDnsClientSubnetIPv4PrefixLength);
            bW.Write(_eDnsClientSubnetIPv6PrefixLength);

            if (_eDnsClientSubnetIpv4Override is null)
            {
                bW.Write(false);
            }
            else
            {
                bW.Write(true);
                _eDnsClientSubnetIpv4Override.WriteTo(bW);
            }

            if (_eDnsClientSubnetIpv6Override is null)
            {
                bW.Write(false);
            }
            else
            {
                bW.Write(true);
                _eDnsClientSubnetIpv6Override.WriteTo(bW);
            }

            if (_qpmPrefixLimitsIPv4.Count == 0)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_qpmPrefixLimitsIPv4.Count));

                foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in _qpmPrefixLimitsIPv4)
                {
                    bW.Write(qpmPrefixLimit.Key);
                    bW.Write(qpmPrefixLimit.Value.Item1);
                    bW.Write(qpmPrefixLimit.Value.Item2);
                }
            }

            if (_qpmPrefixLimitsIPv6.Count == 0)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_qpmPrefixLimitsIPv6.Count));

                foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in _qpmPrefixLimitsIPv6)
                {
                    bW.Write(qpmPrefixLimit.Key);
                    bW.Write(qpmPrefixLimit.Value.Item1);
                    bW.Write(qpmPrefixLimit.Value.Item2);
                }
            }

            bW.Write(_qpmLimitSampleMinutes);
            bW.Write(_qpmLimitUdpTruncationPercentage);

            AuthZoneInfo.WriteNetworkAddressesTo(_qpmLimitBypassList, bW);

            bW.Write(_clientTimeout);
            bW.Write(_tcpSendTimeout);
            bW.Write(_tcpReceiveTimeout);
            bW.Write(_quicIdleTimeout);
            bW.Write(_quicMaxInboundStreams);
            bW.Write(_listenBacklog);
            bW.Write(MaxConcurrentResolutionsPerCore);

            //optional protocols
            bW.Write(_enableDnsOverUdpProxy);
            bW.Write(_enableDnsOverTcpProxy);
            bW.Write(_enableDnsOverHttp);
            bW.Write(_enableDnsOverTls);
            bW.Write(_enableDnsOverHttps);
            bW.Write(_enableDnsOverHttp3);
            bW.Write(_enableDnsOverQuic);

            bW.Write(_dnsOverUdpProxyPort);
            bW.Write(_dnsOverTcpProxyPort);
            bW.Write(_dnsOverHttpPort);
            bW.Write(_dnsOverTlsPort);
            bW.Write(_dnsOverHttpsPort);
            bW.Write(_dnsOverQuicPort);

            AuthZoneInfo.WriteNetworkACLTo(_reverseProxyNetworkACL, bW);

            if (_dnsTlsCertificatePath == null)
                bW.WriteShortString(string.Empty);
            else
                bW.WriteShortString(_dnsTlsCertificatePath);

            if (_dnsTlsCertificatePassword == null)
                bW.WriteShortString(string.Empty);
            else
                bW.WriteShortString(_dnsTlsCertificatePassword);

            bW.WriteShortString(_dnsOverHttpRealIpHeader);

            //tsig
            if (_tsigKeys is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_tsigKeys.Count));

                foreach (KeyValuePair<string, TsigKey> tsigKey in _tsigKeys)
                {
                    bW.WriteShortString(tsigKey.Key);
                    bW.WriteShortString(tsigKey.Value.SharedSecret);
                    bW.Write((byte)tsigKey.Value.Algorithm);
                }
            }

            //recursion
            bW.Write((byte)_recursion);
            AuthZoneInfo.WriteNetworkACLTo(_recursionNetworkACL, bW);

            bW.Write(_randomizeName);
            bW.Write(_qnameMinimization);

            bW.Write(_resolverRetries);
            bW.Write(_resolverTimeout);
            bW.Write(_resolverConcurrency);
            bW.Write(_resolverMaxStackCount);

            //cache
            bW.Write(_saveCacheToDisk);
            bW.Write(_serveStale);
            bW.Write(_cacheZoneManager.ServeStaleTtl);
            bW.Write(_cacheZoneManager.ServeStaleAnswerTtl);
            bW.Write(_cacheZoneManager.ServeStaleResetTtl);
            bW.Write(_serveStaleMaxWaitTime);

            bW.Write(_cacheZoneManager.MaximumEntries);
            bW.Write(_cacheZoneManager.MinimumRecordTtl);
            bW.Write(_cacheZoneManager.MaximumRecordTtl);
            bW.Write(_cacheZoneManager.NegativeRecordTtl);
            bW.Write(_cacheZoneManager.FailureRecordTtl);

            bW.Write(_cachePrefetchEligibility);
            bW.Write(_cachePrefetchTrigger);
            bW.Write(_cachePrefetchSampleIntervalMinutes);
            bW.Write(_cachePrefetchSampleEligibilityHitsPerHour);

            //blocking
            bW.Write(_enableBlocking);
            bW.Write(_allowTxtBlockingReport);

            AuthZoneInfo.WriteNetworkAddressesTo(_blockingBypassList, bW);

            bW.Write((byte)_blockingType);

            {
                bW.Write(Convert.ToByte(_customBlockingARecords.Count + _customBlockingAAAARecords.Count));

                foreach (DnsARecordData record in _customBlockingARecords)
                    record.Address.WriteTo(bW);

                foreach (DnsAAAARecordData record in _customBlockingAAAARecords)
                    record.Address.WriteTo(bW);
            }

            bW.Write(_blockingAnswerTtl);

            //proxy & forwarders
            if (_proxy == null)
            {
                bW.Write((byte)NetProxyType.None);
            }
            else
            {
                bW.Write((byte)_proxy.Type);
                bW.WriteShortString(_proxy.Address);
                bW.Write(_proxy.Port);

                NetworkCredential credential = _proxy.Credential;

                if (credential == null)
                {
                    bW.Write(false);
                }
                else
                {
                    bW.Write(true);
                    bW.WriteShortString(credential.UserName);
                    bW.WriteShortString(credential.Password);
                }

                //bypass list
                {
                    bW.Write(Convert.ToByte(_proxy.BypassList.Count));

                    foreach (NetProxyBypassItem item in _proxy.BypassList)
                        bW.WriteShortString(item.Value);
                }
            }

            if (_forwarders == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_forwarders.Count));

                foreach (NameServerAddress forwarder in _forwarders)
                    forwarder.WriteTo(bW);
            }

            bW.Write(_concurrentForwarding);
            bW.Write(_forwarderRetries);
            bW.Write(_forwarderTimeout);
            bW.Write(_forwarderConcurrency);

            //logging
            bW.Write(_resolverLog is null); //ignore resolver logs
            bW.Write(_queryLog is not null); //log all queries
            bW.Write(_statsManager.EnableInMemoryStats);
            bW.Write(_statsManager.MaxStatFileDays);
        }

        #endregion

        #region tls

        private void StartTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer is null)
            {
                _tlsCertificateUpdateTimer = new Timer(delegate (object state)
                {
                    if (!string.IsNullOrEmpty(_dnsTlsCertificatePath))
                    {
                        string dnsTlsCertificatePath = ConvertToAbsolutePath(_dnsTlsCertificatePath);

                        try
                        {
                            FileInfo fileInfo = new FileInfo(dnsTlsCertificatePath);

                            if (fileInfo.Exists && (fileInfo.LastWriteTimeUtc != _dnsTlsCertificateLastModifiedOn))
                                LoadDnsTlsCertificate(dnsTlsCertificatePath, _dnsTlsCertificatePassword);
                        }
                        catch (Exception ex)
                        {
                            _log.Write("DNS Server encountered an error while updating DNS Server TLS Certificate: " + dnsTlsCertificatePath + "\r\n" + ex.ToString());
                        }
                    }

                }, null, TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL, TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL);
            }
        }

        private void StopTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer is not null)
            {
                _tlsCertificateUpdateTimer.Dispose();
                _tlsCertificateUpdateTimer = null;
            }
        }

        private void LoadDnsTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword)
        {
            FileInfo fileInfo = new FileInfo(tlsCertificatePath);

            if (!fileInfo.Exists)
                throw new ArgumentException("DNS Server TLS certificate file does not exists: " + tlsCertificatePath);

            switch (Path.GetExtension(tlsCertificatePath).ToLowerInvariant())
            {
                case ".pfx":
                case ".p12":
                    break;

                default:
                    throw new ArgumentException("DNS Server TLS certificate file must be PKCS #12 formatted with .pfx or .p12 extension: " + tlsCertificatePath);
            }

            X509Certificate2Collection certificateCollection = X509CertificateLoader.LoadPkcs12CollectionFromFile(tlsCertificatePath, tlsCertificatePassword, X509KeyStorageFlags.PersistKeySet);
            X509Certificate2 serverCertificate = null;

            foreach (X509Certificate2 certificate in certificateCollection)
            {
                if (certificate.HasPrivateKey)
                {
                    serverCertificate = certificate;
                    break;
                }
            }

            if (serverCertificate is null)
                throw new ArgumentException("DNS Server TLS certificate file must contain a certificate with private key.");

            SslStreamCertificateContext certificateContext = SslStreamCertificateContext.Create(serverCertificate, certificateCollection, false);

            _dotSslServerAuthenticationOptions = new SslServerAuthenticationOptions()
            {
                ServerCertificateContext = certificateContext
            };

            _doqSslServerAuthenticationOptions = new SslServerAuthenticationOptions()
            {
                ApplicationProtocols = _doqApplicationProtocols,
                ServerCertificateContext = certificateContext
            };

            List<SslApplicationProtocol> applicationProtocols = new List<SslApplicationProtocol>();

            if (_enableDnsOverHttp3)
                applicationProtocols.Add(new SslApplicationProtocol("h3"));

            if (IsHttp2Supported())
                applicationProtocols.Add(new SslApplicationProtocol("h2"));

            applicationProtocols.Add(new SslApplicationProtocol("http/1.1"));

            _dohSslServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = applicationProtocols,
                ServerCertificateContext = certificateContext,
            };

            _dnsTlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

            _log.Write("DNS Server TLS certificate was loaded: " + tlsCertificatePath);
        }

        public void RemoveDnsTlsCertificate()
        {
            _dotSslServerAuthenticationOptions = null;
            _doqSslServerAuthenticationOptions = null;
            _dohSslServerAuthenticationOptions = null;

            _dnsTlsCertificatePath = null;
            _dnsTlsCertificatePassword = null;

            StopTlsCertificateUpdateTimer();
        }

        public void SetDnsTlsCertificate(string dnsTlsCertificatePath, string dnsTlsCertificatePassword = null)
        {
            if (string.IsNullOrEmpty(dnsTlsCertificatePath))
                throw new ArgumentNullException(nameof(dnsTlsCertificatePath), "DNS optional protocols TLS certificate path cannot be null or empty.");

            if (dnsTlsCertificatePath.Length > 255)
                throw new ArgumentException("DNS optional protocols TLS certificate path length cannot exceed 255 characters.", nameof(dnsTlsCertificatePath));

            if (dnsTlsCertificatePassword?.Length > 255)
                throw new ArgumentException("DNS optional protocols TLS certificate password length cannot exceed 255 characters.", nameof(dnsTlsCertificatePassword));

            dnsTlsCertificatePath = ConvertToAbsolutePath(dnsTlsCertificatePath);

            try
            {
                LoadDnsTlsCertificate(dnsTlsCertificatePath, dnsTlsCertificatePassword);
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading DNS Server TLS certificate: " + dnsTlsCertificatePath + "\r\n" + ex.ToString());
            }

            _dnsTlsCertificatePath = ConvertToRelativePath(dnsTlsCertificatePath);
            _dnsTlsCertificatePassword = dnsTlsCertificatePassword;

            StartTlsCertificateUpdateTimer();
        }

        private string ConvertToRelativePath(string path)
        {
            if (path.StartsWith(_configFolder, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                path = path.Substring(_configFolder.Length).TrimStart(Path.DirectorySeparatorChar);

            return path;
        }

        private string ConvertToAbsolutePath(string path)
        {
            if (path is null)
                return null;

            if (Path.IsPathRooted(path))
                return path;

            return Path.Combine(_configFolder, path);
        }

        #endregion

        #region private

        private async Task ReadUdpRequestAsync(Socket udpListener, DnsTransportProtocol protocol)
        {
            bool sendTruncationResponse;
            byte[] recvBuffer;

            if (protocol == DnsTransportProtocol.UdpProxy)
                recvBuffer = new byte[DnsDatagram.EDNS_MAX_UDP_PAYLOAD_SIZE + 256];
            else
                recvBuffer = new byte[DnsDatagram.EDNS_MAX_UDP_PAYLOAD_SIZE];

            using MemoryStream recvBufferStream = new MemoryStream(recvBuffer);

            try
            {
                int localPort = (udpListener.LocalEndPoint as IPEndPoint).Port;
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

                SocketReceiveMessageFromResult result;

                while (true)
                {
                    recvBufferStream.SetLength(DnsDatagram.EDNS_MAX_UDP_PAYLOAD_SIZE); //resetting length before using buffer

                    try
                    {
                        result = await udpListener.ReceiveMessageFromAsync(recvBuffer, SocketFlags.None, epAny);
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

                        try
                        {
                            recvBufferStream.Position = 0;
                            recvBufferStream.SetLength(result.ReceivedBytes);

                            IPEndPoint returnEP = remoteEP;

                            if (protocol == DnsTransportProtocol.UdpProxy)
                            {
                                if (!NetworkAccessControl.IsAddressAllowed(remoteEP.Address, _reverseProxyNetworkACL))
                                {
                                    //this feature is intended to be used with a reverse proxy or load balancer on private network
                                    continue;
                                }

                                ProxyProtocolStream proxyStream = await ProxyProtocolStream.CreateAsServerAsync(recvBufferStream);

                                if (!proxyStream.IsLocal)
                                    remoteEP = new IPEndPoint(proxyStream.SourceAddress, proxyStream.SourcePort);

                                recvBufferStream.Position = proxyStream.DataOffset;
                            }

                            if (HasQpmLimitExceeded(remoteEP.Address, DnsTransportProtocol.Udp))
                            {
                                if (SendQpmLimitExceededTruncationResponse())
                                {
                                    sendTruncationResponse = true;
                                }
                                else
                                {
                                    _statsManager.QueueUpdate(null, remoteEP, protocol, null, true);
                                    continue;
                                }
                            }
                            else
                            {
                                sendTruncationResponse = false;
                            }

                            DnsDatagram request = DnsDatagram.ReadFrom(recvBufferStream);
                            request.SetMetadata(new NameServerAddress(new IPEndPoint(result.PacketInformation.Address, localPort), DnsTransportProtocol.Udp));

                            _ = ProcessUdpRequestAsync(udpListener, remoteEP, returnEP, protocol, request, sendTruncationResponse);
                        }
                        catch (EndOfStreamException)
                        {
                            //ignore incomplete udp datagrams
                        }
                        catch (Exception ex)
                        {
                            _log.Write(remoteEP, protocol, ex);
                        }
                    }
                }
            }
            catch (ObjectDisposedException)
            {
                //server stopped
            }
            catch (SocketException ex)
            {
                switch (ex.SocketErrorCode)
                {
                    case SocketError.OperationAborted:
                    case SocketError.Interrupted:
                        break; //server stopping

                    default:
                        if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                            return; //server stopping

                        _log.Write(ex);
                        break;
                }
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                _log.Write(ex);
            }
        }

        private async Task ProcessUdpRequestAsync(Socket udpListener, IPEndPoint remoteEP, IPEndPoint returnEP, DnsTransportProtocol protocol, DnsDatagram request, bool sendTruncationResponse)
        {
            byte[] sendBuffer = null;

            try
            {
                bool recursionAllowed = IsRecursionAllowed(remoteEP.Address);
                DnsDatagram response;

                if (sendTruncationResponse)
                {
                    response = new DnsDatagram(request.Identifier, true, request.OPCODE, false, true, request.RecursionDesired, recursionAllowed, false, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize) { Tag = DnsServerResponseType.Authoritative };
                }
                else
                {
                    response = await ProcessRequestAsync(request, remoteEP, protocol, recursionAllowed);
                    if (response is null)
                    {
                        _statsManager.QueueUpdate(null, remoteEP, protocol, null, false);
                        return; //drop request
                    }
                }

                //send response
                int sendBufferSize;

                if (request.EDNS is null)
                    sendBufferSize = 512;
                else if (request.EDNS.UdpPayloadSize > _udpPayloadSize)
                    sendBufferSize = _udpPayloadSize;
                else
                    sendBufferSize = request.EDNS.UdpPayloadSize;

                sendBuffer = ArrayPool<byte>.Shared.Rent(sendBufferSize);

                using (MemoryStream sendBufferStream = new MemoryStream(sendBuffer, 0, sendBufferSize))
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
                            response = new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, true, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, DnsResponseCode.NoError, response.Question, null, null, new DnsResourceRecord[] { response.Additional[response.Additional.Count - 1] }, request.EDNS is null ? ushort.MinValue : _udpPayloadSize) { Tag = DnsServerResponseType.Authoritative };
                        }
                        else
                        {
                            switch (response.Question[0].Type)
                            {
                                case DnsResourceRecordType.MX:
                                case DnsResourceRecordType.SRV:
                                case DnsResourceRecordType.SVCB:
                                case DnsResourceRecordType.HTTPS:
                                    //removing glue records and trying again since some mail servers fail to fallback to TCP on truncation
                                    //removing glue records to prevent truncation for SRV/SVCB/HTTPS
                                    response = response.CloneWithoutGlueRecords();
                                    sendBufferStream.Position = 0;

                                    try
                                    {
                                        response.WriteTo(sendBufferStream);
                                    }
                                    catch (NotSupportedException)
                                    {
                                        //send TC since response is still big even after removing glue records
                                        response = new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, true, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, response.RCODE, response.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize) { Tag = DnsServerResponseType.Authoritative };
                                    }
                                    break;

                                case DnsResourceRecordType.IXFR:
                                    response = new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, false, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, response.RCODE, response.Question, new DnsResourceRecord[] { response.Answer[0] }, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize) { Tag = DnsServerResponseType.Authoritative }; //truncate response
                                    break;

                                default:
                                    response = new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, true, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, response.RCODE, response.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize) { Tag = DnsServerResponseType.Authoritative };
                                    break;
                            }
                        }

                        sendBufferStream.Position = 0;
                        response.WriteTo(sendBufferStream);
                    }

                    //send dns datagram async
                    await udpListener.SendToAsync(new ArraySegment<byte>(sendBuffer, 0, (int)sendBufferStream.Position), SocketFlags.None, returnEP);
                }

                _queryLog?.Write(remoteEP, protocol, request, response);
                _statsManager.QueueUpdate(request, remoteEP, protocol, response, false);
            }
            catch (ObjectDisposedException)
            {
                //ignore
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                _queryLog?.Write(remoteEP, protocol, request, null);
                _log.Write(remoteEP, protocol, ex);
            }
            finally
            {
                if (sendBuffer is not null)
                    ArrayPool<byte>.Shared.Return(sendBuffer);
            }
        }

        private async Task AcceptConnectionAsync(Socket tcpListener, DnsTransportProtocol protocol)
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

                    _ = ProcessConnectionAsync(socket, protocol);
                }
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.OperationAborted)
                    return; //server stopping

                _log.Write(localEP, protocol, ex);
            }
            catch (ObjectDisposedException)
            {
                //server stopped
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                _log.Write(localEP, protocol, ex);
            }
        }

        private async Task ProcessConnectionAsync(Socket socket, DnsTransportProtocol protocol)
        {
            IPEndPoint remoteEP = null;

            try
            {
                remoteEP = socket.RemoteEndPoint as IPEndPoint;

                switch (protocol)
                {
                    case DnsTransportProtocol.Tcp:
                        await ReadStreamRequestAsync(new NetworkStream(socket), remoteEP, new NameServerAddress(socket.LocalEndPoint, DnsTransportProtocol.Tcp), protocol);
                        break;

                    case DnsTransportProtocol.Tls:
                        SslStream tlsStream = new SslStream(new NetworkStream(socket));
                        string serverName = null;

                        await TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                        {
                            return tlsStream.AuthenticateAsServerAsync(delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object state, CancellationToken cancellationToken)
                            {
                                serverName = clientHelloInfo.ServerName;
                                return ValueTask.FromResult(_dotSslServerAuthenticationOptions);
                            }, null, cancellationToken1);
                        }, _tcpReceiveTimeout);

                        NameServerAddress dnsEP;

                        if (string.IsNullOrEmpty(serverName))
                            dnsEP = new NameServerAddress(socket.LocalEndPoint, DnsTransportProtocol.Tls);
                        else
                            dnsEP = new NameServerAddress(serverName, socket.LocalEndPoint as IPEndPoint, DnsTransportProtocol.Tls);

                        await ReadStreamRequestAsync(tlsStream, remoteEP, dnsEP, protocol);
                        break;

                    case DnsTransportProtocol.TcpProxy:
                        if (!NetworkAccessControl.IsAddressAllowed(remoteEP.Address, _reverseProxyNetworkACL))
                        {
                            //this feature is intended to be used with a reverse proxy or load balancer on private network
                            return;
                        }

                        ProxyProtocolStream proxyStream = await TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                        {
                            return ProxyProtocolStream.CreateAsServerAsync(new NetworkStream(socket), cancellationToken1);
                        }, _tcpReceiveTimeout);

                        remoteEP = new IPEndPoint(proxyStream.SourceAddress, proxyStream.SourcePort);

                        await ReadStreamRequestAsync(proxyStream, remoteEP, new NameServerAddress(socket.LocalEndPoint, DnsTransportProtocol.Tcp), protocol);
                        break;

                    default:
                        throw new InvalidOperationException();
                }
            }
            catch (AuthenticationException)
            {
                //ignore TLS auth exception
            }
            catch (TimeoutException)
            {
                //ignore timeout exception on TLS auth
            }
            catch (IOException)
            {
                //ignore IO exceptions
            }
            catch (Exception ex)
            {
                _log.Write(remoteEP, protocol, ex);
            }
            finally
            {
                socket.Dispose();
            }
        }

        private async Task ReadStreamRequestAsync(Stream stream, IPEndPoint remoteEP, NameServerAddress dnsEP, DnsTransportProtocol protocol)
        {
            try
            {
                using MemoryStream readBuffer = new MemoryStream(64);
                using MemoryStream writeBuffer = new MemoryStream(2048);
                using SemaphoreSlim writeSemaphore = new SemaphoreSlim(1, 1);

                while (true)
                {
                    if (HasQpmLimitExceeded(remoteEP.Address, DnsTransportProtocol.Tcp))
                    {
                        _statsManager.QueueUpdate(null, remoteEP, protocol, null, true);
                        break;
                    }

                    DnsDatagram request;

                    //read dns datagram with timeout
                    using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
                    {
                        Task<DnsDatagram> task = DnsDatagram.ReadFromTcpAsync(stream, readBuffer, cancellationTokenSource.Token);

                        if (await Task.WhenAny(task, Task.Delay(_tcpReceiveTimeout, cancellationTokenSource.Token)) != task)
                        {
                            //read timed out
                            await stream.DisposeAsync();
                            return;
                        }

                        cancellationTokenSource.Cancel(); //cancel delay task

                        request = await task;
                        request.SetMetadata(dnsEP);
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
                _log.Write(remoteEP, protocol, ex);
            }
        }

        private async Task ProcessStreamRequestAsync(Stream stream, MemoryStream writeBuffer, SemaphoreSlim writeSemaphore, IPEndPoint remoteEP, DnsDatagram request, DnsTransportProtocol protocol)
        {
            try
            {
                DnsDatagram response = await ProcessRequestAsync(request, remoteEP, protocol, IsRecursionAllowed(remoteEP.Address));
                if (response is null)
                {
                    await stream.DisposeAsync();

                    _statsManager.QueueUpdate(null, remoteEP, protocol, null, false);
                    return; //drop request
                }

                //send response
                await TechnitiumLibrary.TaskExtensions.TimeoutAsync(async delegate (CancellationToken cancellationToken1)
                {
                    await writeSemaphore.WaitAsync(cancellationToken1);
                    try
                    {
                        //send dns datagram
                        await response.WriteToTcpAsync(stream, writeBuffer, cancellationToken1);
                        await stream.FlushAsync(cancellationToken1);
                    }
                    finally
                    {
                        writeSemaphore.Release();
                    }
                }, _tcpSendTimeout);

                _queryLog?.Write(remoteEP, protocol, request, response);
                _statsManager.QueueUpdate(request, remoteEP, protocol, response, false);
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
                if (request is not null)
                    _queryLog?.Write(remoteEP, protocol, request, null);

                _log.Write(remoteEP, protocol, ex);
            }
        }

        private async Task AcceptQuicConnectionAsync(QuicListener quicListener)
        {
            try
            {
                while (true)
                {
                    try
                    {
                        QuicConnection quicConnection = await quicListener.AcceptConnectionAsync();

                        _ = ProcessQuicConnectionAsync(quicConnection);
                    }
                    catch (AuthenticationException)
                    {
                        //ignore failed connection handshake
                    }
                    catch (QuicException ex)
                    {
                        if (ex.InnerException is OperationCanceledException)
                            continue;

                        throw;
                    }
                }
            }
            catch (ObjectDisposedException)
            {
                //server stopped
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                _log.Write(quicListener.LocalEndPoint, DnsTransportProtocol.Quic, ex);
            }
        }

        private async Task ProcessQuicConnectionAsync(QuicConnection quicConnection)
        {
            try
            {
                NameServerAddress dnsEP;

                if (string.IsNullOrEmpty(quicConnection.TargetHostName))
                    dnsEP = new NameServerAddress(quicConnection.LocalEndPoint, DnsTransportProtocol.Quic);
                else
                    dnsEP = new NameServerAddress(quicConnection.TargetHostName, quicConnection.LocalEndPoint, DnsTransportProtocol.Quic);

                while (true)
                {
                    if (HasQpmLimitExceeded(quicConnection.RemoteEndPoint.Address, DnsTransportProtocol.Tcp))
                    {
                        _statsManager.QueueUpdate(null, quicConnection.RemoteEndPoint, DnsTransportProtocol.Quic, null, true);
                        break;
                    }

                    QuicStream quicStream = await quicConnection.AcceptInboundStreamAsync();

                    _ = ProcessQuicStreamRequestAsync(quicStream, quicConnection.RemoteEndPoint, dnsEP);
                }
            }
            catch (QuicException ex)
            {
                switch (ex.QuicError)
                {
                    case QuicError.ConnectionIdle:
                    case QuicError.ConnectionAborted:
                    case QuicError.ConnectionTimeout:
                        break;

                    default:
                        _log.Write(quicConnection.RemoteEndPoint, DnsTransportProtocol.Quic, ex);
                        break;
                }
            }
            catch (Exception ex)
            {
                _log.Write(quicConnection.RemoteEndPoint, DnsTransportProtocol.Quic, ex);
            }
            finally
            {
                await quicConnection.DisposeAsync();
            }
        }

        private async Task ProcessQuicStreamRequestAsync(QuicStream quicStream, IPEndPoint remoteEP, NameServerAddress dnsEP)
        {
            MemoryStream sharedBuffer = new MemoryStream(512);
            DnsDatagram request = null;

            try
            {
                //read dns datagram with timeout
                using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
                {
                    Task<DnsDatagram> task = DnsDatagram.ReadFromTcpAsync(quicStream, sharedBuffer, cancellationTokenSource.Token);

                    if (await Task.WhenAny(task, Task.Delay(_tcpReceiveTimeout, cancellationTokenSource.Token)) != task)
                    {
                        //read timed out
                        quicStream.Abort(QuicAbortDirection.Both, (long)DnsOverQuicErrorCodes.DOQ_UNSPECIFIED_ERROR);
                        return;
                    }

                    cancellationTokenSource.Cancel(); //cancel delay task

                    request = await task;
                    request.SetMetadata(dnsEP);
                }

                //process request async
                DnsDatagram response = await ProcessRequestAsync(request, remoteEP, DnsTransportProtocol.Quic, IsRecursionAllowed(remoteEP.Address));
                if (response is null)
                {
                    _statsManager.QueueUpdate(null, remoteEP, DnsTransportProtocol.Quic, null, false);
                    return; //drop request
                }

                //send response
                await response.WriteToTcpAsync(quicStream, sharedBuffer);

                _queryLog?.Write(remoteEP, DnsTransportProtocol.Quic, request, response);
                _statsManager.QueueUpdate(request, remoteEP, DnsTransportProtocol.Quic, response, false);
            }
            catch (IOException)
            {
                //ignore QuicException / IOException
            }
            catch (Exception ex)
            {
                if (request is not null)
                    _queryLog?.Write(remoteEP, DnsTransportProtocol.Quic, request, null);

                _log.Write(remoteEP, DnsTransportProtocol.Quic, ex);
            }
            finally
            {
                await sharedBuffer.DisposeAsync();
                await quicStream.DisposeAsync();
            }
        }

        private async Task ProcessDoHRequestAsync(HttpContext context)
        {
            IPEndPoint remoteEP = context.GetRemoteEndPoint(); //get the socket connection remote EP
            DnsDatagram dnsRequest = null;

            try
            {
                HttpRequest request = context.Request;
                HttpResponse response = context.Response;

                if (NetworkAccessControl.IsAddressAllowed(remoteEP.Address, _reverseProxyNetworkACL))
                {
                    //try to get client's actual IP from X-Real-IP header, if any
                    if (!string.IsNullOrEmpty(_dnsOverHttpRealIpHeader))
                    {
                        string xRealIp = context.Request.Headers[_dnsOverHttpRealIpHeader];
                        if (IPAddress.TryParse(xRealIp, out IPAddress address))
                            remoteEP = new IPEndPoint(address, 0);
                    }
                }
                else
                {
                    if (!request.IsHttps)
                    {
                        //DNS-over-HTTP insecure protocol is intended to be used with an SSL terminated reverse proxy like nginx on private network
                        response.StatusCode = 403;
                        await response.WriteAsync("DNS-over-HTTPS (DoH) queries are supported only on HTTPS.");
                        return;
                    }
                }

                if (HasQpmLimitExceeded(remoteEP.Address, DnsTransportProtocol.Tcp))
                {
                    _statsManager.QueueUpdate(null, remoteEP, DnsTransportProtocol.Https, null, true);

                    response.StatusCode = 429;
                    await response.WriteAsync("Too Many Requests");
                    return;
                }

                switch (request.Method)
                {
                    case "GET":
                        bool acceptsDoH = false;

                        string requestAccept = request.Headers.Accept;
                        if (string.IsNullOrEmpty(requestAccept))
                        {
                            acceptsDoH = true;
                        }
                        else
                        {
                            foreach (string mediaType in requestAccept.Split(','))
                            {
                                if (mediaType.Equals("application/dns-message", StringComparison.OrdinalIgnoreCase))
                                {
                                    acceptsDoH = true;
                                    break;
                                }
                            }
                        }

                        if (!acceptsDoH)
                        {
                            response.Redirect((request.IsHttps ? "https://" : "http://") + request.Headers.Host);
                            return;
                        }

                        string dnsRequestBase64Url = request.Query["dns"];
                        if (string.IsNullOrEmpty(dnsRequestBase64Url))
                        {
                            response.StatusCode = 400;
                            await response.WriteAsync("Bad Request");
                            return;
                        }

                        //convert from base64url to base64
                        dnsRequestBase64Url = dnsRequestBase64Url.Replace('-', '+');
                        dnsRequestBase64Url = dnsRequestBase64Url.Replace('_', '/');

                        //add padding
                        int x = dnsRequestBase64Url.Length % 4;
                        if (x > 0)
                            dnsRequestBase64Url = dnsRequestBase64Url.PadRight(dnsRequestBase64Url.Length - x + 4, '=');

                        using (MemoryStream mS = new MemoryStream(Convert.FromBase64String(dnsRequestBase64Url)))
                        {
                            dnsRequest = DnsDatagram.ReadFrom(mS);
                            dnsRequest.SetMetadata(new NameServerAddress(new Uri(context.Request.GetDisplayUrl()), context.GetLocalIpAddress()));
                        }

                        break;

                    case "POST":
                        if (!string.Equals(request.Headers.ContentType, "application/dns-message", StringComparison.OrdinalIgnoreCase))
                        {
                            response.StatusCode = 415;
                            await response.WriteAsync("Unsupported Media Type");
                            return;
                        }

                        using (MemoryStream mS = new MemoryStream(32))
                        {
                            await request.Body.CopyToAsync(mS, 32);

                            mS.Position = 0;
                            dnsRequest = DnsDatagram.ReadFrom(mS);
                            dnsRequest.SetMetadata(new NameServerAddress(new Uri(context.Request.GetDisplayUrl()), context.GetLocalIpAddress()));
                        }

                        break;

                    default:
                        throw new InvalidOperationException();
                }

                DnsDatagram dnsResponse = await ProcessRequestAsync(dnsRequest, remoteEP, DnsTransportProtocol.Https, IsRecursionAllowed(remoteEP.Address));
                if (dnsResponse is null)
                {
                    //drop request
                    context.Connection.RequestClose();

                    _statsManager.QueueUpdate(null, remoteEP, DnsTransportProtocol.Https, null, false);
                    return;
                }

                using (MemoryStream mS = new MemoryStream(512))
                {
                    dnsResponse.WriteTo(mS);

                    mS.Position = 0;
                    response.ContentType = "application/dns-message";
                    response.ContentLength = mS.Length;

                    await TechnitiumLibrary.TaskExtensions.TimeoutAsync(async delegate (CancellationToken cancellationToken1)
                    {
                        await using (Stream s = response.Body)
                        {
                            await mS.CopyToAsync(s, 512, cancellationToken1);
                        }
                    }, _tcpSendTimeout);
                }

                _queryLog?.Write(remoteEP, DnsTransportProtocol.Https, dnsRequest, dnsResponse);
                _statsManager.QueueUpdate(dnsRequest, remoteEP, DnsTransportProtocol.Https, dnsResponse, false);
            }
            catch (IOException)
            {
                //ignore IO exceptions
            }
            catch (Exception ex)
            {
                if (dnsRequest is not null)
                    _queryLog?.Write(remoteEP, DnsTransportProtocol.Https, dnsRequest, null);

                _log.Write(remoteEP, DnsTransportProtocol.Https, ex);
            }
        }

        private bool IsRecursionAllowed(IPAddress remoteIP)
        {
            switch (_recursion)
            {
                case DnsServerRecursion.Allow:
                    return true;

                case DnsServerRecursion.AllowOnlyForPrivateNetworks:
                    switch (remoteIP.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                        case AddressFamily.InterNetworkV6:
                            return NetUtilities.IsPrivateIP(remoteIP);

                        default:
                            return false;
                    }

                case DnsServerRecursion.UseSpecifiedNetworkACL:
                    return NetworkAccessControl.IsAddressAllowed(remoteIP, _recursionNetworkACL, true);

                default:
                    return false;
            }
        }

        private async Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            foreach (IDnsRequestController requestController in _dnsApplicationManager.DnsRequestControllers)
            {
                try
                {
                    DnsRequestControllerAction action = await requestController.GetRequestActionAsync(request, remoteEP, protocol);
                    switch (action)
                    {
                        case DnsRequestControllerAction.DropSilently:
                            return null; //drop request

                        case DnsRequestControllerAction.DropWithRefused:
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.Refused, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = DnsServerResponseType.Authoritative }; //drop request with refused
                    }
                }
                catch (Exception ex)
                {
                    _log.Write(remoteEP, protocol, ex);
                }
            }

            if (request.ParsingException is not null)
            {
                //format error
                if (request.ParsingException is not IOException)
                    _log.Write(remoteEP, protocol, request.ParsingException);

                //format error response
                return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = DnsServerResponseType.Authoritative };
            }

            if (request.IsSigned)
            {
                if (!request.VerifySignedRequest(_tsigKeys, out DnsDatagram unsignedRequest, out DnsDatagram errorResponse))
                {
                    _log.Write(remoteEP, protocol, "DNS Server received a request that failed TSIG signature verification (RCODE: " + errorResponse.RCODE + "; TSIG Error: " + errorResponse.TsigError + ")");

                    errorResponse.Tag = DnsServerResponseType.Authoritative;
                    return errorResponse;
                }

                DnsDatagram unsignedResponse = await ProcessQueryAsync(unsignedRequest, remoteEP, protocol, isRecursionAllowed, false, _clientTimeout, request.TsigKeyName);
                if (unsignedResponse is null)
                    return null;

                unsignedResponse = await PostProcessQueryAsync(request, remoteEP, protocol, unsignedResponse);
                if (unsignedResponse is null)
                    return null;

                return unsignedResponse.SignResponse(request, _tsigKeys);
            }

            if (request.EDNS is not null)
            {
                if (request.EDNS.Version != 0)
                    return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.BADVERS, request.Question, null, null, null, _udpPayloadSize, request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = DnsServerResponseType.Authoritative };
            }

            DnsDatagram response = await ProcessQueryAsync(request, remoteEP, protocol, isRecursionAllowed, false, _clientTimeout, null);
            if (response is null)
                return null;

            return await PostProcessQueryAsync(request, remoteEP, protocol, response);
        }

        private async Task<DnsDatagram> PostProcessQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            foreach (IDnsPostProcessor postProcessor in _dnsApplicationManager.DnsPostProcessors)
            {
                try
                {
                    response = await postProcessor.PostProcessAsync(request, remoteEP, protocol, response);
                    if (response is null)
                        return null; //drop request
                }
                catch (Exception ex)
                {
                    _log.Write(remoteEP, protocol, ex);
                }
            }

            if (request.EDNS is null)
            {
                if (response.EDNS is not null)
                    response = response.CloneWithoutEDns();

                return response;
            }

            if (response.EDNS is not null)
                return response;

            IReadOnlyList<EDnsOption> options = null;

            EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption(true);
            if (requestECS is not null)
                options = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(requestECS.SourcePrefixLength, 0, requestECS.Address);

            if (response.Additional.Count == 0)
                return response.Clone(null, null, new DnsResourceRecord[] { DnsDatagramEdns.GetOPTFor(_udpPayloadSize, response.RCODE, 0, request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options) });

            if (response.IsSigned)
                return response;

            DnsResourceRecord[] newAdditional = new DnsResourceRecord[response.Additional.Count + 1];

            for (int i = 0; i < response.Additional.Count; i++)
                newAdditional[i] = response.Additional[i];

            newAdditional[response.Additional.Count] = DnsDatagramEdns.GetOPTFor(_udpPayloadSize, response.RCODE, 0, request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options);

            return response.Clone(null, null, newAdditional);
        }

        private async Task<DnsDatagram> ProcessQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout, string tsigAuthenticatedKeyName)
        {
            if (request.IsResponse)
                return null; //drop response datagram to avoid loops in rare scenarios

            switch (request.OPCODE)
            {
                case DnsOpcode.StandardQuery:
                    if (request.Question.Count != 1)
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                    if (request.Question[0].Class != DnsClass.IN)
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };

                    try
                    {
                        DnsQuestionRecord question = request.Question[0];

                        switch (question.Type)
                        {
                            case DnsResourceRecordType.AXFR:
                                if (protocol == DnsTransportProtocol.Udp)
                                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                                return await ProcessZoneTransferQueryAsync(request, remoteEP, protocol, tsigAuthenticatedKeyName);

                            case DnsResourceRecordType.IXFR:
                                return await ProcessZoneTransferQueryAsync(request, remoteEP, protocol, tsigAuthenticatedKeyName);

                            case DnsResourceRecordType.FWD:
                            case DnsResourceRecordType.APP:
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };
                        }

                        //query authoritative zone
                        DnsDatagram response = await ProcessAuthoritativeQueryAsync(request, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers);
                        if (response is not null)
                        {
                            if ((question.Type == DnsResourceRecordType.ANY) && (protocol == DnsTransportProtocol.Udp)) //force TCP for ANY request
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, true, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, response.RCODE, request.Question) { Tag = DnsServerResponseType.Authoritative };

                            return response;
                        }

                        if (!request.RecursionDesired || !isRecursionAllowed)
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };

                        //do recursive query
                        if ((question.Type == DnsResourceRecordType.ANY) && (protocol == DnsTransportProtocol.Udp)) //force TCP for ANY request
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, true, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.NoError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                        return await ProcessRecursiveQueryAsync(request, remoteEP, protocol, null, _dnssecValidation, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
                    }
                    catch (InvalidDomainNameException)
                    {
                        //format error response
                        return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };
                    }
                    catch (TimeoutException ex)
                    {
                        DnsDatagram response = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.ServerFailure, request.Question) { Tag = DnsServerResponseType.Authoritative };

                        _log.Write(remoteEP, protocol, request, response);
                        _log.Write(remoteEP, protocol, ex);

                        return response;
                    }
                    catch (Exception ex)
                    {
                        _log.Write(remoteEP, protocol, ex);

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.ServerFailure, request.Question) { Tag = DnsServerResponseType.Authoritative };
                    }

                case DnsOpcode.Notify:
                    return await ProcessNotifyQueryAsync(request, remoteEP, protocol);

                case DnsOpcode.Update:
                    return await ProcessUpdateQueryAsync(request, remoteEP, protocol, tsigAuthenticatedKeyName);

                default:
                    return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.NotImplemented, request.Question) { Tag = DnsServerResponseType.Authoritative };
            }
        }

        private async Task<DnsDatagram> ProcessNotifyQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol)
        {
            AuthZoneInfo zoneInfo = _authZoneManager.GetAuthZoneInfo(request.Question[0].Name);
            if ((zoneInfo is null) || ((zoneInfo.Type != AuthZoneType.Secondary) && (zoneInfo.Type != AuthZoneType.SecondaryForwarder) && (zoneInfo.Type != AuthZoneType.SecondaryCatalog)) || zoneInfo.Disabled)
                return new DnsDatagram(request.Identifier, true, DnsOpcode.Notify, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };

            async Task<bool> RemoteVerifiedAsync(IPAddress remoteAddress)
            {
                if (_notifyAllowedNetworks is not null)
                {
                    foreach (NetworkAddress notifyAllowedNetwork in _notifyAllowedNetworks)
                    {
                        if (notifyAllowedNetwork.Contains(remoteAddress))
                            return true;
                    }
                }

                IReadOnlyList<NameServerAddress> primaryNameServerAddresses;

                SecondaryCatalogZone secondaryCatalogZone = zoneInfo.ApexZone.SecondaryCatalogZone;

                if ((secondaryCatalogZone is not null) && !zoneInfo.OverrideCatalogPrimaryNameServers)
                    primaryNameServerAddresses = await zoneInfo.ApexZone.GetResolvedNameServerAddressesAsync(secondaryCatalogZone.PrimaryNameServerAddresses);
                else
                    primaryNameServerAddresses = await zoneInfo.ApexZone.GetResolvedPrimaryNameServerAddressesAsync();

                foreach (NameServerAddress primaryNameServer in primaryNameServerAddresses)
                {
                    if (primaryNameServer.IPEndPoint.Address.Equals(remoteAddress))
                        return true;
                }

                return false;
            }

            if (!await RemoteVerifiedAsync(remoteEP.Address))
            {
                _log.Write(remoteEP, protocol, "DNS Server refused a NOTIFY request since the request IP address was not recognized by the secondary zone: " + zoneInfo.DisplayName);

                return new DnsDatagram(request.Identifier, true, DnsOpcode.Notify, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };
            }

            _log.Write(remoteEP, protocol, "DNS Server received a NOTIFY request for secondary zone: " + zoneInfo.DisplayName);

            if ((request.Answer.Count > 0) && (request.Answer[0].Type == DnsResourceRecordType.SOA))
            {
                IReadOnlyList<DnsResourceRecord> localSoaRecords = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.SOA);

                if (!DnsSOARecordData.IsZoneUpdateAvailable((localSoaRecords[0].RDATA as DnsSOARecordData).Serial, (request.Answer[0].RDATA as DnsSOARecordData).Serial))
                {
                    //no update was available
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.Notify, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question) { Tag = DnsServerResponseType.Authoritative };
                }
            }

            zoneInfo.TriggerRefresh();
            return new DnsDatagram(request.Identifier, true, DnsOpcode.Notify, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question) { Tag = DnsServerResponseType.Authoritative };
        }

        private async Task<DnsDatagram> ProcessUpdateQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, string tsigAuthenticatedKeyName)
        {
            if ((request.Question.Count != 1) || (request.Question[0].Type != DnsResourceRecordType.SOA))
                return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };

            if (request.Question[0].Class != DnsClass.IN)
                return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NotAuth, request.Question) { Tag = DnsServerResponseType.Authoritative };

            AuthZoneInfo zoneInfo = _authZoneManager.FindAuthZoneInfo(request.Question[0].Name);
            if ((zoneInfo is null) || zoneInfo.Disabled)
                return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NotAuth, request.Question) { Tag = DnsServerResponseType.Authoritative };

            _log.Write(remoteEP, protocol, "DNS Server received a zone UPDATE request for zone: " + zoneInfo.DisplayName);

            async Task<bool> IsZoneNameServerAllowedAsync()
            {
                IPAddress remoteAddress = remoteEP.Address;
                IReadOnlyList<NameServerAddress> secondaryNameServers = await zoneInfo.ApexZone.GetResolvedSecondaryNameServerAddressesAsync();

                foreach (NameServerAddress secondaryNameServer in secondaryNameServers)
                {
                    if (secondaryNameServer.IPEndPoint.Address.Equals(remoteAddress))
                        return true;
                }

                return false;
            }

            async Task<bool> IsUpdatePermittedAsync()
            {
                bool isUpdateAllowed;

                switch (zoneInfo.Update)
                {
                    case AuthZoneUpdate.Allow:
                        isUpdateAllowed = true;
                        break;

                    case AuthZoneUpdate.AllowOnlyZoneNameServers:
                        isUpdateAllowed = await IsZoneNameServerAllowedAsync();
                        break;

                    case AuthZoneUpdate.UseSpecifiedNetworkACL:
                        isUpdateAllowed = NetworkAccessControl.IsAddressAllowed(remoteEP.Address, zoneInfo.UpdateNetworkACL);
                        break;

                    case AuthZoneUpdate.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                        isUpdateAllowed = NetworkAccessControl.IsAddressAllowed(remoteEP.Address, zoneInfo.UpdateNetworkACL) || await IsZoneNameServerAllowedAsync();
                        break;

                    case AuthZoneUpdate.Deny:
                    default:
                        isUpdateAllowed = false;
                        break;
                }

                if (!isUpdateAllowed)
                {
                    _log.Write(remoteEP, protocol, "DNS Server refused a zone UPDATE request since the request IP address is not allowed by the zone: " + zoneInfo.DisplayName);

                    return false;
                }

                //check security policies
                if ((zoneInfo.UpdateSecurityPolicies is not null) && (zoneInfo.UpdateSecurityPolicies.Count > 0))
                {
                    if ((tsigAuthenticatedKeyName is null) || !zoneInfo.UpdateSecurityPolicies.TryGetValue(tsigAuthenticatedKeyName.ToLowerInvariant(), out IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>> policyMap))
                    {
                        _log.Write(remoteEP, protocol, "DNS Server refused a zone UPDATE request since the request is missing TSIG auth required by the zone: " + zoneInfo.DisplayName);

                        return false;
                    }

                    //check policy
                    foreach (DnsResourceRecord uRecord in request.Authority)
                    {
                        bool isPermitted = false;

                        foreach (KeyValuePair<string, IReadOnlyList<DnsResourceRecordType>> policy in policyMap)
                        {
                            if (
                                  uRecord.Name.Equals(policy.Key, StringComparison.OrdinalIgnoreCase) ||
                                  (policy.Key.StartsWith("*.") && uRecord.Name.EndsWith(policy.Key.Substring(1), StringComparison.OrdinalIgnoreCase))
                               )
                            {
                                foreach (DnsResourceRecordType allowedType in policy.Value)
                                {
                                    if ((allowedType == DnsResourceRecordType.ANY) || (allowedType == uRecord.Type))
                                    {
                                        isPermitted = true;
                                        break;
                                    }
                                }

                                if (isPermitted)
                                    break;
                            }
                        }

                        if (!isPermitted)
                        {
                            _log.Write(remoteEP, protocol, "DNS Server refused a zone UPDATE request [" + uRecord.Name.ToLowerInvariant() + " " + uRecord.Type.ToString() + " " + uRecord.Class.ToString() + "] due to Dynamic Updates Security Policy for zone: " + zoneInfo.DisplayName);

                            return false;
                        }
                    }
                }

                return true;
            }

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Forwarder:
                    //update
                    {
                        //process prerequisite section
                        {
                            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> temp = new Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>>();

                            foreach (DnsResourceRecord prRecord in request.Answer)
                            {
                                if (prRecord.TTL != 0)
                                    return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                                AuthZoneInfo prAuthZoneInfo = _authZoneManager.FindAuthZoneInfo(prRecord.Name);
                                if ((prAuthZoneInfo is null) || !prAuthZoneInfo.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase))
                                    return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NotZone, request.Question) { Tag = DnsServerResponseType.Authoritative };

                                if (prRecord.Class == DnsClass.ANY)
                                {
                                    if (prRecord.RDATA.RDLENGTH != 0)
                                        return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                                    if (prRecord.Type == DnsResourceRecordType.ANY)
                                    {
                                        //check if name is in use
                                        if (!_authZoneManager.NameExists(zoneInfo.Name, prRecord.Name))
                                            return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NxDomain, request.Question) { Tag = DnsServerResponseType.Authoritative };
                                    }
                                    else
                                    {
                                        //check if RRSet exists (value independent)
                                        IReadOnlyList<DnsResourceRecord> rrset = _authZoneManager.GetRecords(zoneInfo.Name, prRecord.Name, prRecord.Type);
                                        if (rrset.Count == 0)
                                            return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NXRRSet, request.Question) { Tag = DnsServerResponseType.Authoritative };
                                    }
                                }
                                else if (prRecord.Class == DnsClass.NONE)
                                {
                                    if (prRecord.RDATA.RDLENGTH != 0)
                                        return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                                    if (prRecord.Type == DnsResourceRecordType.ANY)
                                    {
                                        //check if name is not in use
                                        if (_authZoneManager.NameExists(zoneInfo.Name, prRecord.Name))
                                            return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.YXDomain, request.Question) { Tag = DnsServerResponseType.Authoritative };
                                    }
                                    else
                                    {
                                        //check if RRSet does not exists
                                        IReadOnlyList<DnsResourceRecord> rrset = _authZoneManager.GetRecords(zoneInfo.Name, prRecord.Name, prRecord.Type);
                                        if (rrset.Count > 0)
                                            return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.YXRRSet, request.Question) { Tag = DnsServerResponseType.Authoritative };
                                    }
                                }
                                else if (prRecord.Class == request.Question[0].Class)
                                {
                                    //check if RRSet exists (value dependent)
                                    //add to temp for later comparison
                                    string recordName = prRecord.Name.ToLowerInvariant();

                                    if (!temp.TryGetValue(recordName, out Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry))
                                    {
                                        rrsetEntry = new Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>();
                                        temp.Add(recordName, rrsetEntry);
                                    }

                                    if (!rrsetEntry.TryGetValue(prRecord.Type, out List<DnsResourceRecord> rrset))
                                    {
                                        rrset = new List<DnsResourceRecord>();
                                        rrsetEntry.Add(prRecord.Type, rrset);
                                    }

                                    rrset.Add(prRecord);
                                }
                                else
                                {
                                    //FORMERR
                                    return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };
                                }
                            }

                            //compare collected RRSets in temp
                            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> zoneEntry in temp)
                            {
                                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                                {
                                    List<DnsResourceRecord> prRRSet = rrsetEntry.Value;
                                    IReadOnlyList<DnsResourceRecord> rrset = _authZoneManager.GetRecords(zoneInfo.Name, zoneEntry.Key, rrsetEntry.Key);

                                    //check if RRSet exists (value dependent)
                                    //compare RRSets

                                    if (prRRSet.Count != rrset.Count)
                                        return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NXRRSet, request.Question) { Tag = DnsServerResponseType.Authoritative };

                                    foreach (DnsResourceRecord prRecord in prRRSet)
                                    {
                                        bool found = false;

                                        foreach (DnsResourceRecord record in rrset)
                                        {
                                            if (
                                                prRecord.Name.Equals(record.Name, StringComparison.OrdinalIgnoreCase) &&
                                                (prRecord.Class == record.Class) &&
                                                (prRecord.Type == record.Type) &&
                                                (prRecord.RDATA.RDLENGTH == record.RDATA.RDLENGTH) &&
                                                prRecord.RDATA.Equals(record.RDATA)
                                               )
                                            {
                                                found = true;
                                                break;
                                            }
                                        }

                                        if (!found)
                                            return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NXRRSet, request.Question) { Tag = DnsServerResponseType.Authoritative };
                                    }
                                }
                            }
                        }

                        //check for permissions
                        if (!await IsUpdatePermittedAsync())
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };

                        //process update section
                        {
                            //prescan
                            foreach (DnsResourceRecord uRecord in request.Authority)
                            {
                                AuthZoneInfo prAuthZoneInfo = _authZoneManager.FindAuthZoneInfo(uRecord.Name);
                                if ((prAuthZoneInfo is null) || !prAuthZoneInfo.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase))
                                    return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NotZone, request.Question) { Tag = DnsServerResponseType.Authoritative };

                                if (uRecord.Class == request.Question[0].Class)
                                {
                                    if (uRecord.RDATA.RDLENGTH == 0) //RDATA must be present to add record
                                        return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                                    switch (uRecord.Type)
                                    {
                                        case DnsResourceRecordType.ANY:
                                        case DnsResourceRecordType.AXFR:
                                        case DnsResourceRecordType.MAILA:
                                        case DnsResourceRecordType.MAILB:
                                        case DnsResourceRecordType.IXFR:
                                            return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };
                                    }
                                }
                                else if (uRecord.Class == DnsClass.ANY)
                                {
                                    if ((uRecord.TTL != 0) || (uRecord.RDATA.RDLENGTH != 0))
                                        return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                                    switch (uRecord.Type)
                                    {
                                        case DnsResourceRecordType.AXFR:
                                        case DnsResourceRecordType.MAILA:
                                        case DnsResourceRecordType.MAILB:
                                        case DnsResourceRecordType.IXFR:
                                            return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };
                                    }
                                }
                                else if (uRecord.Class == DnsClass.NONE)
                                {
                                    if ((uRecord.TTL != 0) || (uRecord.RDATA.RDLENGTH == 0)) //RDATA must be present for deletion
                                        return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };

                                    switch (uRecord.Type)
                                    {
                                        case DnsResourceRecordType.ANY:
                                        case DnsResourceRecordType.AXFR:
                                        case DnsResourceRecordType.MAILA:
                                        case DnsResourceRecordType.MAILB:
                                        case DnsResourceRecordType.IXFR:
                                            return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };
                                    }
                                }
                                else
                                {
                                    //FORMERR
                                    return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };
                                }
                            }

                            //update
                            Dictionary<string, Dictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>> originalRRSets = new Dictionary<string, Dictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>>();

                            void AddToOriginalRRSets(string domain, DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> existingRRSet)
                            {
                                if (!originalRRSets.TryGetValue(domain, out Dictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> originalRRSetEntries))
                                {
                                    originalRRSetEntries = new Dictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>();
                                    originalRRSets.Add(domain, originalRRSetEntries);
                                }

                                originalRRSetEntries.TryAdd(type, existingRRSet);
                            }

                            try
                            {
                                foreach (DnsResourceRecord uRecord in request.Authority)
                                {
                                    if (uRecord.Class == request.Question[0].Class)
                                    {
                                        //Add to an RRset
                                        if (uRecord.Type == DnsResourceRecordType.CNAME)
                                        {
                                            if (_authZoneManager.NameExists(zoneInfo.Name, uRecord.Name) && (_authZoneManager.GetRecords(zoneInfo.Name, uRecord.Name, DnsResourceRecordType.CNAME).Count == 0))
                                                continue; //current name exists and has non-CNAME records so cannot add CNAME record

                                            IReadOnlyList<DnsResourceRecord> existingRRSet = _authZoneManager.GetRecords(zoneInfo.Name, uRecord.Name, uRecord.Type);
                                            AddToOriginalRRSets(uRecord.Name, uRecord.Type, existingRRSet);

                                            GenericRecordInfo recordInfo = uRecord.GetAuthGenericRecordInfo();
                                            recordInfo.LastModified = DateTime.UtcNow;
                                            recordInfo.Comments = "Via Dynamic Updates (RFC 2136)" + (string.IsNullOrEmpty(tsigAuthenticatedKeyName) ? "" : " using key '" + tsigAuthenticatedKeyName + "'") + " from '" + remoteEP.ToString() + "'";

                                            _authZoneManager.SetRecord(zoneInfo.Name, uRecord);
                                        }
                                        else if (uRecord.Type == DnsResourceRecordType.DNAME)
                                        {
                                            IReadOnlyList<DnsResourceRecord> existingRRSet = _authZoneManager.GetRecords(zoneInfo.Name, uRecord.Name, uRecord.Type);
                                            AddToOriginalRRSets(uRecord.Name, uRecord.Type, existingRRSet);

                                            GenericRecordInfo recordInfo = uRecord.GetAuthGenericRecordInfo();
                                            recordInfo.LastModified = DateTime.UtcNow;
                                            recordInfo.Comments = "Via Dynamic Updates (RFC 2136)" + (string.IsNullOrEmpty(tsigAuthenticatedKeyName) ? "" : " using key '" + tsigAuthenticatedKeyName + "'") + " from '" + remoteEP.ToString() + "'";

                                            _authZoneManager.SetRecord(zoneInfo.Name, uRecord);
                                        }
                                        else if (uRecord.Type == DnsResourceRecordType.SOA)
                                        {
                                            if (!uRecord.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase))
                                                continue; //can add SOA only to apex

                                            IReadOnlyList<DnsResourceRecord> existingRRSet = _authZoneManager.GetRecords(zoneInfo.Name, uRecord.Name, uRecord.Type);
                                            AddToOriginalRRSets(uRecord.Name, uRecord.Type, existingRRSet);

                                            GenericRecordInfo recordInfo = uRecord.GetAuthGenericRecordInfo();
                                            recordInfo.LastModified = DateTime.UtcNow;
                                            recordInfo.Comments = "Via Dynamic Updates (RFC 2136)" + (string.IsNullOrEmpty(tsigAuthenticatedKeyName) ? "" : " using key '" + tsigAuthenticatedKeyName + "'") + " from '" + remoteEP.ToString() + "'";

                                            _authZoneManager.SetRecord(zoneInfo.Name, uRecord);
                                        }
                                        else
                                        {
                                            if (_authZoneManager.GetRecords(zoneInfo.Name, uRecord.Name, DnsResourceRecordType.CNAME).Count > 0)
                                                continue; //current name contains CNAME so cannot add non-CNAME record

                                            IReadOnlyList<DnsResourceRecord> existingRRSet = _authZoneManager.GetRecords(zoneInfo.Name, uRecord.Name, uRecord.Type);
                                            AddToOriginalRRSets(uRecord.Name, uRecord.Type, existingRRSet);

                                            if (uRecord.Type == DnsResourceRecordType.NS)
                                                uRecord.SyncGlueRecords(request.Additional);

                                            GenericRecordInfo recordInfo = uRecord.GetAuthGenericRecordInfo();
                                            recordInfo.LastModified = DateTime.UtcNow;
                                            recordInfo.Comments = "Via Dynamic Updates (RFC 2136)" + (string.IsNullOrEmpty(tsigAuthenticatedKeyName) ? "" : " using key '" + tsigAuthenticatedKeyName + "'") + " from '" + remoteEP.ToString() + "'";

                                            _authZoneManager.AddRecord(zoneInfo.Name, uRecord);
                                        }
                                    }
                                    else if (uRecord.Class == DnsClass.ANY)
                                    {
                                        if (uRecord.Type == DnsResourceRecordType.ANY)
                                        {
                                            //Delete all RRsets from a name
                                            IReadOnlyDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> existingRRSets = _authZoneManager.GetEntriesFor(zoneInfo.Name, uRecord.Name);

                                            if (uRecord.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase))
                                            {
                                                foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> existingRRSet in existingRRSets)
                                                {
                                                    switch (existingRRSet.Key)
                                                    {
                                                        case DnsResourceRecordType.SOA:
                                                        case DnsResourceRecordType.NS:
                                                        case DnsResourceRecordType.DNSKEY:
                                                        case DnsResourceRecordType.RRSIG:
                                                        case DnsResourceRecordType.NSEC:
                                                        case DnsResourceRecordType.NSEC3PARAM:
                                                        case DnsResourceRecordType.NSEC3:
                                                            continue; //no apex SOA/NS can be deleted; skip DNSSEC rrsets
                                                    }

                                                    AddToOriginalRRSets(uRecord.Name, existingRRSet.Key, existingRRSet.Value);

                                                    _authZoneManager.DeleteRecords(zoneInfo.Name, uRecord.Name, existingRRSet.Key);
                                                }
                                            }
                                            else
                                            {
                                                foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> existingRRSet in existingRRSets)
                                                {
                                                    switch (existingRRSet.Key)
                                                    {
                                                        case DnsResourceRecordType.DNSKEY:
                                                        case DnsResourceRecordType.RRSIG:
                                                        case DnsResourceRecordType.NSEC:
                                                        case DnsResourceRecordType.NSEC3PARAM:
                                                        case DnsResourceRecordType.NSEC3:
                                                            continue; //skip DNSSEC rrsets
                                                    }

                                                    AddToOriginalRRSets(uRecord.Name, existingRRSet.Key, existingRRSet.Value);

                                                    _authZoneManager.DeleteRecords(zoneInfo.Name, uRecord.Name, existingRRSet.Key);
                                                }
                                            }
                                        }
                                        else
                                        {
                                            //Delete an RRset
                                            if (uRecord.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase))
                                            {
                                                switch (uRecord.Type)
                                                {
                                                    case DnsResourceRecordType.SOA:
                                                    case DnsResourceRecordType.NS:
                                                    case DnsResourceRecordType.DNSKEY:
                                                    case DnsResourceRecordType.RRSIG:
                                                    case DnsResourceRecordType.NSEC:
                                                    case DnsResourceRecordType.NSEC3PARAM:
                                                    case DnsResourceRecordType.NSEC3:
                                                        continue; //no apex SOA/NS can be deleted; skip DNSSEC rrsets
                                                }
                                            }

                                            IReadOnlyList<DnsResourceRecord> existingRRSet = _authZoneManager.GetRecords(zoneInfo.Name, uRecord.Name, uRecord.Type);
                                            AddToOriginalRRSets(uRecord.Name, uRecord.Type, existingRRSet);

                                            _authZoneManager.DeleteRecords(zoneInfo.Name, uRecord.Name, uRecord.Type);
                                        }
                                    }
                                    else if (uRecord.Class == DnsClass.NONE)
                                    {
                                        //Delete an RR from an RRset

                                        switch (uRecord.Type)
                                        {
                                            case DnsResourceRecordType.SOA:
                                            case DnsResourceRecordType.DNSKEY:
                                            case DnsResourceRecordType.RRSIG:
                                            case DnsResourceRecordType.NSEC:
                                            case DnsResourceRecordType.NSEC3PARAM:
                                            case DnsResourceRecordType.NSEC3:
                                                continue; //no SOA can be deleted; skip DNSSEC rrsets
                                        }

                                        IReadOnlyList<DnsResourceRecord> existingRRSet = _authZoneManager.GetRecords(zoneInfo.Name, uRecord.Name, uRecord.Type);

                                        if ((uRecord.Type == DnsResourceRecordType.NS) && (existingRRSet.Count == 1) && uRecord.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase))
                                            continue; //no apex NS can be deleted if only 1 NS exists

                                        AddToOriginalRRSets(uRecord.Name, uRecord.Type, existingRRSet);

                                        _authZoneManager.DeleteRecord(zoneInfo.Name, uRecord.Name, uRecord.Type, uRecord.RDATA);
                                    }
                                }
                            }
                            catch
                            {
                                //revert
                                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>> originalRRSetEntries in originalRRSets)
                                {
                                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> originalRRSet in originalRRSetEntries.Value)
                                    {
                                        if (originalRRSet.Value.Count == 0)
                                            _authZoneManager.DeleteRecords(zoneInfo.Name, originalRRSetEntries.Key, originalRRSet.Key);
                                        else
                                            _authZoneManager.SetRecords(zoneInfo.Name, originalRRSet.Value);
                                    }
                                }

                                throw;
                            }
                        }

                        _authZoneManager.SaveZoneFile(zoneInfo.Name);

                        _log.Write(remoteEP, protocol, "DNS Server successfully processed a zone UPDATE request for zone: " + zoneInfo.DisplayName);

                        //NOERROR
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question) { Tag = DnsServerResponseType.Authoritative };
                    }

                case AuthZoneType.Secondary:
                case AuthZoneType.SecondaryForwarder:
                    //forward
                    {
                        //check for permissions
                        if (!await IsUpdatePermittedAsync())
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };

                        //forward to primary
                        IReadOnlyList<NameServerAddress> primaryNameServerAddresses;
                        DnsTransportProtocol primaryZoneTransferProtocol;

                        SecondaryCatalogZone secondaryCatalogZone = zoneInfo.ApexZone.SecondaryCatalogZone;

                        if ((secondaryCatalogZone is not null) && !zoneInfo.OverrideCatalogPrimaryNameServers)
                        {
                            primaryNameServerAddresses = await zoneInfo.ApexZone.GetResolvedNameServerAddressesAsync(secondaryCatalogZone.PrimaryNameServerAddresses);
                            primaryZoneTransferProtocol = secondaryCatalogZone.PrimaryZoneTransferProtocol;
                        }
                        else
                        {
                            primaryNameServerAddresses = await zoneInfo.ApexZone.GetResolvedPrimaryNameServerAddressesAsync();
                            primaryZoneTransferProtocol = zoneInfo.PrimaryZoneTransferProtocol;
                        }

                        switch (primaryZoneTransferProtocol)
                        {
                            case DnsTransportProtocol.Tls:
                            case DnsTransportProtocol.Quic:
                                {
                                    //change name server protocol to TLS/QUIC
                                    List<NameServerAddress> updatedNameServers = new List<NameServerAddress>(primaryNameServerAddresses.Count);

                                    foreach (NameServerAddress primaryNameServer in primaryNameServerAddresses)
                                    {
                                        if (primaryNameServer.Protocol == primaryZoneTransferProtocol)
                                            updatedNameServers.Add(primaryNameServer);
                                        else
                                            updatedNameServers.Add(primaryNameServer.ChangeProtocol(primaryZoneTransferProtocol));
                                    }

                                    primaryNameServerAddresses = updatedNameServers;
                                }
                                break;

                            default:
                                if (protocol == DnsTransportProtocol.Tcp)
                                {
                                    //change name server protocol to TCP
                                    List<NameServerAddress> updatedNameServers = new List<NameServerAddress>(primaryNameServerAddresses.Count);

                                    foreach (NameServerAddress primaryNameServer in primaryNameServerAddresses)
                                    {
                                        if (primaryNameServer.Protocol == DnsTransportProtocol.Tcp)
                                            updatedNameServers.Add(primaryNameServer);
                                        else
                                            updatedNameServers.Add(primaryNameServer.ChangeProtocol(DnsTransportProtocol.Tcp));
                                    }

                                    primaryNameServerAddresses = updatedNameServers;
                                }
                                break;
                        }

                        TsigKey key = null;

                        if (!string.IsNullOrEmpty(tsigAuthenticatedKeyName) && ((_tsigKeys is null) || !_tsigKeys.TryGetValue(tsigAuthenticatedKeyName, out key)))
                            throw new DnsServerException("DNS Server does not have TSIG key '" + tsigAuthenticatedKeyName + "' configured to authenticate dynamic updates for " + zoneInfo.TypeName + " zone: " + zoneInfo.DisplayName);

                        DnsClient dnsClient = new DnsClient(primaryNameServerAddresses);

                        dnsClient.Proxy = _proxy;
                        dnsClient.PreferIPv6 = _preferIPv6;
                        dnsClient.Retries = _forwarderRetries;
                        dnsClient.Timeout = _forwarderTimeout;
                        dnsClient.Concurrency = 1;

                        DnsDatagram newRequest = request.Clone();
                        newRequest.SetRandomIdentifier();

                        DnsDatagram newResponse;

                        if (key is null)
                            newResponse = await dnsClient.RawResolveAsync(newRequest);
                        else
                            newResponse = await dnsClient.TsigResolveAsync(newRequest, key);

                        newResponse.SetIdentifier(request.Identifier);

                        return newResponse;
                    }

                default:
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.Update, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NotAuth, request.Question) { Tag = DnsServerResponseType.Authoritative };
            }
        }

        private async Task<DnsDatagram> ProcessZoneTransferQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, string tsigAuthenticatedKeyName)
        {
            AuthZoneInfo zoneInfo = _authZoneManager.GetAuthZoneInfo(request.Question[0].Name);
            if ((zoneInfo is null) || !zoneInfo.ApexZone.IsActive)
                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Secondary:
                case AuthZoneType.Forwarder:
                case AuthZoneType.Catalog:
                    break;

                default:
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };
            }

            async Task<bool> IsZoneNameServerAllowedAsync(ApexZone apexZone)
            {
                IPAddress remoteAddress = remoteEP.Address;
                IReadOnlyList<NameServerAddress> secondaryNameServers = await apexZone.GetResolvedSecondaryNameServerAddressesAsync();

                foreach (NameServerAddress secondaryNameServer in secondaryNameServers)
                {
                    if (secondaryNameServer.IPEndPoint.Address.Equals(remoteAddress))
                        return true;
                }

                return false;
            }

            async Task<bool> IsZoneTransferAllowed(ApexZone apexZone)
            {
                switch (apexZone.ZoneTransfer)
                {
                    case AuthZoneTransfer.Allow:
                        return true;

                    case AuthZoneTransfer.AllowOnlyZoneNameServers:
                        return await IsZoneNameServerAllowedAsync(apexZone);

                    case AuthZoneTransfer.UseSpecifiedNetworkACL:
                        return NetworkAccessControl.IsAddressAllowed(remoteEP.Address, apexZone.ZoneTransferNetworkACL);

                    case AuthZoneTransfer.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                        return NetworkAccessControl.IsAddressAllowed(remoteEP.Address, apexZone.ZoneTransferNetworkACL) || await IsZoneNameServerAllowedAsync(apexZone);

                    case AuthZoneTransfer.Deny:
                    default:
                        return false;
                }
            }

            bool IsTsigAuthenticated(ApexZone apexZone)
            {
                if ((apexZone.ZoneTransferTsigKeyNames is null) || (apexZone.ZoneTransferTsigKeyNames.Count < 1))
                    return true; //no auth needed

                if ((tsigAuthenticatedKeyName is not null) && apexZone.ZoneTransferTsigKeyNames.Contains(tsigAuthenticatedKeyName.ToLowerInvariant()))
                    return true; //key matches

                return false;
            }

            bool isInZoneTransferAllowedList = false;

            if (_zoneTransferAllowedNetworks is not null)
            {
                IPAddress remoteAddress = remoteEP.Address;

                foreach (NetworkAddress networkAddress in _zoneTransferAllowedNetworks)
                {
                    if (networkAddress.Contains(remoteAddress))
                    {
                        isInZoneTransferAllowedList = true;
                        break;
                    }
                }
            }

            if (!isInZoneTransferAllowedList)
            {
                ApexZone apexZone = zoneInfo.ApexZone;

                CatalogZone catalogZone = apexZone.CatalogZone;
                if (catalogZone is not null)
                {
                    if (!apexZone.OverrideCatalogZoneTransfer)
                        apexZone = catalogZone; //use catalog zone transfer options
                }
                else
                {
                    SecondaryCatalogZone secondaryCatalogZone = apexZone.SecondaryCatalogZone;
                    if (secondaryCatalogZone is not null)
                    {
                        if (!apexZone.OverrideCatalogZoneTransfer)
                            apexZone = secondaryCatalogZone; //use secondary zone transfer options
                    }
                }

                if (!await IsZoneTransferAllowed(apexZone))
                {
                    _log.Write(remoteEP, protocol, "DNS Server refused a zone transfer request since the request IP address is not allowed by the zone: " + zoneInfo.DisplayName);

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };
                }

                if (!IsTsigAuthenticated(apexZone))
                {
                    _log.Write(remoteEP, protocol, "DNS Server refused a zone transfer request since the request is missing TSIG auth required by the zone: " + zoneInfo.DisplayName);

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question) { Tag = DnsServerResponseType.Authoritative };
                }
            }

            _log.Write(remoteEP, protocol, "DNS Server received zone transfer request for zone: " + zoneInfo.DisplayName);

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

            //update notify failed list
            NameServerAddress allowedZoneNameServer = null;

            switch (zoneInfo.Notify)
            {
                case AuthZoneNotify.ZoneNameServers:
                case AuthZoneNotify.BothZoneAndSpecifiedNameServers:
                    IPAddress remoteAddress = remoteEP.Address;
                    IReadOnlyList<NameServerAddress> secondaryNameServers = await zoneInfo.ApexZone.GetResolvedSecondaryNameServerAddressesAsync();

                    foreach (NameServerAddress secondaryNameServer in secondaryNameServers)
                    {
                        if (secondaryNameServer.IPEndPoint.Address.Equals(remoteAddress))
                        {
                            allowedZoneNameServer = secondaryNameServer;
                            break;
                        }
                    }

                    break;
            }

            zoneInfo.ApexZone.RemoveFromNotifyFailedList(allowedZoneNameServer, remoteEP.Address);

            return xfrResponse;
        }

        private async Task<DnsDatagram> ProcessAuthoritativeQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers)
        {
            DnsDatagram response = await AuthoritativeQueryAsync(request, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, remoteEP);
            if (response is null)
                return null;

            bool reprocessResponse; //to allow resolving CNAME/ANAME in response
            do
            {
                reprocessResponse = false;

                if (response.RCODE == DnsResponseCode.NoError)
                {
                    if (response.Answer.Count > 0)
                    {
                        DnsResourceRecordType questionType = request.Question[0].Type;
                        DnsResourceRecord lastRR = response.GetLastAnswerRecord();

                        if ((lastRR.Type != questionType) && (questionType != DnsResourceRecordType.ANY))
                        {
                            switch (lastRR.Type)
                            {
                                case DnsResourceRecordType.CNAME:
                                    return await ProcessCNAMEAsync(request, response, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, _clientTimeout);

                                case DnsResourceRecordType.ANAME:
                                case DnsResourceRecordType.ALIAS:
                                    return await ProcessANAMEAsync(request, response, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, _clientTimeout);
                            }
                        }
                    }
                    else if (response.Authority.Count > 0)
                    {
                        DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
                        switch (firstAuthority.Type)
                        {
                            case DnsResourceRecordType.NS:
                                if (request.RecursionDesired && isRecursionAllowed)
                                {
                                    //do forced recursive resolution (with blocking support) using empty conditional forwarders; name servers will be provided via ResolverDnsCache
                                    return await ProcessRecursiveQueryAsync(request, remoteEP, protocol, [], _dnssecValidation, false, skipDnsAppAuthoritativeRequestHandlers, _clientTimeout);
                                }

                                break;

                            case DnsResourceRecordType.FWD:
                                //do conditional forwarding (with blocking support)
                                return await ProcessRecursiveQueryAsync(request, remoteEP, protocol, response.Authority, _dnssecValidation, false, skipDnsAppAuthoritativeRequestHandlers, _clientTimeout);

                            case DnsResourceRecordType.APP:
                                response = await ProcessAPPAsync(request, response, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, _clientTimeout);
                                if (response is null)
                                    return null; //drop request

                                reprocessResponse = true;
                                break;
                        }
                    }
                }
            }
            while (reprocessResponse);

            return response;
        }

        internal async Task<DnsDatagram> AuthoritativeQueryAsync(DnsDatagram request, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers, IPEndPoint remoteEP = null)
        {
            DnsDatagram authResponse;

            if (remoteEP is null)
                authResponse = _authZoneManager.Query(request, isRecursionAllowed);
            else
                authResponse = await _authZoneManager.QueryAsync(request, remoteEP.Address, isRecursionAllowed);

            if (authResponse is not null)
            {
                if ((authResponse.RCODE != DnsResponseCode.NoError) || (authResponse.Answer.Count > 0) || (authResponse.Authority.Count == 0) || authResponse.IsFirstAuthoritySOA())
                {
                    authResponse.Tag = DnsServerResponseType.Authoritative;
                    return authResponse;
                }
            }

            DnsDatagram appResponse = null;

            if (!skipDnsAppAuthoritativeRequestHandlers)
            {
                if (remoteEP is null)
                    remoteEP = IPENDPOINT_ANY_0;

                foreach (IDnsAuthoritativeRequestHandler requestHandler in _dnsApplicationManager.DnsAuthoritativeRequestHandlers)
                {
                    try
                    {
                        appResponse = await requestHandler.ProcessRequestAsync(request, remoteEP, protocol, isRecursionAllowed);
                        if (appResponse is not null)
                        {
                            if ((appResponse.RCODE != DnsResponseCode.NoError) || (appResponse.Answer.Count > 0) || (appResponse.Authority.Count == 0) || appResponse.IsFirstAuthoritySOA())
                            {
                                if (appResponse.Tag is null)
                                    appResponse.Tag = DnsServerResponseType.Authoritative;

                                return appResponse;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Write(remoteEP, protocol, ex);
                    }
                }
            }

            if ((authResponse is not null) && (authResponse.Authority.Count > 0))
            {
                if ((appResponse is not null) && (appResponse.Authority.Count > 0))
                {
                    DnsResourceRecord authResponseFirstAuthority = authResponse.FindFirstAuthorityRecord();
                    DnsResourceRecord appResponseFirstAuthority = appResponse.FindFirstAuthorityRecord();

                    if (appResponseFirstAuthority.Name.Length > authResponseFirstAuthority.Name.Length)
                        return appResponse;
                }

                return authResponse;
            }
            else
            {
                return appResponse;
            }
        }

        private async Task<DnsDatagram> ProcessAPPAsync(DnsDatagram request, DnsDatagram response, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout)
        {
            DnsResourceRecord appResourceRecord = response.Authority[0];
            DnsApplicationRecordData appRecord = appResourceRecord.RDATA as DnsApplicationRecordData;

            if (_dnsApplicationManager.Applications.TryGetValue(appRecord.AppName, out DnsApplication application))
            {
                if (application.DnsAppRecordRequestHandlers.TryGetValue(appRecord.ClassPath, out IDnsAppRecordRequestHandler appRecordRequestHandler))
                {
                    AuthZoneInfo zoneInfo = _authZoneManager.FindAuthZoneInfo(appResourceRecord.Name);

                    DnsDatagram appResponse = await appRecordRequestHandler.ProcessRequestAsync(request, remoteEP, protocol, isRecursionAllowed, zoneInfo.Name, appResourceRecord.Name, appResourceRecord.TTL, appRecord.Data);
                    if (appResponse is null)
                    {
                        DnsResponseCode rcode;
                        IReadOnlyList<DnsResourceRecord> authority = null;

                        if ((zoneInfo.Type == AuthZoneType.Forwarder) || (zoneInfo.Type == AuthZoneType.SecondaryForwarder))
                        {
                            //process FWD record if exists
                            if (!zoneInfo.Name.Equals(appResourceRecord.Name, StringComparison.OrdinalIgnoreCase))
                            {
                                AuthZone authZone = _authZoneManager.GetAuthZone(zoneInfo.Name, appResourceRecord.Name);
                                if (authZone is not null)
                                    authority = authZone.QueryRecords(DnsResourceRecordType.FWD, false);
                            }

                            if ((authority is null) || (authority.Count == 0))
                                authority = zoneInfo.ApexZone.QueryRecords(DnsResourceRecordType.FWD, false);

                            if (authority.Count > 0)
                                return await RecursiveResolveAsync(request, remoteEP, authority, _dnssecValidation, false, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);

                            rcode = DnsResponseCode.NoError;
                        }
                        else
                        {
                            //return NODATA/NXDOMAIN response
                            if ((request.Question[0].Name.Length == appResourceRecord.Name.Length) || appResourceRecord.Name.StartsWith('*'))
                                rcode = DnsResponseCode.NoError;
                            else
                                rcode = DnsResponseCode.NxDomain;

                            authority = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.SOA);
                        }

                        return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, rcode, request.Question, null, authority) { Tag = DnsServerResponseType.Authoritative };
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
                    _log.Write(remoteEP, protocol, "DNS request handler '" + appRecord.ClassPath + "' was not found in the application '" + appRecord.AppName + "': " + appResourceRecord.Name);
                }
            }
            else
            {
                _log.Write(remoteEP, protocol, "DNS application '" + appRecord.AppName + "' was not found: " + appResourceRecord.Name);
            }

            //return server failure response with SOA
            {
                AuthZoneInfo zoneInfo = _authZoneManager.FindAuthZoneInfo(request.Question[0].Name);
                IReadOnlyList<DnsResourceRecord> authority = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.SOA);

                return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.ServerFailure, request.Question, null, authority) { Tag = DnsServerResponseType.Authoritative };
            }
        }

        private async Task<DnsDatagram> ProcessCNAMEAsync(DnsDatagram request, DnsDatagram response, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout)
        {
            List<DnsResourceRecord> newAnswer = new List<DnsResourceRecord>(response.Answer.Count + 4);
            newAnswer.AddRange(response.Answer);

            //copying NSEC/NSEC3 for for wildcard answers
            List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(2);

            foreach (DnsResourceRecord record in response.Authority)
            {
                switch (record.Type)
                {
                    case DnsResourceRecordType.NSEC:
                    case DnsResourceRecordType.NSEC3:
                        newAuthority.Add(record);
                        break;

                    case DnsResourceRecordType.RRSIG:
                        switch ((record.RDATA as DnsRRSIGRecordData).TypeCovered)
                        {
                            case DnsResourceRecordType.NSEC:
                            case DnsResourceRecordType.NSEC3:
                                newAuthority.Add(record);
                                break;
                        }
                        break;
                }
            }

            DnsDatagram lastResponse = response;
            bool isAuthoritativeAnswer = response.AuthoritativeAnswer;
            DnsResourceRecord lastRR = response.GetLastAnswerRecord();
            EDnsOption[] eDnsClientSubnetOption = null;
            DnsDatagram newResponse = null;
            double responseRtt = 0.0;

            if (response.Metadata is not null)
                responseRtt = response.Metadata.RoundTripTime;

            if (_eDnsClientSubnet)
            {
                EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                if (requestECS is not null)
                    eDnsClientSubnetOption = [new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, requestECS)];
            }

            int queryCount = 0;
            do
            {
                string cnameDomain = (lastRR.RDATA as DnsCNAMERecordData).Domain;
                if (lastRR.Name.Equals(cnameDomain, StringComparison.OrdinalIgnoreCase))
                    break; //loop detected

                DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, request.CheckingDisabled, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(cnameDomain, request.Question[0].Type, request.Question[0].Class) }, null, null, null, _udpPayloadSize, request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, eDnsClientSubnetOption);

                //query authoritative zone first
                newResponse = await AuthoritativeQueryAsync(newRequest, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, remoteEP);
                if (newResponse is null)
                {
                    //not found in auth zone
                    if (newRequest.RecursionDesired && isRecursionAllowed)
                    {
                        //do recursion
                        newResponse = await RecursiveResolveAsync(newRequest, remoteEP, null, _dnssecValidation, false, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout); //CNAME expansion does not need to use cache refresh operation and should use data from cache instead
                        if (newResponse is null)
                            return null; //drop request

                        isAuthoritativeAnswer = false;
                    }
                    else
                    {
                        //break since no recursion allowed/desired
                        break;
                    }
                }
                else if ((newResponse.Answer.Count > 0) && (newResponse.GetLastAnswerRecord() is DnsResourceRecord lastAnswer) && ((lastAnswer.Type == DnsResourceRecordType.ANAME) || (lastAnswer.Type == DnsResourceRecordType.ALIAS)))
                {
                    newResponse = await ProcessANAMEAsync(request, newResponse, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
                    if (newResponse is null)
                        return null; //drop request
                }
                else if ((newResponse.Answer.Count == 0) && (newResponse.Authority.Count > 0))
                {
                    //found delegated/forwarded zone
                    DnsResourceRecord firstAuthority = newResponse.FindFirstAuthorityRecord();
                    switch (firstAuthority.Type)
                    {
                        case DnsResourceRecordType.NS:
                            if (newRequest.RecursionDesired && isRecursionAllowed)
                            {
                                //do forced recursive resolution using empty conditional forwarders; name servers will be provided via ResolveDnsCache
                                newResponse = await RecursiveResolveAsync(newRequest, remoteEP, [], _dnssecValidation, false, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
                                if (newResponse is null)
                                    return null; //drop request

                                isAuthoritativeAnswer = false;
                            }

                            break;

                        case DnsResourceRecordType.FWD:
                            //do conditional forwarding
                            newResponse = await RecursiveResolveAsync(newRequest, remoteEP, newResponse.Authority, _dnssecValidation, false, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
                            if (newResponse is null)
                                return null; //drop request

                            isAuthoritativeAnswer = false;
                            break;

                        case DnsResourceRecordType.APP:
                            newResponse = await ProcessAPPAsync(newRequest, newResponse, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
                            if (newResponse is null)
                                return null; //drop request

                            break;
                    }
                }

                if (newResponse.Metadata is not null)
                    responseRtt += newResponse.Metadata.RoundTripTime;

                //check last response
                if (newResponse.Answer.Count == 0)
                    break; //cannot proceed to resolve further

                lastRR = newResponse.GetLastAnswerRecord();
                if (lastRR.Type != DnsResourceRecordType.CNAME)
                {
                    newAnswer.AddRange(newResponse.Answer);
                    break; //cname was resolved
                }

                bool foundRepeat = false;

                foreach (DnsResourceRecord newResponseAnswerRecord in newResponse.Answer)
                {
                    if ((newResponseAnswerRecord.Type == DnsResourceRecordType.CNAME) || (newResponseAnswerRecord.Type == DnsResourceRecordType.DNAME))
                    {
                        foreach (DnsResourceRecord answerRecord in newAnswer)
                        {
                            if (newResponseAnswerRecord.Equals(answerRecord))
                            {
                                foundRepeat = true;
                                break;
                            }
                        }

                        if (foundRepeat)
                            break;
                    }

                    newAnswer.Add(newResponseAnswerRecord);
                }

                if (foundRepeat)
                    break; //loop detected

                lastResponse = newResponse;
            }
            while (++queryCount < MAX_CNAME_HOPS);

            DnsResponseCode rcode;
            IReadOnlyList<DnsResourceRecord> authority;
            IReadOnlyList<DnsResourceRecord> additional;

            if (newResponse is null)
            {
                //no recursion available
                rcode = DnsResponseCode.NoError;

                if (newAuthority.Count == 0)
                {
                    authority = lastResponse.Authority;
                }
                else
                {
                    newAuthority.AddRange(lastResponse.Authority);
                    authority = newAuthority;
                }

                additional = lastResponse.Additional;
            }
            else
            {
                rcode = newResponse.RCODE;

                if (newAuthority.Count == 0)
                {
                    authority = newResponse.Authority;
                }
                else
                {
                    newAuthority.AddRange(newResponse.Authority);
                    authority = newAuthority;
                }

                additional = newResponse.Additional;
            }

            DnsDatagram finalResponse = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, isAuthoritativeAnswer, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, rcode, request.Question, newAnswer, authority, additional) { Tag = response.Tag };
            finalResponse.SetMetadata(null, responseRtt);

            return finalResponse;
        }

        private async Task<DnsDatagram> ProcessANAMEAsync(DnsDatagram request, DnsDatagram response, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout)
        {
            EDnsOption[] eDnsClientSubnetOption = null;

            if (_eDnsClientSubnet)
            {
                EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                if (requestECS is not null)
                    eDnsClientSubnetOption = [new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, requestECS)];
            }

            Queue<Task<IReadOnlyList<DnsResourceRecord>>> resolveQueue = new Queue<Task<IReadOnlyList<DnsResourceRecord>>>();

            async Task<IReadOnlyList<DnsResourceRecord>> ResolveANAMEAsync(DnsResourceRecord anameRR, int queryCount = 0)
            {
                string lastDomain = (anameRR.RDATA as DnsANAMERecordData).Domain;
                if (anameRR.Name.Equals(lastDomain, StringComparison.OrdinalIgnoreCase))
                    return null; //loop detected

                do
                {
                    DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, request.CheckingDisabled, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(lastDomain, request.Question[0].Type, request.Question[0].Class) }, null, null, null, _udpPayloadSize, request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, eDnsClientSubnetOption);

                    //query authoritative zone first
                    DnsDatagram newResponse = await AuthoritativeQueryAsync(newRequest, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, remoteEP);
                    if (newResponse is null)
                    {
                        //not found in auth zone; do recursion
                        newResponse = await RecursiveResolveAsync(newRequest, remoteEP, null, _dnssecValidation, false, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
                        if (newResponse is null)
                            return null; //drop request
                    }
                    else if ((newResponse.Answer.Count == 0) && (newResponse.Authority.Count > 0))
                    {
                        //found delegated/forwarded zone
                        DnsResourceRecord firstAuthority = newResponse.FindFirstAuthorityRecord();
                        switch (firstAuthority.Type)
                        {
                            case DnsResourceRecordType.NS:
                                //do forced recursive resolution using empty conditional forwarders; name servers will be provided via ResolverDnsCache
                                newResponse = await RecursiveResolveAsync(newRequest, remoteEP, [], _dnssecValidation, false, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
                                if (newResponse is null)
                                    return null; //drop request

                                break;

                            case DnsResourceRecordType.FWD:
                                //do conditional forwarding
                                newResponse = await RecursiveResolveAsync(newRequest, remoteEP, newResponse.Authority, _dnssecValidation, false, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
                                if (newResponse is null)
                                    return null; //drop request

                                break;

                            case DnsResourceRecordType.APP:
                                newResponse = await ProcessAPPAsync(newRequest, newResponse, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
                                if (newResponse is null)
                                    return null; //drop request

                                break;
                        }
                    }

                    //check new response
                    if (newResponse.RCODE != DnsResponseCode.NoError)
                        return null; //cannot proceed to resolve further

                    if (newResponse.Answer.Count == 0)
                        return Array.Empty<DnsResourceRecord>(); //NO DATA

                    DnsResourceRecordType questionType = request.Question[0].Type;
                    DnsResourceRecord lastRR = newResponse.GetLastAnswerRecord();
                    if (lastRR.Type == questionType)
                    {
                        //found final answer
                        List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                        foreach (DnsResourceRecord answer in newResponse.Answer)
                        {
                            if (answer.Type != questionType)
                                continue;

                            if (anameRR.TTL < answer.TTL)
                                answers.Add(new DnsResourceRecord(anameRR.Name, answer.Type, answer.Class, anameRR.TTL, answer.RDATA));
                            else
                                answers.Add(new DnsResourceRecord(anameRR.Name, answer.Type, answer.Class, answer.TTL, answer.RDATA));
                        }

                        return answers;
                    }

                    switch (lastRR.Type)
                    {
                        case DnsResourceRecordType.ANAME:
                        case DnsResourceRecordType.ALIAS:
                            if (newResponse.Answer.Count == 1)
                            {
                                lastDomain = (lastRR.RDATA as DnsANAMERecordData).Domain;
                            }
                            else
                            {
                                //resolve multiple ANAME records async
                                queryCount++; //increment since one query was done already

                                foreach (DnsResourceRecord newAnswer in newResponse.Answer)
                                    resolveQueue.Enqueue(ResolveANAMEAsync(newAnswer, queryCount));

                                return Array.Empty<DnsResourceRecord>();
                            }
                            break;

                        case DnsResourceRecordType.CNAME:
                            lastDomain = (lastRR.RDATA as DnsCNAMERecordData).Domain;
                            break;

                        default:
                            //aname/cname was resolved, but no answer found
                            return Array.Empty<DnsResourceRecord>();
                    }
                }
                while (++queryCount < MAX_CNAME_HOPS);

                //max hops limit crossed
                return null;
            }

            List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord answer in response.Answer)
            {
                switch (answer.Type)
                {
                    case DnsResourceRecordType.ANAME:
                    case DnsResourceRecordType.ALIAS:
                        resolveQueue.Enqueue(ResolveANAMEAsync(answer));
                        break;

                    default:
                        if (resolveQueue.Count == 0)
                            responseAnswer.Add(answer);

                        break;
                }
            }

            bool foundErrors = false;

            while (resolveQueue.Count > 0)
            {
                IReadOnlyList<DnsResourceRecord> records = await resolveQueue.Dequeue();
                if (records is null)
                    foundErrors = true;
                else if (records.Count > 0)
                    responseAnswer.AddRange(records);
            }

            DnsResponseCode rcode = DnsResponseCode.NoError;
            IReadOnlyList<DnsResourceRecord> authority = null;

            if (responseAnswer.Count == 0)
            {
                if (foundErrors)
                {
                    rcode = DnsResponseCode.ServerFailure;
                }
                else
                {
                    authority = response.Authority;

                    //update last used on
                    DateTime utcNow = DateTime.UtcNow;

                    foreach (DnsResourceRecord record in authority)
                        record.GetAuthGenericRecordInfo().LastUsedOn = utcNow;
                }
            }

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, rcode, request.Question, responseAnswer, authority, null) { Tag = response.Tag };
        }

        private async Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol)
        {
            if (request.Question.Count > 0)
            {
                DnsQuestionRecord question = request.Question[0];
                if (question.Type == DnsResourceRecordType.DS)
                {
                    //DS is at parent zone which causes IsAllowed() to return null; change QTYPE to A to fix this issue that causes allowed domains to fail DNSSEC validation at downstream
                    DnsQuestionRecord newQuestion = new DnsQuestionRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN);
                    request = new DnsDatagram(request.Identifier, request.IsResponse, request.OPCODE, request.AuthoritativeAnswer, request.Truncation, request.RecursionDesired, request.RecursionAvailable, request.AuthenticData, request.CheckingDisabled, request.RCODE, [newQuestion], request.Answer, request.Authority, request.Additional);
                }
            }

            if (_enableBlocking)
            {
                if (_blockingBypassList is not null)
                {
                    IPAddress remoteIP = remoteEP.Address;

                    foreach (NetworkAddress network in _blockingBypassList)
                    {
                        if (network.Contains(remoteIP))
                            return true;
                    }
                }

                if (_allowedZoneManager.IsAllowed(request) || _blockListZoneManager.IsAllowed(request))
                    return true;
            }

            foreach (IDnsRequestBlockingHandler blockingHandler in _dnsApplicationManager.DnsRequestBlockingHandlers)
            {
                try
                {
                    if (await blockingHandler.IsAllowedAsync(request, remoteEP))
                        return true;
                }
                catch (Exception ex)
                {
                    _log.Write(remoteEP, protocol, ex);
                }
            }

            return false;
        }

        private async Task<DnsDatagram> ProcessBlockedQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol)
        {
            if (_enableBlocking)
            {
                DnsDatagram response = _blockedZoneManager.Query(request);
                if (response is null)
                {
                    //domain not blocked in blocked zone
                    response = _blockListZoneManager.Query(request); //check in block list zone
                    if (response is not null)
                    {
                        //domain is blocked in block list zone
                        response.Tag = DnsServerResponseType.Blocked;
                        return response;
                    }

                    //domain not blocked in block list zone; continue to check app blocking handlers
                }
                else
                {
                    //domain is blocked in blocked zone
                    DnsQuestionRecord question = request.Question[0];

                    string GetBlockedDomain()
                    {
                        DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
                        if ((firstAuthority is not null) && (firstAuthority.Type == DnsResourceRecordType.SOA))
                            return firstAuthority.Name;
                        else
                            return question.Name;
                    }

                    if (_allowTxtBlockingReport && (question.Type == DnsResourceRecordType.TXT))
                    {
                        //return meta data
                        string blockedDomain = GetBlockedDomain();

                        IReadOnlyList<DnsResourceRecord> answer = [new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, _blockingAnswerTtl, new DnsTXTRecordData("source=blocked-zone; domain=" + blockedDomain))];

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answer) { Tag = DnsServerResponseType.Blocked };
                    }
                    else
                    {
                        string blockedDomain = null;
                        EDnsOption[] options = null;

                        if (_allowTxtBlockingReport && (request.EDNS is not null))
                        {
                            blockedDomain = GetBlockedDomain();
                            options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, "source=blocked-zone; domain=" + blockedDomain))];
                        }

                        IReadOnlyCollection<DnsARecordData> aRecords;
                        IReadOnlyCollection<DnsAAAARecordData> aaaaRecords;

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
                                if (blockedDomain is null)
                                    blockedDomain = GetBlockedDomain();

                                string parentDomain = AuthZoneManager.GetParentZone(blockedDomain);
                                if (parentDomain is null)
                                    parentDomain = string.Empty;

                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NxDomain, request.Question, null, [new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, _blockingAnswerTtl, _blockedZoneManager.DnsSOARecord)], null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, EDnsHeaderFlags.None, options) { Tag = DnsServerResponseType.Blocked };

                            default:
                                throw new InvalidOperationException();
                        }

                        IReadOnlyList<DnsResourceRecord> answer;
                        IReadOnlyList<DnsResourceRecord> authority = null;

                        switch (question.Type)
                        {
                            case DnsResourceRecordType.A:
                                {
                                    if (aRecords.Count > 0)
                                    {
                                        DnsResourceRecord[] rrList = new DnsResourceRecord[aRecords.Count];
                                        int i = 0;

                                        foreach (DnsARecordData record in aRecords)
                                            rrList[i++] = new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, _blockingAnswerTtl, record);

                                        answer = rrList;
                                    }
                                    else
                                    {
                                        answer = null;
                                        authority = response.Authority;
                                    }
                                }
                                break;

                            case DnsResourceRecordType.AAAA:
                                {
                                    if (aaaaRecords.Count > 0)
                                    {
                                        DnsResourceRecord[] rrList = new DnsResourceRecord[aaaaRecords.Count];
                                        int i = 0;

                                        foreach (DnsAAAARecordData record in aaaaRecords)
                                            rrList[i++] = new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, _blockingAnswerTtl, record);

                                        answer = rrList;
                                    }
                                    else
                                    {
                                        answer = null;
                                        authority = response.Authority;
                                    }
                                }
                                break;

                            default:
                                answer = response.Answer;
                                authority = response.Authority;
                                break;
                        }

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answer, authority, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, EDnsHeaderFlags.None, options) { Tag = DnsServerResponseType.Blocked };
                    }
                }
            }

            foreach (IDnsRequestBlockingHandler blockingHandler in _dnsApplicationManager.DnsRequestBlockingHandlers)
            {
                try
                {
                    DnsDatagram appBlockedResponse = await blockingHandler.ProcessRequestAsync(request, remoteEP);
                    if (appBlockedResponse is not null)
                    {
                        if (appBlockedResponse.Tag is null)
                            appBlockedResponse.Tag = DnsServerResponseType.Blocked;

                        return appBlockedResponse;
                    }
                }
                catch (Exception ex)
                {
                    _log.Write(remoteEP, protocol, ex);
                }
            }

            return null;
        }

        private async Task<DnsDatagram> ProcessRecursiveQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, IReadOnlyList<DnsResourceRecord> conditionalForwarders, bool dnssecValidation, bool cacheRefreshOperation, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout)
        {
            bool isAllowed;

            if (cacheRefreshOperation)
            {
                //cache refresh operation should be able to refresh all the records in cache
                //this is since a blocked CNAME record could still be used by an allowed domain name and so must resolve
                isAllowed = true;
            }
            else
            {
                isAllowed = await IsAllowedAsync(request, remoteEP, protocol);
                if (!isAllowed)
                {
                    DnsDatagram blockedResponse = await ProcessBlockedQueryAsync(request, remoteEP, protocol);
                    if (blockedResponse is not null)
                        return blockedResponse;
                }
            }

            DnsDatagram response = await RecursiveResolveAsync(request, remoteEP, conditionalForwarders, dnssecValidation, false, cacheRefreshOperation, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
            if (response is null)
                return null; //drop request

            if (response.Answer.Count > 0)
            {
                DnsResourceRecordType questionType = request.Question[0].Type;
                DnsResourceRecord lastRR = response.GetLastAnswerRecord();

                if ((lastRR.Type != questionType) && (lastRR.Type == DnsResourceRecordType.CNAME) && (questionType != DnsResourceRecordType.ANY))
                {
                    response = await ProcessCNAMEAsync(request, response, remoteEP, protocol, true, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
                    if (response is null)
                        return null; //drop request
                }

                if (!isAllowed)
                {
                    //check for CNAME cloaking
                    for (int i = 0; i < response.Answer.Count; i++)
                    {
                        DnsResourceRecord record = response.Answer[i];

                        if (record.Type != DnsResourceRecordType.CNAME)
                            break; //no further CNAME records exists

                        DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord((record.RDATA as DnsCNAMERecordData).Domain, request.Question[0].Type, request.Question[0].Class) }, null, null, null, _udpPayloadSize);

                        if (request.Metadata is not null)
                            newRequest.SetMetadata(request.Metadata.NameServer);

                        //check allowed zone
                        isAllowed = await IsAllowedAsync(newRequest, remoteEP, protocol);
                        if (isAllowed)
                            break; //CNAME is in allowed zone

                        //check blocked zone and block list zone
                        DnsDatagram blockedResponse = await ProcessBlockedQueryAsync(newRequest, remoteEP, protocol);
                        if (blockedResponse is not null)
                        {
                            //found cname cloaking
                            List<DnsResourceRecord> answer = new List<DnsResourceRecord>();

                            //copy current and previous CNAME records
                            for (int j = 0; j <= i; j++)
                                answer.Add(response.Answer[j]);

                            //copy last response answers
                            answer.AddRange(blockedResponse.Answer);

                            //include blocked response additional section to pass on Extended DNS Errors
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, blockedResponse.RCODE, request.Question, answer, blockedResponse.Authority, blockedResponse.Additional) { Tag = blockedResponse.Tag };
                        }
                    }
                }
            }

            if (response.Tag is null)
            {
                if (response.IsBlockedResponse())
                    response.Tag = DnsServerResponseType.UpstreamBlocked;
            }
            else if ((DnsServerResponseType)response.Tag == DnsServerResponseType.Cached)
            {
                if (response.IsBlockedResponse())
                    response.Tag = DnsServerResponseType.UpstreamBlockedCached;
            }

            return response;
        }

        private async Task<DnsDatagram> RecursiveResolveAsync(DnsDatagram request, IPEndPoint remoteEP, IReadOnlyList<DnsResourceRecord> conditionalForwarders, bool dnssecValidation, bool cachePrefetchOperation, bool cacheRefreshOperation, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout)
        {
            DnsQuestionRecord question = request.Question[0];
            NetworkAddress eDnsClientSubnet = null;
            bool advancedForwardingClientSubnet = false; //this feature is used by Advanced Forwarding app to cache response per network group

            if (_eDnsClientSubnet)
            {
                EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                if (requestECS is null)
                {
                    if ((_eDnsClientSubnetIpv4Override is not null) && (remoteEP.AddressFamily == AddressFamily.InterNetwork))
                    {
                        //set ipv4 override shadow ECS option
                        eDnsClientSubnet = _eDnsClientSubnetIpv4Override;
                        request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                    }
                    else if ((_eDnsClientSubnetIpv6Override is not null) && (remoteEP.AddressFamily == AddressFamily.InterNetworkV6))
                    {
                        //set ipv6 override shadow ECS option
                        eDnsClientSubnet = _eDnsClientSubnetIpv6Override;
                        request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                    }
                    else if (!NetUtilities.IsPrivateIP(remoteEP.Address))
                    {
                        //set shadow ECS option
                        switch (remoteEP.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                eDnsClientSubnet = new NetworkAddress(remoteEP.Address, _eDnsClientSubnetIPv4PrefixLength);
                                request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                                break;

                            case AddressFamily.InterNetworkV6:
                                eDnsClientSubnet = new NetworkAddress(remoteEP.Address, _eDnsClientSubnetIPv6PrefixLength);
                                request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                                break;

                            default:
                                request.ShadowHideEDnsClientSubnetOption();
                                break;
                        }
                    }
                }
                else if ((requestECS.Family != EDnsClientSubnetAddressFamily.IPv4) && (requestECS.Family != EDnsClientSubnetAddressFamily.IPv6))
                {
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question) { Tag = DnsServerResponseType.Authoritative };
                }
                else if (requestECS.AdvancedForwardingClientSubnet)
                {
                    //request from Advanced Forwarding app
                    advancedForwardingClientSubnet = true;
                    eDnsClientSubnet = new NetworkAddress(requestECS.Address, requestECS.SourcePrefixLength);
                }
                else if ((requestECS.SourcePrefixLength == 0) || NetUtilities.IsPrivateIP(requestECS.Address))
                {
                    //disable ECS option
                    request.ShadowHideEDnsClientSubnetOption();
                }
                else if ((_eDnsClientSubnetIpv4Override is not null) && (remoteEP.AddressFamily == AddressFamily.InterNetwork))
                {
                    //set ipv4 override shadow ECS option
                    eDnsClientSubnet = _eDnsClientSubnetIpv4Override;
                    request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                }
                else if ((_eDnsClientSubnetIpv6Override is not null) && (remoteEP.AddressFamily == AddressFamily.InterNetworkV6))
                {
                    //set ipv6 override shadow ECS option
                    eDnsClientSubnet = _eDnsClientSubnetIpv6Override;
                    request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                }
                else
                {
                    //use ECS from client request
                    switch (requestECS.Family)
                    {
                        case EDnsClientSubnetAddressFamily.IPv4:
                            eDnsClientSubnet = new NetworkAddress(requestECS.Address, Math.Min(requestECS.SourcePrefixLength, _eDnsClientSubnetIPv4PrefixLength));
                            request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                            break;

                        case EDnsClientSubnetAddressFamily.IPv6:
                            eDnsClientSubnet = new NetworkAddress(requestECS.Address, Math.Min(requestECS.SourcePrefixLength, _eDnsClientSubnetIPv6PrefixLength));
                            request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                            break;
                    }
                }
            }
            else
            {
                //ECS feature disabled
                EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                if (requestECS is not null)
                {
                    advancedForwardingClientSubnet = requestECS.AdvancedForwardingClientSubnet;
                    if (advancedForwardingClientSubnet)
                        eDnsClientSubnet = new NetworkAddress(requestECS.Address, requestECS.SourcePrefixLength); //request from Advanced Forwarding app
                    else
                        request.ShadowHideEDnsClientSubnetOption(); //hide ECS option
                }
            }

            if (!cachePrefetchOperation && !cacheRefreshOperation)
            {
                //query cache zone to see if answer available
                DnsDatagram cacheResponse = await QueryCacheAsync(request, false, false);
                if (cacheResponse is not null)
                {
                    if (_cachePrefetchTrigger > 0)
                    {
                        //inspect response TTL values to decide if prefetch trigger is needed
                        foreach (DnsResourceRecord answer in cacheResponse.Answer)
                        {
                            if ((answer.OriginalTtlValue >= _cachePrefetchEligibility) && ((answer.TTL <= _cachePrefetchTrigger) || answer.IsStale))
                            {
                                //trigger prefetch async for this specific answer record
                                _ = PrefetchCacheAsync(new DnsQuestionRecord(answer.Name, question.Type, question.Class), remoteEP, conditionalForwarders);
                                break;
                            }
                        }
                    }

                    return cacheResponse;
                }
            }

            //recursion with locking
            TaskCompletionSource<RecursiveResolveResponse> resolverTaskCompletionSource = new TaskCompletionSource<RecursiveResolveResponse>();
            Task<RecursiveResolveResponse> resolverTask = _resolverTasks.GetOrAdd(GetResolverQueryKey(question, eDnsClientSubnet), resolverTaskCompletionSource.Task);

            if (resolverTask.Equals(resolverTaskCompletionSource.Task))
            {
                //got new resolver task added so question is not being resolved; do recursive resolution in another task on resolver thread pool
                if (!_resolverTaskPool.TryQueueTask(delegate (object state)
                    {
                        return RecursiveResolverBackgroundTaskAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, conditionalForwarders, dnssecValidation, cachePrefetchOperation, cacheRefreshOperation, skipDnsAppAuthoritativeRequestHandlers, resolverTaskCompletionSource);
                    })
                )
                {
                    //resolver queue full
                    if (!_resolverTasks.TryRemove(GetResolverQueryKey(question, eDnsClientSubnet), out _)) //remove recursion lock entry
                        throw new InvalidOperationException();

                    return null; //drop request
                }
            }

            //request is being recursively resolved by another thread

            if (cachePrefetchOperation)
                return null; //return null as prefetch worker thread does not need valid response and thus does not need to wait

            if (_serveStale)
            {
                int waitTimeout = Math.Min(_serveStaleMaxWaitTime, clientTimeout - SERVE_STALE_TIME_DIFFERENCE); //200ms before client timeout or max 1800ms [RFC 8767]
                using CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource();

                //wait till short timeout for response
                if ((waitTimeout > 0) && (await Task.WhenAny(resolverTask, Task.Delay(waitTimeout, timeoutCancellationTokenSource.Token)) == resolverTask))
                {
                    //resolver signaled
                    timeoutCancellationTokenSource.Cancel(); //to stop delay task

                    RecursiveResolveResponse response = await resolverTask;

                    if (response is not null)
                        return PrepareRecursiveResolveResponse(request, response);

                    //resolver had exception
                }
                else
                {
                    //wait timed out

                    //query cache zone to return stale answer (if available) as per RFC 8767
                    DnsDatagram staleResponse = await QueryCacheAsync(request, true, false);
                    if (staleResponse is not null)
                        return staleResponse;

                    //no stale record was found
                    //wait till full timeout before responding as ServerFailure
                    int timeout = clientTimeout - waitTimeout;

                    if (await Task.WhenAny(resolverTask, Task.Delay(timeout, timeoutCancellationTokenSource.Token)) == resolverTask)
                    {
                        //resolver signaled
                        timeoutCancellationTokenSource.Cancel(); //to stop delay task

                        RecursiveResolveResponse response = await resolverTask;

                        if (response is not null)
                            return PrepareRecursiveResolveResponse(request, response);

                        //resolver had exception
                    }
                }
            }
            else
            {
                using CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource();

                //wait till full client timeout for response
                if (await Task.WhenAny(resolverTask, Task.Delay(clientTimeout, timeoutCancellationTokenSource.Token)) == resolverTask)
                {
                    //resolver signaled
                    timeoutCancellationTokenSource.Cancel(); //to stop delay task

                    RecursiveResolveResponse response = await resolverTask;

                    if (response is not null)
                        return PrepareRecursiveResolveResponse(request, response);

                    //resolver had exception
                }
            }

            //no response available; respond with ServerFailure
            EDnsOption[] options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Other, "Waiting for resolver. Please try again."))];
            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, request.CheckingDisabled, DnsResponseCode.ServerFailure, request.Question, null, null, null, _udpPayloadSize, request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options);
        }

        private async Task RecursiveResolverBackgroundTaskAsync(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, IReadOnlyList<DnsResourceRecord> conditionalForwarders, bool dnssecValidation, bool cachePrefetchOperation, bool cacheRefreshOperation, bool skipDnsAppAuthoritativeRequestHandlers, TaskCompletionSource<RecursiveResolveResponse> taskCompletionSource)
        {
            try
            {
                //recursive resolve and update cache
                IDnsCache dnsCache;

                if (cachePrefetchOperation || cacheRefreshOperation)
                    dnsCache = new ResolverPrefetchDnsCache(this, skipDnsAppAuthoritativeRequestHandlers, question);
                else if (skipDnsAppAuthoritativeRequestHandlers || advancedForwardingClientSubnet)
                    dnsCache = _dnsCacheSkipDnsApps; //to prevent request reaching apps again
                else
                    dnsCache = _dnsCache;

                DnsDatagram response;

                if (conditionalForwarders is not null)
                {
                    if (conditionalForwarders.Count > 0)
                    {
                        //do priority based conditional forwarding
                        response = await PriorityConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, skipDnsAppAuthoritativeRequestHandlers, conditionalForwarders);
                    }
                    else
                    {
                        //do force recursive resolution
                        response = await TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                        {
                            return DnsClient.RecursiveResolveAsync(question, dnsCache, _proxy, _preferIPv6, _udpPayloadSize, _randomizeName, _qnameMinimization, dnssecValidation, eDnsClientSubnet, _resolverRetries, _resolverTimeout, _resolverConcurrency, _resolverMaxStackCount, true, true, cancellationToken: cancellationToken1);
                        }, RECURSIVE_RESOLUTION_TIMEOUT);
                    }
                }
                else
                {
                    //do default recursive resolution
                    response = await DefaultRecursiveResolveAsync(question, eDnsClientSubnet, dnsCache, dnssecValidation, skipDnsAppAuthoritativeRequestHandlers);
                }

                switch (response.RCODE)
                {
                    case DnsResponseCode.NoError:
                    case DnsResponseCode.NxDomain:
                    case DnsResponseCode.YXDomain:
                        taskCompletionSource.SetResult(new RecursiveResolveResponse(response, response));
                        break;

                    default:
                        throw new DnsServerException("All name servers failed to answer the request '" + question.ToString() + "'. Received last response with RCODE=" + response.RCODE.ToString() + " from: " + (response.Metadata is null ? "unknown" : response.Metadata.NameServer));
                }
            }
            catch (Exception ex)
            {
                if (_resolverLog is not null)
                {
                    string strForwarders = null;

                    if (conditionalForwarders is not null)
                    {
                        //empty conditional forwarder array is used to force recursive resolution
                        if (conditionalForwarders.Count > 0)
                        {
                            foreach (DnsResourceRecord conditionalForwarder in conditionalForwarders)
                            {
                                NameServerAddress nameServer = (conditionalForwarder.RDATA as DnsForwarderRecordData).NameServer;

                                if (strForwarders is null)
                                    strForwarders = nameServer.ToString();
                                else
                                    strForwarders += ", " + nameServer.ToString();
                            }
                        }
                    }
                    else if ((_forwarders is not null) && (_forwarders.Count > 0))
                    {
                        foreach (NameServerAddress nameServer in _forwarders)
                        {
                            if (strForwarders is null)
                                strForwarders = nameServer.ToString();
                            else
                                strForwarders += ", " + nameServer.ToString();
                        }
                    }

                    _resolverLog.Write("DNS Server failed to resolve the request '" + question.ToString() + "'" + (strForwarders is null ? "" : " using forwarders: " + strForwarders) + ".\r\n" + ex.ToString());
                }

                //fetch failure/stale response to signal; reset stale records
                DnsDatagram cacheRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, dnssecValidation, DnsResponseCode.NoError, [question], null, null, null, _udpPayloadSize, dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(eDnsClientSubnet));
                DnsDatagram cacheResponse = await QueryCacheAsync(cacheRequest, _serveStale, _serveStale);
                if (cacheResponse is not null)
                {
                    //signal failure/stale response
                    if (!dnssecValidation || cacheResponse.AuthenticData)
                    {
                        //no dnssec validation enabled OR cache response is validated data
                        taskCompletionSource.SetResult(new RecursiveResolveResponse(cacheResponse, cacheResponse));
                    }
                    else
                    {
                        //dnssec validation enabled; cache response may be a bogus/failure response

                        static bool HasBogusRecords(IReadOnlyList<DnsResourceRecord> records)
                        {
                            foreach (DnsResourceRecord record in records)
                            {
                                switch (record.DnssecStatus)
                                {
                                    case DnssecStatus.Disabled:
                                    case DnssecStatus.Secure:
                                    case DnssecStatus.Insecure:
                                    case DnssecStatus.Indeterminate:
                                        break;

                                    default:
                                        return true;
                                }
                            }

                            return false;
                        }

                        bool isFailureResponse = false;

                        switch (cacheResponse.RCODE)
                        {
                            case DnsResponseCode.NoError:
                            case DnsResponseCode.NxDomain:
                            case DnsResponseCode.YXDomain:
                                isFailureResponse = HasBogusRecords(cacheResponse.Answer);
                                if (!isFailureResponse)
                                    isFailureResponse = HasBogusRecords(cacheResponse.Authority);

                                break;

                            default:
                                isFailureResponse = true;
                                break;
                        }

                        if (isFailureResponse)
                        {
                            //return failure response
                            List<EDnsOption> options;

                            if ((cacheResponse.EDNS is not null) && (cacheResponse.EDNS.Options.Count > 0))
                            {
                                options = new List<EDnsOption>(cacheResponse.EDNS.Options.Count);

                                foreach (EDnsOption option in cacheResponse.EDNS.Options)
                                {
                                    if (option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR)
                                        options.Add(option);
                                }
                            }
                            else
                            {
                                options = null;
                            }

                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, dnssecValidation, DnsResponseCode.ServerFailure, [question], null, null, null, _udpPayloadSize, dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options);

                            taskCompletionSource.SetResult(new RecursiveResolveResponse(failureResponse, cacheResponse));
                        }
                        else
                        {
                            //return cached stale answer
                            taskCompletionSource.SetResult(new RecursiveResolveResponse(cacheResponse, cacheResponse));
                        }
                    }
                }
                else
                {
                    IReadOnlyList<EDnsOption> options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Other, "Resolver exception"))];
                    DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, dnssecValidation, DnsResponseCode.ServerFailure, [question], null, null, null, _udpPayloadSize, dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options);

                    taskCompletionSource.SetResult(new RecursiveResolveResponse(failureResponse, failureResponse));
                }
            }
            finally
            {
                _resolverTasks.TryRemove(GetResolverQueryKey(question, eDnsClientSubnet), out _);
            }
        }

        private async Task<DnsDatagram> DefaultRecursiveResolveAsync(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet, IDnsCache dnsCache, bool dnssecValidation, bool skipDnsAppAuthoritativeRequestHandlers, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<NameServerAddress> forwarders = _forwarders;

            if ((forwarders is not null) && (forwarders.Count > 0))
            {
                //use forwarders
                if (_concurrentForwarding)
                {
                    if (_proxy is null)
                    {
                        //recursive resolve forwarders only when proxy is null else let proxy resolve it to allow using .onion or private domains
                        List<NameServerAddress> newForwarders = new List<NameServerAddress>(forwarders.Count);
                        List<Task<NameServerAddress>> resolveTasks = new List<Task<NameServerAddress>>(forwarders.Count);

                        foreach (NameServerAddress forwarder in forwarders)
                        {
                            if (forwarder.IsIPEndPointStale)
                            {
                                //refresh forwarder IPEndPoint if stale
                                resolveTasks.Add(TechnitiumLibrary.TaskExtensions.TimeoutAsync(async delegate (CancellationToken cancellationToken1)
                                {
                                    await forwarder.RecursiveResolveIPAddressAsync(dnsCache, null, _preferIPv6, _udpPayloadSize, _randomizeName, _resolverRetries, _resolverTimeout, _resolverConcurrency, _resolverMaxStackCount, cancellationToken1);
                                    return forwarder;
                                }, RECURSIVE_RESOLUTION_TIMEOUT, cancellationToken));
                            }
                            else
                            {
                                newForwarders.Add(forwarder);
                            }
                        }

                        Exception lastException = null;

                        foreach (Task<NameServerAddress> resolveTask in resolveTasks)
                        {
                            try
                            {
                                newForwarders.Add(await resolveTask);
                            }
                            catch (Exception ex)
                            {
                                lastException = ex;
                                _resolverLog?.Write(ex);
                            }
                        }

                        if (newForwarders.Count < 1)
                            throw new DnsServerException("Failed to resolve forwarder domain name for all forwarders: " + forwarders.Join(), lastException);

                        forwarders = newForwarders;
                    }

                    //query forwarders and update cache
                    DnsClient dnsClient = new DnsClient(forwarders);

                    dnsClient.Cache = dnsCache;
                    dnsClient.Proxy = _proxy;
                    dnsClient.PreferIPv6 = _preferIPv6;
                    dnsClient.RandomizeName = _randomizeName;
                    dnsClient.Retries = _forwarderRetries;
                    dnsClient.Timeout = _forwarderTimeout;
                    dnsClient.Concurrency = _forwarderConcurrency;
                    dnsClient.UdpPayloadSize = _udpPayloadSize;
                    dnsClient.DnssecValidation = dnssecValidation;
                    dnsClient.EDnsClientSubnet = eDnsClientSubnet;
                    dnsClient.ConditionalForwardingZoneCut = question.Name; //adding zone cut to allow CNAME domains to be resolved independently to handle cases when private/forwarder zone is configured for them

                    return await dnsClient.ResolveAsync(question, cancellationToken);
                }
                else
                {
                    //do sequentially ordered forwarding
                    Exception lastException = null;

                    foreach (NameServerAddress forwarder in forwarders)
                    {
                        if (_proxy is null)
                        {
                            //recursive resolve forwarder only when proxy is null else let proxy resolve it to allow using .onion or private domains
                            if (forwarder.IsIPEndPointStale)
                            {
                                try
                                {
                                    //refresh forwarder IPEndPoint if stale
                                    await TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                                    {
                                        return forwarder.RecursiveResolveIPAddressAsync(dnsCache, null, _preferIPv6, _udpPayloadSize, _randomizeName, _resolverRetries, _resolverTimeout, _resolverConcurrency, _resolverMaxStackCount, cancellationToken1);
                                    }, RECURSIVE_RESOLUTION_TIMEOUT, cancellationToken);
                                }
                                catch (Exception ex)
                                {
                                    //failed to refresh forwarder IP address; try next forwarder
                                    lastException = ex;
                                    _resolverLog?.Write(ex);
                                    continue;
                                }
                            }
                        }

                        //query forwarder and update cache
                        DnsClient dnsClient = new DnsClient(forwarder);

                        dnsClient.Cache = dnsCache;
                        dnsClient.Proxy = _proxy;
                        dnsClient.PreferIPv6 = _preferIPv6;
                        dnsClient.RandomizeName = _randomizeName;
                        dnsClient.Retries = _forwarderRetries;
                        dnsClient.Timeout = _forwarderTimeout;
                        dnsClient.Concurrency = _forwarderConcurrency;
                        dnsClient.UdpPayloadSize = _udpPayloadSize;
                        dnsClient.DnssecValidation = dnssecValidation;
                        dnsClient.EDnsClientSubnet = eDnsClientSubnet;
                        dnsClient.ConditionalForwardingZoneCut = question.Name; //adding zone cut to allow CNAME domains to be resolved independently to handle cases when private/forwarder zone is configured for them

                        try
                        {
                            return await dnsClient.ResolveAsync(question, cancellationToken);
                        }
                        catch (Exception ex)
                        {
                            lastException = ex;
                        }

                        if (dnsCache is not ResolverPrefetchDnsCache)
                            dnsCache = new ResolverPrefetchDnsCache(this, skipDnsAppAuthoritativeRequestHandlers, question); //to prevent low priority tasks to read failure response from cache
                    }

                    ExceptionDispatchInfo.Capture(lastException).Throw();
                    throw lastException;
                }
            }
            else
            {
                //do recursive resolution
                return await TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                {
                    return DnsClient.RecursiveResolveAsync(question, dnsCache, _proxy, _preferIPv6, _udpPayloadSize, _randomizeName, _qnameMinimization, dnssecValidation, eDnsClientSubnet, _resolverRetries, _resolverTimeout, _resolverConcurrency, _resolverMaxStackCount, true, true, null, cancellationToken1);
                }, RECURSIVE_RESOLUTION_TIMEOUT, cancellationToken);
            }
        }

        internal async Task<DnsDatagram> PriorityConditionalForwarderResolveAsync(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, IDnsCache dnsCache, bool skipDnsAppAuthoritativeRequestHandlers, IReadOnlyList<DnsResourceRecord> conditionalForwarders)
        {
            if (conditionalForwarders.Count == 1)
            {
                DnsResourceRecord conditionalForwarder = conditionalForwarders[0];
                return await ConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, conditionalForwarder.RDATA as DnsForwarderRecordData, conditionalForwarder.Name, skipDnsAppAuthoritativeRequestHandlers);
            }

            //check for forwarder name server resolution
            List<Task> resolveTasks = new List<Task>(conditionalForwarders.Count);

            foreach (DnsResourceRecord conditionalForwarder in conditionalForwarders)
            {
                if (conditionalForwarder.Type != DnsResourceRecordType.FWD)
                    continue;

                DnsForwarderRecordData forwarder = conditionalForwarder.RDATA as DnsForwarderRecordData;

                if (forwarder.Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                    continue; //skip resolving

                NetProxy proxy = forwarder.GetProxy(_proxy);
                if (proxy is null)
                {
                    //recursive resolve forwarder only when proxy is null else let proxy resolve it to allow using .onion or private domains
                    if (forwarder.NameServer.IsIPEndPointStale)
                    {
                        //refresh forwarder IPEndPoint if stale
                        resolveTasks.Add(TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                        {
                            return forwarder.NameServer.RecursiveResolveIPAddressAsync(dnsCache, null, _preferIPv6, _udpPayloadSize, _randomizeName, _resolverRetries, _resolverTimeout, _resolverConcurrency, _resolverMaxStackCount, cancellationToken1);
                        }, RECURSIVE_RESOLUTION_TIMEOUT));
                    }
                }
            }

            Exception lastResolverException = null;

            foreach (Task resolverTask in resolveTasks)
            {
                try
                {
                    await resolverTask;
                }
                catch (Exception ex)
                {
                    lastResolverException = ex;
                    _resolverLog?.Write(ex);
                }
            }

            //group by priority
            Dictionary<byte, List<DnsResourceRecord>> conditionalForwarderGroups = new Dictionary<byte, List<DnsResourceRecord>>(conditionalForwarders.Count);
            {
                foreach (DnsResourceRecord conditionalForwarder in conditionalForwarders)
                {
                    if (conditionalForwarder.Type != DnsResourceRecordType.FWD)
                        continue;

                    DnsForwarderRecordData forwarder = conditionalForwarder.RDATA as DnsForwarderRecordData;

                    if (forwarder.NameServer.IsIPEndPointStale)
                        continue; //skip stale forwarders since they failed to resolve

                    if (conditionalForwarderGroups.TryGetValue(forwarder.Priority, out List<DnsResourceRecord> conditionalForwardersEntry))
                    {
                        conditionalForwardersEntry.Add(conditionalForwarder);
                    }
                    else
                    {
                        conditionalForwardersEntry = new List<DnsResourceRecord>(2)
                        {
                            conditionalForwarder
                        };

                        conditionalForwarderGroups[forwarder.Priority] = conditionalForwardersEntry;
                    }
                }
            }

            if (conditionalForwarderGroups.Count < 1)
            {
                List<NameServerAddress> forwarders = new List<NameServerAddress>(conditionalForwarders.Count);

                foreach (DnsResourceRecord conditionalForwarder in conditionalForwarders)
                {
                    if (conditionalForwarder.Type != DnsResourceRecordType.FWD)
                        continue;

                    forwarders.Add((conditionalForwarder.RDATA as DnsForwarderRecordData).NameServer);
                }

                throw new DnsServerException("Failed to resolve forwarder domain name for all conditional forwarders: " + forwarders.Join(), lastResolverException);
            }

            if (conditionalForwarderGroups.Count == 1)
            {
                foreach (KeyValuePair<byte, List<DnsResourceRecord>> conditionalForwardersEntry in conditionalForwarderGroups)
                    return await ConcurrentConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, conditionalForwardersEntry.Value, skipDnsAppAuthoritativeRequestHandlers);
            }

            List<byte> priorities = new List<byte>(conditionalForwarderGroups.Keys);
            priorities.Sort();

            using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
            {
                CancellationToken currentCancellationToken = cancellationTokenSource.Token;

                DnsDatagram lastResponse = null;
                Exception lastException = null;

                foreach (byte priority in priorities)
                {
                    if (!conditionalForwarderGroups.TryGetValue(priority, out List<DnsResourceRecord> conditionalForwardersEntry))
                        continue;

                    Task<DnsDatagram> priorityTask = ConcurrentConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, conditionalForwardersEntry, skipDnsAppAuthoritativeRequestHandlers, currentCancellationToken);

                    try
                    {
                        DnsDatagram priorityTaskResponse = await priorityTask; //await to get response

                        switch (priorityTaskResponse.RCODE)
                        {
                            case DnsResponseCode.NoError:
                            case DnsResponseCode.NxDomain:
                            case DnsResponseCode.YXDomain:
                                cancellationTokenSource.Cancel(); //to stop other priority resolver tasks
                                return priorityTaskResponse;

                            default:
                                //keep response
                                lastResponse = priorityTaskResponse;
                                break;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        lastException = ex;

                        if (lastException is AggregateException)
                            lastException = lastException.InnerException;
                    }

                    if (dnsCache is not ResolverPrefetchDnsCache)
                        dnsCache = new ResolverPrefetchDnsCache(this, skipDnsAppAuthoritativeRequestHandlers, question); //to prevent low priority tasks to read failure response from cache
                }

                if (lastResponse is not null)
                    return lastResponse;

                if (lastException is not null)
                    ExceptionDispatchInfo.Capture(lastException).Throw();

                throw new InvalidOperationException();
            }
        }

        private async Task<DnsDatagram> ConcurrentConditionalForwarderResolveAsync(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, IDnsCache dnsCache, List<DnsResourceRecord> conditionalForwarders, bool skipDnsAppAuthoritativeRequestHandlers, CancellationToken cancellationToken = default)
        {
            if (conditionalForwarders.Count == 1)
            {
                DnsResourceRecord conditionalForwarder = conditionalForwarders[0];
                return await ConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, conditionalForwarder.RDATA as DnsForwarderRecordData, conditionalForwarder.Name, skipDnsAppAuthoritativeRequestHandlers, cancellationToken);
            }

            using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
            {
                using CancellationTokenRegistration r = cancellationToken.Register(cancellationTokenSource.Cancel);

                CancellationToken currentCancellationToken = cancellationTokenSource.Token;
                List<Task<DnsDatagram>> tasks = new List<Task<DnsDatagram>>(conditionalForwarders.Count);

                //start worker tasks
                foreach (DnsResourceRecord conditionalForwarder in conditionalForwarders)
                {
                    if (conditionalForwarder.Type != DnsResourceRecordType.FWD)
                        continue;

                    DnsForwarderRecordData forwarder = conditionalForwarder.RDATA as DnsForwarderRecordData;

                    tasks.Add(Task.Factory.StartNew(delegate ()
                    {
                        return ConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, forwarder, conditionalForwarder.Name, skipDnsAppAuthoritativeRequestHandlers, currentCancellationToken);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current).Unwrap());
                }

                //wait for first positive response, or for all tasks to fault
                DnsDatagram lastResponse = null;
                Exception lastException = null;

                while (tasks.Count > 0)
                {
                    Task<DnsDatagram> completedTask = await Task.WhenAny(tasks);

                    try
                    {
                        DnsDatagram taskResponse = await completedTask; //await to get response

                        switch (taskResponse.RCODE)
                        {
                            case DnsResponseCode.NoError:
                            case DnsResponseCode.NxDomain:
                            case DnsResponseCode.YXDomain:
                                cancellationTokenSource.Cancel(); //to stop other resolver tasks
                                return taskResponse;

                            default:
                                //keep response
                                lastResponse = taskResponse;
                                break;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        lastException = ex;

                        if (lastException is AggregateException)
                            lastException = lastException.InnerException;
                    }

                    tasks.Remove(completedTask);
                }

                if (lastResponse is not null)
                    return lastResponse;

                if (lastException is not null)
                    ExceptionDispatchInfo.Capture(lastException).Throw();

                throw new InvalidOperationException();
            }
        }

        private Task<DnsDatagram> ConditionalForwarderResolveAsync(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, IDnsCache dnsCache, DnsForwarderRecordData forwarder, string conditionalForwardingZoneCut, bool skipDnsAppAuthoritativeRequestHandlers, CancellationToken cancellationToken = default)
        {
            if (forwarder.Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
            {
                //resolve via default recursive resolver with DNSSEC validation preference
                return DefaultRecursiveResolveAsync(question, eDnsClientSubnet, dnsCache, forwarder.DnssecValidation, skipDnsAppAuthoritativeRequestHandlers, cancellationToken);
            }
            else
            {
                //resolve via conditional forwarder
                DnsClient dnsClient = new DnsClient(forwarder.NameServer);

                dnsClient.Cache = dnsCache;
                dnsClient.Proxy = forwarder.GetProxy(_proxy);
                dnsClient.PreferIPv6 = _preferIPv6;
                dnsClient.RandomizeName = _randomizeName;
                dnsClient.Retries = _forwarderRetries;
                dnsClient.Timeout = _forwarderTimeout;
                dnsClient.Concurrency = _forwarderConcurrency;
                dnsClient.UdpPayloadSize = _udpPayloadSize;
                dnsClient.DnssecValidation = forwarder.DnssecValidation;
                dnsClient.EDnsClientSubnet = eDnsClientSubnet;
                dnsClient.AdvancedForwardingClientSubnet = advancedForwardingClientSubnet;
                dnsClient.ConditionalForwardingZoneCut = conditionalForwardingZoneCut;

                return dnsClient.ResolveAsync(question, cancellationToken);
            }
        }

        private DnsDatagram PrepareRecursiveResolveResponse(DnsDatagram request, RecursiveResolveResponse resolveResponse)
        {
            //get a tailored response for the request
            bool dnssecOk = request.DnssecOk;

            if (request.CheckingDisabled)
            {
                DnsDatagram cdResponse = resolveResponse.CheckingDisabledResponse;
                bool authenticData = false;
                IReadOnlyList<DnsResourceRecord> cdAnswer;
                IReadOnlyList<DnsResourceRecord> cdAuthority;
                IReadOnlyList<DnsResourceRecord> cdAdditional = RemoveOPTFromAdditional(cdResponse.Additional, dnssecOk);
                EDnsHeaderFlags ednsFlags;

                if (dnssecOk)
                {
                    if (cdResponse.Answer.Count > 0)
                    {
                        authenticData = true;

                        foreach (DnsResourceRecord record in cdResponse.Answer)
                        {
                            if (record.DnssecStatus != DnssecStatus.Secure)
                            {
                                authenticData = false;
                                break;
                            }
                        }
                    }
                    else if (cdResponse.Authority.Count > 0)
                    {
                        authenticData = true;

                        foreach (DnsResourceRecord record in cdResponse.Authority)
                        {
                            if (record.DnssecStatus != DnssecStatus.Secure)
                            {
                                authenticData = false;
                                break;
                            }
                        }
                    }

                    cdAnswer = cdResponse.Answer;
                    cdAuthority = cdResponse.Authority;
                    ednsFlags = EDnsHeaderFlags.DNSSEC_OK;
                }
                else
                {
                    cdAnswer = FilterDnssecRecords(cdResponse.Answer);
                    cdAuthority = FilterDnssecRecords(cdResponse.Authority);
                    ednsFlags = EDnsHeaderFlags.None;
                }

                DnsDatagram finalCdResponse = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, authenticData, true, cdResponse.RCODE, request.Question, cdAnswer, cdAuthority, cdAdditional, _udpPayloadSize, ednsFlags, cdResponse.EDNS?.Options);
                DnsDatagramMetadata metadata = cdResponse.Metadata;
                if (metadata is not null)
                    finalCdResponse.SetMetadata(metadata.NameServer, metadata.RoundTripTime);

                return finalCdResponse;
            }

            DnsResponseCode rCode;
            DnsDatagram response = resolveResponse.Response;
            IReadOnlyList<DnsResourceRecord> answer = response.Answer;
            IReadOnlyList<DnsResourceRecord> authority = response.Authority;
            IReadOnlyList<DnsResourceRecord> additional = response.Additional;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                case DnsResponseCode.NxDomain:
                case DnsResponseCode.YXDomain:
                    rCode = response.RCODE;
                    break;

                default:
                    rCode = DnsResponseCode.ServerFailure;
                    break;
            }

            //answer section checks
            if (!dnssecOk && (answer.Count > 0) && (response.Question[0].Type != DnsResourceRecordType.ANY))
            {
                //remove RRSIGs from answer
                bool foundRRSIG = false;

                foreach (DnsResourceRecord record in answer)
                {
                    if (record.Type == DnsResourceRecordType.RRSIG)
                    {
                        foundRRSIG = true;
                        break;
                    }
                }

                if (foundRRSIG)
                {
                    List<DnsResourceRecord> newAnswer = new List<DnsResourceRecord>(answer.Count);

                    foreach (DnsResourceRecord record in answer)
                    {
                        if (record.Type == DnsResourceRecordType.RRSIG)
                            continue;

                        newAnswer.Add(record);
                    }

                    answer = newAnswer;
                }
            }

            //authority section checks
            if (!dnssecOk && (authority.Count > 0))
            {
                //remove DNSSEC records
                bool foundDnssecRecords = false;
                bool foundOther = false;

                foreach (DnsResourceRecord record in authority)
                {
                    switch (record.Type)
                    {
                        case DnsResourceRecordType.DS:
                        case DnsResourceRecordType.DNSKEY:
                        case DnsResourceRecordType.RRSIG:
                        case DnsResourceRecordType.NSEC:
                        case DnsResourceRecordType.NSEC3:
                            foundDnssecRecords = true;
                            break;

                        default:
                            foundOther = true;
                            break;
                    }
                }

                if (foundDnssecRecords)
                {
                    if (foundOther)
                    {
                        List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(2);

                        foreach (DnsResourceRecord record in authority)
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.DS:
                                case DnsResourceRecordType.DNSKEY:
                                case DnsResourceRecordType.RRSIG:
                                case DnsResourceRecordType.NSEC:
                                case DnsResourceRecordType.NSEC3:
                                    break;

                                default:
                                    newAuthority.Add(record);
                                    break;
                            }
                        }

                        authority = newAuthority;
                    }
                    else
                    {
                        authority = Array.Empty<DnsResourceRecord>();
                    }
                }
            }

            //additional section checks
            if (additional.Count > 0)
            {
                if ((request.EDNS is not null) && (response.EDNS is not null) && ((response.EDNS.Options.Count > 0) || (response.DnsClientExtendedErrors.Count > 0)))
                {
                    //copy options as new OPT and keep other records
                    List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>(additional.Count);

                    foreach (DnsResourceRecord record in additional)
                    {
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.OPT:
                                continue;

                            case DnsResourceRecordType.RRSIG:
                            case DnsResourceRecordType.DNSKEY:
                                if (dnssecOk)
                                    break;

                                continue;
                        }

                        newAdditional.Add(record);
                    }

                    IReadOnlyList<EDnsOption> options;

                    if (response.GetEDnsClientSubnetOption(true) is not null)
                    {
                        //response contains ECS
                        if (request.GetEDnsClientSubnetOption(true) is not null)
                        {
                            //request has ECS and type is supported; keep ECS in response
                            options = response.EDNS.Options;
                        }
                        else
                        {
                            //cache does not support the qtype so remove ECS from response
                            if (response.EDNS.Options.Count == 1)
                            {
                                options = Array.Empty<EDnsOption>();
                            }
                            else
                            {
                                List<EDnsOption> newOptions = new List<EDnsOption>(response.EDNS.Options.Count);

                                foreach (EDnsOption option in response.EDNS.Options)
                                {
                                    if (option.Code != EDnsOptionCode.EDNS_CLIENT_SUBNET)
                                        newOptions.Add(option);
                                }

                                options = newOptions;
                            }
                        }
                    }
                    else
                    {
                        options = response.EDNS.Options;
                    }

                    if (response.DnsClientExtendedErrors.Count > 0)
                    {
                        //add dns client extended errors
                        List<EDnsOption> newOptions = new List<EDnsOption>(options.Count + response.DnsClientExtendedErrors.Count);

                        newOptions.AddRange(options);

                        foreach (EDnsExtendedDnsErrorOptionData ee in response.DnsClientExtendedErrors)
                            newOptions.Add(new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, ee));

                        options = newOptions;
                    }

                    newAdditional.Add(DnsDatagramEdns.GetOPTFor(_udpPayloadSize, rCode, 0, request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options));

                    additional = newAdditional;
                }
                else if (response.EDNS is not null)
                {
                    //remove OPT from additional
                    additional = RemoveOPTFromAdditional(additional, dnssecOk);
                }
            }

            {
                bool authenticData = false;

                if (dnssecOk)
                {
                    if (answer.Count > 0)
                    {
                        authenticData = true;

                        foreach (DnsResourceRecord record in answer)
                        {
                            if (record.DnssecStatus != DnssecStatus.Secure)
                            {
                                authenticData = false;
                                break;
                            }
                        }
                    }
                    else if (authority.Count > 0)
                    {
                        authenticData = true;

                        foreach (DnsResourceRecord record in authority)
                        {
                            if (record.DnssecStatus != DnssecStatus.Secure)
                            {
                                authenticData = false;
                                break;
                            }
                        }
                    }
                }

                DnsDatagram finalResponse = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, authenticData, request.CheckingDisabled, rCode, request.Question, answer, authority, additional);
                DnsDatagramMetadata metadata = response.Metadata;
                if (metadata is not null)
                    finalResponse.SetMetadata(metadata.NameServer, metadata.RoundTripTime);

                return finalResponse;
            }
        }

        private static IReadOnlyList<DnsResourceRecord> FilterDnssecRecords(IReadOnlyList<DnsResourceRecord> records)
        {
            foreach (DnsResourceRecord record1 in records)
            {
                switch (record1.Type)
                {
                    case DnsResourceRecordType.RRSIG:
                    case DnsResourceRecordType.NSEC:
                    case DnsResourceRecordType.NSEC3:
                        List<DnsResourceRecord> noDnssecRecords = new List<DnsResourceRecord>();

                        foreach (DnsResourceRecord record2 in records)
                        {
                            switch (record2.Type)
                            {
                                case DnsResourceRecordType.RRSIG:
                                case DnsResourceRecordType.NSEC:
                                case DnsResourceRecordType.NSEC3:
                                    break;

                                default:
                                    noDnssecRecords.Add(record2);
                                    break;
                            }
                        }

                        return noDnssecRecords;
                }
            }

            return records;
        }

        private static IReadOnlyList<DnsResourceRecord> RemoveOPTFromAdditional(IReadOnlyList<DnsResourceRecord> additional, bool dnssecOk)
        {
            if (additional.Count == 0)
                return additional;

            if ((additional.Count == 1) && (additional[0].Type == DnsResourceRecordType.OPT))
                return Array.Empty<DnsResourceRecord>();

            List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>(additional.Count - 1);

            foreach (DnsResourceRecord record in additional)
            {
                switch (record.Type)
                {
                    case DnsResourceRecordType.OPT:
                        continue;

                    case DnsResourceRecordType.RRSIG:
                    case DnsResourceRecordType.DNSKEY:
                        if (dnssecOk)
                            break;

                        continue;
                }

                newAdditional.Add(record);
            }

            return newAdditional;
        }

        private static string GetResolverQueryKey(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet)
        {
            if (eDnsClientSubnet is null)
                return question.ToString();

            return question.ToString() + " " + eDnsClientSubnet.ToString();
        }

        private async Task<DnsDatagram> QueryCacheAsync(DnsDatagram request, bool serveStale, bool resetExpiry)
        {
            DnsDatagram cacheResponse = await _cacheZoneManager.QueryAsync(request, serveStale, false, resetExpiry);
            if (cacheResponse is not null)
            {
                if ((cacheResponse.RCODE != DnsResponseCode.NoError) || (cacheResponse.Answer.Count > 0) || (cacheResponse.Authority.Count == 0) || cacheResponse.IsFirstAuthoritySOA())
                {
                    cacheResponse.Tag = DnsServerResponseType.Cached;

                    return cacheResponse;
                }
            }

            return null;
        }

        private async Task PrefetchCacheAsync(DnsQuestionRecord question, IPEndPoint remoteEP, IReadOnlyList<DnsResourceRecord> conditionalForwarders)
        {
            try
            {
                DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [question]);
                _ = await RecursiveResolveAsync(request, remoteEP, conditionalForwarders, _dnssecValidation, true, false, false, _clientTimeout);
            }
            catch (Exception ex)
            {
                _resolverLog?.Write(ex);
            }
        }

        private async Task RefreshCacheAsync(DnsQuestionRecord neededQuestion, IList<CacheRefreshSample> cacheRefreshSampleList, CacheRefreshSample sample, int sampleQuestionIndex)
        {
            try
            {
                //refresh cache
                DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [neededQuestion]);
                _ = await ProcessRecursiveQueryAsync(request, IPENDPOINT_ANY_0, DnsTransportProtocol.Udp, sample.ConditionalForwarders, _dnssecValidation, true, false, _clientTimeout);
            }
            catch (Exception ex)
            {
                _resolverLog?.Write(ex);
            }
            finally
            {
                cacheRefreshSampleList[sampleQuestionIndex] = sample; //put back into sample list to allow refreshing it again
            }
        }

        private async Task<DnsQuestionRecord> GetCacheRefreshNeededQueryAsync(DnsQuestionRecord question, int trigger)
        {
            DnsDatagram cacheResponse = await QueryCacheAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }), false, false);
            if (cacheResponse is null)
                return question; //cache expired so refresh question

            if (cacheResponse.Answer.Count == 0)
                return null; //dont refresh empty responses

            //inspect response TTL values to decide if refresh is needed
            foreach (DnsResourceRecord answer in cacheResponse.Answer)
            {
                if ((answer.OriginalTtlValue >= _cachePrefetchEligibility) && ((answer.TTL <= trigger) || answer.IsStale))
                    return new DnsQuestionRecord(answer.Name, question.Type, question.Class); //TTL eligible and less than trigger so refresh for current answer record
            }

            DnsResourceRecord lastRR = cacheResponse.Answer[cacheResponse.Answer.Count - 1];
            if (lastRR.Type == DnsResourceRecordType.CNAME)
                return new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecordData).Domain, question.Type, question.Class); //found incomplete response; refresh the last CNAME domain name

            return null; //refresh not needed
        }

        private async void CachePrefetchSamplingTimerCallback(object state)
        {
            try
            {
                List<KeyValuePair<DnsQuestionRecord, long>> eligibleQueries = _statsManager.GetLastHourEligibleQueries(_cachePrefetchSampleEligibilityHitsPerHour);
                List<CacheRefreshSample> cacheRefreshSampleList = new List<CacheRefreshSample>(eligibleQueries.Count);
                int cacheRefreshTrigger = (_cachePrefetchSampleIntervalMinutes + 1) * 60; //extra 1 min to account for any delays in next sampling

                foreach (KeyValuePair<DnsQuestionRecord, long> eligibleQuery in eligibleQueries)
                {
                    DnsQuestionRecord eligibleQuerySample = eligibleQuery.Key;

                    if (eligibleQuerySample.Type == DnsResourceRecordType.ANY)
                        continue; //dont refresh type ANY queries

                    DnsQuestionRecord refreshQuery = null;
                    IReadOnlyList<DnsResourceRecord> conditionalForwarders = null;

                    //query auth zone for refresh query
                    int queryCount = 0;
                    bool reQueryAuthZone;
                    do
                    {
                        reQueryAuthZone = false;

                        DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { eligibleQuerySample });
                        DnsDatagram response = await AuthoritativeQueryAsync(request, DnsTransportProtocol.Tcp, true, false, IPENDPOINT_ANY_0);
                        if (response is null)
                        {
                            //zone not hosted; do refresh
                            refreshQuery = await GetCacheRefreshNeededQueryAsync(eligibleQuerySample, cacheRefreshTrigger);
                        }
                        else
                        {
                            //zone is hosted; check further
                            if (response.Answer.Count > 0)
                            {
                                DnsResourceRecord lastRR = response.GetLastAnswerRecord();
                                if ((lastRR.Type == DnsResourceRecordType.CNAME) && (eligibleQuerySample.Type != DnsResourceRecordType.CNAME))
                                {
                                    eligibleQuerySample = new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecordData).Domain, eligibleQuerySample.Type, eligibleQuerySample.Class);
                                    reQueryAuthZone = true;
                                }
                            }
                            else if (response.Authority.Count > 0)
                            {
                                DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
                                switch (firstAuthority.Type)
                                {
                                    case DnsResourceRecordType.NS: //zone is delegated
                                        refreshQuery = await GetCacheRefreshNeededQueryAsync(eligibleQuerySample, cacheRefreshTrigger);
                                        conditionalForwarders = Array.Empty<DnsResourceRecord>(); //do forced recursive resolution using empty conditional forwarders
                                        break;

                                    case DnsResourceRecordType.FWD: //zone is conditional forwarder
                                        refreshQuery = await GetCacheRefreshNeededQueryAsync(eligibleQuerySample, cacheRefreshTrigger);
                                        conditionalForwarders = response.Authority; //do conditional forwarding
                                        break;
                                }
                            }
                        }
                    }
                    while (reQueryAuthZone && (++queryCount < MAX_CNAME_HOPS));

                    if (refreshQuery is not null)
                    {
                        bool alreadyExists = false;

                        foreach (CacheRefreshSample cacheRefreshSample in cacheRefreshSampleList)
                        {
                            if (cacheRefreshSample.SampleQuestion.Equals(refreshQuery))
                            {
                                alreadyExists = true;
                                break; //already exists in sample list
                            }
                        }

                        if (!alreadyExists)
                            cacheRefreshSampleList.Add(new CacheRefreshSample(refreshQuery, conditionalForwarders));
                    }
                }

                _cacheRefreshSampleList = cacheRefreshSampleList;
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
            finally
            {
                lock (_cachePrefetchSamplingTimerLock)
                {
                    _cachePrefetchSamplingTimer?.Change(_cachePrefetchSampleIntervalMinutes * 60 * 1000, Timeout.Infinite);
                }
            }
        }

        private async void CachePrefetchRefreshTimerCallback(object state)
        {
            try
            {
                IList<CacheRefreshSample> cacheRefreshSampleList = _cacheRefreshSampleList;
                if (cacheRefreshSampleList is not null)
                {
                    const int MIN_TRIGGER = 10 + 4; //minimum trigger is 10 (timer interval) + 4 (additional margin for resolution delays to avoid record expiry)
                    int cacheRefreshTrigger = _cachePrefetchTrigger < MIN_TRIGGER ? MIN_TRIGGER : _cachePrefetchTrigger;

                    for (int i = 0; i < cacheRefreshSampleList.Count; i++)
                    {
                        CacheRefreshSample sample = cacheRefreshSampleList[i];
                        if (sample is null)
                            continue; //currently being refreshed

                        DnsQuestionRecord neededQuestion = await GetCacheRefreshNeededQueryAsync(sample.SampleQuestion, cacheRefreshTrigger);
                        if (neededQuestion is null)
                            continue; //no need to refresh for this query

                        //run in resolver thread pool
                        if (_resolverTaskPool.TryQueueTask(delegate (object state)
                            {
                                return RefreshCacheAsync(neededQuestion, cacheRefreshSampleList, sample, (int)state);
                            }, i)
                        )
                        {
                            //refresh cache task was queued
                            cacheRefreshSampleList[i] = null; //remove from sample list to avoid concurrent refresh attempt
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
            finally
            {
                lock (_cachePrefetchRefreshTimerLock)
                {
                    _cachePrefetchRefreshTimer?.Change(CACHE_PREFETCH_REFRESH_TIMER_INTEVAL, Timeout.Infinite);
                }
            }
        }

        private void ResetPrefetchTimers()
        {
            if ((_cachePrefetchTrigger == 0) || (_recursion == DnsServerRecursion.Deny))
            {
                lock (_cachePrefetchSamplingTimerLock)
                {
                    _cachePrefetchSamplingTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                }

                lock (_cachePrefetchRefreshTimerLock)
                {
                    _cachePrefetchRefreshTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
            else if (_state == ServiceState.Running)
            {
                lock (_cachePrefetchSamplingTimerLock)
                {
                    _cachePrefetchSamplingTimer?.Change(CACHE_PREFETCH_SAMPLING_TIMER_INITIAL_INTEVAL, Timeout.Infinite);
                }

                lock (_cachePrefetchRefreshTimerLock)
                {
                    _cachePrefetchRefreshTimer?.Change(CACHE_PREFETCH_REFRESH_TIMER_INTEVAL, Timeout.Infinite);
                }
            }
        }

        private bool IsQpmLimitBypassed(IPAddress remoteIP)
        {
            if (IPAddress.IsLoopback(remoteIP))
                return true;

            if (_qpmLimitBypassList is not null)
            {
                foreach (NetworkAddress networkAddress in _qpmLimitBypassList)
                {
                    if (networkAddress.Contains(remoteIP))
                        return true;
                }
            }

            return false;
        }

        private bool HasQpmLimitExceeded(NetworkAddress clientSubnet, DnsTransportProtocol protocol, (int, int) qpmLimits, IReadOnlyDictionary<NetworkAddress, (long, long)> qpmLimitClientSubnetStats, out int qpmLimit, out int currentQpm)
        {
            qpmLimit = protocol == DnsTransportProtocol.Udp ? qpmLimits.Item1 : qpmLimits.Item2;

            if ((qpmLimit > 0) && qpmLimitClientSubnetStats.TryGetValue(clientSubnet, out (long, long) countPerSampleTuple))
            {
                long countPerSample = protocol == DnsTransportProtocol.Udp ? countPerSampleTuple.Item1 : countPerSampleTuple.Item2;

                long averageCountPerMinute = countPerSample / _qpmLimitSampleMinutes;
                if (averageCountPerMinute >= qpmLimit)
                {
                    currentQpm = (int)averageCountPerMinute;
                    return true;
                }
            }

            currentQpm = 0;
            return false;
        }

        internal bool HasQpmLimitExceeded(IPAddress remoteIP, DnsTransportProtocol protocol)
        {
            if (_qpmLimitClientSubnetStats is null)
                return false;

            if ((_qpmPrefixLimitsIPv4.Count < 1) && (_qpmPrefixLimitsIPv6.Count < 1))
                return false;

            if (IsQpmLimitBypassed(remoteIP))
                return false;

            switch (remoteIP.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in _qpmPrefixLimitsIPv4)
                    {
                        if (HasQpmLimitExceeded(new NetworkAddress(remoteIP, (byte)qpmPrefixLimit.Key), protocol, qpmPrefixLimit.Value, _qpmLimitClientSubnetStats, out _, out _))
                            return true;
                    }

                    break;

                case AddressFamily.InterNetworkV6:
                    foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in _qpmPrefixLimitsIPv6)
                    {
                        if (HasQpmLimitExceeded(new NetworkAddress(remoteIP, (byte)qpmPrefixLimit.Key), protocol, qpmPrefixLimit.Value, _qpmLimitClientSubnetStats, out _, out _))
                            return true;
                    }

                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            return false;
        }

        private void QpmLimitSamplingTimerCallback(object state)
        {
            try
            {
                Dictionary<NetworkAddress, (long, long)> qpmLimitClientSubnetStats = _statsManager.GetLatestClientSubnetStats(_qpmLimitSampleMinutes, _qpmPrefixLimitsIPv4.Keys, _qpmPrefixLimitsIPv6.Keys);

                WriteClientSubnetRateLimitLog(_qpmLimitClientSubnetStats, qpmLimitClientSubnetStats);

                _qpmLimitClientSubnetStats = qpmLimitClientSubnetStats;
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
            finally
            {
                lock (_qpmLimitSamplingTimerLock)
                {
                    _qpmLimitSamplingTimer?.Change(QPM_LIMIT_SAMPLING_TIMER_INTERVAL, Timeout.Infinite);
                }
            }
        }

        private void WriteClientSubnetRateLimitLog(IReadOnlyDictionary<NetworkAddress, (long, long)> oldQpmLimitClientSubnetStats, Dictionary<NetworkAddress, (long, long)> newQpmLimitClientSubnetStats)
        {
            if (oldQpmLimitClientSubnetStats is not null)
            {
                foreach (KeyValuePair<NetworkAddress, (long, long)> sampleEntry in oldQpmLimitClientSubnetStats)
                {
                    if (IsQpmLimitBypassed(sampleEntry.Key.GetLastAddress()))
                        continue; //network bypassed

                    IReadOnlyDictionary<int, (int, int)> qpmPrefixLimits;

                    switch (sampleEntry.Key.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            qpmPrefixLimits = _qpmPrefixLimitsIPv4;
                            break;

                        case AddressFamily.InterNetworkV6:
                            qpmPrefixLimits = _qpmPrefixLimitsIPv6;
                            break;

                        default:
                            continue;
                    }

                    if (qpmPrefixLimits.TryGetValue(sampleEntry.Key.PrefixLength, out (int, int) qpmPrefixLimitValue))
                    {
                        //for udp
                        if (HasQpmLimitExceeded(sampleEntry.Key, DnsTransportProtocol.Udp, qpmPrefixLimitValue, oldQpmLimitClientSubnetStats, out _, out _))
                        {
                            //previously over limit
                            if (!HasQpmLimitExceeded(sampleEntry.Key, DnsTransportProtocol.Udp, qpmPrefixLimitValue, newQpmLimitClientSubnetStats, out int qpmLimitUdp, out int currentQpmUdp))
                            {
                                //currently under limit
                                _log.Write("Client subnet '" + sampleEntry.Key + "' is no longer being rate limited for UDP services since current query rate (" + currentQpmUdp + " qpm) is below " + qpmLimitUdp + " qpm limit.");
                            }
                        }

                        //for tcp
                        if (HasQpmLimitExceeded(sampleEntry.Key, DnsTransportProtocol.Tcp, qpmPrefixLimitValue, oldQpmLimitClientSubnetStats, out _, out _))
                        {
                            //previously over limit
                            if (!HasQpmLimitExceeded(sampleEntry.Key, DnsTransportProtocol.Tcp, qpmPrefixLimitValue, newQpmLimitClientSubnetStats, out int qpmLimitTcp, out int currentQpmTcp))
                            {
                                //currently under limit
                                _log.Write("Client subnet '" + sampleEntry.Key + "' is no longer being rate limited for TCP services since current query rate (" + currentQpmTcp + " qpm) is below " + qpmLimitTcp + " qpm limit.");
                            }
                        }
                    }
                }
            }

            foreach (KeyValuePair<NetworkAddress, (long, long)> sampleEntry in newQpmLimitClientSubnetStats)
            {
                if (IsQpmLimitBypassed(sampleEntry.Key.GetLastAddress()))
                    continue; //network bypassed

                IReadOnlyDictionary<int, (int, int)> qpmPrefixLimits;

                switch (sampleEntry.Key.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        qpmPrefixLimits = _qpmPrefixLimitsIPv4;
                        break;

                    case AddressFamily.InterNetworkV6:
                        qpmPrefixLimits = _qpmPrefixLimitsIPv6;
                        break;

                    default:
                        continue;
                }

                if (qpmPrefixLimits.TryGetValue(sampleEntry.Key.PrefixLength, out (int, int) qpmPrefixLimitValue))
                {
                    //for udp
                    if (HasQpmLimitExceeded(sampleEntry.Key, DnsTransportProtocol.Udp, qpmPrefixLimitValue, newQpmLimitClientSubnetStats, out int qpmLimitUdp, out int currentQpmUdp))
                    {
                        //currently over limit
                        if ((oldQpmLimitClientSubnetStats is null) || !HasQpmLimitExceeded(sampleEntry.Key, DnsTransportProtocol.Udp, qpmPrefixLimitValue, oldQpmLimitClientSubnetStats, out _, out _))
                        {
                            //previously under limit
                            _log.Write("Client subnet '" + sampleEntry.Key + "' is being rate limited for UDP services till the current query rate (" + currentQpmUdp + " qpm) falls below " + qpmLimitUdp + " qpm limit.");
                        }
                    }

                    //for tcp
                    if (HasQpmLimitExceeded(sampleEntry.Key, DnsTransportProtocol.Tcp, qpmPrefixLimitValue, newQpmLimitClientSubnetStats, out int qpmLimitTcp, out int currentQpmTcp))
                    {
                        //currently over limit
                        if ((oldQpmLimitClientSubnetStats is null) || !HasQpmLimitExceeded(sampleEntry.Key, DnsTransportProtocol.Tcp, qpmPrefixLimitValue, oldQpmLimitClientSubnetStats, out _, out _))
                        {
                            //previously under limit
                            _log.Write("Client subnet '" + sampleEntry.Key + "' is being rate limited for TCP services till the current query rate (" + currentQpmTcp + " qpm) falls below " + qpmLimitTcp + " qpm limit.");
                        }
                    }
                }
            }
        }

        private bool SendQpmLimitExceededTruncationResponse()
        {
            switch (_qpmLimitUdpTruncationPercentage)
            {
                case 0:
                    return false;

                case 100:
                    return true;

                default:
                    int p = RandomNumberGenerator.GetInt32(100);
                    return p < _qpmLimitUdpTruncationPercentage;
            }
        }

        private void ResetQpsLimitTimer()
        {
            if ((_qpmPrefixLimitsIPv4.Count < 1) && (_qpmPrefixLimitsIPv6.Count < 1))
            {
                lock (_qpmLimitSamplingTimerLock)
                {
                    _qpmLimitSamplingTimer?.Change(Timeout.Infinite, Timeout.Infinite);

                    _qpmLimitClientSubnetStats = null;
                }
            }
            else if (_state == ServiceState.Running)
            {
                lock (_qpmLimitSamplingTimerLock)
                {
                    _qpmLimitSamplingTimer?.Change(0, Timeout.Infinite);
                }
            }
        }

        private void UpdateThisServer()
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

        #endregion

        #region resolver task pool

        internal bool TryQueueResolverTask(Func<object, Task> task, object state = null)
        {
            return _resolverTaskPool.TryQueueTask(task, state);
        }

        private void ReconfigureResolverTaskPool(ushort maxConcurrentResolutionsPerCore)
        {
            TaskPool previousResolverTaskPool = _resolverTaskPool;

            int maxConcurrentResolutions = Environment.ProcessorCount * maxConcurrentResolutionsPerCore;
            int resolverQueueSize = maxConcurrentResolutions * 5 * 10; //assuming 5 qps average resolution rate for 10 sec
            _resolverTaskPool = new TaskPool(resolverQueueSize, maxConcurrentResolutions, _resolverTaskScheduler);

            previousResolverTaskPool?.Dispose(); //stop previous task pool from queuing new tasks and complete reading
        }

        #endregion

        #region doh web service

        private async Task StartDoHAsync(bool throwIfBindFails)
        {
            IReadOnlyList<IPAddress> localAddresses = WebUtilities.GetValidKestrelLocalAddresses(_localEndPoints.Convert(delegate (IPEndPoint ep) { return ep.Address; }));

            try
            {
                WebApplicationBuilder builder = WebApplication.CreateBuilder();

                builder.Environment.ContentRootFileProvider = new PhysicalFileProvider(Path.GetDirectoryName(_dohwwwFolder))
                {
                    UseActivePolling = true,
                    UsePollingFileWatcher = true
                };

                builder.Environment.WebRootFileProvider = new PhysicalFileProvider(_dohwwwFolder)
                {
                    UseActivePolling = true,
                    UsePollingFileWatcher = true
                };

                builder.WebHost.ConfigureKestrel(delegate (WebHostBuilderContext context, KestrelServerOptions serverOptions)
                {
                    //bind to http port
                    if (_enableDnsOverHttp)
                    {
                        foreach (IPAddress localAddress in localAddresses)
                            serverOptions.Listen(localAddress, _dnsOverHttpPort);
                    }

                    //bind to https port
                    if (_enableDnsOverHttps && (_dohSslServerAuthenticationOptions is not null))
                    {
                        foreach (IPAddress localAddress in localAddresses)
                        {
                            serverOptions.Listen(localAddress, _dnsOverHttpsPort, delegate (ListenOptions listenOptions)
                            {
                                if (_enableDnsOverHttp3)
                                    listenOptions.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
                                else if (IsHttp2Supported())
                                    listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
                                else
                                    listenOptions.Protocols = HttpProtocols.Http1;

                                listenOptions.UseHttps(delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object state, CancellationToken cancellationToken)
                                {
                                    return ValueTask.FromResult(_dohSslServerAuthenticationOptions);
                                }, null);
                            });
                        }
                    }

                    serverOptions.AddServerHeader = false;
                    serverOptions.Limits.RequestHeadersTimeout = TimeSpan.FromMilliseconds(_tcpReceiveTimeout);
                    serverOptions.Limits.KeepAliveTimeout = TimeSpan.FromMilliseconds(_tcpReceiveTimeout);
                    serverOptions.Limits.MaxRequestHeadersTotalSize = 4096;
                    serverOptions.Limits.MaxRequestLineSize = serverOptions.Limits.MaxRequestHeadersTotalSize;
                    serverOptions.Limits.MaxRequestBufferSize = serverOptions.Limits.MaxRequestLineSize;
                    serverOptions.Limits.MaxRequestBodySize = 64 * 1024;
                    serverOptions.Limits.MaxResponseBufferSize = 4096;
                });

                builder.Logging.ClearProviders();

                _dohWebService = builder.Build();

                _dohWebService.UseDefaultFiles();
                _dohWebService.UseStaticFiles(new StaticFileOptions()
                {
                    OnPrepareResponse = delegate (StaticFileResponseContext ctx)
                    {
                        ctx.Context.Response.Headers["X-Robots-Tag"] = "noindex, nofollow";
                        ctx.Context.Response.Headers.CacheControl = "no-cache";
                    },
                    ServeUnknownFileTypes = true
                });

                _dohWebService.UseRouting();
                _dohWebService.MapGet("/dns-query", ProcessDoHRequestAsync);
                _dohWebService.MapPost("/dns-query", ProcessDoHRequestAsync);

                await _dohWebService.StartAsync();

                foreach (IPAddress localAddress in localAddresses)
                {
                    if (_enableDnsOverHttp)
                        _log.Write(new IPEndPoint(localAddress, _dnsOverHttpPort), "Http", "DNS Server was bound successfully.");

                    if (_enableDnsOverHttps && (_dohSslServerAuthenticationOptions is not null))
                        _log.Write(new IPEndPoint(localAddress, _dnsOverHttpsPort), "Https", "DNS Server was bound successfully.");
                }
            }
            catch (Exception ex)
            {
                await StopDoHAsync();

                foreach (IPAddress localAddress in localAddresses)
                {
                    if (_enableDnsOverHttp)
                        _log.Write(new IPEndPoint(localAddress, _dnsOverHttpPort), "Http", "DNS Server failed to bind.");

                    if (_enableDnsOverHttps && (_dohSslServerAuthenticationOptions is not null))
                        _log.Write(new IPEndPoint(localAddress, _dnsOverHttpsPort), "Https", "DNS Server failed to bind.");
                }

                _log.Write(ex);

                if (throwIfBindFails)
                    throw;
            }
        }

        private async Task StopDoHAsync()
        {
            if (_dohWebService is not null)
            {
                try
                {
                    await _dohWebService.DisposeAsync();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }

                _dohWebService = null;
            }
        }

        private bool IsHttp2Supported()
        {
            if (_enableDnsOverHttp3)
                return true;

            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                    return Environment.OSVersion.Version.Major >= 10; //http/2 supported on Windows Server 2016/Windows 10 or later

                case PlatformID.Unix:
                    return true; //http/2 supported on Linux with OpenSSL 1.0.2 or later (for example, Ubuntu 16.04 or later)

                default:
                    return false;
            }
        }

        #endregion

        #region public

        public async Task StartAsync(bool throwIfBindFails = false)
        {
            if (_disposed)
                ObjectDisposedException.ThrowIf(_disposed, this);

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

                    if (Environment.OSVersion.Platform == PlatformID.Unix)
                        udpListener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1); //to allow binding to same port with different addresses

                    udpListener.ReceiveBufferSize = 512 * 1024;
                    udpListener.SendBufferSize = 512 * 1024;

                    try
                    {
                        udpListener.Bind(localEP);
                    }
                    catch (SocketException ex1)
                    {
                        switch (ex1.ErrorCode)
                        {
                            case 99: //SocketException (99): Cannot assign requested address
                                await Task.Delay(5000); //wait for address to be available before retrying
                                udpListener.Bind(localEP);
                                break;

                            default:
                                throw;
                        }
                    }

                    _udpListeners.Add(udpListener);

                    _log.Write(localEP, DnsTransportProtocol.Udp, "DNS Server was bound successfully.");
                }
                catch (Exception ex)
                {
                    _log.Write(localEP, DnsTransportProtocol.Udp, "DNS Server failed to bind.\r\n" + ex.ToString());

                    udpListener?.Dispose();

                    if (throwIfBindFails)
                        throw;
                }

                if (_enableDnsOverUdpProxy)
                {
                    IPEndPoint udpProxyEP = new IPEndPoint(localEP.Address, _dnsOverUdpProxyPort);
                    Socket udpProxyListener = null;

                    try
                    {
                        udpProxyListener = new Socket(udpProxyEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

                        #region this code ignores ICMP port unreachable responses which creates SocketException in ReceiveFrom()

                        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                        {
                            const uint IOC_IN = 0x80000000;
                            const uint IOC_VENDOR = 0x18000000;
                            const uint SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

                            udpProxyListener.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { Convert.ToByte(false) }, null);
                        }

                        #endregion

                        if (Environment.OSVersion.Platform == PlatformID.Unix)
                            udpProxyListener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1); //to allow binding to same port with different addresses

                        udpProxyListener.ReceiveBufferSize = 512 * 1024;
                        udpProxyListener.SendBufferSize = 512 * 1024;

                        udpProxyListener.Bind(udpProxyEP);

                        _udpProxyListeners.Add(udpProxyListener);

                        _log.Write(udpProxyEP, DnsTransportProtocol.UdpProxy, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write(udpProxyEP, DnsTransportProtocol.UdpProxy, "DNS Server failed to bind.\r\n" + ex.ToString());

                        udpProxyListener?.Dispose();

                        if (throwIfBindFails)
                            throw;
                    }
                }

                Socket tcpListener = null;

                try
                {
                    tcpListener = new Socket(localEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                    if (Environment.OSVersion.Platform == PlatformID.Unix)
                        tcpListener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1); //to allow binding to same port with different addresses

                    tcpListener.Bind(localEP);
                    tcpListener.Listen(_listenBacklog);

                    _tcpListeners.Add(tcpListener);

                    _log.Write(localEP, DnsTransportProtocol.Tcp, "DNS Server was bound successfully.");
                }
                catch (Exception ex)
                {
                    _log.Write(localEP, DnsTransportProtocol.Tcp, "DNS Server failed to bind.\r\n" + ex.ToString());

                    tcpListener?.Dispose();

                    if (throwIfBindFails)
                        throw;
                }

                if (_enableDnsOverTcpProxy)
                {
                    IPEndPoint tcpProxyEP = new IPEndPoint(localEP.Address, _dnsOverTcpProxyPort);
                    Socket tcpProxyListner = null;

                    try
                    {
                        tcpProxyListner = new Socket(tcpProxyEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        if (Environment.OSVersion.Platform == PlatformID.Unix)
                            tcpProxyListner.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1); //to allow binding to same port with different addresses

                        tcpProxyListner.Bind(tcpProxyEP);
                        tcpProxyListner.Listen(_listenBacklog);

                        _tcpProxyListeners.Add(tcpProxyListner);

                        _log.Write(tcpProxyEP, DnsTransportProtocol.TcpProxy, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write(tcpProxyEP, DnsTransportProtocol.TcpProxy, "DNS Server failed to bind.\r\n" + ex.ToString());

                        tcpProxyListner?.Dispose();

                        if (throwIfBindFails)
                            throw;
                    }
                }

                if (_enableDnsOverTls && (_dotSslServerAuthenticationOptions is not null))
                {
                    IPEndPoint tlsEP = new IPEndPoint(localEP.Address, _dnsOverTlsPort);
                    Socket tlsListener = null;

                    try
                    {
                        tlsListener = new Socket(tlsEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        if (Environment.OSVersion.Platform == PlatformID.Unix)
                            tlsListener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1); //to allow binding to same port with different addresses

                        tlsListener.Bind(tlsEP);
                        tlsListener.Listen(_listenBacklog);

                        _tlsListeners.Add(tlsListener);

                        _log.Write(tlsEP, DnsTransportProtocol.Tls, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write(tlsEP, DnsTransportProtocol.Tls, "DNS Server failed to bind.\r\n" + ex.ToString());

                        tlsListener?.Dispose();

                        if (throwIfBindFails)
                            throw;
                    }
                }

                if (_enableDnsOverQuic && (_doqSslServerAuthenticationOptions is not null))
                {
                    IPEndPoint quicEP = new IPEndPoint(localEP.Address, _dnsOverQuicPort);
                    QuicListener quicListener = null;

                    try
                    {
                        QuicListenerOptions listenerOptions = new QuicListenerOptions()
                        {
                            ListenEndPoint = quicEP,
                            ListenBacklog = _listenBacklog,
                            ApplicationProtocols = _doqApplicationProtocols,
                            ConnectionOptionsCallback = delegate (QuicConnection quicConnection, SslClientHelloInfo sslClientHello, CancellationToken cancellationToken)
                            {
                                QuicServerConnectionOptions serverConnectionOptions = new QuicServerConnectionOptions()
                                {
                                    DefaultCloseErrorCode = (long)DnsOverQuicErrorCodes.DOQ_NO_ERROR,
                                    DefaultStreamErrorCode = (long)DnsOverQuicErrorCodes.DOQ_UNSPECIFIED_ERROR,
                                    MaxInboundUnidirectionalStreams = 0,
                                    MaxInboundBidirectionalStreams = _quicMaxInboundStreams,
                                    IdleTimeout = TimeSpan.FromMilliseconds(_quicIdleTimeout),
                                    ServerAuthenticationOptions = _doqSslServerAuthenticationOptions
                                };

                                return ValueTask.FromResult(serverConnectionOptions);
                            }
                        };

                        quicListener = await QuicListener.ListenAsync(listenerOptions);

                        _quicListeners.Add(quicListener);

                        _log.Write(quicEP, DnsTransportProtocol.Quic, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write(quicEP, DnsTransportProtocol.Quic, "DNS Server failed to bind.\r\n" + ex.ToString());

                        if (quicListener is not null)
                            await quicListener.DisposeAsync();

                        if (throwIfBindFails)
                            throw;
                    }
                }
            }

            //start reading query packets
            int listenerTaskCount = Environment.ProcessorCount;

            foreach (Socket udpListener in _udpListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return ReadUdpRequestAsync(udpListener, DnsTransportProtocol.Udp);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _queryTaskScheduler);
                }
            }

            foreach (Socket udpProxyListener in _udpProxyListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return ReadUdpRequestAsync(udpProxyListener, DnsTransportProtocol.UdpProxy);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _queryTaskScheduler);
                }
            }

            foreach (Socket tcpListener in _tcpListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(tcpListener, DnsTransportProtocol.Tcp);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _queryTaskScheduler);
                }
            }

            foreach (Socket tcpProxyListener in _tcpProxyListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(tcpProxyListener, DnsTransportProtocol.TcpProxy);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _queryTaskScheduler);
                }
            }

            foreach (Socket tlsListener in _tlsListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(tlsListener, DnsTransportProtocol.Tls);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _queryTaskScheduler);
                }
            }

            foreach (QuicListener quicListener in _quicListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptQuicConnectionAsync(quicListener);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _queryTaskScheduler);
                }
            }

            if (_enableDnsOverHttp || (_enableDnsOverHttps && (_dohSslServerAuthenticationOptions is not null)))
                await StartDoHAsync(throwIfBindFails);

            _cachePrefetchSamplingTimer = new Timer(CachePrefetchSamplingTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
            _cachePrefetchRefreshTimer = new Timer(CachePrefetchRefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
            _qpmLimitSamplingTimer = new Timer(QpmLimitSamplingTimerCallback, null, Timeout.Infinite, Timeout.Infinite);

            _state = ServiceState.Running;

            UpdateThisServer();
            ResetPrefetchTimers();
            ResetQpsLimitTimer();
        }

        public async Task StopAsync()
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

            lock (_qpmLimitSamplingTimerLock)
            {
                if (_qpmLimitSamplingTimer is not null)
                {
                    _qpmLimitSamplingTimer.Dispose();
                    _qpmLimitSamplingTimer = null;
                }
            }

            foreach (Socket udpListener in _udpListeners)
            {
                try
                {
                    udpListener.Dispose();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            foreach (Socket udpProxyListener in _udpProxyListeners)
            {
                try
                {
                    udpProxyListener.Dispose();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            foreach (Socket tcpListener in _tcpListeners)
            {
                try
                {
                    tcpListener.Dispose();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            foreach (Socket tcpProxyListener in _tcpProxyListeners)
            {
                try
                {
                    tcpProxyListener.Dispose();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            foreach (Socket tlsListener in _tlsListeners)
            {
                try
                {
                    tlsListener.Dispose();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            foreach (QuicListener quicListener in _quicListeners)
            {
                try
                {
                    await quicListener.DisposeAsync();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            _udpListeners.Clear();
            _udpProxyListeners.Clear();
            _tcpListeners.Clear();
            _tcpProxyListeners.Clear();
            _tlsListeners.Clear();
            _quicListeners.Clear();

            await StopDoHAsync();

            _state = ServiceState.Stopped;
        }

        public Task<DnsDatagram> DirectQueryAsync(DnsQuestionRecord question, int timeout = 4000, bool skipDnsAppAuthoritativeRequestHandlers = false, CancellationToken cancellationToken = default)
        {
            return DirectQueryAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [question]), timeout, skipDnsAppAuthoritativeRequestHandlers, cancellationToken);
        }

        public Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, int timeout = 4000, bool skipDnsAppAuthoritativeRequestHandlers = false, CancellationToken cancellationToken = default)
        {
            return TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
            {
                return ProcessQueryAsync(request, IPENDPOINT_ANY_0, DnsTransportProtocol.Tcp, true, skipDnsAppAuthoritativeRequestHandlers, timeout, null);
            }, timeout, cancellationToken);
        }

        Task<DnsDatagram> IDnsClient.ResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken)
        {
            return DirectQueryAsync(question, cancellationToken: cancellationToken);
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
                    if (DnsClient.IsDomainNameUnicode(value))
                        value = DnsClient.ConvertDomainNameToAscii(value);

                    DnsClient.IsDomainNameValid(value, true);

                    if (IPAddress.TryParse(value, out _))
                        throw new DnsServerException("Invalid domain name [" + value + "]: IP address cannot be used for DNS server domain name.");

                    _serverDomain = value.ToLowerInvariant();
                    _defaultResponsiblePerson = new MailAddress("hostadmin@" + _serverDomain);

                    _authZoneManager.TriggerUpdateServerDomain();
                    _allowedZoneManager.UpdateServerDomain();
                    _blockedZoneManager.UpdateServerDomain();
                    _blockListZoneManager.UpdateServerDomain();

                    UpdateThisServer();
                }
            }
        }

        public string ConfigFolder
        { get { return _configFolder; } }

        public IReadOnlyList<IPEndPoint> LocalEndPoints
        {
            get { return _localEndPoints; }
            set
            {
                if ((value is null) || (value.Count == 0))
                {
                    _localEndPoints = [new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53)];
                }
                else
                {
                    foreach (IPEndPoint ep in value)
                    {
                        if (ep.Port == 853)
                            throw new ArgumentException("Port 853 is reserved for DNS-over-TLS service. Please use a different port for DNS Server Local End Points.", nameof(LocalEndPoints));
                    }

                    _localEndPoints = value;
                }
            }
        }

        public LogManager LogManager
        { get { return _log; } }

        internal MailAddress ResponsiblePersonInternal
        {
            get { return _responsiblePerson; }
            set { _responsiblePerson = value; }
        }

        public MailAddress ResponsiblePerson
        {
            get
            {
                if (_responsiblePerson is not null)
                    return _responsiblePerson;

                if (_defaultResponsiblePerson is null)
                    _defaultResponsiblePerson = new MailAddress("hostadmin@" + _serverDomain);

                return _defaultResponsiblePerson;
            }
        }

        public NameServerAddress ThisServer
        { get { return _thisServer; } }

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

        public StatsManager StatsManager
        { get { return _statsManager; } }

        public IReadOnlyCollection<NetworkAddress> ZoneTransferAllowedNetworks
        {
            get { return _zoneTransferAllowedNetworks; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _zoneTransferAllowedNetworks = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(ZoneTransferAllowedNetworks), "Networks cannot have more than 255 entries.");
                else
                    _zoneTransferAllowedNetworks = value;
            }
        }

        public IReadOnlyCollection<NetworkAddress> NotifyAllowedNetworks
        {
            get { return _notifyAllowedNetworks; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _notifyAllowedNetworks = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(NotifyAllowedNetworks), "Networks cannot have more than 255 entries.");
                else
                    _notifyAllowedNetworks = value;
            }
        }

        public bool PreferIPv6
        {
            get { return _preferIPv6; }
            set
            {
                if (_preferIPv6 != value)
                {
                    _preferIPv6 = value;

                    //init udp socket pool async for port randomization
                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            if (_enableUdpSocketPool)
                                UdpClientConnection.CreateSocketPool(_preferIPv6);
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }
                    });
                }
            }
        }

        public bool EnableUdpSocketPool
        {
            get { return _enableUdpSocketPool; }
            set
            {
                if (_enableUdpSocketPool != value)
                {
                    _enableUdpSocketPool = value;

                    //init udp socket pool async for port randomization
                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            if (_enableUdpSocketPool)
                                UdpClientConnection.CreateSocketPool(_preferIPv6);
                            else
                                UdpClientConnection.DisposeSocketPool();
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }
                    });
                }
            }
        }

        public ushort UdpPayloadSize
        {
            get { return _udpPayloadSize; }
            set
            {
                if ((value < 512) || (value > 4096))
                    throw new ArgumentOutOfRangeException(nameof(UdpPayloadSize), "Invalid EDNS UDP payload size: valid range is 512-4096 bytes.");

                _udpPayloadSize = value;
            }
        }

        public bool DnssecValidation
        {
            get { return _dnssecValidation; }
            set
            {
                if (_dnssecValidation != value)
                {
                    if (!_dnssecValidation)
                        _cacheZoneManager.Flush(); //flush cache to remove non validated data

                    _dnssecValidation = value;
                }
            }
        }

        public bool EDnsClientSubnet
        {
            get { return _eDnsClientSubnet; }
            set
            {
                if (_eDnsClientSubnet != value)
                {
                    _eDnsClientSubnet = value;

                    if (!_eDnsClientSubnet)
                    {
                        ThreadPool.QueueUserWorkItem(delegate (object state)
                        {
                            try
                            {
                                _cacheZoneManager.DeleteEDnsClientSubnetData();
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        });
                    }
                }
            }
        }

        public byte EDnsClientSubnetIPv4PrefixLength
        {
            get { return _eDnsClientSubnetIPv4PrefixLength; }
            set
            {
                if (value > 32)
                    throw new ArgumentOutOfRangeException(nameof(EDnsClientSubnetIPv4PrefixLength), "EDNS Client Subnet IPv4 prefix length cannot be greater than 32.");

                _eDnsClientSubnetIPv4PrefixLength = value;
            }
        }

        public byte EDnsClientSubnetIPv6PrefixLength
        {
            get { return _eDnsClientSubnetIPv6PrefixLength; }
            set
            {
                if (value > 64)
                    throw new ArgumentOutOfRangeException(nameof(EDnsClientSubnetIPv6PrefixLength), "EDNS Client Subnet IPv6 prefix length cannot be greater than 64.");

                _eDnsClientSubnetIPv6PrefixLength = value;
            }
        }

        public NetworkAddress EDnsClientSubnetIpv4Override
        {
            get { return _eDnsClientSubnetIpv4Override; }
            set
            {
                if (value is not null)
                {
                    if (value.AddressFamily != AddressFamily.InterNetwork)
                        throw new ArgumentException("EDNS Client Subnet IPv4 Override must be an IPv4 network address.", nameof(EDnsClientSubnetIpv4Override));

                    if (value.IsHostAddress)
                        value = new NetworkAddress(value.Address, _eDnsClientSubnetIPv4PrefixLength);
                }

                _eDnsClientSubnetIpv4Override = value;
            }
        }

        public NetworkAddress EDnsClientSubnetIpv6Override
        {
            get { return _eDnsClientSubnetIpv6Override; }
            set
            {
                if (value is not null)
                {
                    if (value.AddressFamily != AddressFamily.InterNetworkV6)
                        throw new ArgumentException("EDNS Client Subnet IPv6 Override must be an IPv6 network address.", nameof(EDnsClientSubnetIpv6Override));

                    if (value.IsHostAddress)
                        value = new NetworkAddress(value.Address, _eDnsClientSubnetIPv6PrefixLength);
                }

                _eDnsClientSubnetIpv6Override = value;
            }
        }

        public IReadOnlyDictionary<int, (int, int)> QpmPrefixLimitsIPv4
        {
            get { return _qpmPrefixLimitsIPv4; }
            set
            {
                if (value is null)
                {
                    _qpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>();
                }
                else if (value.Count > byte.MaxValue)
                {
                    throw new ArgumentOutOfRangeException(nameof(QpmPrefixLimitsIPv4), "QPM Prefix Limits for IPv4 cannot have more than 255 entries.");
                }
                else
                {
                    foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in value)
                    {
                        if ((qpmPrefixLimit.Key < 0) || (qpmPrefixLimit.Key > 32))
                            throw new ArgumentOutOfRangeException(nameof(QpmPrefixLimitsIPv4), "QPM limit IPv4 prefix valid range is between 0 and 32.");

                        if ((qpmPrefixLimit.Value.Item1 < 0) || (qpmPrefixLimit.Value.Item2 < 0))
                            throw new ArgumentOutOfRangeException(nameof(QpmPrefixLimitsIPv4), "QPM limit value cannot be less than 0.");
                    }

                    _qpmPrefixLimitsIPv4 = value;
                }
            }
        }

        public IReadOnlyDictionary<int, (int, int)> QpmPrefixLimitsIPv6
        {
            get { return _qpmPrefixLimitsIPv6; }
            set
            {
                if (value is null)
                {
                    _qpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>();
                }
                else if (value.Count > byte.MaxValue)
                {
                    throw new ArgumentOutOfRangeException(nameof(QpmPrefixLimitsIPv6), "QPM Prefix Limits for IPv6 cannot have more than 255 entries.");
                }
                else
                {
                    foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in value)
                    {
                        if ((qpmPrefixLimit.Key < 0) || (qpmPrefixLimit.Key > 128))
                            throw new ArgumentOutOfRangeException(nameof(QpmPrefixLimitsIPv6), "QPM limit IPv6 prefix valid range is between 0 and 128.");

                        if ((qpmPrefixLimit.Value.Item1 < 0) || (qpmPrefixLimit.Value.Item2 < 0))
                            throw new ArgumentOutOfRangeException(nameof(QpmPrefixLimitsIPv6), "QPM limit value cannot be less than 0.");
                    }

                    _qpmPrefixLimitsIPv6 = value;
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

        public int QpmLimitUdpTruncationPercentage
        {
            get { return _qpmLimitUdpTruncationPercentage; }
            set
            {
                if ((value < 0) || (value > 100))
                    throw new ArgumentOutOfRangeException(nameof(QpmLimitUdpTruncationPercentage), "Percentage value valid range is between 0 and 100.");

                _qpmLimitUdpTruncationPercentage = value;
            }
        }

        public IReadOnlyCollection<NetworkAddress> QpmLimitBypassList
        {
            get { return _qpmLimitBypassList; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _qpmLimitBypassList = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(QpmLimitBypassList), "Networks cannot have more than 255 entries.");
                else
                    _qpmLimitBypassList = value;
            }
        }

        public int ClientTimeout
        {
            get { return _clientTimeout; }
            set
            {
                if ((value < 1000) || (value > 10000))
                    throw new ArgumentOutOfRangeException(nameof(ClientTimeout), "Valid range is from 1000 to 10000.");

                _clientTimeout = value;
            }
        }

        public int TcpSendTimeout
        {
            get { return _tcpSendTimeout; }
            set
            {
                if ((value < 1000) || (value > 90000))
                    throw new ArgumentOutOfRangeException(nameof(TcpSendTimeout), "Valid range is from 1000 to 90000.");

                _tcpSendTimeout = value;
            }
        }

        public int TcpReceiveTimeout
        {
            get { return _tcpReceiveTimeout; }
            set
            {
                if ((value < 1000) || (value > 90000))
                    throw new ArgumentOutOfRangeException(nameof(TcpReceiveTimeout), "Valid range is from 1000 to 90000.");

                _tcpReceiveTimeout = value;
            }
        }

        public int QuicIdleTimeout
        {
            get { return _quicIdleTimeout; }
            set
            {
                if ((value < 1000) || (value > 90000))
                    throw new ArgumentOutOfRangeException(nameof(QuicIdleTimeout), "Valid range is from 1000 to 90000.");

                _quicIdleTimeout = value;
            }
        }

        public int QuicMaxInboundStreams
        {
            get { return _quicMaxInboundStreams; }
            set
            {
                if ((value < 0) || (value > 1000))
                    throw new ArgumentOutOfRangeException(nameof(QuicMaxInboundStreams), "Valid range is from 1 to 1000.");

                _quicMaxInboundStreams = value;
            }
        }

        public int ListenBacklog
        {
            get { return _listenBacklog; }
            set { _listenBacklog = value; }
        }

        public ushort MaxConcurrentResolutionsPerCore
        {
            get { return Convert.ToUInt16(_resolverTaskPool.MaximumConcurrencyLevel / Environment.ProcessorCount); }
            set
            {
                if (value < 1)
                    throw new ArgumentOutOfRangeException(nameof(MaxConcurrentResolutionsPerCore), "Value cannot be less than 1.");

                if (MaxConcurrentResolutionsPerCore != value)
                    ReconfigureResolverTaskPool(value);
            }
        }

        public bool EnableDnsOverUdpProxy
        {
            get { return _enableDnsOverUdpProxy; }
            set { _enableDnsOverUdpProxy = value; }
        }

        public bool EnableDnsOverTcpProxy
        {
            get { return _enableDnsOverTcpProxy; }
            set { _enableDnsOverTcpProxy = value; }
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

        public bool EnableDnsOverHttp3
        {
            get { return _enableDnsOverHttp3; }
            set { _enableDnsOverHttp3 = value; }
        }

        public bool EnableDnsOverQuic
        {
            get { return _enableDnsOverQuic; }
            set { _enableDnsOverQuic = value; }
        }

        public IReadOnlyCollection<NetworkAccessControl> ReverseProxyNetworkACL
        {
            get { return _reverseProxyNetworkACL; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _reverseProxyNetworkACL = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(ReverseProxyNetworkACL), "Network Access Control List cannot have more than 255 entries.");
                else
                    _reverseProxyNetworkACL = value;
            }
        }

        public int DnsOverUdpProxyPort
        {
            get { return _dnsOverUdpProxyPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverUdpProxyPort), "Port number valid range is from 0 to 65535.");

                _dnsOverUdpProxyPort = value;
            }
        }

        public int DnsOverTcpProxyPort
        {
            get { return _dnsOverTcpProxyPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverTcpProxyPort), "Port number valid range is from 0 to 65535.");

                _dnsOverTcpProxyPort = value;
            }
        }

        public int DnsOverHttpPort
        {
            get { return _dnsOverHttpPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpPort), "Port number valid range is from 0 to 65535.");

                if (value == 53)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpPort), "Port 53 cannot be used for DNS-over-HTTP service. Please use a different port.");

                if (value == 853)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpPort), "Port 853 is reserved for DNS-over-TLS service. Please use a different port for DNS-over-HTTP service.");

                _dnsOverHttpPort = value;
            }
        }

        public int DnsOverTlsPort
        {
            get { return _dnsOverTlsPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverTlsPort), "Port number valid range is from 0 to 65535.");

                if (value == 53)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverTlsPort), "Port 53 cannot be used for DNS-over-TLS service. Please use a different port.");

                _dnsOverTlsPort = value;
            }
        }

        public int DnsOverHttpsPort
        {
            get { return _dnsOverHttpsPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpsPort), "Port number valid range is from 0 to 65535.");

                if (value == 53)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpsPort), "Port 53 cannot be used for DNS-over-HTTPS service. Please use a different port.");

                if (value == 853)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpsPort), "Port 853 is reserved for DNS-over-TLS service. Please use a different port for DNS-over-HTTPS service.");

                _dnsOverHttpsPort = value;
            }
        }

        public int DnsOverQuicPort
        {
            get { return _dnsOverQuicPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverQuicPort), "Port number valid range is from 0 to 65535.");

                if (value == 53)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverQuicPort), "Port 53 cannot be used for DNS-over-QUIC service. Please use a different port.");

                _dnsOverQuicPort = value;
            }
        }

        public string DnsTlsCertificatePath
        { get { return _dnsTlsCertificatePath; } }

        public string DnsTlsCertificatePassword
        { get { return _dnsTlsCertificatePassword; } }

        public string DnsOverHttpRealIpHeader
        {
            get { return _dnsOverHttpRealIpHeader; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    _dnsOverHttpRealIpHeader = "X-Real-IP";
                else if (value.Length > 255)
                    throw new ArgumentException("DNS-over-HTTP Real IP header name cannot exceed 255 characters.", nameof(DnsOverHttpRealIpHeader));
                else if (value.Contains(' '))
                    throw new ArgumentException("DNS-over-HTTP Real IP header name cannot contain invalid characters.", nameof(DnsOverHttpRealIpHeader));
                else
                    _dnsOverHttpRealIpHeader = value;
            }
        }

        public IReadOnlyDictionary<string, TsigKey> TsigKeys
        {
            get { return _tsigKeys; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _tsigKeys = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(TsigKeys), "TSIG keys cannot have more than 255 entries.");
                else
                    _tsigKeys = value;
            }
        }

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

        public IReadOnlyCollection<NetworkAccessControl> RecursionNetworkACL
        {
            get { return _recursionNetworkACL; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _recursionNetworkACL = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(RecursionNetworkACL), "Network Access Control List cannot have more than 255 entries.");
                else
                    _recursionNetworkACL = value;
            }
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

        public int ResolverRetries
        {
            get { return _resolverRetries; }
            set
            {
                if ((value < 1) || (value > 10))
                    throw new ArgumentOutOfRangeException(nameof(ResolverRetries), "Valid range is from 1 to 10.");

                _resolverRetries = value;
            }
        }

        public int ResolverTimeout
        {
            get { return _resolverTimeout; }
            set
            {
                if ((value < 1000) || (value > 10000))
                    throw new ArgumentOutOfRangeException(nameof(ResolverTimeout), "Valid range is from 1000 to 10000.");

                _resolverTimeout = value;
            }
        }

        public int ResolverConcurrency
        {
            get { return _resolverConcurrency; }
            set
            {
                if ((value < 1) || (value > 4))
                    throw new ArgumentOutOfRangeException(nameof(ResolverConcurrency), "Valid range is from 1 to 4.");

                _resolverConcurrency = value;
            }
        }

        public int ResolverMaxStackCount
        {
            get { return _resolverMaxStackCount; }
            set
            {
                if ((value < 10) || (value > 30))
                    throw new ArgumentOutOfRangeException(nameof(ResolverMaxStackCount), "Valid range is from 10 to 30.");

                _resolverMaxStackCount = value;
            }
        }

        public bool SaveCacheToDisk
        {
            get { return _saveCacheToDisk; }
            set
            {
                _saveCacheToDisk = value;

                if (!_saveCacheToDisk)
                {
                    try
                    {
                        _cacheZoneManager.DeleteCacheZoneFile();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                }
            }
        }

        public bool ServeStale
        {
            get { return _serveStale; }
            set { _serveStale = value; }
        }

        public int ServeStaleMaxWaitTime
        {
            get { return _serveStaleMaxWaitTime; }
            set
            {
                if ((value < 0) || (value > 1800))
                    throw new ArgumentOutOfRangeException(nameof(ServeStaleMaxWaitTime), "Serve stale max wait time valid range is 0 to 1800 milliseconds. Default value is 1800 milliseconds.");

                _serveStaleMaxWaitTime = value;
            }
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

        public int CachePrefetchSampleIntervalMinutes
        {
            get { return _cachePrefetchSampleIntervalMinutes; }
            set
            {
                if ((value < 1) || (value > 60))
                    throw new ArgumentOutOfRangeException(nameof(CachePrefetchSampleIntervalMinutes), "Valid range is between 1 and 60 minutes.");

                _cachePrefetchSampleIntervalMinutes = value;
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
            set
            {
                _enableBlocking = value;

                if (_enableBlocking)
                    _blockListZoneManager.StopTemporaryDisableBlockingTimer();
            }
        }

        public bool AllowTxtBlockingReport
        {
            get { return _allowTxtBlockingReport; }
            set { _allowTxtBlockingReport = value; }
        }

        public IReadOnlyCollection<NetworkAddress> BlockingBypassList
        {
            get { return _blockingBypassList; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _blockingBypassList = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(BlockingBypassList), "Networks cannot have more than 255 entries.");
                else
                    _blockingBypassList = value;
            }
        }

        public DnsServerBlockingType BlockingType
        {
            get { return _blockingType; }
            set { _blockingType = value; }
        }

        public uint BlockingAnswerTtl
        {
            get { return _blockingAnswerTtl; }
            set
            {
                if (_blockingAnswerTtl != value)
                {
                    _blockingAnswerTtl = value;

                    //update SOA MINIMUM values
                    _blockedZoneManager.UpdateServerDomain();
                    _blockListZoneManager.UpdateServerDomain();
                }
            }
        }

        public IReadOnlyCollection<DnsARecordData> CustomBlockingARecords
        {
            get { return _customBlockingARecords; }
            set
            {
                if (value is null)
                    value = [];

                _customBlockingARecords = value;
            }
        }

        public IReadOnlyCollection<DnsAAAARecordData> CustomBlockingAAAARecords
        {
            get { return _customBlockingAAAARecords; }
            set
            {
                if (value is null)
                    value = [];

                _customBlockingAAAARecords = value;
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

        public bool ConcurrentForwarding
        {
            get { return _concurrentForwarding; }
            set { _concurrentForwarding = value; }
        }

        public int ForwarderRetries
        {
            get { return _forwarderRetries; }
            set
            {
                if ((value < 1) || (value > 10))
                    throw new ArgumentOutOfRangeException(nameof(ForwarderRetries), "Valid range is from 1 to 10.");

                _forwarderRetries = value;
            }
        }

        public int ForwarderTimeout
        {
            get { return _forwarderTimeout; }
            set
            {
                if ((value < 1000) || (value > 10000))
                    throw new ArgumentOutOfRangeException(nameof(ForwarderTimeout), "Valid range is from 1000 to 10000.");

                _forwarderTimeout = value;
            }
        }

        public int ForwarderConcurrency
        {
            get { return _forwarderConcurrency; }
            set
            {
                if ((value < 1) || (value > 10))
                    throw new ArgumentOutOfRangeException(nameof(ForwarderConcurrency), "Valid range is from 1 to 10.");

                _forwarderConcurrency = value;
            }
        }

        public LogManager ResolverLogManager
        {
            get { return _resolverLog; }
            set { _resolverLog = value; }
        }

        public LogManager QueryLogManager
        {
            get { return _queryLog; }
            set { _queryLog = value; }
        }

        #endregion

        class CacheRefreshSample
        {
            public CacheRefreshSample(DnsQuestionRecord sampleQuestion, IReadOnlyList<DnsResourceRecord> conditionalForwarders)
            {
                SampleQuestion = sampleQuestion;
                ConditionalForwarders = conditionalForwarders;
            }

            public DnsQuestionRecord SampleQuestion { get; }

            public IReadOnlyList<DnsResourceRecord> ConditionalForwarders { get; }
        }

        class RecursiveResolveResponse
        {
            public RecursiveResolveResponse(DnsDatagram response, DnsDatagram checkingDisabledResponse)
            {
                Response = response;
                CheckingDisabledResponse = checkingDisabledResponse;
            }

            public DnsDatagram Response { get; }

            public DnsDatagram CheckingDisabledResponse { get; }
        }
    }

#pragma warning restore CA2252 // This API requires opting into preview features
#pragma warning restore CA1416 // Validate platform compatibility
}
