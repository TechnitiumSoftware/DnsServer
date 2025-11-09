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

using DnsServerCore.Dns;
using DnsServerCore.Dns.ZoneManagers;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Text;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ClientConnection;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        #region legacy config

        private void TryLoadOldConfigFile()
        {
            string configFile = Path.Combine(_configFolder, "dns.config");

            try
            {
                using (FileStream fS = new FileStream(configFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader bR = new BinaryReader(fS);

                    if (Encoding.ASCII.GetString(bR.ReadBytes(2)) == "DS")
                    {
                        int version = bR.ReadByte();

                        ReadOldConfigFrom(bR, version);

                        fS.Dispose();
                        _dnsServer.SaveConfigFileInternal();

                        _log.Write("Old DNS config file was loaded: " + configFile);
                    }
                }
            }
            catch (FileNotFoundException)
            {
                //do nothing
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while trying to load old DNS config file: " + configFile + "\r\n" + ex.ToString());
            }
        }

        private void ReadOldConfigFrom(BinaryReader bR, int version)
        {
            if ((version >= 28) && (version <= 42))
            {
                ReadConfigFromV42(bR, version);
            }
            else if ((version >= 2) && (version <= 27))
            {
                ReadConfigFromV27(bR, version);

                //new default settings
                DnsClientConnection.IPv4SourceAddresses = null;
                DnsClientConnection.IPv6SourceAddresses = null;
                _dnsServer.EnableUdpSocketPool = Environment.OSVersion.Platform == PlatformID.Win32NT;
                UdpClientConnection.SocketPoolExcludedPorts = [(ushort)_webServiceTlsPort];
                _dnsServer.MaxConcurrentResolutionsPerCore = 100;
                _dnsServer.DnsApplicationManager.EnableAutomaticUpdate = true;
                _webServiceEnableHttp3 = _webServiceEnableTls && IsQuicSupported();
                _dnsServer.EnableDnsOverHttp3 = _dnsServer.EnableDnsOverHttps && IsQuicSupported();
                _webServiceRealIpHeader = "X-Real-IP";
                _dnsServer.DnsOverHttpRealIpHeader = "X-Real-IP";
                _dnsServer.ResponsiblePersonInternal = null;
                _dnsServer.AuthZoneManager.UseSoaSerialDateScheme = false;
                _dnsServer.AuthZoneManager.MinSoaRefresh = 300;
                _dnsServer.AuthZoneManager.MinSoaRetry = 300;
                _dnsServer.ZoneTransferAllowedNetworks = null;
                _dnsServer.NotifyAllowedNetworks = null;
                _dnsServer.EDnsClientSubnet = false;
                _dnsServer.EDnsClientSubnetIPv4PrefixLength = 24;
                _dnsServer.EDnsClientSubnetIPv6PrefixLength = 56;
                _dnsServer.EDnsClientSubnetIpv4Override = null;
                _dnsServer.EDnsClientSubnetIpv6Override = null;
                _dnsServer.QpmLimitBypassList = null;

                if (_dnsServer.EnableDnsOverUdpProxy || _dnsServer.EnableDnsOverTcpProxy || _dnsServer.EnableDnsOverHttp)
                {
                    _dnsServer.ReverseProxyNetworkACL =
                        [
                            new NetworkAccessControl(IPAddress.Parse("127.0.0.0"), 8),
                            new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8),
                            new NetworkAccessControl(IPAddress.Parse("100.64.0.0"), 10),
                            new NetworkAccessControl(IPAddress.Parse("169.254.0.0"), 16),
                            new NetworkAccessControl(IPAddress.Parse("172.16.0.0"), 12),
                            new NetworkAccessControl(IPAddress.Parse("192.168.0.0"), 16),
                            new NetworkAccessControl(IPAddress.Parse("2000::"), 3, true),
                            new NetworkAccessControl(IPAddress.IPv6Any, 0)
                        ];
                }

                _dnsServer.BlockingBypassList = null;
                _dnsServer.BlockingAnswerTtl = 30;
                _dnsServer.ResolverConcurrency = 2;
                _dnsServer.CacheZoneManager.ServeStaleAnswerTtl = CacheZoneManager.SERVE_STALE_ANSWER_TTL;
                _dnsServer.CacheZoneManager.ServeStaleResetTtl = CacheZoneManager.SERVE_STALE_RESET_TTL;
                _dnsServer.ServeStaleMaxWaitTime = DnsServer.SERVE_STALE_MAX_WAIT_TIME;
                _dnsServer.ConcurrentForwarding = true;
                _dnsServer.ResolverLogManager = _log;
                _dnsServer.StatsManager.EnableInMemoryStats = false;
            }
            else
            {
                throw new InvalidDataException("DNS Server config version not supported.");
            }
        }

        private void ReadConfigFromV42(BinaryReader bR, int version)
        {
            //web service
            {
                _webServiceHttpPort = bR.ReadInt32();
                _webServiceTlsPort = bR.ReadInt32();

                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        IPAddress[] localAddresses = new IPAddress[count];

                        for (int i = 0; i < count; i++)
                            localAddresses[i] = IPAddressExtensions.ReadFrom(bR);

                        _webServiceLocalAddresses = localAddresses;
                    }
                    else
                    {
                        _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };
                    }
                }

                _webServiceEnableTls = bR.ReadBoolean();

                if (version >= 33)
                    _webServiceEnableHttp3 = bR.ReadBoolean();
                else
                    _webServiceEnableHttp3 = _webServiceEnableTls && IsQuicSupported();

                _webServiceHttpToTlsRedirect = bR.ReadBoolean();
                _webServiceUseSelfSignedTlsCertificate = bR.ReadBoolean();

                _webServiceTlsCertificatePath = bR.ReadShortString();
                _webServiceTlsCertificatePassword = bR.ReadShortString();

                if (_webServiceTlsCertificatePath.Length == 0)
                    _webServiceTlsCertificatePath = null;

                if (_webServiceTlsCertificatePath is null)
                {
                    StopTlsCertificateUpdateTimer();
                }
                else
                {
                    string webServiceTlsCertificatePath = ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                    try
                    {
                        LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + webServiceTlsCertificatePath + "\r\n" + ex.ToString());
                    }

                    StartTlsCertificateUpdateTimer();
                }

                CheckAndLoadSelfSignedCertificate(false, false);

                if (version >= 38)
                    _webServiceRealIpHeader = bR.ReadShortString();
                else
                    _webServiceRealIpHeader = "X-Real-IP";
            }

            //dns
            {
                //general
                _dnsServer.ServerDomain = bR.ReadShortString();

                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        List<IPEndPoint> localEndPoints = new List<IPEndPoint>(count);

                        for (int i = 0; i < count; i++)
                        {
                            IPEndPoint ep = EndPointExtensions.ReadFrom(bR) as IPEndPoint;
                            if (ep.Port == 853)
                                continue; //to avoid validation exception

                            localEndPoints.Add(ep);
                        }

                        _dnsServer.LocalEndPoints = localEndPoints;
                    }
                    else
                    {
                        _dnsServer.LocalEndPoints = new IPEndPoint[] { new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53) };
                    }
                }

                if (version >= 34)
                {
                    DnsClientConnection.IPv4SourceAddresses = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                    DnsClientConnection.IPv6SourceAddresses = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                }
                else
                {
                    DnsClientConnection.IPv4SourceAddresses = null;
                    DnsClientConnection.IPv6SourceAddresses = null;
                }

                _dnsServer.AuthZoneManager.DefaultRecordTtl = bR.ReadUInt32();

                if (version >= 36)
                {
                    string rp = bR.ReadString();
                    if (rp.Length == 0)
                        _dnsServer.ResponsiblePersonInternal = null;
                    else
                        _dnsServer.ResponsiblePersonInternal = new MailAddress(rp);
                }
                else
                {
                    _dnsServer.ResponsiblePersonInternal = null;
                }

                if (version >= 33)
                    _dnsServer.AuthZoneManager.UseSoaSerialDateScheme = bR.ReadBoolean();
                else
                    _dnsServer.AuthZoneManager.UseSoaSerialDateScheme = false;

                if (version >= 40)
                {
                    _dnsServer.AuthZoneManager.MinSoaRefresh = bR.ReadUInt32();
                    _dnsServer.AuthZoneManager.MinSoaRetry = bR.ReadUInt32();
                }
                else
                {
                    _dnsServer.AuthZoneManager.MinSoaRefresh = 300;
                    _dnsServer.AuthZoneManager.MinSoaRetry = 300;
                }

                if (version >= 33)
                    _dnsServer.ZoneTransferAllowedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                else
                    _dnsServer.ZoneTransferAllowedNetworks = null;

                if (version >= 34)
                    _dnsServer.NotifyAllowedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                else
                    _dnsServer.NotifyAllowedNetworks = null;

                _dnsServer.DnsApplicationManager.EnableAutomaticUpdate = bR.ReadBoolean();

                _dnsServer.PreferIPv6 = bR.ReadBoolean();

                if (version >= 42)
                {
                    _dnsServer.EnableUdpSocketPool = bR.ReadBoolean();

                    int count = bR.ReadUInt16();
                    ushort[] socketPoolExcludedPorts = new ushort[count];

                    for (int i = 0; i < count; i++)
                        socketPoolExcludedPorts[i] = bR.ReadUInt16();

                    UdpClientConnection.SocketPoolExcludedPorts = socketPoolExcludedPorts;
                }
                else
                {
                    _dnsServer.EnableUdpSocketPool = Environment.OSVersion.Platform == PlatformID.Win32NT;
                    UdpClientConnection.SocketPoolExcludedPorts = [(ushort)_webServiceTlsPort];
                }

                _dnsServer.UdpPayloadSize = bR.ReadUInt16();
                _dnsServer.DnssecValidation = bR.ReadBoolean();

                if (version >= 29)
                {
                    _dnsServer.EDnsClientSubnet = bR.ReadBoolean();
                    _dnsServer.EDnsClientSubnetIPv4PrefixLength = bR.ReadByte();
                    _dnsServer.EDnsClientSubnetIPv6PrefixLength = bR.ReadByte();
                }
                else
                {
                    _dnsServer.EDnsClientSubnet = false;
                    _dnsServer.EDnsClientSubnetIPv4PrefixLength = 24;
                    _dnsServer.EDnsClientSubnetIPv6PrefixLength = 56;
                }

                if (version >= 35)
                {
                    if (bR.ReadBoolean())
                        _dnsServer.EDnsClientSubnetIpv4Override = NetworkAddress.ReadFrom(bR);
                    else
                        _dnsServer.EDnsClientSubnetIpv4Override = null;

                    if (bR.ReadBoolean())
                        _dnsServer.EDnsClientSubnetIpv6Override = NetworkAddress.ReadFrom(bR);
                    else
                        _dnsServer.EDnsClientSubnetIpv6Override = null;
                }
                else
                {
                    _dnsServer.EDnsClientSubnetIpv4Override = null;
                    _dnsServer.EDnsClientSubnetIpv6Override = null;
                }

                if (version >= 42)
                {
                    {
                        int count = bR.ReadByte();
                        Dictionary<int, (int, int)> qpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>(count);

                        for (int i = 0; i < count; i++)
                            qpmPrefixLimitsIPv4.Add(bR.ReadInt32(), (bR.ReadInt32(), bR.ReadInt32()));

                        _dnsServer.QpmPrefixLimitsIPv4 = qpmPrefixLimitsIPv4;
                    }

                    {
                        int count = bR.ReadByte();
                        Dictionary<int, (int, int)> qpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>(count);

                        for (int i = 0; i < count; i++)
                            qpmPrefixLimitsIPv6.Add(bR.ReadInt32(), (bR.ReadInt32(), bR.ReadInt32()));

                        _dnsServer.QpmPrefixLimitsIPv6 = qpmPrefixLimitsIPv6;
                    }

                    _dnsServer.QpmLimitSampleMinutes = bR.ReadInt32();
                    _dnsServer.QpmLimitUdpTruncationPercentage = bR.ReadInt32();
                }
                else
                {
                    int qpmLimitRequests = bR.ReadInt32();
                    _ = bR.ReadInt32(); //obsolete qpmLimitErrors
                    int qpmLimitSampleMinutes = bR.ReadInt32();
                    int qpmLimitIPv4PrefixLength = bR.ReadInt32();
                    int qpmLimitIPv6PrefixLength = bR.ReadInt32();

                    _dnsServer.QpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>()
                    {
                        { qpmLimitIPv4PrefixLength, (qpmLimitRequests, qpmLimitRequests) }
                    };

                    _dnsServer.QpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>()
                    {
                        { qpmLimitIPv6PrefixLength, (qpmLimitRequests, qpmLimitRequests) }
                    };

                    _dnsServer.QpmLimitSampleMinutes = qpmLimitSampleMinutes;
                    _dnsServer.QpmLimitUdpTruncationPercentage = 0;
                }

                if (version >= 34)
                    _dnsServer.QpmLimitBypassList = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                else
                    _dnsServer.QpmLimitBypassList = null;

                _dnsServer.ClientTimeout = bR.ReadInt32();
                if (version < 34)
                {
                    if (_dnsServer.ClientTimeout == 4000)
                        _dnsServer.ClientTimeout = 2000;
                }

                _dnsServer.TcpSendTimeout = bR.ReadInt32();
                _dnsServer.TcpReceiveTimeout = bR.ReadInt32();

                if (version >= 30)
                {
                    _dnsServer.QuicIdleTimeout = bR.ReadInt32();
                    _dnsServer.QuicMaxInboundStreams = bR.ReadInt32();
                    _dnsServer.ListenBacklog = bR.ReadInt32();
                }
                else
                {
                    _dnsServer.QuicIdleTimeout = 60000;
                    _dnsServer.QuicMaxInboundStreams = 100;
                    _dnsServer.ListenBacklog = 100;
                }

                if (version >= 40)
                    _dnsServer.MaxConcurrentResolutionsPerCore = bR.ReadUInt16();
                else
                    _dnsServer.MaxConcurrentResolutionsPerCore = 100;

                //optional protocols
                if (version >= 32)
                {
                    _dnsServer.EnableDnsOverUdpProxy = bR.ReadBoolean();
                    _dnsServer.EnableDnsOverTcpProxy = bR.ReadBoolean();
                }
                else
                {
                    _dnsServer.EnableDnsOverUdpProxy = false;
                    _dnsServer.EnableDnsOverTcpProxy = false;
                }

                _dnsServer.EnableDnsOverHttp = bR.ReadBoolean();
                _dnsServer.EnableDnsOverTls = bR.ReadBoolean();
                _dnsServer.EnableDnsOverHttps = bR.ReadBoolean();

                if (version >= 37)
                    _dnsServer.EnableDnsOverHttp3 = bR.ReadBoolean();
                else
                    _dnsServer.EnableDnsOverHttp3 = _dnsServer.EnableDnsOverHttps && IsQuicSupported();

                if (version >= 32)
                {
                    _dnsServer.EnableDnsOverQuic = bR.ReadBoolean();

                    _dnsServer.DnsOverUdpProxyPort = bR.ReadInt32();
                    _dnsServer.DnsOverTcpProxyPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpPort = bR.ReadInt32();
                    _dnsServer.DnsOverTlsPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpsPort = bR.ReadInt32();
                    _dnsServer.DnsOverQuicPort = bR.ReadInt32();
                }
                else if (version >= 31)
                {
                    _dnsServer.EnableDnsOverQuic = bR.ReadBoolean();

                    _dnsServer.DnsOverHttpPort = bR.ReadInt32();
                    _dnsServer.DnsOverTlsPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpsPort = bR.ReadInt32();
                    _dnsServer.DnsOverQuicPort = bR.ReadInt32();
                }
                else if (version >= 30)
                {
                    _ = bR.ReadBoolean(); //removed EnableDnsOverHttpPort80 value
                    _dnsServer.EnableDnsOverQuic = bR.ReadBoolean();

                    _dnsServer.DnsOverHttpPort = bR.ReadInt32();
                    _dnsServer.DnsOverTlsPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpsPort = bR.ReadInt32();
                    _dnsServer.DnsOverQuicPort = bR.ReadInt32();
                }
                else
                {
                    _dnsServer.EnableDnsOverQuic = false;

                    _dnsServer.DnsOverUdpProxyPort = 538;
                    _dnsServer.DnsOverTcpProxyPort = 538;

                    if (_dnsServer.EnableDnsOverHttps)
                    {
                        _dnsServer.EnableDnsOverHttp = true;
                        _dnsServer.DnsOverHttpPort = 80;
                    }
                    else if (_dnsServer.EnableDnsOverHttp)
                    {
                        _dnsServer.DnsOverHttpPort = 8053;
                    }
                    else
                    {
                        _dnsServer.DnsOverHttpPort = 80;
                    }

                    _dnsServer.DnsOverTlsPort = 853;
                    _dnsServer.DnsOverHttpsPort = 443;
                    _dnsServer.DnsOverQuicPort = 853;
                }

                if (version >= 39)
                {
                    _dnsServer.ReverseProxyNetworkACL = AuthZoneInfo.ReadNetworkACLFrom(bR);
                }
                else
                {
                    if (_dnsServer.EnableDnsOverUdpProxy || _dnsServer.EnableDnsOverTcpProxy || _dnsServer.EnableDnsOverHttp)
                    {
                        _dnsServer.ReverseProxyNetworkACL =
                            [
                                new NetworkAccessControl(IPAddress.Parse("127.0.0.0"), 8),
                                new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8),
                                new NetworkAccessControl(IPAddress.Parse("100.64.0.0"), 10),
                                new NetworkAccessControl(IPAddress.Parse("169.254.0.0"), 16),
                                new NetworkAccessControl(IPAddress.Parse("172.16.0.0"), 12),
                                new NetworkAccessControl(IPAddress.Parse("192.168.0.0"), 16),
                                new NetworkAccessControl(IPAddress.Parse("2000::"), 3, true),
                                new NetworkAccessControl(IPAddress.IPv6Any, 0)
                            ];
                    }
                }

                string dnsTlsCertificatePath = bR.ReadShortString();
                string dnsTlsCertificatePassword = bR.ReadShortString();

                if (dnsTlsCertificatePath.Length == 0)
                    dnsTlsCertificatePath = null;

                if (dnsTlsCertificatePath is null)
                    _dnsServer.RemoveDnsTlsCertificate();
                else
                    _dnsServer.SetDnsTlsCertificate(dnsTlsCertificatePath, dnsTlsCertificatePassword);

                if (version >= 38)
                    _dnsServer.DnsOverHttpRealIpHeader = bR.ReadShortString();
                else
                    _dnsServer.DnsOverHttpRealIpHeader = "X-Real-IP";

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

                    _dnsServer.TsigKeys = tsigKeys;
                }

                //recursion
                _dnsServer.Recursion = (DnsServerRecursion)bR.ReadByte();

                if (version >= 37)
                {
                    _dnsServer.RecursionNetworkACL = AuthZoneInfo.ReadNetworkACLFrom(bR);
                }
                else
                {
                    NetworkAddress[] recursionDeniedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                    NetworkAddress[] recursionAllowedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                    _dnsServer.RecursionNetworkACL = AuthZoneInfo.ConvertDenyAllowToACL(recursionDeniedNetworks, recursionAllowedNetworks);
                }

                _dnsServer.RandomizeName = bR.ReadBoolean();
                _dnsServer.QnameMinimization = bR.ReadBoolean();

                if (version <= 40)
                    _ = bR.ReadBoolean(); //removed NsRevalidation option

                _dnsServer.ResolverRetries = bR.ReadInt32();
                _dnsServer.ResolverTimeout = bR.ReadInt32();

                if (version >= 37)
                    _dnsServer.ResolverConcurrency = bR.ReadInt32();
                else
                    _dnsServer.ResolverConcurrency = 2;

                _dnsServer.ResolverMaxStackCount = bR.ReadInt32();

                //cache
                if (version >= 30)
                    _dnsServer.SaveCacheToDisk = bR.ReadBoolean();
                else
                    _dnsServer.SaveCacheToDisk = true;

                _dnsServer.ServeStale = bR.ReadBoolean();
                _dnsServer.CacheZoneManager.ServeStaleTtl = bR.ReadUInt32();

                if (version >= 36)
                {
                    _dnsServer.CacheZoneManager.ServeStaleAnswerTtl = bR.ReadUInt32();
                    _dnsServer.CacheZoneManager.ServeStaleResetTtl = bR.ReadUInt32();
                    _dnsServer.ServeStaleMaxWaitTime = bR.ReadInt32();
                }
                else
                {
                    _dnsServer.CacheZoneManager.ServeStaleAnswerTtl = CacheZoneManager.SERVE_STALE_ANSWER_TTL;
                    _dnsServer.CacheZoneManager.ServeStaleResetTtl = CacheZoneManager.SERVE_STALE_RESET_TTL;
                    _dnsServer.ServeStaleMaxWaitTime = DnsServer.SERVE_STALE_MAX_WAIT_TIME;
                }

                _dnsServer.CacheZoneManager.MaximumEntries = bR.ReadInt64();
                _dnsServer.CacheZoneManager.MinimumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.MaximumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.NegativeRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.FailureRecordTtl = bR.ReadUInt32();

                _dnsServer.CachePrefetchEligibility = bR.ReadInt32();
                _dnsServer.CachePrefetchTrigger = bR.ReadInt32();
                _dnsServer.CachePrefetchSampleIntervalMinutes = bR.ReadInt32();
                _dnsServer.CachePrefetchSampleEligibilityHitsPerHour = bR.ReadInt32();

                //blocking
                _dnsServer.EnableBlocking = bR.ReadBoolean();
                _dnsServer.AllowTxtBlockingReport = bR.ReadBoolean();

                if (version >= 33)
                    _dnsServer.BlockingBypassList = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                else
                    _dnsServer.BlockingBypassList = null;

                _dnsServer.BlockingType = (DnsServerBlockingType)bR.ReadByte();

                if (version >= 38)
                    _dnsServer.BlockingAnswerTtl = bR.ReadUInt32();
                else
                    _dnsServer.BlockingAnswerTtl = 30;

                {
                    //read custom blocking addresses
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                        List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

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

                        _dnsServer.CustomBlockingARecords = dnsARecords;
                        _dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                    }
                    else
                    {
                        _dnsServer.CustomBlockingARecords = null;
                        _dnsServer.CustomBlockingAAAARecords = null;
                    }
                }

                {
                    //read block list urls
                    int count = bR.ReadByte();
                    string[] blockListUrls = new string[count];

                    for (int i = 0; i < count; i++)
                        blockListUrls[i] = bR.ReadShortString();

                    _dnsServer.BlockListZoneManager.BlockListUrls = blockListUrls;

                    _dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours = bR.ReadInt32();
                    _dnsServer.BlockListZoneManager.BlockListLastUpdatedOn = bR.ReadDateTime();
                }

                //proxy & forwarders
                NetProxyType proxyType = (NetProxyType)bR.ReadByte();
                if (proxyType != NetProxyType.None)
                {
                    string address = bR.ReadShortString();
                    int port = bR.ReadInt32();
                    NetworkCredential credential = null;

                    if (bR.ReadBoolean()) //credential set
                        credential = new NetworkCredential(bR.ReadShortString(), bR.ReadShortString());

                    _dnsServer.Proxy = NetProxy.CreateProxy(proxyType, address, port, credential);

                    int count = bR.ReadByte();
                    List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(count);

                    for (int i = 0; i < count; i++)
                        bypassList.Add(new NetProxyBypassItem(bR.ReadShortString()));

                    _dnsServer.Proxy.BypassList = bypassList;
                }
                else
                {
                    _dnsServer.Proxy = null;
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

                        _dnsServer.Forwarders = forwarders;
                    }
                    else
                    {
                        _dnsServer.Forwarders = null;
                    }
                }

                if (version >= 37)
                    _dnsServer.ConcurrentForwarding = bR.ReadBoolean();
                else
                    _dnsServer.ConcurrentForwarding = true;

                _dnsServer.ForwarderRetries = bR.ReadInt32();
                _dnsServer.ForwarderTimeout = bR.ReadInt32();
                _dnsServer.ForwarderConcurrency = bR.ReadInt32();

                //logging
                if (version >= 33)
                {
                    if (bR.ReadBoolean()) //ignore resolver logs
                        _dnsServer.ResolverLogManager = null;
                    else
                        _dnsServer.ResolverLogManager = _log;
                }
                else
                {
                    _dnsServer.ResolverLogManager = _log;
                }

                if (bR.ReadBoolean()) //log all queries
                    _dnsServer.QueryLogManager = _log;
                else
                    _dnsServer.QueryLogManager = null;

                if (version >= 34)
                    _dnsServer.StatsManager.EnableInMemoryStats = bR.ReadBoolean();
                else
                    _dnsServer.StatsManager.EnableInMemoryStats = false;

                {
                    int maxStatFileDays = bR.ReadInt32();
                    if (maxStatFileDays < 0)
                        maxStatFileDays = 0;

                    _dnsServer.StatsManager.MaxStatFileDays = maxStatFileDays;
                }
            }
        }

        private void ReadConfigFromV27(BinaryReader bR, int version)
        {
            _dnsServer.ServerDomain = bR.ReadShortString();
            _webServiceHttpPort = bR.ReadInt32();

            if (version >= 13)
            {
                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        IPAddress[] localAddresses = new IPAddress[count];

                        for (int i = 0; i < count; i++)
                            localAddresses[i] = IPAddressExtensions.ReadFrom(bR);

                        _webServiceLocalAddresses = localAddresses;
                    }
                    else
                    {
                        _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };
                    }
                }

                _webServiceTlsPort = bR.ReadInt32();
                _webServiceEnableTls = bR.ReadBoolean();
                _webServiceHttpToTlsRedirect = bR.ReadBoolean();
                _webServiceTlsCertificatePath = bR.ReadShortString();
                _webServiceTlsCertificatePassword = bR.ReadShortString();

                if (_webServiceTlsCertificatePath.Length == 0)
                    _webServiceTlsCertificatePath = null;

                if (_webServiceTlsCertificatePath is null)
                {
                    StopTlsCertificateUpdateTimer();
                }
                else
                {
                    string webServiceTlsCertificatePath = ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                    try
                    {
                        LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + webServiceTlsCertificatePath + "\r\n" + ex.ToString());
                    }

                    StartTlsCertificateUpdateTimer();
                }
            }
            else
            {
                _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };

                _webServiceTlsPort = 53443;
                _webServiceEnableTls = false;
                _webServiceHttpToTlsRedirect = false;
                _webServiceTlsCertificatePath = string.Empty;
                _webServiceTlsCertificatePassword = string.Empty;
            }

            _dnsServer.PreferIPv6 = bR.ReadBoolean();

            if (bR.ReadBoolean()) //logQueries
                _dnsServer.QueryLogManager = _log;

            if (version >= 14)
            {
                int maxStatFileDays = bR.ReadInt32();
                if (maxStatFileDays < 0)
                    maxStatFileDays = 0;

                _dnsServer.StatsManager.MaxStatFileDays = maxStatFileDays;
            }
            else
            {
                _dnsServer.StatsManager.MaxStatFileDays = 0;
            }

            if (version >= 17)
            {
                _dnsServer.Recursion = (DnsServerRecursion)bR.ReadByte();

                NetworkAddress[] recursionDeniedNetworks;
                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NetworkAddress[] networks = new NetworkAddress[count];

                        for (int i = 0; i < count; i++)
                            networks[i] = NetworkAddress.ReadFrom(bR);

                        recursionDeniedNetworks = networks;
                    }
                    else
                    {
                        recursionDeniedNetworks = null;
                    }
                }

                NetworkAddress[] recursionAllowedNetworks;
                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NetworkAddress[] networks = new NetworkAddress[count];

                        for (int i = 0; i < count; i++)
                            networks[i] = NetworkAddress.ReadFrom(bR);

                        recursionAllowedNetworks = networks;
                    }
                    else
                    {
                        recursionAllowedNetworks = null;
                    }
                }

                _dnsServer.RecursionNetworkACL = AuthZoneInfo.ConvertDenyAllowToACL(recursionDeniedNetworks, recursionAllowedNetworks);
            }
            else
            {
                bool allowRecursion = bR.ReadBoolean();
                bool allowRecursionOnlyForPrivateNetworks;

                if (version >= 4)
                    allowRecursionOnlyForPrivateNetworks = bR.ReadBoolean();
                else
                    allowRecursionOnlyForPrivateNetworks = true; //default true for security reasons

                if (allowRecursion)
                {
                    if (allowRecursionOnlyForPrivateNetworks)
                        _dnsServer.Recursion = DnsServerRecursion.AllowOnlyForPrivateNetworks;
                    else
                        _dnsServer.Recursion = DnsServerRecursion.Allow;
                }
                else
                {
                    _dnsServer.Recursion = DnsServerRecursion.Deny;
                }
            }

            if (version >= 12)
                _dnsServer.RandomizeName = bR.ReadBoolean();
            else
                _dnsServer.RandomizeName = false; //default false to allow resolving from bad name servers

            if (version >= 15)
                _dnsServer.QnameMinimization = bR.ReadBoolean();
            else
                _dnsServer.QnameMinimization = true; //default true to enable privacy feature

            if (version >= 20)
            {
                int qpmLimitRequests = bR.ReadInt32();
                _ = bR.ReadInt32(); //obsolete qpmLimitErrors
                int qpmLimitSampleMinutes = bR.ReadInt32();
                int qpmLimitIPv4PrefixLength = bR.ReadInt32();
                int qpmLimitIPv6PrefixLength = bR.ReadInt32();

                _dnsServer.QpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>()
                {
                    { qpmLimitIPv4PrefixLength, (qpmLimitRequests, qpmLimitRequests) }
                };

                _dnsServer.QpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>()
                {
                    { qpmLimitIPv6PrefixLength, (qpmLimitRequests, qpmLimitRequests) }
                };

                _dnsServer.QpmLimitSampleMinutes = qpmLimitSampleMinutes;
                _dnsServer.QpmLimitUdpTruncationPercentage = 0;
            }
            else if (version >= 17)
            {
                int qpmLimitRequests = bR.ReadInt32();
                int qpmLimitSampleMinutes = bR.ReadInt32();
                _ = bR.ReadInt32(); //read obsolete value _dnsServer.QpmLimitSamplingIntervalInMinutes

                _dnsServer.QpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>()
                {
                    { 24, (qpmLimitRequests, qpmLimitRequests) }
                };

                _dnsServer.QpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>()
                {
                    { 56, (qpmLimitRequests, qpmLimitRequests) }
                };

                _dnsServer.QpmLimitSampleMinutes = qpmLimitSampleMinutes;
                _dnsServer.QpmLimitUdpTruncationPercentage = 0;
            }
            else
            {
                _dnsServer.QpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>()
                {
                    { 32, (600, 600) },
                    { 24, (6000, 6000) }
                };

                _dnsServer.QpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>()
                {
                    { 128, (600, 600) },
                    { 64, (1200, 1200) },
                    { 56, (6000, 6000) }
                };

                _dnsServer.QpmLimitSampleMinutes = 5;
                _dnsServer.QpmLimitUdpTruncationPercentage = 50;
            }

            if (version >= 13)
            {
                _dnsServer.ServeStale = bR.ReadBoolean();
                _dnsServer.CacheZoneManager.ServeStaleTtl = bR.ReadUInt32();
            }
            else
            {
                _dnsServer.ServeStale = true;
                _dnsServer.CacheZoneManager.ServeStaleTtl = CacheZoneManager.SERVE_STALE_TTL;
            }

            if (version >= 9)
            {
                _dnsServer.CachePrefetchEligibility = bR.ReadInt32();
                _dnsServer.CachePrefetchTrigger = bR.ReadInt32();
                _dnsServer.CachePrefetchSampleIntervalMinutes = bR.ReadInt32();
                _dnsServer.CachePrefetchSampleEligibilityHitsPerHour = bR.ReadInt32();
            }
            else
            {
                _dnsServer.CachePrefetchEligibility = 2;
                _dnsServer.CachePrefetchTrigger = 9;
                _dnsServer.CachePrefetchSampleIntervalMinutes = 5;
                _dnsServer.CachePrefetchSampleEligibilityHitsPerHour = 30;
            }

            NetProxyType proxyType = (NetProxyType)bR.ReadByte();
            if (proxyType != NetProxyType.None)
            {
                string address = bR.ReadShortString();
                int port = bR.ReadInt32();
                NetworkCredential credential = null;

                if (bR.ReadBoolean()) //credential set
                    credential = new NetworkCredential(bR.ReadShortString(), bR.ReadShortString());

                _dnsServer.Proxy = NetProxy.CreateProxy(proxyType, address, port, credential);

                if (version >= 10)
                {
                    int count = bR.ReadByte();
                    List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(count);

                    for (int i = 0; i < count; i++)
                        bypassList.Add(new NetProxyBypassItem(bR.ReadShortString()));

                    _dnsServer.Proxy.BypassList = bypassList;
                }
                else
                {
                    _dnsServer.Proxy.BypassList = null;
                }
            }
            else
            {
                _dnsServer.Proxy = null;
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

                    _dnsServer.Forwarders = forwarders;
                }
                else
                {
                    _dnsServer.Forwarders = null;
                }
            }

            if (version <= 10)
            {
                DnsTransportProtocol forwarderProtocol = (DnsTransportProtocol)bR.ReadByte();
                if (forwarderProtocol == DnsTransportProtocol.HttpsJson)
                    forwarderProtocol = DnsTransportProtocol.Https;

                if (_dnsServer.Forwarders != null)
                {
                    List<NameServerAddress> forwarders = new List<NameServerAddress>();

                    foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                    {
                        if (forwarder.Protocol == forwarderProtocol)
                            forwarders.Add(forwarder);
                        else
                            forwarders.Add(forwarder.ChangeProtocol(forwarderProtocol));
                    }

                    _dnsServer.Forwarders = forwarders;
                }
            }

            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    if (version > 2)
                    {
                        for (int i = 0; i < count; i++)
                        {
                            string username = bR.ReadShortString();
                            string passwordHash = bR.ReadShortString();

                            if (username.Equals("admin", StringComparison.OrdinalIgnoreCase))
                            {
                                _authManager.LoadOldConfig(passwordHash, true);
                                break;
                            }
                        }
                    }
                    else
                    {
                        for (int i = 0; i < count; i++)
                        {
                            string username = bR.ReadShortString();
                            string password = bR.ReadShortString();

                            if (username.Equals("admin", StringComparison.OrdinalIgnoreCase))
                            {
                                _authManager.LoadOldConfig(password, false);
                                break;
                            }
                        }
                    }
                }
            }

            if (version <= 6)
            {
                int count = bR.ReadInt32();
                _configDisabledZones = new List<string>(count);

                for (int i = 0; i < count; i++)
                {
                    string domain = bR.ReadShortString();
                    _configDisabledZones.Add(domain);
                }
            }

            if (version >= 18)
                _dnsServer.EnableBlocking = bR.ReadBoolean();
            else
                _dnsServer.EnableBlocking = true;

            if (version >= 18)
                _dnsServer.BlockingType = (DnsServerBlockingType)bR.ReadByte();
            else if (version >= 16)
                _dnsServer.BlockingType = bR.ReadBoolean() ? DnsServerBlockingType.NxDomain : DnsServerBlockingType.AnyAddress;
            else
                _dnsServer.BlockingType = DnsServerBlockingType.AnyAddress;

            if (version >= 18)
            {
                //read custom blocking addresses
                int count = bR.ReadByte();
                if (count > 0)
                {
                    List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                    List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

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

                    _dnsServer.CustomBlockingARecords = dnsARecords;
                    _dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                }
                else
                {
                    _dnsServer.CustomBlockingARecords = null;
                    _dnsServer.CustomBlockingAAAARecords = null;
                }
            }
            else
            {
                _dnsServer.CustomBlockingARecords = null;
                _dnsServer.CustomBlockingAAAARecords = null;
            }

            if (version > 4)
            {
                //read block list urls
                int count = bR.ReadByte();
                string[] blockListUrls = new string[count];

                for (int i = 0; i < count; i++)
                    blockListUrls[i] = bR.ReadShortString();

                _dnsServer.BlockListZoneManager.BlockListUrls = blockListUrls;

                _dnsServer.BlockListZoneManager.BlockListLastUpdatedOn = bR.ReadDateTime();

                if (version >= 13)
                    _dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours = bR.ReadInt32();
            }
            else
            {
                _dnsServer.BlockListZoneManager.BlockListUrls = null;
                _dnsServer.BlockListZoneManager.BlockListLastUpdatedOn = DateTime.MinValue;
                _dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours = 24;
            }

            if (version >= 11)
            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    List<IPEndPoint> localEndPoints = new List<IPEndPoint>(count);

                    for (int i = 0; i < count; i++)
                    {
                        IPEndPoint ep = EndPointExtensions.ReadFrom(bR) as IPEndPoint;
                        if (ep.Port == 853)
                            continue; //to avoid validation exception

                        localEndPoints.Add(ep);
                    }

                    _dnsServer.LocalEndPoints = localEndPoints;
                }
                else
                {
                    _dnsServer.LocalEndPoints = new IPEndPoint[] { new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53) };
                }
            }
            else if (version >= 6)
            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    List<IPEndPoint> localEndPoints = new List<IPEndPoint>(count);

                    for (int i = 0; i < count; i++)
                    {
                        IPEndPoint ep = EndPointExtensions.ReadFrom(bR) as IPEndPoint;
                        if (ep.Port == 853)
                            continue; //to avoid validation exception

                        localEndPoints.Add(ep);
                    }

                    _dnsServer.LocalEndPoints = localEndPoints;
                }
                else
                {
                    _dnsServer.LocalEndPoints = new IPEndPoint[] { new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53) };
                }
            }
            else
            {
                _dnsServer.LocalEndPoints = new IPEndPoint[] { new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53) };
            }

            if (version >= 8)
            {
                _dnsServer.EnableDnsOverHttp = bR.ReadBoolean();
                _dnsServer.EnableDnsOverTls = bR.ReadBoolean();
                _dnsServer.EnableDnsOverHttps = bR.ReadBoolean();
                string dnsTlsCertificatePath = bR.ReadShortString();
                string dnsTlsCertificatePassword = bR.ReadShortString();

                if (dnsTlsCertificatePath.Length == 0)
                    dnsTlsCertificatePath = null;

                if (dnsTlsCertificatePath is null)
                    _dnsServer.RemoveDnsTlsCertificate();
                else
                    _dnsServer.SetDnsTlsCertificate(dnsTlsCertificatePath, dnsTlsCertificatePassword);
            }
            else
            {
                _dnsServer.EnableDnsOverHttp = false;
                _dnsServer.EnableDnsOverTls = false;
                _dnsServer.EnableDnsOverHttps = false;

                _dnsServer.RemoveDnsTlsCertificate();
            }

            if (version >= 19)
            {
                _dnsServer.CacheZoneManager.MinimumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.MaximumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.NegativeRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.FailureRecordTtl = bR.ReadUInt32();
            }
            else
            {
                _dnsServer.CacheZoneManager.MinimumRecordTtl = CacheZoneManager.MINIMUM_RECORD_TTL;
                _dnsServer.CacheZoneManager.MaximumRecordTtl = CacheZoneManager.MAXIMUM_RECORD_TTL;
                _dnsServer.CacheZoneManager.NegativeRecordTtl = CacheZoneManager.NEGATIVE_RECORD_TTL;
                _dnsServer.CacheZoneManager.FailureRecordTtl = CacheZoneManager.FAILURE_RECORD_TTL;
            }

            if (version >= 21)
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

                _dnsServer.TsigKeys = tsigKeys;
            }
            else if (version >= 20)
            {
                int count = bR.ReadByte();
                Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(count);

                for (int i = 0; i < count; i++)
                {
                    string keyName = bR.ReadShortString();
                    string sharedSecret = bR.ReadShortString();

                    tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, TsigAlgorithm.HMAC_SHA256));
                }

                _dnsServer.TsigKeys = tsigKeys;
            }
            else
            {
                _dnsServer.TsigKeys = null;
            }

            if (version >= 22)
                _ = bR.ReadBoolean(); //removed NsRevalidation option

            if (version >= 23)
            {
                _dnsServer.AllowTxtBlockingReport = bR.ReadBoolean();
                _dnsServer.AuthZoneManager.DefaultRecordTtl = bR.ReadUInt32();
            }
            else
            {
                _dnsServer.AllowTxtBlockingReport = true;
                _dnsServer.AuthZoneManager.DefaultRecordTtl = 3600;
            }

            if (version >= 24)
            {
                _webServiceUseSelfSignedTlsCertificate = bR.ReadBoolean();

                CheckAndLoadSelfSignedCertificate(false, false);
            }
            else
            {
                _webServiceUseSelfSignedTlsCertificate = false;
            }

            if (version >= 25)
                _dnsServer.UdpPayloadSize = bR.ReadUInt16();
            else
                _dnsServer.UdpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE;

            if (version >= 26)
            {
                _dnsServer.DnssecValidation = bR.ReadBoolean();

                _dnsServer.ResolverRetries = bR.ReadInt32();
                _dnsServer.ResolverTimeout = bR.ReadInt32();
                _dnsServer.ResolverMaxStackCount = bR.ReadInt32();

                _dnsServer.ForwarderRetries = bR.ReadInt32();
                _dnsServer.ForwarderTimeout = bR.ReadInt32();
                _dnsServer.ForwarderConcurrency = bR.ReadInt32();

                _dnsServer.ClientTimeout = bR.ReadInt32();
                if (_dnsServer.ClientTimeout == 4000)
                    _dnsServer.ClientTimeout = 2000;

                _dnsServer.TcpSendTimeout = bR.ReadInt32();
                _dnsServer.TcpReceiveTimeout = bR.ReadInt32();
            }
            else
            {
                _dnsServer.DnssecValidation = true;
                CreateForwarderZoneToDisableDnssecForNTP();

                _dnsServer.ResolverRetries = 2;
                _dnsServer.ResolverTimeout = 1500;
                _dnsServer.ResolverMaxStackCount = 16;

                _dnsServer.ForwarderRetries = 3;
                _dnsServer.ForwarderTimeout = 2000;
                _dnsServer.ForwarderConcurrency = 2;

                _dnsServer.ClientTimeout = 2000;
                _dnsServer.TcpSendTimeout = 10000;
                _dnsServer.TcpReceiveTimeout = 10000;
            }

            if (version >= 27)
                _dnsServer.CacheZoneManager.MaximumEntries = bR.ReadInt32();
            else
                _dnsServer.CacheZoneManager.MaximumEntries = 10000;
        }

        #endregion
    }
}
