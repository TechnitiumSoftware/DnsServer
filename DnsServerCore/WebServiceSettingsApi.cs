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

using DnsServerCore.Auth;
using DnsServerCore.Cluster;
using DnsServerCore.Dns;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ClientConnection;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        sealed class WebServiceSettingsApi
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceSettingsApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            private void RestartService(bool restartDnsService, bool restartWebService, IReadOnlyList<IPAddress> oldWebServiceLocalAddresses, int oldWebServiceHttpPort, int oldWebServiceTlsPort)
            {
                if (restartDnsService)
                {
                    ThreadPool.QueueUserWorkItem(async delegate (object state)
                    {
                        try
                        {
                            _dnsWebService._log.Write("Attempting to restart DNS service.");

                            await _dnsWebService._dnsServer.StopAsync();
                            await _dnsWebService._dnsServer.StartAsync();

                            _dnsWebService._log.Write("DNS service was restarted successfully.");
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write("Failed to restart DNS service.\r\n" + ex.ToString());
                        }
                    });
                }

                if (restartWebService)
                {
                    ThreadPool.QueueUserWorkItem(async delegate (object state)
                    {
                        try
                        {
                            await Task.Delay(2000); //wait for this HTTP response to be delivered before stopping web server

                            _dnsWebService._log.Write("Attempting to restart web service.");

                            try
                            {
                                await _dnsWebService.StopWebServiceAsync();
                                await _dnsWebService.TryStartWebServiceAsync(oldWebServiceLocalAddresses, oldWebServiceHttpPort, oldWebServiceTlsPort);

                                _dnsWebService._log.Write("Web service was restarted successfully.");
                            }
                            catch (Exception ex)
                            {
                                _dnsWebService._log.Write("Failed to restart web service.\r\n" + ex.ToString());
                            }

                            //update cluster node URL to reflect latest TLS port
                            if (_dnsWebService._clusterManager.ClusterInitialized)
                                _dnsWebService._clusterManager.UpdateSelfNodeUrlAndCertificate();
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    });
                }
            }

            private void WriteDnsSettings(Utf8JsonWriter jsonWriter)
            {
                //info
                jsonWriter.WriteString("version", _dnsWebService.GetServerVersion());
                jsonWriter.WriteString("uptimestamp", _dnsWebService._uptimestamp);

                jsonWriter.WriteBoolean("clusterInitialized", _dnsWebService._clusterManager.ClusterInitialized);

                if (_dnsWebService._clusterManager.ClusterInitialized)
                {
                    jsonWriter.WriteString("clusterDomain", _dnsWebService._clusterManager.ClusterDomain);

                    _dnsWebService._clusterApi.WriteClusterNodes(jsonWriter);
                }

                //general
                jsonWriter.WriteString("dnsServerDomain", _dnsWebService._dnsServer.ServerDomain);

                jsonWriter.WriteStringArray("dnsServerLocalEndPoints", _dnsWebService._dnsServer.LocalEndPoints);

                jsonWriter.WriteStringArray("dnsServerIPv4SourceAddresses", DnsClientConnection.IPv4SourceAddresses);
                jsonWriter.WriteStringArray("dnsServerIPv6SourceAddresses", DnsClientConnection.IPv6SourceAddresses);

                jsonWriter.WriteNumber("defaultRecordTtl", _dnsWebService._dnsServer.AuthZoneManager.DefaultRecordTtl);
                jsonWriter.WriteString("defaultResponsiblePerson", _dnsWebService._dnsServer.ResponsiblePersonInternal?.Address);
                jsonWriter.WriteBoolean("useSoaSerialDateScheme", _dnsWebService._dnsServer.AuthZoneManager.UseSoaSerialDateScheme);
                jsonWriter.WriteNumber("minSoaRefresh", _dnsWebService._dnsServer.AuthZoneManager.MinSoaRefresh);
                jsonWriter.WriteNumber("minSoaRetry", _dnsWebService._dnsServer.AuthZoneManager.MinSoaRetry);
                jsonWriter.WriteStringArray("zoneTransferAllowedNetworks", _dnsWebService._dnsServer.ZoneTransferAllowedNetworks);
                jsonWriter.WriteStringArray("notifyAllowedNetworks", _dnsWebService._dnsServer.NotifyAllowedNetworks);

                jsonWriter.WriteBoolean("dnsAppsEnableAutomaticUpdate", _dnsWebService._dnsServer.DnsApplicationManager.EnableAutomaticUpdate);

                jsonWriter.WriteBoolean("preferIPv6", _dnsWebService._dnsServer.PreferIPv6);
                jsonWriter.WriteBoolean("enableUdpSocketPool", _dnsWebService._dnsServer.EnableUdpSocketPool);

                jsonWriter.WriteStartArray("socketPoolExcludedPorts");

                ushort[] socketPoolExcludedPorts = UdpClientConnection.SocketPoolExcludedPorts;
                if (socketPoolExcludedPorts is not null)
                {
                    foreach (ushort excludedPort in socketPoolExcludedPorts)
                        jsonWriter.WriteNumberValue(excludedPort);
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("udpPayloadSize", _dnsWebService._dnsServer.UdpPayloadSize);

                jsonWriter.WriteBoolean("dnssecValidation", _dnsWebService._dnsServer.DnssecValidation);

                jsonWriter.WriteBoolean("eDnsClientSubnet", _dnsWebService._dnsServer.EDnsClientSubnet);
                jsonWriter.WriteNumber("eDnsClientSubnetIPv4PrefixLength", _dnsWebService._dnsServer.EDnsClientSubnetIPv4PrefixLength);
                jsonWriter.WriteNumber("eDnsClientSubnetIPv6PrefixLength", _dnsWebService._dnsServer.EDnsClientSubnetIPv6PrefixLength);
                jsonWriter.WriteString("eDnsClientSubnetIpv4Override", _dnsWebService._dnsServer.EDnsClientSubnetIpv4Override?.ToString());
                jsonWriter.WriteString("eDnsClientSubnetIpv6Override", _dnsWebService._dnsServer.EDnsClientSubnetIpv6Override?.ToString());

                jsonWriter.WriteStartArray("qpmPrefixLimitsIPv4");

                foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in _dnsWebService._dnsServer.QpmPrefixLimitsIPv4)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteNumber("prefix", qpmPrefixLimit.Key);
                    jsonWriter.WriteNumber("udpLimit", qpmPrefixLimit.Value.Item1);
                    jsonWriter.WriteNumber("tcpLimit", qpmPrefixLimit.Value.Item2);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteStartArray("qpmPrefixLimitsIPv6");

                foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in _dnsWebService._dnsServer.QpmPrefixLimitsIPv6)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteNumber("prefix", qpmPrefixLimit.Key);
                    jsonWriter.WriteNumber("udpLimit", qpmPrefixLimit.Value.Item1);
                    jsonWriter.WriteNumber("tcpLimit", qpmPrefixLimit.Value.Item2);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("qpmLimitSampleMinutes", _dnsWebService._dnsServer.QpmLimitSampleMinutes);
                jsonWriter.WriteNumber("qpmLimitUdpTruncationPercentage", _dnsWebService._dnsServer.QpmLimitUdpTruncationPercentage);

                jsonWriter.WritePropertyName("qpmLimitBypassList");
                jsonWriter.WriteStartArray();

                if (_dnsWebService._dnsServer.QpmLimitBypassList is not null)
                {
                    foreach (NetworkAddress network in _dnsWebService._dnsServer.QpmLimitBypassList)
                        jsonWriter.WriteStringValue(network.ToString());
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("clientTimeout", _dnsWebService._dnsServer.ClientTimeout);
                jsonWriter.WriteNumber("tcpSendTimeout", _dnsWebService._dnsServer.TcpSendTimeout);
                jsonWriter.WriteNumber("tcpReceiveTimeout", _dnsWebService._dnsServer.TcpReceiveTimeout);
                jsonWriter.WriteNumber("quicIdleTimeout", _dnsWebService._dnsServer.QuicIdleTimeout);
                jsonWriter.WriteNumber("quicMaxInboundStreams", _dnsWebService._dnsServer.QuicMaxInboundStreams);
                jsonWriter.WriteNumber("listenBacklog", _dnsWebService._dnsServer.ListenBacklog);
                jsonWriter.WriteNumber("maxConcurrentResolutionsPerCore", _dnsWebService._dnsServer.MaxConcurrentResolutionsPerCore);

                //web service
                jsonWriter.WritePropertyName("webServiceLocalAddresses");
                jsonWriter.WriteStartArray();

                foreach (IPAddress localAddress in _dnsWebService._webServiceLocalAddresses)
                {
                    if (localAddress.AddressFamily == AddressFamily.InterNetworkV6)
                        jsonWriter.WriteStringValue("[" + localAddress.ToString() + "]");
                    else
                        jsonWriter.WriteStringValue(localAddress.ToString());
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("webServiceHttpPort", _dnsWebService._webServiceHttpPort);
                jsonWriter.WriteBoolean("webServiceEnableTls", _dnsWebService._webServiceEnableTls);
                jsonWriter.WriteBoolean("webServiceEnableHttp3", _dnsWebService._webServiceEnableHttp3);
                jsonWriter.WriteBoolean("webServiceHttpToTlsRedirect", _dnsWebService._webServiceHttpToTlsRedirect);
                jsonWriter.WriteBoolean("webServiceUseSelfSignedTlsCertificate", _dnsWebService._webServiceUseSelfSignedTlsCertificate);
                jsonWriter.WriteNumber("webServiceTlsPort", _dnsWebService._webServiceTlsPort);
                jsonWriter.WriteString("webServiceTlsCertificatePath", _dnsWebService._webServiceTlsCertificatePath);
                jsonWriter.WriteString("webServiceTlsCertificatePassword", "************");
                jsonWriter.WriteString("webServiceRealIpHeader", _dnsWebService._webServiceRealIpHeader);

                //optional protocols
                jsonWriter.WriteBoolean("enableDnsOverUdpProxy", _dnsWebService._dnsServer.EnableDnsOverUdpProxy);
                jsonWriter.WriteBoolean("enableDnsOverTcpProxy", _dnsWebService._dnsServer.EnableDnsOverTcpProxy);
                jsonWriter.WriteBoolean("enableDnsOverHttp", _dnsWebService._dnsServer.EnableDnsOverHttp);
                jsonWriter.WriteBoolean("enableDnsOverTls", _dnsWebService._dnsServer.EnableDnsOverTls);
                jsonWriter.WriteBoolean("enableDnsOverHttps", _dnsWebService._dnsServer.EnableDnsOverHttps);
                jsonWriter.WriteBoolean("enableDnsOverHttp3", _dnsWebService._dnsServer.EnableDnsOverHttp3);
                jsonWriter.WriteBoolean("enableDnsOverQuic", _dnsWebService._dnsServer.EnableDnsOverQuic);
                jsonWriter.WriteNumber("dnsOverUdpProxyPort", _dnsWebService._dnsServer.DnsOverUdpProxyPort);
                jsonWriter.WriteNumber("dnsOverTcpProxyPort", _dnsWebService._dnsServer.DnsOverTcpProxyPort);
                jsonWriter.WriteNumber("dnsOverHttpPort", _dnsWebService._dnsServer.DnsOverHttpPort);
                jsonWriter.WriteNumber("dnsOverTlsPort", _dnsWebService._dnsServer.DnsOverTlsPort);
                jsonWriter.WriteNumber("dnsOverHttpsPort", _dnsWebService._dnsServer.DnsOverHttpsPort);
                jsonWriter.WriteNumber("dnsOverQuicPort", _dnsWebService._dnsServer.DnsOverQuicPort);

                jsonWriter.WritePropertyName("reverseProxyNetworkACL");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._dnsServer.ReverseProxyNetworkACL is not null)
                    {
                        foreach (NetworkAccessControl nac in _dnsWebService._dnsServer.ReverseProxyNetworkACL)
                            jsonWriter.WriteStringValue(nac.ToString());
                    }

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteString("dnsTlsCertificatePath", _dnsWebService._dnsServer.DnsTlsCertificatePath);
                jsonWriter.WriteString("dnsTlsCertificatePassword", "************");
                jsonWriter.WriteString("dnsOverHttpRealIpHeader", _dnsWebService._dnsServer.DnsOverHttpRealIpHeader);

                //tsig
                jsonWriter.WritePropertyName("tsigKeys");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._dnsServer.TsigKeys is not null)
                    {
                        foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsWebService._dnsServer.TsigKeys.ToImmutableSortedDictionary())
                        {
                            jsonWriter.WriteStartObject();

                            jsonWriter.WriteString("keyName", tsigKey.Key);
                            jsonWriter.WriteString("sharedSecret", tsigKey.Value.SharedSecret);
                            jsonWriter.WriteString("algorithmName", tsigKey.Value.AlgorithmName);

                            jsonWriter.WriteEndObject();
                        }
                    }

                    jsonWriter.WriteEndArray();
                }

                //recursion
                jsonWriter.WriteString("recursion", _dnsWebService._dnsServer.Recursion.ToString());

                jsonWriter.WritePropertyName("recursionNetworkACL");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._dnsServer.RecursionNetworkACL is not null)
                    {
                        foreach (NetworkAccessControl nac in _dnsWebService._dnsServer.RecursionNetworkACL)
                            jsonWriter.WriteStringValue(nac.ToString());
                    }

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteBoolean("randomizeName", _dnsWebService._dnsServer.RandomizeName);
                jsonWriter.WriteBoolean("qnameMinimization", _dnsWebService._dnsServer.QnameMinimization);

                jsonWriter.WriteNumber("resolverRetries", _dnsWebService._dnsServer.ResolverRetries);
                jsonWriter.WriteNumber("resolverTimeout", _dnsWebService._dnsServer.ResolverTimeout);
                jsonWriter.WriteNumber("resolverConcurrency", _dnsWebService._dnsServer.ResolverConcurrency);
                jsonWriter.WriteNumber("resolverMaxStackCount", _dnsWebService._dnsServer.ResolverMaxStackCount);

                //cache
                jsonWriter.WriteBoolean("saveCache", _dnsWebService._dnsServer.SaveCacheToDisk);
                jsonWriter.WriteBoolean("serveStale", _dnsWebService._dnsServer.ServeStale);
                jsonWriter.WriteNumber("serveStaleTtl", _dnsWebService._dnsServer.CacheZoneManager.ServeStaleTtl);
                jsonWriter.WriteNumber("serveStaleAnswerTtl", _dnsWebService._dnsServer.CacheZoneManager.ServeStaleAnswerTtl);
                jsonWriter.WriteNumber("serveStaleResetTtl", _dnsWebService._dnsServer.CacheZoneManager.ServeStaleResetTtl);
                jsonWriter.WriteNumber("serveStaleMaxWaitTime", _dnsWebService._dnsServer.ServeStaleMaxWaitTime);

                jsonWriter.WriteNumber("cacheMaximumEntries", _dnsWebService._dnsServer.CacheZoneManager.MaximumEntries);
                jsonWriter.WriteNumber("cacheMinimumRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.MinimumRecordTtl);
                jsonWriter.WriteNumber("cacheMaximumRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.MaximumRecordTtl);
                jsonWriter.WriteNumber("cacheNegativeRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.NegativeRecordTtl);
                jsonWriter.WriteNumber("cacheFailureRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.FailureRecordTtl);

                jsonWriter.WriteNumber("cachePrefetchEligibility", _dnsWebService._dnsServer.CachePrefetchEligibility);
                jsonWriter.WriteNumber("cachePrefetchTrigger", _dnsWebService._dnsServer.CachePrefetchTrigger);
                jsonWriter.WriteNumber("cachePrefetchSampleIntervalInMinutes", _dnsWebService._dnsServer.CachePrefetchSampleIntervalMinutes);
                jsonWriter.WriteNumber("cachePrefetchSampleEligibilityHitsPerHour", _dnsWebService._dnsServer.CachePrefetchSampleEligibilityHitsPerHour);

                //blocking
                jsonWriter.WriteBoolean("enableBlocking", _dnsWebService._dnsServer.EnableBlocking);
                jsonWriter.WriteBoolean("allowTxtBlockingReport", _dnsWebService._dnsServer.AllowTxtBlockingReport);

                jsonWriter.WritePropertyName("blockingBypassList");
                jsonWriter.WriteStartArray();

                if (_dnsWebService._dnsServer.BlockingBypassList is not null)
                {
                    foreach (NetworkAddress network in _dnsWebService._dnsServer.BlockingBypassList)
                        jsonWriter.WriteStringValue(network.ToString());
                }

                jsonWriter.WriteEndArray();

                if (!_dnsWebService._dnsServer.EnableBlocking && (DateTime.UtcNow < _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlockingTill))
                    jsonWriter.WriteString("temporaryDisableBlockingTill", _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlockingTill);

                jsonWriter.WriteString("blockingType", _dnsWebService._dnsServer.BlockingType.ToString());
                jsonWriter.WriteNumber("blockingAnswerTtl", _dnsWebService._dnsServer.BlockingAnswerTtl);

                jsonWriter.WritePropertyName("customBlockingAddresses");
                jsonWriter.WriteStartArray();

                foreach (DnsARecordData record in _dnsWebService._dnsServer.CustomBlockingARecords)
                    jsonWriter.WriteStringValue(record.Address.ToString());

                foreach (DnsAAAARecordData record in _dnsWebService._dnsServer.CustomBlockingAAAARecords)
                    jsonWriter.WriteStringValue(record.Address.ToString());

                jsonWriter.WriteEndArray();

                jsonWriter.WritePropertyName("blockListUrls");

                if (_dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Count == 0)
                {
                    jsonWriter.WriteNullValue();
                }
                else
                {
                    jsonWriter.WriteStartArray();

                    foreach (string blockListUrl in _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls)
                        jsonWriter.WriteStringValue(blockListUrl);

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteNumber("blockListUpdateIntervalHours", _dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours);

                if (_dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateEnabled)
                {
                    DateTime blockListNextUpdatedOn = _dnsWebService._dnsServer.BlockListZoneManager.BlockListLastUpdatedOn.AddHours(_dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours);

                    jsonWriter.WriteString("blockListNextUpdatedOn", blockListNextUpdatedOn);
                }

                //proxy & forwarders
                jsonWriter.WritePropertyName("proxy");
                if (_dnsWebService._dnsServer.Proxy == null)
                {
                    jsonWriter.WriteNullValue();
                }
                else
                {
                    jsonWriter.WriteStartObject();

                    NetProxy proxy = _dnsWebService._dnsServer.Proxy;

                    jsonWriter.WriteString("type", proxy.Type.ToString());
                    jsonWriter.WriteString("address", proxy.Address);
                    jsonWriter.WriteNumber("port", proxy.Port);

                    NetworkCredential credential = proxy.Credential;
                    if (credential != null)
                    {
                        jsonWriter.WriteString("username", credential.UserName);
                        jsonWriter.WriteString("password", credential.Password);
                    }

                    jsonWriter.WritePropertyName("bypass");
                    jsonWriter.WriteStartArray();

                    foreach (NetProxyBypassItem item in proxy.BypassList)
                        jsonWriter.WriteStringValue(item.Value);

                    jsonWriter.WriteEndArray();

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WritePropertyName("forwarders");

                DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;

                if (_dnsWebService._dnsServer.Forwarders == null)
                {
                    jsonWriter.WriteNullValue();
                }
                else
                {
                    forwarderProtocol = _dnsWebService._dnsServer.Forwarders[0].Protocol;

                    jsonWriter.WriteStartArray();

                    foreach (NameServerAddress forwarder in _dnsWebService._dnsServer.Forwarders)
                        jsonWriter.WriteStringValue(forwarder.OriginalAddress);

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteString("forwarderProtocol", forwarderProtocol.ToString());
                jsonWriter.WriteBoolean("concurrentForwarding", _dnsWebService._dnsServer.ConcurrentForwarding);

                jsonWriter.WriteNumber("forwarderRetries", _dnsWebService._dnsServer.ForwarderRetries);
                jsonWriter.WriteNumber("forwarderTimeout", _dnsWebService._dnsServer.ForwarderTimeout);
                jsonWriter.WriteNumber("forwarderConcurrency", _dnsWebService._dnsServer.ForwarderConcurrency);

                //logging
                jsonWriter.WriteBoolean("enableLogging", _dnsWebService._log.LoggingType != LoggingType.None);
                jsonWriter.WriteString("loggingType", _dnsWebService._log.LoggingType.ToString());
                jsonWriter.WriteBoolean("ignoreResolverLogs", _dnsWebService._dnsServer.ResolverLogManager == null);
                jsonWriter.WriteBoolean("logQueries", _dnsWebService._dnsServer.QueryLogManager != null);
                jsonWriter.WriteBoolean("useLocalTime", _dnsWebService._log.UseLocalTime);
                jsonWriter.WriteString("logFolder", _dnsWebService._log.LogFolder);
                jsonWriter.WriteNumber("maxLogFileDays", _dnsWebService._log.MaxLogFileDays);

                jsonWriter.WriteBoolean("enableInMemoryStats", _dnsWebService._dnsServer.StatsManager.EnableInMemoryStats);
                jsonWriter.WriteNumber("maxStatFileDays", _dnsWebService._dnsServer.StatsManager.MaxStatFileDays);
            }

            #endregion

            #region public

            public void GetDnsSettings(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteDnsSettings(jsonWriter);
            }

            public async Task SetDnsSettingsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                bool serverDomainChanged = false;
                bool webServiceLocalAddressesChanged = false;
                bool webServiceTlsCertificateChanged = false;
                bool restartDnsService = false;
                bool restartWebService = false;
                IReadOnlyList<IPAddress> oldWebServiceLocalAddresses = _dnsWebService._webServiceLocalAddresses;
                int oldWebServiceHttpPort = _dnsWebService._webServiceHttpPort;
                int oldWebServiceTlsPort = _dnsWebService._webServiceTlsPort;
                bool _webServiceEnablingTls = false;

                Dictionary<string, string> clusterParameters = new Dictionary<string, string>(128);

                HttpRequest request = context.Request;
                JsonDocument jsonDocument = null;

                if (request.HasJsonContentType())
                {
                    jsonDocument = await JsonDocument.ParseAsync(request.Body);
                    context.Items["jsonContent"] = jsonDocument;
                }

                try
                {
                    try
                    {
                        #region general

                        if (request.TryGetQueryOrForm("dnsServerDomain", out string dnsServerDomain))
                        {
                            dnsServerDomain = dnsServerDomain.TrimEnd('.');

                            if (!_dnsWebService._dnsServer.ServerDomain.Equals(dnsServerDomain, StringComparison.OrdinalIgnoreCase))
                            {
                                if (_dnsWebService._clusterManager.ClusterInitialized)
                                {
                                    if (!dnsServerDomain.EndsWith("." + _dnsWebService._clusterManager.ClusterDomain, StringComparison.OrdinalIgnoreCase))
                                        throw new ArgumentException("DNS server domain name must end with the cluster domain name.", nameof(dnsServerDomain));
                                }

                                _dnsWebService._dnsServer.ServerDomain = dnsServerDomain;
                                serverDomainChanged = true;
                            }
                        }

                        if (request.TryGetQueryOrFormArray("dnsServerLocalEndPoints", IPEndPoint.Parse, out IPEndPoint[] dnsServerLocalEndPoints))
                        {
                            if ((dnsServerLocalEndPoints is null) || (dnsServerLocalEndPoints.Length == 0))
                            {
                                dnsServerLocalEndPoints = [new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53)];
                            }
                            else
                            {
                                foreach (IPEndPoint localEndPoint in dnsServerLocalEndPoints)
                                {
                                    if (localEndPoint.Port == 0)
                                        localEndPoint.Port = 53;
                                }
                            }

                            if (!_dnsWebService._dnsServer.LocalEndPoints.HasSameItems(dnsServerLocalEndPoints))
                                restartDnsService = true;

                            _dnsWebService._dnsServer.LocalEndPoints = dnsServerLocalEndPoints;
                        }

                        if (request.TryGetQueryOrFormArray("dnsServerIPv4SourceAddresses", NetworkAddress.Parse, out NetworkAddress[] dnsServerIPv4SourceAddresses))
                            DnsClientConnection.IPv4SourceAddresses = dnsServerIPv4SourceAddresses;

                        if (request.TryGetQueryOrFormArray("dnsServerIPv6SourceAddresses", NetworkAddress.Parse, out NetworkAddress[] dnsServerIPv6SourceAddresses))
                            DnsClientConnection.IPv6SourceAddresses = dnsServerIPv6SourceAddresses;

                        if (request.TryGetQueryOrForm("defaultRecordTtl", ZoneFile.ParseTtl, out uint defaultRecordTtl))
                        {
                            _dnsWebService._dnsServer.AuthZoneManager.DefaultRecordTtl = defaultRecordTtl;

                            clusterParameters.Add("defaultRecordTtl", defaultRecordTtl.ToString());
                        }

                        string defaultResponsiblePerson = request.QueryOrForm("defaultResponsiblePerson");
                        if (defaultResponsiblePerson is not null)
                        {
                            if (defaultResponsiblePerson.Length == 0)
                                _dnsWebService._dnsServer.ResponsiblePersonInternal = null;
                            else if (defaultResponsiblePerson.Length > 255)
                                throw new ArgumentException("Default responsible person email address length cannot exceed 255 characters.", nameof(defaultResponsiblePerson));
                            else
                                _dnsWebService._dnsServer.ResponsiblePersonInternal = new MailAddress(defaultResponsiblePerson);

                            clusterParameters.Add("defaultResponsiblePerson", defaultResponsiblePerson);
                        }

                        if (request.TryGetQueryOrForm("useSoaSerialDateScheme", bool.Parse, out bool useSoaSerialDateScheme))
                        {
                            _dnsWebService._dnsServer.AuthZoneManager.UseSoaSerialDateScheme = useSoaSerialDateScheme;

                            clusterParameters.Add("useSoaSerialDateScheme", useSoaSerialDateScheme.ToString());
                        }

                        if (request.TryGetQueryOrForm("minSoaRefresh", ZoneFile.ParseTtl, out uint minSoaRefresh))
                        {
                            _dnsWebService._dnsServer.AuthZoneManager.MinSoaRefresh = minSoaRefresh;

                            clusterParameters.Add("minSoaRefresh", minSoaRefresh.ToString());
                        }

                        if (request.TryGetQueryOrForm("minSoaRetry", ZoneFile.ParseTtl, out uint minSoaRetry))
                        {
                            _dnsWebService._dnsServer.AuthZoneManager.MinSoaRetry = minSoaRetry;

                            clusterParameters.Add("minSoaRetry", minSoaRetry.ToString());
                        }

                        if (request.TryGetQueryOrFormArray("zoneTransferAllowedNetworks", NetworkAddress.Parse, out NetworkAddress[] zoneTransferAllowedNetworks))
                        {
                            _dnsWebService._dnsServer.ZoneTransferAllowedNetworks = zoneTransferAllowedNetworks;

                            clusterParameters.Add("zoneTransferAllowedNetworks", request.GetQueryOrForm("zoneTransferAllowedNetworks"));
                        }

                        if (request.TryGetQueryOrFormArray("notifyAllowedNetworks", NetworkAddress.Parse, out NetworkAddress[] notifyAllowedNetworks))
                        {
                            _dnsWebService._dnsServer.NotifyAllowedNetworks = notifyAllowedNetworks;

                            clusterParameters.Add("notifyAllowedNetworks", request.GetQueryOrForm("notifyAllowedNetworks"));
                        }

                        if (request.TryGetQueryOrForm("dnsAppsEnableAutomaticUpdate", bool.Parse, out bool dnsAppsEnableAutomaticUpdate))
                        {
                            _dnsWebService._dnsServer.DnsApplicationManager.EnableAutomaticUpdate = dnsAppsEnableAutomaticUpdate;

                            clusterParameters.Add("dnsAppsEnableAutomaticUpdate", dnsAppsEnableAutomaticUpdate.ToString());
                        }

                        if (request.TryGetQueryOrForm("preferIPv6", bool.Parse, out bool preferIPv6))
                            _dnsWebService._dnsServer.PreferIPv6 = preferIPv6;

                        if (request.TryGetQueryOrForm("enableUdpSocketPool", bool.Parse, out bool enableUdpSocketPool))
                            _dnsWebService._dnsServer.EnableUdpSocketPool = enableUdpSocketPool;

                        if (request.TryGetQueryOrFormArray("socketPoolExcludedPorts", ushort.Parse, out ushort[] socketPoolExcludedPorts))
                            UdpClientConnection.SocketPoolExcludedPorts = socketPoolExcludedPorts;

                        if (request.TryGetQueryOrForm("udpPayloadSize", ushort.Parse, out ushort udpPayloadSize))
                        {
                            _dnsWebService._dnsServer.UdpPayloadSize = udpPayloadSize;

                            clusterParameters.Add("udpPayloadSize", udpPayloadSize.ToString());
                        }

                        if (request.TryGetQueryOrForm("dnssecValidation", bool.Parse, out bool dnssecValidation))
                        {
                            _dnsWebService._dnsServer.DnssecValidation = dnssecValidation;

                            clusterParameters.Add("dnssecValidation", dnssecValidation.ToString());
                        }

                        if (request.TryGetQueryOrForm("eDnsClientSubnet", bool.Parse, out bool eDnsClientSubnet))
                        {
                            _dnsWebService._dnsServer.EDnsClientSubnet = eDnsClientSubnet;

                            clusterParameters.Add("eDnsClientSubnet", eDnsClientSubnet.ToString());
                        }

                        if (request.TryGetQueryOrForm("eDnsClientSubnetIPv4PrefixLength", byte.Parse, out byte eDnsClientSubnetIPv4PrefixLength))
                        {
                            _dnsWebService._dnsServer.EDnsClientSubnetIPv4PrefixLength = eDnsClientSubnetIPv4PrefixLength;

                            clusterParameters.Add("eDnsClientSubnetIPv4PrefixLength", eDnsClientSubnetIPv4PrefixLength.ToString());
                        }

                        if (request.TryGetQueryOrForm("eDnsClientSubnetIPv6PrefixLength", byte.Parse, out byte eDnsClientSubnetIPv6PrefixLength))
                        {
                            _dnsWebService._dnsServer.EDnsClientSubnetIPv6PrefixLength = eDnsClientSubnetIPv6PrefixLength;

                            clusterParameters.Add("eDnsClientSubnetIPv6PrefixLength", eDnsClientSubnetIPv6PrefixLength.ToString());
                        }

                        string eDnsClientSubnetIpv4Override = request.QueryOrForm("eDnsClientSubnetIpv4Override");
                        if (eDnsClientSubnetIpv4Override is not null)
                        {
                            if (eDnsClientSubnetIpv4Override.Length == 0)
                                _dnsWebService._dnsServer.EDnsClientSubnetIpv4Override = null;
                            else
                                _dnsWebService._dnsServer.EDnsClientSubnetIpv4Override = NetworkAddress.Parse(eDnsClientSubnetIpv4Override);

                            clusterParameters.Add("eDnsClientSubnetIpv4Override", eDnsClientSubnetIpv4Override);
                        }

                        string eDnsClientSubnetIpv6Override = request.QueryOrForm("eDnsClientSubnetIpv6Override");
                        if (eDnsClientSubnetIpv6Override is not null)
                        {
                            if (eDnsClientSubnetIpv6Override.Length == 0)
                                _dnsWebService._dnsServer.EDnsClientSubnetIpv6Override = null;
                            else
                                _dnsWebService._dnsServer.EDnsClientSubnetIpv6Override = NetworkAddress.Parse(eDnsClientSubnetIpv6Override);

                            clusterParameters.Add("eDnsClientSubnetIpv6Override", eDnsClientSubnetIpv6Override);
                        }

                        if (request.TryGetQueryOrFormArray("qpmPrefixLimitsIPv4", delegate (JsonElement jsonObject)
                            {
                                int prefix = jsonObject.GetProperty("prefix").GetInt32();
                                int udpLimit = jsonObject.GetProperty("udpLimit").GetInt32();
                                int tcpLimit = jsonObject.GetProperty("tcpLimit").GetInt32();

                                return new KeyValuePair<int, (int, int)>(prefix, (udpLimit, tcpLimit));
                            }, delegate (ArraySegment<string> tableRow)
                            {
                                int prefix = int.Parse(tableRow[0]);
                                int udpLimit = int.Parse(tableRow[1]);
                                int tcpLimit = int.Parse(tableRow[2]);

                                return new KeyValuePair<int, (int, int)>(prefix, (udpLimit, tcpLimit));
                            },
                            3, out KeyValuePair<int, (int, int)>[] qpmPrefixLimitsIPv4, '|'))
                        {
                            if ((qpmPrefixLimitsIPv4 is null) || (qpmPrefixLimitsIPv4.Length == 0))
                            {
                                _dnsWebService._dnsServer.QpmPrefixLimitsIPv4 = null;
                            }
                            else
                            {
                                Dictionary<int, (int, int)> qpmPrefixLimitsIPv4Map = new Dictionary<int, (int, int)>(qpmPrefixLimitsIPv4.Length);

                                foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in qpmPrefixLimitsIPv4)
                                    qpmPrefixLimitsIPv4Map.Add(qpmPrefixLimit.Key, qpmPrefixLimit.Value);

                                _dnsWebService._dnsServer.QpmPrefixLimitsIPv4 = qpmPrefixLimitsIPv4Map;
                            }

                            clusterParameters.Add("qpmPrefixLimitsIPv4", request.GetQueryOrForm("qpmPrefixLimitsIPv4"));
                        }

                        if (request.TryGetQueryOrFormArray("qpmPrefixLimitsIPv6", delegate (JsonElement jsonObject)
                        {
                            int prefix = jsonObject.GetProperty("prefix").GetInt32();
                            int udpLimit = jsonObject.GetProperty("udpLimit").GetInt32();
                            int tcpLimit = jsonObject.GetProperty("tcpLimit").GetInt32();

                            return new KeyValuePair<int, (int, int)>(prefix, (udpLimit, tcpLimit));
                        }, delegate (ArraySegment<string> tableRow)
                        {
                            int prefix = int.Parse(tableRow[0]);
                            int udpLimit = int.Parse(tableRow[1]);
                            int tcpLimit = int.Parse(tableRow[2]);

                            return new KeyValuePair<int, (int, int)>(prefix, (udpLimit, tcpLimit));
                        },
                            3, out KeyValuePair<int, (int, int)>[] qpmPrefixLimitsIPv6, '|'))
                        {
                            if ((qpmPrefixLimitsIPv6 is null) || (qpmPrefixLimitsIPv6.Length == 0))
                            {
                                _dnsWebService._dnsServer.QpmPrefixLimitsIPv6 = null;
                            }
                            else
                            {
                                Dictionary<int, (int, int)> qpmPrefixLimitsIPv6Map = new Dictionary<int, (int, int)>(qpmPrefixLimitsIPv6.Length);

                                foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in qpmPrefixLimitsIPv6)
                                    qpmPrefixLimitsIPv6Map.Add(qpmPrefixLimit.Key, qpmPrefixLimit.Value);

                                _dnsWebService._dnsServer.QpmPrefixLimitsIPv6 = qpmPrefixLimitsIPv6Map;
                            }

                            clusterParameters.Add("qpmPrefixLimitsIPv6", request.GetQueryOrForm("qpmPrefixLimitsIPv6"));
                        }

                        if (request.TryGetQueryOrForm("qpmLimitSampleMinutes", int.Parse, out int qpmLimitSampleMinutes))
                        {
                            _dnsWebService._dnsServer.QpmLimitSampleMinutes = qpmLimitSampleMinutes;

                            clusterParameters.Add("qpmLimitSampleMinutes", qpmLimitSampleMinutes.ToString());
                        }

                        if (request.TryGetQueryOrForm("qpmLimitUdpTruncationPercentage", int.Parse, out int qpmLimitUdpTruncationPercentage))
                        {
                            _dnsWebService._dnsServer.QpmLimitUdpTruncationPercentage = qpmLimitUdpTruncationPercentage;

                            clusterParameters.Add("qpmLimitUdpTruncationPercentage", qpmLimitUdpTruncationPercentage.ToString());
                        }

                        if (request.TryGetQueryOrFormArray("qpmLimitBypassList", NetworkAddress.Parse, out NetworkAddress[] qpmLimitBypassList))
                        {
                            _dnsWebService._dnsServer.QpmLimitBypassList = qpmLimitBypassList;

                            clusterParameters.Add("qpmLimitBypassList", request.GetQueryOrForm("qpmLimitBypassList"));
                        }

                        if (request.TryGetQueryOrForm("clientTimeout", int.Parse, out int clientTimeout))
                        {
                            _dnsWebService._dnsServer.ClientTimeout = clientTimeout;

                            clusterParameters.Add("clientTimeout", clientTimeout.ToString());
                        }

                        if (request.TryGetQueryOrForm("tcpSendTimeout", int.Parse, out int tcpSendTimeout))
                        {
                            _dnsWebService._dnsServer.TcpSendTimeout = tcpSendTimeout;

                            clusterParameters.Add("tcpSendTimeout", tcpSendTimeout.ToString());
                        }

                        if (request.TryGetQueryOrForm("tcpReceiveTimeout", int.Parse, out int tcpReceiveTimeout))
                        {
                            _dnsWebService._dnsServer.TcpReceiveTimeout = tcpReceiveTimeout;

                            clusterParameters.Add("tcpReceiveTimeout", tcpReceiveTimeout.ToString());
                        }

                        if (request.TryGetQueryOrForm("quicIdleTimeout", int.Parse, out int quicIdleTimeout))
                        {
                            _dnsWebService._dnsServer.QuicIdleTimeout = quicIdleTimeout;

                            clusterParameters.Add("quicIdleTimeout", quicIdleTimeout.ToString());
                        }

                        if (request.TryGetQueryOrForm("quicMaxInboundStreams", int.Parse, out int quicMaxInboundStreams))
                        {
                            _dnsWebService._dnsServer.QuicMaxInboundStreams = quicMaxInboundStreams;

                            clusterParameters.Add("quicMaxInboundStreams", quicMaxInboundStreams.ToString());
                        }

                        if (request.TryGetQueryOrForm("listenBacklog", int.Parse, out int listenBacklog))
                        {
                            _dnsWebService._dnsServer.ListenBacklog = listenBacklog;

                            clusterParameters.Add("listenBacklog", listenBacklog.ToString());
                        }

                        if (request.TryGetQueryOrForm("maxConcurrentResolutionsPerCore", ushort.Parse, out ushort maxConcurrentResolutionsPerCore))
                        {
                            _dnsWebService._dnsServer.MaxConcurrentResolutionsPerCore = maxConcurrentResolutionsPerCore;

                            clusterParameters.Add("maxConcurrentResolutionsPerCore", maxConcurrentResolutionsPerCore.ToString());
                        }

                        #endregion

                        #region web service

                        if (request.TryGetQueryOrFormArray("webServiceLocalAddresses", IPAddress.Parse, out IPAddress[] webServiceLocalAddresses))
                        {
                            if ((webServiceLocalAddresses is null) || (webServiceLocalAddresses.Length == 0))
                                webServiceLocalAddresses = [IPAddress.Any, IPAddress.IPv6Any];

                            if (!_dnsWebService._webServiceLocalAddresses.HasSameItems(webServiceLocalAddresses))
                            {
                                webServiceLocalAddressesChanged = true;
                                restartWebService = true;
                            }

                            _dnsWebService._webServiceLocalAddresses = WebUtilities.GetValidKestrelLocalAddresses(webServiceLocalAddresses);
                        }

                        if (request.TryGetQueryOrForm("webServiceHttpPort", int.Parse, out int webServiceHttpPort))
                        {
                            if (_dnsWebService._webServiceHttpPort != webServiceHttpPort)
                            {
                                _dnsWebService._webServiceHttpPort = webServiceHttpPort;
                                restartWebService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceEnableTls", bool.Parse, out bool webServiceEnableTls))
                        {
                            if (_dnsWebService._webServiceEnableTls != webServiceEnableTls)
                            {
                                _dnsWebService._webServiceEnableTls = webServiceEnableTls;
                                _webServiceEnablingTls = webServiceEnableTls;
                                restartWebService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceEnableHttp3", bool.Parse, out bool webServiceEnableHttp3))
                        {
                            if (_dnsWebService._webServiceEnableHttp3 != webServiceEnableHttp3)
                            {
                                if (webServiceEnableHttp3)
                                    DnsWebService.ValidateQuicSupport("HTTP/3");

                                _dnsWebService._webServiceEnableHttp3 = webServiceEnableHttp3;
                                restartWebService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceHttpToTlsRedirect", bool.Parse, out bool webServiceHttpToTlsRedirect))
                        {
                            if (_dnsWebService._webServiceHttpToTlsRedirect != webServiceHttpToTlsRedirect)
                            {
                                _dnsWebService._webServiceHttpToTlsRedirect = webServiceHttpToTlsRedirect;
                                restartWebService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceUseSelfSignedTlsCertificate", bool.Parse, out bool webServiceUseSelfSignedTlsCertificate))
                            _dnsWebService._webServiceUseSelfSignedTlsCertificate = webServiceUseSelfSignedTlsCertificate;

                        if (request.TryGetQueryOrForm("webServiceTlsPort", int.Parse, out int webServiceTlsPort))
                        {
                            if (_dnsWebService._webServiceTlsPort != webServiceTlsPort)
                            {
                                _dnsWebService._webServiceTlsPort = webServiceTlsPort;
                                restartWebService = true;
                            }
                        }

                        string webServiceTlsCertificatePath = request.QueryOrForm("webServiceTlsCertificatePath");
                        if (webServiceTlsCertificatePath is not null)
                        {
                            if (webServiceTlsCertificatePath.Length == 0)
                            {
                                if (!string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath))
                                {
                                    _dnsWebService.RemoveWebServiceTlsCertificate();
                                    webServiceTlsCertificateChanged = true;
                                }
                            }
                            else
                            {
                                string webServiceTlsCertificatePassword = request.QueryOrForm("webServiceTlsCertificatePassword");

                                if ((webServiceTlsCertificatePassword is null) || (webServiceTlsCertificatePassword == "************"))
                                    webServiceTlsCertificatePassword = _dnsWebService._webServiceTlsCertificatePassword;

                                if ((webServiceTlsCertificatePath != _dnsWebService._webServiceTlsCertificatePath) || (webServiceTlsCertificatePassword != _dnsWebService._webServiceTlsCertificatePassword))
                                {
                                    _dnsWebService.SetWebServiceTlsCertificate(webServiceTlsCertificatePath, webServiceTlsCertificatePassword);
                                    webServiceTlsCertificateChanged = true;
                                }
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceRealIpHeader", out string webServiceRealIpHeader))
                        {
                            if (webServiceRealIpHeader.Length > 255)
                                throw new ArgumentException("Web service Real IP header name cannot exceed 255 characters.", nameof(webServiceRealIpHeader));

                            if (webServiceRealIpHeader.Contains(' '))
                                throw new ArgumentException("Web service Real IP header name cannot contain invalid characters.", nameof(webServiceRealIpHeader));

                            _dnsWebService._webServiceRealIpHeader = webServiceRealIpHeader;
                        }

                        #endregion

                        #region optional protocols

                        if (request.TryGetQueryOrForm("enableDnsOverUdpProxy", bool.Parse, out bool enableDnsOverUdpProxy))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverUdpProxy != enableDnsOverUdpProxy)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverUdpProxy = enableDnsOverUdpProxy;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverTcpProxy", bool.Parse, out bool enableDnsOverTcpProxy))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverTcpProxy != enableDnsOverTcpProxy)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverTcpProxy = enableDnsOverTcpProxy;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverHttp", bool.Parse, out bool enableDnsOverHttp))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverHttp != enableDnsOverHttp)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverHttp = enableDnsOverHttp;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverTls", bool.Parse, out bool enableDnsOverTls))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverTls != enableDnsOverTls)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverTls = enableDnsOverTls;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverHttps", bool.Parse, out bool enableDnsOverHttps))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverHttps != enableDnsOverHttps)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverHttps = enableDnsOverHttps;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverHttp3", bool.Parse, out bool enableDnsOverHttp3))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverHttp3 != enableDnsOverHttp3)
                            {
                                if (enableDnsOverHttp3)
                                    DnsWebService.ValidateQuicSupport("DNS-over-HTTP/3");

                                _dnsWebService._dnsServer.EnableDnsOverHttp3 = enableDnsOverHttp3;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverQuic", bool.Parse, out bool enableDnsOverQuic))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverQuic != enableDnsOverQuic)
                            {
                                if (enableDnsOverQuic)
                                    DnsWebService.ValidateQuicSupport();

                                _dnsWebService._dnsServer.EnableDnsOverQuic = enableDnsOverQuic;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverUdpProxyPort", int.Parse, out int dnsOverUdpProxyPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverUdpProxyPort != dnsOverUdpProxyPort)
                            {
                                _dnsWebService._dnsServer.DnsOverUdpProxyPort = dnsOverUdpProxyPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverTcpProxyPort", int.Parse, out int dnsOverTcpProxyPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverTcpProxyPort != dnsOverTcpProxyPort)
                            {
                                _dnsWebService._dnsServer.DnsOverTcpProxyPort = dnsOverTcpProxyPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverHttpPort", int.Parse, out int dnsOverHttpPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverHttpPort != dnsOverHttpPort)
                            {
                                _dnsWebService._dnsServer.DnsOverHttpPort = dnsOverHttpPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverTlsPort", int.Parse, out int dnsOverTlsPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverTlsPort != dnsOverTlsPort)
                            {
                                _dnsWebService._dnsServer.DnsOverTlsPort = dnsOverTlsPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverHttpsPort", int.Parse, out int dnsOverHttpsPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverHttpsPort != dnsOverHttpsPort)
                            {
                                _dnsWebService._dnsServer.DnsOverHttpsPort = dnsOverHttpsPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverQuicPort", int.Parse, out int dnsOverQuicPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverQuicPort != dnsOverQuicPort)
                            {
                                _dnsWebService._dnsServer.DnsOverQuicPort = dnsOverQuicPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrFormArray("reverseProxyNetworkACL", NetworkAccessControl.Parse, out NetworkAccessControl[] reverseProxyNetworkACL))
                            _dnsWebService._dnsServer.ReverseProxyNetworkACL = reverseProxyNetworkACL;

                        string dnsTlsCertificatePath = request.QueryOrForm("dnsTlsCertificatePath");
                        if (dnsTlsCertificatePath is not null)
                        {
                            if (dnsTlsCertificatePath.Length == 0)
                            {
                                if (!string.IsNullOrEmpty(_dnsWebService._dnsServer.DnsTlsCertificatePath) && (_dnsWebService._dnsServer.EnableDnsOverTls || _dnsWebService._dnsServer.EnableDnsOverHttps || _dnsWebService._dnsServer.EnableDnsOverQuic))
                                    restartDnsService = true;

                                _dnsWebService._dnsServer.RemoveDnsTlsCertificate();
                            }
                            else
                            {
                                string dnsTlsCertificatePassword = request.QueryOrForm("dnsTlsCertificatePassword");

                                if ((dnsTlsCertificatePassword is null) || (dnsTlsCertificatePassword == "************"))
                                    dnsTlsCertificatePassword = _dnsWebService._dnsServer.DnsTlsCertificatePassword;

                                if ((dnsTlsCertificatePath != _dnsWebService._dnsServer.DnsTlsCertificatePath) || (dnsTlsCertificatePassword != _dnsWebService._dnsServer.DnsTlsCertificatePassword))
                                {
                                    _dnsWebService._dnsServer.SetDnsTlsCertificate(dnsTlsCertificatePath, dnsTlsCertificatePassword);

                                    if (string.IsNullOrEmpty(_dnsWebService._dnsServer.DnsTlsCertificatePath) && (_dnsWebService._dnsServer.EnableDnsOverTls || _dnsWebService._dnsServer.EnableDnsOverHttps || _dnsWebService._dnsServer.EnableDnsOverQuic))
                                        restartDnsService = true;
                                }
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverHttpRealIpHeader", out string dnsOverHttpRealIpHeader))
                            _dnsWebService._dnsServer.DnsOverHttpRealIpHeader = dnsOverHttpRealIpHeader;

                        #endregion

                        #region tsig

                        if (request.TryGetQueryOrFormArray("tsigKeys", delegate (JsonElement jsonObject)
                            {
                                string keyName = jsonObject.GetProperty("keyName").GetString().TrimEnd('.').ToLowerInvariant();
                                string sharedSecret = jsonObject.GetProperty("sharedSecret").GetString();
                                string algorithmName = jsonObject.GetProperty("algorithmName").GetString();

                                if (DnsClient.IsDomainNameUnicode(keyName))
                                    keyName = DnsClient.ConvertDomainNameToAscii(keyName);

                                DnsClient.IsDomainNameValid(keyName, true);

                                if (sharedSecret.Length == 0)
                                    return new TsigKey(keyName, algorithmName);

                                return new TsigKey(keyName, sharedSecret, algorithmName);
                            },
                            delegate (ArraySegment<string> tableRow)
                            {
                                string keyName = tableRow[0].TrimEnd('.').ToLowerInvariant();
                                string sharedSecret = tableRow[1];
                                string algorithmName = tableRow[2];

                                if (DnsClient.IsDomainNameUnicode(keyName))
                                    keyName = DnsClient.ConvertDomainNameToAscii(keyName);

                                DnsClient.IsDomainNameValid(keyName, true);

                                if (sharedSecret.Length == 0)
                                    return new TsigKey(keyName, algorithmName);

                                return new TsigKey(keyName, sharedSecret, algorithmName);
                            },
                            3, out TsigKey[] tsigKeys, '|')
                        )
                        {
                            if ((tsigKeys is null) || (tsigKeys.Length == 0))
                            {
                                if (_dnsWebService._clusterManager.ClusterInitialized)
                                    throw new DnsWebServiceException($"Cannot remove TSIG key for 'cluster-catalog.{_dnsWebService._clusterManager.ClusterDomain}' Cluster Catalog zone.");

                                _dnsWebService._dnsServer.TsigKeys = null;
                            }
                            else
                            {
                                Dictionary<string, TsigKey> tsigKeysMap = new Dictionary<string, TsigKey>(tsigKeys.Length);

                                foreach (TsigKey tsigKey in tsigKeys)
                                    tsigKeysMap.Add(tsigKey.KeyName, tsigKey);

                                if (_dnsWebService._clusterManager.ClusterInitialized)
                                {
                                    if (!tsigKeysMap.ContainsKey($"cluster-catalog.{_dnsWebService._clusterManager.ClusterDomain}"))
                                        throw new DnsWebServiceException($"Cannot remove TSIG key for 'cluster-catalog.{_dnsWebService._clusterManager.ClusterDomain}' Cluster Catalog zone.");
                                }

                                _dnsWebService._dnsServer.TsigKeys = tsigKeysMap;
                            }

                            clusterParameters.Add("tsigKeys", request.GetQueryOrForm("tsigKeys"));
                        }

                        #endregion

                        #region recursion

                        if (request.TryGetQueryOrFormEnum("recursion", out DnsServerRecursion recursion))
                        {
                            _dnsWebService._dnsServer.Recursion = recursion;

                            clusterParameters.Add("recursion", recursion.ToString());
                        }

                        if (request.TryGetQueryOrFormArray("recursionNetworkACL", NetworkAccessControl.Parse, out NetworkAccessControl[] recursionNetworkACL))
                        {
                            _dnsWebService._dnsServer.RecursionNetworkACL = recursionNetworkACL;

                            clusterParameters.Add("recursionNetworkACL", request.GetQueryOrForm("recursionNetworkACL"));
                        }

                        if (request.TryGetQueryOrForm("randomizeName", bool.Parse, out bool randomizeName))
                        {
                            _dnsWebService._dnsServer.RandomizeName = randomizeName;

                            clusterParameters.Add("randomizeName", randomizeName.ToString());
                        }

                        if (request.TryGetQueryOrForm("qnameMinimization", bool.Parse, out bool qnameMinimization))
                        {
                            _dnsWebService._dnsServer.QnameMinimization = qnameMinimization;

                            clusterParameters.Add("qnameMinimization", qnameMinimization.ToString());
                        }

                        if (request.TryGetQueryOrForm("resolverRetries", int.Parse, out int resolverRetries))
                        {
                            _dnsWebService._dnsServer.ResolverRetries = resolverRetries;

                            clusterParameters.Add("resolverRetries", resolverRetries.ToString());
                        }

                        if (request.TryGetQueryOrForm("resolverTimeout", int.Parse, out int resolverTimeout))
                        {
                            _dnsWebService._dnsServer.ResolverTimeout = resolverTimeout;

                            clusterParameters.Add("resolverTimeout", resolverTimeout.ToString());
                        }

                        if (request.TryGetQueryOrForm("resolverConcurrency", int.Parse, out int resolverConcurrency))
                        {
                            _dnsWebService._dnsServer.ResolverConcurrency = resolverConcurrency;

                            clusterParameters.Add("resolverConcurrency", resolverConcurrency.ToString());
                        }

                        if (request.TryGetQueryOrForm("resolverMaxStackCount", int.Parse, out int resolverMaxStackCount))
                        {
                            _dnsWebService._dnsServer.ResolverMaxStackCount = resolverMaxStackCount;

                            clusterParameters.Add("resolverMaxStackCount", resolverMaxStackCount.ToString());
                        }

                        #endregion

                        #region cache

                        //cache
                        if (request.TryGetQueryOrForm("saveCache", bool.Parse, out bool saveCache))
                            _dnsWebService._dnsServer.SaveCacheToDisk = saveCache;

                        if (request.TryGetQueryOrForm("serveStale", bool.Parse, out bool serveStale))
                            _dnsWebService._dnsServer.ServeStale = serveStale;

                        if (request.TryGetQueryOrForm("serveStaleTtl", ZoneFile.ParseTtl, out uint serveStaleTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.ServeStaleTtl = serveStaleTtl;

                        if (request.TryGetQueryOrForm("serveStaleAnswerTtl", ZoneFile.ParseTtl, out uint serveStaleAnswerTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.ServeStaleAnswerTtl = serveStaleAnswerTtl;

                        if (request.TryGetQueryOrForm("serveStaleResetTtl", ZoneFile.ParseTtl, out uint serveStaleResetTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.ServeStaleResetTtl = serveStaleResetTtl;

                        if (request.TryGetQueryOrForm("serveStaleMaxWaitTime", int.Parse, out int serveStaleMaxWaitTime))
                            _dnsWebService._dnsServer.ServeStaleMaxWaitTime = serveStaleMaxWaitTime;

                        if (request.TryGetQueryOrForm("cacheMaximumEntries", long.Parse, out long cacheMaximumEntries))
                            _dnsWebService._dnsServer.CacheZoneManager.MaximumEntries = cacheMaximumEntries;

                        if (request.TryGetQueryOrForm("cacheMinimumRecordTtl", ZoneFile.ParseTtl, out uint cacheMinimumRecordTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.MinimumRecordTtl = cacheMinimumRecordTtl;

                        if (request.TryGetQueryOrForm("cacheMaximumRecordTtl", ZoneFile.ParseTtl, out uint cacheMaximumRecordTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.MaximumRecordTtl = cacheMaximumRecordTtl;

                        if (request.TryGetQueryOrForm("cacheNegativeRecordTtl", ZoneFile.ParseTtl, out uint cacheNegativeRecordTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.NegativeRecordTtl = cacheNegativeRecordTtl;

                        if (request.TryGetQueryOrForm("cacheFailureRecordTtl", ZoneFile.ParseTtl, out uint cacheFailureRecordTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.FailureRecordTtl = cacheFailureRecordTtl;

                        if (request.TryGetQueryOrForm("cachePrefetchEligibility", int.Parse, out int cachePrefetchEligibility))
                            _dnsWebService._dnsServer.CachePrefetchEligibility = cachePrefetchEligibility;

                        if (request.TryGetQueryOrForm("cachePrefetchTrigger", int.Parse, out int cachePrefetchTrigger))
                            _dnsWebService._dnsServer.CachePrefetchTrigger = cachePrefetchTrigger;

                        if (request.TryGetQueryOrForm("cachePrefetchSampleIntervalInMinutes", int.Parse, out int cachePrefetchSampleIntervalMinutes))
                            _dnsWebService._dnsServer.CachePrefetchSampleIntervalMinutes = cachePrefetchSampleIntervalMinutes;

                        if (request.TryGetQueryOrForm("cachePrefetchSampleEligibilityHitsPerHour", int.Parse, out int cachePrefetchSampleEligibilityHitsPerHour))
                            _dnsWebService._dnsServer.CachePrefetchSampleEligibilityHitsPerHour = cachePrefetchSampleEligibilityHitsPerHour;

                        #endregion

                        #region blocking

                        if (request.TryGetQueryOrForm("enableBlocking", bool.Parse, out bool enableBlocking))
                        {
                            _dnsWebService._dnsServer.EnableBlocking = enableBlocking;

                            clusterParameters.Add("enableBlocking", enableBlocking.ToString());
                        }

                        if (request.TryGetQueryOrForm("allowTxtBlockingReport", bool.Parse, out bool allowTxtBlockingReport))
                        {
                            _dnsWebService._dnsServer.AllowTxtBlockingReport = allowTxtBlockingReport;

                            clusterParameters.Add("allowTxtBlockingReport", allowTxtBlockingReport.ToString());
                        }

                        if (request.TryGetQueryOrFormArray("blockingBypassList", NetworkAddress.Parse, out NetworkAddress[] blockingBypassList))
                        {
                            _dnsWebService._dnsServer.BlockingBypassList = blockingBypassList;

                            clusterParameters.Add("blockingBypassList", request.GetQueryOrForm("blockingBypassList"));
                        }

                        if (request.TryGetQueryOrFormEnum("blockingType", out DnsServerBlockingType blockingType))
                        {
                            _dnsWebService._dnsServer.BlockingType = blockingType;

                            clusterParameters.Add("blockingType", blockingType.ToString());
                        }

                        if (request.TryGetQueryOrForm("blockingAnswerTtl", ZoneFile.ParseTtl, out uint blockingAnswerTtl))
                        {
                            _dnsWebService._dnsServer.BlockingAnswerTtl = blockingAnswerTtl;

                            clusterParameters.Add("blockingAnswerTtl", blockingAnswerTtl.ToString());
                        }

                        if (request.TryGetQueryOrFormArray("customBlockingAddresses", out string[] customBlockingAddresses))
                        {
                            if ((customBlockingAddresses is null) || (customBlockingAddresses.Length == 0))
                            {
                                _dnsWebService._dnsServer.CustomBlockingARecords = null;
                                _dnsWebService._dnsServer.CustomBlockingAAAARecords = null;
                            }
                            else
                            {
                                List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                                List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

                                foreach (string strAddress in customBlockingAddresses)
                                {
                                    if (IPAddress.TryParse(strAddress, out IPAddress customAddress))
                                    {
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

                                _dnsWebService._dnsServer.CustomBlockingARecords = dnsARecords;
                                _dnsWebService._dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                            }

                            clusterParameters.Add("customBlockingAddresses", request.GetQueryOrForm("customBlockingAddresses"));
                        }

                        if (request.TryGetQueryOrFormArray("blockListUrls", out string[] blockListUrls))
                        {
                            _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls = blockListUrls;
                            _dnsWebService._dnsServer.BlockListZoneManager.SaveConfigFile();

                            clusterParameters.Add("blockListUrls", request.GetQueryOrForm("blockListUrls"));
                        }

                        if (request.TryGetQueryOrForm("blockListUpdateIntervalHours", int.Parse, out int blockListUpdateIntervalHours))
                        {
                            _dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours = blockListUpdateIntervalHours;
                            _dnsWebService._dnsServer.BlockListZoneManager.SaveConfigFile();

                            clusterParameters.Add("blockListUpdateIntervalHours", blockListUpdateIntervalHours.ToString());
                        }

                        #endregion

                        #region proxy & forwarders

                        //proxy & forwarders
                        if (request.TryGetQueryOrFormEnum("proxyType", out NetProxyType proxyType))
                        {
                            if (proxyType == NetProxyType.None)
                            {
                                _dnsWebService._dnsServer.Proxy = null;
                            }
                            else
                            {
                                NetworkCredential credential = null;

                                if (request.TryGetQueryOrForm("proxyUsername", out string proxyUsername))
                                {
                                    if (proxyUsername.Length > 255)
                                        throw new ArgumentException("Proxy username length cannot exceed 255 characters.", nameof(proxyUsername));

                                    string proxyPassword = request.QueryOrForm("proxyPassword");
                                    if (proxyPassword?.Length > 255)
                                        throw new ArgumentException("Proxy password length cannot exceed 255 characters.", nameof(proxyPassword));

                                    credential = new NetworkCredential(proxyUsername, proxyPassword);

                                    clusterParameters.Add("proxyUsername", proxyUsername);
                                    clusterParameters.Add("proxyPassword", proxyPassword ?? "");
                                }

                                string proxyAddress = request.QueryOrForm("proxyAddress");
                                string proxyPort = request.QueryOrForm("proxyPort");

                                _dnsWebService._dnsServer.Proxy = NetProxy.CreateProxy(proxyType, proxyAddress, int.Parse(proxyPort), credential);

                                clusterParameters.Add("proxyAddress", proxyAddress);
                                clusterParameters.Add("proxyPort", proxyPort);

                                if (request.TryGetQueryOrFormArray("proxyBypass", delegate (string value) { return new NetProxyBypassItem(value); }, out NetProxyBypassItem[] proxyBypass))
                                {
                                    _dnsWebService._dnsServer.Proxy.BypassList = proxyBypass;

                                    clusterParameters.Add("proxyBypass", request.GetQueryOrForm("proxyBypass"));
                                }
                            }

                            clusterParameters.Add("proxyType", proxyType.ToString());
                        }

                        if (request.TryGetQueryOrFormArray("forwarders", NameServerAddress.Parse, out NameServerAddress[] forwarders))
                        {
                            if ((forwarders is null) || (forwarders.Length == 0))
                            {
                                _dnsWebService._dnsServer.Forwarders = null;
                            }
                            else
                            {
                                DnsTransportProtocol forwarderProtocol = request.GetQueryOrFormEnum("forwarderProtocol", DnsTransportProtocol.Udp);

                                switch (forwarderProtocol)
                                {
                                    case DnsTransportProtocol.Udp:
                                        if (proxyType == NetProxyType.Http)
                                            throw new DnsWebServiceException("HTTP proxy server can transport only DNS-over-TCP, DNS-over-TLS, or DNS-over-HTTPS forwarder protocols. Use SOCKS5 proxy server for DNS-over-UDP or DNS-over-QUIC forwarder protocols.");

                                        break;

                                    case DnsTransportProtocol.HttpsJson:
                                        forwarderProtocol = DnsTransportProtocol.Https;
                                        break;

                                    case DnsTransportProtocol.Quic:
                                        DnsWebService.ValidateQuicSupport();

                                        if (proxyType == NetProxyType.Http)
                                            throw new DnsWebServiceException("HTTP proxy server can transport only DNS-over-TCP, DNS-over-TLS, or DNS-over-HTTPS forwarder protocols. Use SOCKS5 proxy server for DNS-over-UDP or DNS-over-QUIC forwarder protocols.");

                                        break;
                                }

                                for (int i = 0; i < forwarders.Length; i++)
                                {
                                    if (forwarders[i].Protocol != forwarderProtocol)
                                        forwarders[i] = forwarders[i].ChangeProtocol(forwarderProtocol);
                                }

                                if (!_dnsWebService._dnsServer.Forwarders.ListEquals(forwarders))
                                    _dnsWebService._dnsServer.Forwarders = forwarders;

                                clusterParameters.Add("forwarderProtocol", forwarderProtocol.ToString());
                            }

                            clusterParameters.Add("forwarders", request.GetQueryOrForm("forwarders"));
                        }

                        if (request.TryGetQueryOrForm("concurrentForwarding", bool.Parse, out bool concurrentForwarding))
                        {
                            _dnsWebService._dnsServer.ConcurrentForwarding = concurrentForwarding;

                            clusterParameters.Add("concurrentForwarding", concurrentForwarding.ToString());
                        }

                        if (request.TryGetQueryOrForm("forwarderRetries", int.Parse, out int forwarderRetries))
                        {
                            _dnsWebService._dnsServer.ForwarderRetries = forwarderRetries;

                            clusterParameters.Add("forwarderRetries", forwarderRetries.ToString());
                        }

                        if (request.TryGetQueryOrForm("forwarderTimeout", int.Parse, out int forwarderTimeout))
                        {
                            _dnsWebService._dnsServer.ForwarderTimeout = forwarderTimeout;

                            clusterParameters.Add("forwarderTimeout", forwarderTimeout.ToString());
                        }

                        if (request.TryGetQueryOrForm("forwarderConcurrency", int.Parse, out int forwarderConcurrency))
                        {
                            _dnsWebService._dnsServer.ForwarderConcurrency = forwarderConcurrency;

                            clusterParameters.Add("forwarderConcurrency", forwarderConcurrency.ToString());
                        }

                        #endregion

                        #region logging

                        if (request.TryGetQueryOrFormEnum("loggingType", out LoggingType loggingType))
                            _dnsWebService._log.LoggingType = loggingType;
                        else if (request.TryGetQueryOrForm("enableLogging", bool.Parse, out bool enableLogging))
                            _dnsWebService._log.LoggingType = enableLogging ? LoggingType.File : LoggingType.None;

                        if (request.TryGetQueryOrForm("ignoreResolverLogs", bool.Parse, out bool ignoreResolverLogs))
                            _dnsWebService._dnsServer.ResolverLogManager = ignoreResolverLogs ? null : _dnsWebService._log;

                        if (request.TryGetQueryOrForm("logQueries", bool.Parse, out bool logQueries))
                            _dnsWebService._dnsServer.QueryLogManager = logQueries ? _dnsWebService._log : null;

                        if (request.TryGetQueryOrForm("useLocalTime", bool.Parse, out bool useLocalTime))
                            _dnsWebService._log.UseLocalTime = useLocalTime;

                        if (request.TryGetQueryOrForm("logFolder", out string logFolder))
                            _dnsWebService._log.LogFolder = logFolder;

                        if (request.TryGetQueryOrForm("maxLogFileDays", int.Parse, out int maxLogFileDays))
                            _dnsWebService._log.MaxLogFileDays = maxLogFileDays;

                        if (request.TryGetQueryOrForm("enableInMemoryStats", bool.Parse, out bool enableInMemoryStats))
                            _dnsWebService._dnsServer.StatsManager.EnableInMemoryStats = enableInMemoryStats;

                        if (request.TryGetQueryOrForm("maxStatFileDays", int.Parse, out int maxStatFileDays))
                            _dnsWebService._dnsServer.StatsManager.MaxStatFileDays = maxStatFileDays;

                        #endregion
                    }
                    finally
                    {
                        jsonDocument?.Dispose();

                        //enforce cluster mandatory TLS requirement
                        if (_dnsWebService._clusterManager.ClusterInitialized)
                        {
                            if (!_dnsWebService._webServiceEnableTls || string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath))
                            {
                                //force enable TLS with self-signed certificate if cluster is initialized
                                _dnsWebService._webServiceEnableTls = true;
                                _dnsWebService._webServiceUseSelfSignedTlsCertificate = true;
                            }
                        }

                        //TLS actions
                        _dnsWebService.CheckAndLoadSelfSignedCertificate(serverDomainChanged || webServiceLocalAddressesChanged, true);

                        if (_dnsWebService._webServiceEnableTls && string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath) && !_dnsWebService._webServiceUseSelfSignedTlsCertificate)
                        {
                            //disable TLS
                            _dnsWebService._webServiceEnableTls = false;
                            restartWebService = true;
                        }

                        //cluster update actions
                        if (_dnsWebService._clusterManager.ClusterInitialized)
                        {
                            if (webServiceTlsCertificateChanged || serverDomainChanged || webServiceLocalAddressesChanged)
                                _dnsWebService._clusterManager.UpdateSelfNodeUrlAndCertificate();
                        }

                        //save config
                        _dnsWebService.SaveConfigFile();
                        _dnsWebService._dnsServer.SaveConfigFile();
                        _dnsWebService._dnsServer.BlockListZoneManager.SaveConfigFile();
                        _dnsWebService._log.SaveConfigFile();
                    }

                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DNS Settings were updated successfully.");

                    //trigger cluster update
                    if (_dnsWebService._clusterManager.ClusterInitialized)
                    {
                        if (_dnsWebService._clusterManager.GetSelfNode().Type == ClusterNodeType.Primary)
                            _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodes();
                        else if (clusterParameters.Count > 0)
                            await _dnsWebService._clusterManager.GetPrimaryNode().SetClusterSettingsAsync(clusterParameters);
                    }

                    Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                    WriteDnsSettings(jsonWriter);
                }
                finally
                {
                    if (restartDnsService || restartWebService)
                        RestartService(restartDnsService, restartWebService, oldWebServiceLocalAddresses, oldWebServiceHttpPort, oldWebServiceTlsPort);
                }
            }

            public void GetTsigKeyNames(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View) &&
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify)
                   )
                {
                    throw new DnsWebServiceException("Access was denied.");
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("tsigKeyNames");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._dnsServer.TsigKeys is not null)
                    {
                        foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsWebService._dnsServer.TsigKeys)
                            jsonWriter.WriteStringValue(tsigKey.Key);
                    }

                    jsonWriter.WriteEndArray();
                }
            }

            public async Task BackupSettingsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool authConfig = request.GetQueryOrForm("authConfig", bool.Parse, false);
                bool clusterConfig = request.GetQueryOrForm("clusterConfig", bool.Parse, false);
                bool webServiceSettings = request.GetQueryOrForm("webServiceSettings", bool.Parse, false);
                bool dnsSettings = request.GetQueryOrForm("dnsSettings", bool.Parse, false);
                bool logSettings = request.GetQueryOrForm("logSettings", bool.Parse, false);
                bool zones = request.GetQueryOrForm("zones", bool.Parse, false);
                bool allowedZones = request.GetQueryOrForm("allowedZones", bool.Parse, false);
                bool blockedZones = request.GetQueryOrForm("blockedZones", bool.Parse, false);
                bool blockLists = request.GetQueryOrForm("blockLists", bool.Parse, false);
                bool apps = request.GetQueryOrForm("apps", bool.Parse, false);
                bool scopes = request.GetQueryOrForm("scopes", bool.Parse, false);
                bool stats = request.GetQueryOrForm("stats", bool.Parse, false);
                bool logs = request.GetQueryOrForm("logs", bool.Parse, false);

                string tmpFile = Path.GetTempFileName();
                try
                {
                    await using (FileStream backupZipStream = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        //create backup zip
                        await _dnsWebService.BackupConfigAsync(backupZipStream, authConfig, clusterConfig, webServiceSettings, dnsSettings, logSettings, zones, allowedZones, blockedZones, blockLists, apps, scopes, stats, logs);

                        //send zip file
                        backupZipStream.Position = 0;

                        HttpResponse response = context.Response;

                        response.ContentType = "application/zip";
                        response.ContentLength = backupZipStream.Length;
                        response.Headers.ContentDisposition = "attachment;filename=" + _dnsWebService._dnsServer.ServerDomain + DateTime.UtcNow.ToString("_yyyy-MM-dd_HH-mm-ss") + "_backup.zip";

                        await using (Stream output = response.Body)
                        {
                            await backupZipStream.CopyToAsync(output);
                        }
                    }
                }
                finally
                {
                    try
                    {
                        File.Delete(tmpFile);
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService._log.Write(ex);
                    }
                }

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Settings backup zip file was exported.");
            }

            public async Task RestoreSettingsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool authConfig = request.GetQueryOrForm("authConfig", bool.Parse, false);
                bool clusterConfig = request.GetQueryOrForm("clusterConfig", bool.Parse, false);
                bool webServiceSettings = request.GetQueryOrForm("webServiceSettings", bool.Parse, false);
                bool dnsSettings = request.GetQueryOrForm("dnsSettings", bool.Parse, false);
                bool logSettings = request.GetQueryOrForm("logSettings", bool.Parse, false);
                bool zones = request.GetQueryOrForm("zones", bool.Parse, false);
                bool allowedZones = request.GetQueryOrForm("allowedZones", bool.Parse, false);
                bool blockedZones = request.GetQueryOrForm("blockedZones", bool.Parse, false);
                bool blockLists = request.GetQueryOrForm("blockLists", bool.Parse, false);
                bool apps = request.GetQueryOrForm("apps", bool.Parse, false);
                bool scopes = request.GetQueryOrForm("scopes", bool.Parse, false);
                bool stats = request.GetQueryOrForm("stats", bool.Parse, false);
                bool logs = request.GetQueryOrForm("logs", bool.Parse, false);
                bool deleteExistingFiles = request.GetQueryOrForm("deleteExistingFiles", bool.Parse, false);

                if (!request.HasFormContentType || (request.Form.Files.Count == 0))
                    throw new DnsWebServiceException("DNS backup zip file is missing.");

                IReadOnlyList<IPAddress> oldWebServiceLocalAddresses = _dnsWebService._webServiceLocalAddresses;
                int oldWebServiceHttpPort = _dnsWebService._webServiceHttpPort;
                int oldWebServiceTlsPort = _dnsWebService._webServiceTlsPort;

                try
                {
                    //write to temp file
                    string tmpFile = Path.GetTempFileName();
                    try
                    {
                        await using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                        {
                            await request.Form.Files[0].CopyToAsync(fS);

                            fS.Position = 0;

                            await _dnsWebService.RestoreConfigAsync(fS, authConfig, clusterConfig, webServiceSettings, dnsSettings, logSettings, zones, allowedZones, blockedZones, blockLists, apps, scopes, stats, logs, deleteExistingFiles, context.GetCurrentSession());

                            _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Settings backup zip file was restored.");
                        }
                    }
                    finally
                    {
                        try
                        {
                            File.Delete(tmpFile);
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    }

                    //trigger cluster update
                    if (_dnsWebService._clusterManager.ClusterInitialized)
                        _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();

                    Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                    WriteDnsSettings(jsonWriter);

                }
                finally
                {
                    if (dnsSettings || webServiceSettings)
                        RestartService(dnsSettings, webServiceSettings, oldWebServiceLocalAddresses, oldWebServiceHttpPort, oldWebServiceTlsPort);
                }
            }

            public void ForceUpdateBlockLists(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._dnsServer.BlockListZoneManager.ForceUpdateBlockLists();

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Block list update was triggered.");

                if (_dnsWebService._clusterManager.ClusterInitialized)
                {
                    UserSession session = context.GetCurrentSession();

                    if ((session.Type == UserSessionType.ApiToken) && session.TokenName.Equals(_dnsWebService._clusterManager.ClusterDomain, StringComparison.OrdinalIgnoreCase))
                        return; //call from cluster node itself

                    //relay action on all other cluster nodes async
                    ThreadPool.QueueUserWorkItem(async delegate (object state)
                    {
                        try
                        {
                            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _dnsWebService._clusterManager.ClusterNodes;
                            List<Task> tasks = new List<Task>(clusterNodes.Count);

                            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                            {
                                if (clusterNode.Value.State == ClusterNodeState.Self)
                                    continue;

                                tasks.Add(clusterNode.Value.ForceUpdateBlockListsAsync());
                            }

                            foreach (Task task in tasks)
                            {
                                try
                                {
                                    await task;
                                }
                                catch (Exception ex)
                                {
                                    _dnsWebService._log.Write(ex);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    });
                }
            }

            public void TemporaryDisableBlocking(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                int minutes = context.Request.GetQueryOrForm("minutes", int.Parse);

                _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlocking(minutes, context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), sessionUser.Username);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteString("temporaryDisableBlockingTill", _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlockingTill);

                if (_dnsWebService._clusterManager.ClusterInitialized)
                {
                    UserSession session = context.GetCurrentSession();

                    if ((session.Type == UserSessionType.ApiToken) && session.TokenName.Equals(_dnsWebService._clusterManager.ClusterDomain, StringComparison.OrdinalIgnoreCase))
                        return; //call from cluster node itself

                    //relay action on all other cluster nodes async
                    ThreadPool.QueueUserWorkItem(async delegate (object state)
                    {
                        try
                        {
                            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _dnsWebService._clusterManager.ClusterNodes;
                            List<Task> tasks = new List<Task>(clusterNodes.Count);

                            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                            {
                                if (clusterNode.Value.State == ClusterNodeState.Self)
                                    continue;

                                tasks.Add(clusterNode.Value.TemporaryDisableBlockingAsync(minutes));
                            }

                            foreach (Task task in tasks)
                            {
                                try
                                {
                                    await task;
                                }
                                catch (Exception ex)
                                {
                                    _dnsWebService._log.Write(ex);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    });
                }
            }

            #endregion
        }
    }
}
