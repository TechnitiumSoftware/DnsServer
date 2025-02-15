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
using DnsServerCore.Dns;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Text;
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
        sealed class WebServiceSettingsApi : IDisposable
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            Timer _blockListUpdateTimer;
            DateTime _blockListLastUpdatedOn;
            int _blockListUpdateIntervalHours = 24;
            const int BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL = 5000;
            const int BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL = 900000;

            Timer _temporaryDisableBlockingTimer;
            DateTime _temporaryDisableBlockingTill;

            #endregion

            #region constructor

            public WebServiceSettingsApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region IDisposable

            bool _disposed;

            public void Dispose()
            {
                if (_disposed)
                    return;

                if (_blockListUpdateTimer is not null)
                    _blockListUpdateTimer.Dispose();

                if (_temporaryDisableBlockingTimer is not null)
                    _temporaryDisableBlockingTimer.Dispose();

                _disposed = true;
            }

            #endregion

            #region block list

            private void ForceUpdateBlockLists(bool forceReload)
            {
                Task.Run(async delegate ()
                {
                    if (await _dnsWebService._dnsServer.BlockListZoneManager.UpdateBlockListsAsync(forceReload))
                    {
                        //block lists were updated
                        //save last updated on time
                        _blockListLastUpdatedOn = DateTime.UtcNow;
                        _dnsWebService.SaveConfigFile();
                    }
                });
            }

            public void StartBlockListUpdateTimer(bool forceUpdateAndReload)
            {
                if (_blockListUpdateTimer is null)
                {
                    if (forceUpdateAndReload)
                        _blockListLastUpdatedOn = default;

                    _blockListUpdateTimer = new Timer(async delegate (object state)
                    {
                        try
                        {
                            if (DateTime.UtcNow > _blockListLastUpdatedOn.AddHours(_blockListUpdateIntervalHours))
                            {
                                if (await _dnsWebService._dnsServer.BlockListZoneManager.UpdateBlockListsAsync(_blockListLastUpdatedOn == default))
                                {
                                    //block lists were updated
                                    //save last updated on time
                                    _blockListLastUpdatedOn = DateTime.UtcNow;
                                    _dnsWebService.SaveConfigFile();
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write("DNS Server encountered an error while updating block lists.\r\n" + ex.ToString());
                        }

                    }, null, BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL);
                }
            }

            public void StopBlockListUpdateTimer()
            {
                if (_blockListUpdateTimer is not null)
                {
                    _blockListUpdateTimer.Dispose();
                    _blockListUpdateTimer = null;
                }
            }

            public void StopTemporaryDisableBlockingTimer()
            {
                Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
                if (temporaryDisableBlockingTimer is not null)
                    temporaryDisableBlockingTimer.Dispose();
            }

            #endregion

            #region private

            private void RestartService(bool restartDnsService, bool restartWebService, IReadOnlyList<IPAddress> oldWebServiceLocalAddresses, int oldWebServiceHttpPort, int oldWebServiceTlsPort)
            {
                if (restartDnsService)
                {
                    _ = Task.Run(async delegate ()
                    {
                        _dnsWebService._log.Write("Attempting to restart DNS service.");

                        try
                        {
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
                    _ = Task.Run(async delegate ()
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
                    });
                }
            }

            private static async Task CreateBackupEntryFromFileAsync(ZipArchive backupZip, string sourceFileName, string entryName)
            {
                using (FileStream fS = new FileStream(sourceFileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    ZipArchiveEntry entry = backupZip.CreateEntry(entryName);

                    DateTime lastWrite = File.GetLastWriteTime(sourceFileName);

                    // If file to be archived has an invalid last modified time, use the first datetime representable in the Zip timestamp format
                    // (midnight on January 1, 1980):
                    if (lastWrite.Year < 1980 || lastWrite.Year > 2107)
                        lastWrite = new DateTime(1980, 1, 1, 0, 0, 0);

                    entry.LastWriteTime = lastWrite;

                    using (Stream sE = entry.Open())
                    {
                        await fS.CopyToAsync(sE);
                    }
                }
            }

            private void WriteDnsSettings(Utf8JsonWriter jsonWriter)
            {
                //general
                jsonWriter.WriteString("version", _dnsWebService.GetServerVersion());
                jsonWriter.WriteString("uptimestamp", _dnsWebService._uptimestamp);
                jsonWriter.WriteString("dnsServerDomain", _dnsWebService._dnsServer.ServerDomain);

                jsonWriter.WriteStringArray("dnsServerLocalEndPoints", _dnsWebService._dnsServer.LocalEndPoints);

                jsonWriter.WriteStringArray("dnsServerIPv4SourceAddresses", DnsClientConnection.IPv4SourceAddresses);
                jsonWriter.WriteStringArray("dnsServerIPv6SourceAddresses", DnsClientConnection.IPv6SourceAddresses);

                jsonWriter.WriteNumber("defaultRecordTtl", _dnsWebService._zonesApi.DefaultRecordTtl);
                jsonWriter.WriteString("defaultResponsiblePerson", _dnsWebService._dnsServer.ResponsiblePersonInternal?.Address);
                jsonWriter.WriteBoolean("useSoaSerialDateScheme", _dnsWebService._dnsServer.AuthZoneManager.UseSoaSerialDateScheme);
                jsonWriter.WriteNumber("minSoaRefresh", _dnsWebService._dnsServer.AuthZoneManager.MinSoaRefresh);
                jsonWriter.WriteNumber("minSoaRetry", _dnsWebService._dnsServer.AuthZoneManager.MinSoaRetry);
                jsonWriter.WriteStringArray("zoneTransferAllowedNetworks", _dnsWebService._dnsServer.ZoneTransferAllowedNetworks);
                jsonWriter.WriteStringArray("notifyAllowedNetworks", _dnsWebService._dnsServer.NotifyAllowedNetworks);

                jsonWriter.WriteBoolean("dnsAppsEnableAutomaticUpdate", _dnsWebService._appsApi.EnableAutomaticUpdate);

                jsonWriter.WriteBoolean("preferIPv6", _dnsWebService._dnsServer.PreferIPv6);

                jsonWriter.WriteNumber("udpPayloadSize", _dnsWebService._dnsServer.UdpPayloadSize);

                jsonWriter.WriteBoolean("dnssecValidation", _dnsWebService._dnsServer.DnssecValidation);

                jsonWriter.WriteBoolean("eDnsClientSubnet", _dnsWebService._dnsServer.EDnsClientSubnet);
                jsonWriter.WriteNumber("eDnsClientSubnetIPv4PrefixLength", _dnsWebService._dnsServer.EDnsClientSubnetIPv4PrefixLength);
                jsonWriter.WriteNumber("eDnsClientSubnetIPv6PrefixLength", _dnsWebService._dnsServer.EDnsClientSubnetIPv6PrefixLength);
                jsonWriter.WriteString("eDnsClientSubnetIpv4Override", _dnsWebService._dnsServer.EDnsClientSubnetIpv4Override?.ToString());
                jsonWriter.WriteString("eDnsClientSubnetIpv6Override", _dnsWebService._dnsServer.EDnsClientSubnetIpv6Override?.ToString());

                jsonWriter.WriteNumber("qpmLimitRequests", _dnsWebService._dnsServer.QpmLimitRequests);
                jsonWriter.WriteNumber("qpmLimitErrors", _dnsWebService._dnsServer.QpmLimitErrors);
                jsonWriter.WriteNumber("qpmLimitSampleMinutes", _dnsWebService._dnsServer.QpmLimitSampleMinutes);
                jsonWriter.WriteNumber("qpmLimitIPv4PrefixLength", _dnsWebService._dnsServer.QpmLimitIPv4PrefixLength);
                jsonWriter.WriteNumber("qpmLimitIPv6PrefixLength", _dnsWebService._dnsServer.QpmLimitIPv6PrefixLength);

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

                jsonWriter.WriteString("dnsTlsCertificatePath", _dnsWebService._dnsTlsCertificatePath);
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
                jsonWriter.WriteBoolean("nsRevalidation", _dnsWebService._dnsServer.NsRevalidation);

                jsonWriter.WriteNumber("resolverRetries", _dnsWebService._dnsServer.ResolverRetries);
                jsonWriter.WriteNumber("resolverTimeout", _dnsWebService._dnsServer.ResolverTimeout);
                jsonWriter.WriteNumber("resolverConcurrency", _dnsWebService._dnsServer.ResolverConcurrency);
                jsonWriter.WriteNumber("resolverMaxStackCount", _dnsWebService._dnsServer.ResolverMaxStackCount);

                //cache
                jsonWriter.WriteBoolean("saveCache", _dnsWebService._saveCache);
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
                jsonWriter.WriteNumber("cachePrefetchSampleIntervalInMinutes", _dnsWebService._dnsServer.CachePrefetchSampleIntervalInMinutes);
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

                if (!_dnsWebService._dnsServer.EnableBlocking && (DateTime.UtcNow < _temporaryDisableBlockingTill))
                    jsonWriter.WriteString("temporaryDisableBlockingTill", _temporaryDisableBlockingTill);

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

                if ((_dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Count == 0) && (_dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Count == 0))
                {
                    jsonWriter.WriteNullValue();
                }
                else
                {
                    jsonWriter.WriteStartArray();

                    foreach (Uri allowListUrl in _dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls)
                        jsonWriter.WriteStringValue("!" + allowListUrl.AbsoluteUri);

                    foreach (Uri blockListUrl in _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls)
                        jsonWriter.WriteStringValue(blockListUrl.AbsoluteUri);

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteNumber("blockListUpdateIntervalHours", _blockListUpdateIntervalHours);

                if (_blockListUpdateTimer is not null)
                {
                    DateTime blockListNextUpdatedOn = _blockListLastUpdatedOn.AddHours(_blockListUpdateIntervalHours);

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
                jsonWriter.WriteBoolean("enableLogging", _dnsWebService._log.EnableLogging);
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
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteDnsSettings(jsonWriter);
            }

            public async Task SetDnsSettingsAsync(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                bool serverDomainChanged = false;
                bool webServiceLocalAddressesChanged = false;
                bool restartDnsService = false;
                bool restartWebService = false;
                bool blockListUrlsUpdated = false;
                IReadOnlyList<IPAddress> oldWebServiceLocalAddresses = _dnsWebService._webServiceLocalAddresses;
                int oldWebServiceHttpPort = _dnsWebService._webServiceHttpPort;
                int oldWebServiceTlsPort = _dnsWebService._webServiceTlsPort;
                bool _webServiceEnablingTls = false;

                HttpRequest request = context.Request;
                JsonDocument jsonDocument = null;

                if (request.HasJsonContentType())
                {
                    jsonDocument = await JsonDocument.ParseAsync(request.Body);
                    context.Items["jsonContent"] = jsonDocument;
                }

                try
                {
                    #region general

                    if (request.TryGetQueryOrForm("dnsServerDomain", out string dnsServerDomain))
                    {
                        dnsServerDomain = dnsServerDomain.TrimEnd('.');

                        if (!_dnsWebService._dnsServer.ServerDomain.Equals(dnsServerDomain, StringComparison.OrdinalIgnoreCase))
                        {
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

                    if (request.TryGetQueryOrForm("defaultRecordTtl", uint.Parse, out uint defaultRecordTtl))
                        _dnsWebService._zonesApi.DefaultRecordTtl = defaultRecordTtl;

                    string defaultResponsiblePerson = request.QueryOrForm("defaultResponsiblePerson");
                    if (defaultResponsiblePerson is not null)
                    {
                        if (defaultResponsiblePerson.Length == 0)
                            _dnsWebService._dnsServer.ResponsiblePersonInternal = null;
                        else if (defaultResponsiblePerson.Length > 255)
                            throw new ArgumentException("Default responsible person email address length cannot exceed 255 characters.", "defaultResponsiblePerson");
                        else
                            _dnsWebService._dnsServer.ResponsiblePersonInternal = new MailAddress(defaultResponsiblePerson);
                    }

                    if (request.TryGetQueryOrForm("useSoaSerialDateScheme", bool.Parse, out bool useSoaSerialDateScheme))
                        _dnsWebService._dnsServer.AuthZoneManager.UseSoaSerialDateScheme = useSoaSerialDateScheme;

                    if (request.TryGetQueryOrForm("minSoaRefresh", uint.Parse, out uint minSoaRefresh))
                        _dnsWebService._dnsServer.AuthZoneManager.MinSoaRefresh = minSoaRefresh;

                    if (request.TryGetQueryOrForm("minSoaRetry", uint.Parse, out uint minSoaRetry))
                        _dnsWebService._dnsServer.AuthZoneManager.MinSoaRetry = minSoaRetry;

                    if (request.TryGetQueryOrFormArray("zoneTransferAllowedNetworks", NetworkAddress.Parse, out NetworkAddress[] zoneTransferAllowedNetworks))
                        _dnsWebService._dnsServer.ZoneTransferAllowedNetworks = zoneTransferAllowedNetworks;

                    if (request.TryGetQueryOrFormArray("notifyAllowedNetworks", NetworkAddress.Parse, out NetworkAddress[] notifyAllowedNetworks))
                        _dnsWebService._dnsServer.NotifyAllowedNetworks = notifyAllowedNetworks;

                    if (request.TryGetQueryOrForm("dnsAppsEnableAutomaticUpdate", bool.Parse, out bool dnsAppsEnableAutomaticUpdate))
                        _dnsWebService._appsApi.EnableAutomaticUpdate = dnsAppsEnableAutomaticUpdate;

                    if (request.TryGetQueryOrForm("preferIPv6", bool.Parse, out bool preferIPv6))
                        _dnsWebService._dnsServer.PreferIPv6 = preferIPv6;

                    if (request.TryGetQueryOrForm("udpPayloadSize", ushort.Parse, out ushort udpPayloadSize))
                        _dnsWebService._dnsServer.UdpPayloadSize = udpPayloadSize;

                    if (request.TryGetQueryOrForm("dnssecValidation", bool.Parse, out bool dnssecValidation))
                        _dnsWebService._dnsServer.DnssecValidation = dnssecValidation;

                    if (request.TryGetQueryOrForm("eDnsClientSubnet", bool.Parse, out bool eDnsClientSubnet))
                        _dnsWebService._dnsServer.EDnsClientSubnet = eDnsClientSubnet;

                    if (request.TryGetQueryOrForm("eDnsClientSubnetIPv4PrefixLength", byte.Parse, out byte eDnsClientSubnetIPv4PrefixLength))
                        _dnsWebService._dnsServer.EDnsClientSubnetIPv4PrefixLength = eDnsClientSubnetIPv4PrefixLength;

                    if (request.TryGetQueryOrForm("eDnsClientSubnetIPv6PrefixLength", byte.Parse, out byte eDnsClientSubnetIPv6PrefixLength))
                        _dnsWebService._dnsServer.EDnsClientSubnetIPv6PrefixLength = eDnsClientSubnetIPv6PrefixLength;

                    string eDnsClientSubnetIpv4Override = request.QueryOrForm("eDnsClientSubnetIpv4Override");
                    if (eDnsClientSubnetIpv4Override is not null)
                    {
                        if (eDnsClientSubnetIpv4Override.Length == 0)
                            _dnsWebService._dnsServer.EDnsClientSubnetIpv4Override = null;
                        else
                            _dnsWebService._dnsServer.EDnsClientSubnetIpv4Override = NetworkAddress.Parse(eDnsClientSubnetIpv4Override);
                    }

                    string eDnsClientSubnetIpv6Override = request.QueryOrForm("eDnsClientSubnetIpv6Override");
                    if (eDnsClientSubnetIpv6Override is not null)
                    {
                        if (eDnsClientSubnetIpv6Override.Length == 0)
                            _dnsWebService._dnsServer.EDnsClientSubnetIpv6Override = null;
                        else
                            _dnsWebService._dnsServer.EDnsClientSubnetIpv6Override = NetworkAddress.Parse(eDnsClientSubnetIpv6Override);
                    }

                    if (request.TryGetQueryOrForm("qpmLimitRequests", int.Parse, out int qpmLimitRequests))
                        _dnsWebService._dnsServer.QpmLimitRequests = qpmLimitRequests;

                    if (request.TryGetQueryOrForm("qpmLimitErrors", int.Parse, out int qpmLimitErrors))
                        _dnsWebService._dnsServer.QpmLimitErrors = qpmLimitErrors;

                    if (request.TryGetQueryOrForm("qpmLimitSampleMinutes", int.Parse, out int qpmLimitSampleMinutes))
                        _dnsWebService._dnsServer.QpmLimitSampleMinutes = qpmLimitSampleMinutes;

                    if (request.TryGetQueryOrForm("qpmLimitIPv4PrefixLength", int.Parse, out int qpmLimitIPv4PrefixLength))
                        _dnsWebService._dnsServer.QpmLimitIPv4PrefixLength = qpmLimitIPv4PrefixLength;

                    if (request.TryGetQueryOrForm("qpmLimitIPv6PrefixLength", int.Parse, out int qpmLimitIPv6PrefixLength))
                        _dnsWebService._dnsServer.QpmLimitIPv6PrefixLength = qpmLimitIPv6PrefixLength;

                    if (request.TryGetQueryOrFormArray("qpmLimitBypassList", NetworkAddress.Parse, out NetworkAddress[] qpmLimitBypassList))
                        _dnsWebService._dnsServer.QpmLimitBypassList = qpmLimitBypassList;

                    if (request.TryGetQueryOrForm("clientTimeout", int.Parse, out int clientTimeout))
                        _dnsWebService._dnsServer.ClientTimeout = clientTimeout;

                    if (request.TryGetQueryOrForm("tcpSendTimeout", int.Parse, out int tcpSendTimeout))
                        _dnsWebService._dnsServer.TcpSendTimeout = tcpSendTimeout;

                    if (request.TryGetQueryOrForm("tcpReceiveTimeout", int.Parse, out int tcpReceiveTimeout))
                        _dnsWebService._dnsServer.TcpReceiveTimeout = tcpReceiveTimeout;

                    if (request.TryGetQueryOrForm("quicIdleTimeout", int.Parse, out int quicIdleTimeout))
                        _dnsWebService._dnsServer.QuicIdleTimeout = quicIdleTimeout;

                    if (request.TryGetQueryOrForm("quicMaxInboundStreams", int.Parse, out int quicMaxInboundStreams))
                        _dnsWebService._dnsServer.QuicMaxInboundStreams = quicMaxInboundStreams;

                    if (request.TryGetQueryOrForm("listenBacklog", int.Parse, out int listenBacklog))
                        _dnsWebService._dnsServer.ListenBacklog = listenBacklog;

                    if (request.TryGetQueryOrForm("maxConcurrentResolutionsPerCore", ushort.Parse, out ushort maxConcurrentResolutionsPerCore))
                        _dnsWebService._dnsServer.MaxConcurrentResolutionsPerCore = maxConcurrentResolutionsPerCore;

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
                            _dnsWebService._webServiceTlsCertificatePath = null;
                            _dnsWebService._webServiceTlsCertificatePassword = "";
                        }
                        else
                        {
                            string webServiceTlsCertificatePassword = request.QueryOrForm("webServiceTlsCertificatePassword");

                            if ((webServiceTlsCertificatePassword is null) || (webServiceTlsCertificatePassword == "************"))
                                webServiceTlsCertificatePassword = _dnsWebService._webServiceTlsCertificatePassword;

                            if ((webServiceTlsCertificatePath != _dnsWebService._webServiceTlsCertificatePath) || (webServiceTlsCertificatePassword != _dnsWebService._webServiceTlsCertificatePassword))
                            {
                                if (webServiceTlsCertificatePath.Length > 255)
                                    throw new ArgumentException("Web service TLS certificate path length cannot exceed 255 characters.", "webServiceTlsCertificatePath");

                                if (webServiceTlsCertificatePassword?.Length > 255)
                                    throw new ArgumentException("Web service TLS certificate password length cannot exceed 255 characters.", "webServiceTlsCertificatePassword");

                                _dnsWebService.LoadWebServiceTlsCertificate(_dnsWebService.ConvertToAbsolutePath(webServiceTlsCertificatePath), webServiceTlsCertificatePassword);

                                _dnsWebService._webServiceTlsCertificatePath = _dnsWebService.ConvertToRelativePath(webServiceTlsCertificatePath);
                                _dnsWebService._webServiceTlsCertificatePassword = webServiceTlsCertificatePassword;

                                _dnsWebService.StartTlsCertificateUpdateTimer();
                            }
                        }
                    }

                    if (request.TryGetQueryOrForm("webServiceRealIpHeader", out string webServiceRealIpHeader))
                    {
                        if (webServiceRealIpHeader.Length > 255)
                            throw new ArgumentException("Web service Real IP header name cannot exceed 255 characters.", "webServiceRealIpHeader");

                        if (webServiceRealIpHeader.Contains(' '))
                            throw new ArgumentException("Web service Real IP header name cannot contain invalid characters.", "webServiceRealIpHeader");

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
                            if (!string.IsNullOrEmpty(_dnsWebService._dnsTlsCertificatePath) && (_dnsWebService._dnsServer.EnableDnsOverTls || _dnsWebService._dnsServer.EnableDnsOverHttps || _dnsWebService._dnsServer.EnableDnsOverQuic))
                                restartDnsService = true;

                            _dnsWebService._dnsServer.CertificateCollection = null;
                            _dnsWebService._dnsTlsCertificatePath = null;
                            _dnsWebService._dnsTlsCertificatePassword = "";
                        }
                        else
                        {
                            string dnsTlsCertificatePassword = request.QueryOrForm("dnsTlsCertificatePassword");

                            if ((dnsTlsCertificatePassword is null) || (dnsTlsCertificatePassword == "************"))
                                dnsTlsCertificatePassword = _dnsWebService._dnsTlsCertificatePassword;

                            if ((dnsTlsCertificatePath != _dnsWebService._dnsTlsCertificatePath) || (dnsTlsCertificatePassword != _dnsWebService._dnsTlsCertificatePassword))
                            {
                                if (dnsTlsCertificatePath.Length > 255)
                                    throw new ArgumentException("DNS optional protocols TLS certificate path length cannot exceed 255 characters.", "dnsTlsCertificatePath");

                                if (dnsTlsCertificatePassword?.Length > 255)
                                    throw new ArgumentException("DNS optional protocols TLS certificate password length cannot exceed 255 characters.", "dnsTlsCertificatePassword");

                                _dnsWebService.LoadDnsTlsCertificate(_dnsWebService.ConvertToAbsolutePath(dnsTlsCertificatePath), dnsTlsCertificatePassword);

                                if (string.IsNullOrEmpty(_dnsWebService._dnsTlsCertificatePath) && (_dnsWebService._dnsServer.EnableDnsOverTls || _dnsWebService._dnsServer.EnableDnsOverHttps || _dnsWebService._dnsServer.EnableDnsOverQuic))
                                    restartDnsService = true;

                                _dnsWebService._dnsTlsCertificatePath = _dnsWebService.ConvertToRelativePath(dnsTlsCertificatePath);
                                _dnsWebService._dnsTlsCertificatePassword = dnsTlsCertificatePassword;

                                _dnsWebService.StartTlsCertificateUpdateTimer();
                            }
                        }
                    }

                    if (request.TryGetQueryOrForm("dnsOverHttpRealIpHeader", out string dnsOverHttpRealIpHeader))
                        _dnsWebService._dnsServer.DnsOverHttpRealIpHeader = dnsOverHttpRealIpHeader;

                    #endregion

                    #region tsig

                    if (request.TryGetQueryOrFormArray("tsigKeys", delegate (JsonElement jsonObject)
                        {
                            string keyName = jsonObject.GetProperty("keyName").GetString().TrimEnd('.').ToLowerInvariant(); ;
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
                            _dnsWebService._dnsServer.TsigKeys = null;
                        }
                        else
                        {
                            Dictionary<string, TsigKey> tsigKeysMap = new Dictionary<string, TsigKey>(tsigKeys.Length);

                            foreach (TsigKey tsigKey in tsigKeys)
                                tsigKeysMap.Add(tsigKey.KeyName, tsigKey);

                            _dnsWebService._dnsServer.TsigKeys = tsigKeysMap;
                        }
                    }

                    #endregion

                    #region recursion

                    if (request.TryGetQueryOrFormEnum("recursion", out DnsServerRecursion recursion))
                        _dnsWebService._dnsServer.Recursion = recursion;

                    if (request.TryGetQueryOrFormArray("recursionNetworkACL", NetworkAccessControl.Parse, out NetworkAccessControl[] recursionNetworkACL))
                        _dnsWebService._dnsServer.RecursionNetworkACL = recursionNetworkACL;

                    if (request.TryGetQueryOrForm("randomizeName", bool.Parse, out bool randomizeName))
                        _dnsWebService._dnsServer.RandomizeName = randomizeName;

                    if (request.TryGetQueryOrForm("qnameMinimization", bool.Parse, out bool qnameMinimization))
                        _dnsWebService._dnsServer.QnameMinimization = qnameMinimization;

                    if (request.TryGetQueryOrForm("nsRevalidation", bool.Parse, out bool nsRevalidation))
                        _dnsWebService._dnsServer.NsRevalidation = nsRevalidation;

                    if (request.TryGetQueryOrForm("resolverRetries", int.Parse, out int resolverRetries))
                        _dnsWebService._dnsServer.ResolverRetries = resolverRetries;

                    if (request.TryGetQueryOrForm("resolverTimeout", int.Parse, out int resolverTimeout))
                        _dnsWebService._dnsServer.ResolverTimeout = resolverTimeout;

                    if (request.TryGetQueryOrForm("resolverConcurrency", int.Parse, out int resolverConcurrency))
                        _dnsWebService._dnsServer.ResolverConcurrency = resolverConcurrency;

                    if (request.TryGetQueryOrForm("resolverMaxStackCount", int.Parse, out int resolverMaxStackCount))
                        _dnsWebService._dnsServer.ResolverMaxStackCount = resolverMaxStackCount;

                    #endregion

                    #region cache

                    //cache
                    if (request.TryGetQueryOrForm("saveCache", bool.Parse, out bool saveCache))
                    {
                        if (!saveCache)
                            _dnsWebService._dnsServer.CacheZoneManager.DeleteCacheZoneFile();

                        _dnsWebService._saveCache = saveCache;
                    }

                    if (request.TryGetQueryOrForm("serveStale", bool.Parse, out bool serveStale))
                        _dnsWebService._dnsServer.ServeStale = serveStale;

                    if (request.TryGetQueryOrForm("serveStaleTtl", uint.Parse, out uint serveStaleTtl))
                        _dnsWebService._dnsServer.CacheZoneManager.ServeStaleTtl = serveStaleTtl;

                    if (request.TryGetQueryOrForm("serveStaleAnswerTtl", uint.Parse, out uint serveStaleAnswerTtl))
                        _dnsWebService._dnsServer.CacheZoneManager.ServeStaleAnswerTtl = serveStaleAnswerTtl;

                    if (request.TryGetQueryOrForm("serveStaleResetTtl", uint.Parse, out uint serveStaleResetTtl))
                        _dnsWebService._dnsServer.CacheZoneManager.ServeStaleResetTtl = serveStaleResetTtl;

                    if (request.TryGetQueryOrForm("serveStaleMaxWaitTime", int.Parse, out int serveStaleMaxWaitTime))
                        _dnsWebService._dnsServer.ServeStaleMaxWaitTime = serveStaleMaxWaitTime;

                    if (request.TryGetQueryOrForm("cacheMaximumEntries", long.Parse, out long cacheMaximumEntries))
                        _dnsWebService._dnsServer.CacheZoneManager.MaximumEntries = cacheMaximumEntries;

                    if (request.TryGetQueryOrForm("cacheMinimumRecordTtl", uint.Parse, out uint cacheMinimumRecordTtl))
                        _dnsWebService._dnsServer.CacheZoneManager.MinimumRecordTtl = cacheMinimumRecordTtl;

                    if (request.TryGetQueryOrForm("cacheMaximumRecordTtl", uint.Parse, out uint cacheMaximumRecordTtl))
                        _dnsWebService._dnsServer.CacheZoneManager.MaximumRecordTtl = cacheMaximumRecordTtl;

                    if (request.TryGetQueryOrForm("cacheNegativeRecordTtl", uint.Parse, out uint cacheNegativeRecordTtl))
                        _dnsWebService._dnsServer.CacheZoneManager.NegativeRecordTtl = cacheNegativeRecordTtl;

                    if (request.TryGetQueryOrForm("cacheFailureRecordTtl", uint.Parse, out uint cacheFailureRecordTtl))
                        _dnsWebService._dnsServer.CacheZoneManager.FailureRecordTtl = cacheFailureRecordTtl;

                    if (request.TryGetQueryOrForm("cachePrefetchEligibility", int.Parse, out int cachePrefetchEligibility))
                        _dnsWebService._dnsServer.CachePrefetchEligibility = cachePrefetchEligibility;

                    if (request.TryGetQueryOrForm("cachePrefetchTrigger", int.Parse, out int cachePrefetchTrigger))
                        _dnsWebService._dnsServer.CachePrefetchTrigger = cachePrefetchTrigger;

                    if (request.TryGetQueryOrForm("cachePrefetchSampleIntervalInMinutes", int.Parse, out int cachePrefetchSampleIntervalInMinutes))
                        _dnsWebService._dnsServer.CachePrefetchSampleIntervalInMinutes = cachePrefetchSampleIntervalInMinutes;

                    if (request.TryGetQueryOrForm("cachePrefetchSampleEligibilityHitsPerHour", int.Parse, out int cachePrefetchSampleEligibilityHitsPerHour))
                        _dnsWebService._dnsServer.CachePrefetchSampleEligibilityHitsPerHour = cachePrefetchSampleEligibilityHitsPerHour;

                    #endregion

                    #region blocking

                    if (request.TryGetQueryOrForm("enableBlocking", bool.Parse, out bool enableBlocking))
                    {
                        _dnsWebService._dnsServer.EnableBlocking = enableBlocking;
                        if (_dnsWebService._dnsServer.EnableBlocking)
                        {
                            if (_temporaryDisableBlockingTimer is not null)
                                _temporaryDisableBlockingTimer.Dispose();
                        }
                    }

                    if (request.TryGetQueryOrForm("allowTxtBlockingReport", bool.Parse, out bool allowTxtBlockingReport))
                        _dnsWebService._dnsServer.AllowTxtBlockingReport = allowTxtBlockingReport;

                    if (request.TryGetQueryOrFormArray("blockingBypassList", NetworkAddress.Parse, out NetworkAddress[] blockingBypassList))
                        _dnsWebService._dnsServer.BlockingBypassList = blockingBypassList;

                    if (request.TryGetQueryOrFormEnum("blockingType", out DnsServerBlockingType blockingType))
                        _dnsWebService._dnsServer.BlockingType = blockingType;

                    if (request.TryGetQueryOrForm("blockingAnswerTtl", uint.Parse, out uint blockingAnswerTtl))
                        _dnsWebService._dnsServer.BlockingAnswerTtl = blockingAnswerTtl;

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
                    }

                    if (request.TryGetQueryOrFormArray("blockListUrls", out string[] blockListUrls))
                    {
                        if ((blockListUrls is null) || (blockListUrls.Length == 0))
                        {
                            _dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                            _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Clear();
                            _dnsWebService._dnsServer.BlockListZoneManager.Flush();
                        }
                        else
                        {
                            if (oldWebServiceHttpPort != _dnsWebService._webServiceHttpPort)
                            {
                                for (int i = 0; i < blockListUrls.Length; i++)
                                {
                                    if (blockListUrls[i].Contains("http://localhost:" + oldWebServiceHttpPort + "/blocklist.txt"))
                                    {
                                        blockListUrls[i] = "http://localhost:" + _dnsWebService._webServiceHttpPort + "/blocklist.txt";
                                        blockListUrlsUpdated = true;
                                        break;
                                    }
                                }
                            }

                            if (!blockListUrlsUpdated)
                            {
                                if (blockListUrls.Length != (_dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Count))
                                {
                                    blockListUrlsUpdated = true;
                                }
                                else
                                {
                                    foreach (string strBlockListUrl in blockListUrls)
                                    {
                                        if (strBlockListUrl.StartsWith('!'))
                                        {
                                            string strAllowListUrl = strBlockListUrl.Substring(1);

                                            if (!_dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Contains(new Uri(strAllowListUrl)))
                                            {
                                                blockListUrlsUpdated = true;
                                                break;
                                            }
                                        }
                                        else
                                        {
                                            if (!_dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Contains(new Uri(strBlockListUrl)))
                                            {
                                                blockListUrlsUpdated = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }

                            if (blockListUrlsUpdated)
                            {
                                _dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                                _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Clear();

                                foreach (string strBlockListUrl in blockListUrls)
                                {
                                    if (strBlockListUrl.StartsWith('!'))
                                    {
                                        Uri allowListUrl = new Uri(strBlockListUrl.Substring(1));

                                        if (allowListUrl.AbsoluteUri.Length > 255)
                                            throw new ArgumentException("Allow list URL length cannot exceed 255 characters.", "blockListUrls");

                                        if (!_dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Contains(allowListUrl))
                                            _dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Add(allowListUrl);
                                    }
                                    else
                                    {
                                        Uri blockListUrl = new Uri(strBlockListUrl);

                                        if (blockListUrl.AbsoluteUri.Length > 255)
                                            throw new ArgumentException("Block list URL length cannot exceed 255 characters.", "blockListUrls");

                                        if (!_dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Contains(blockListUrl))
                                            _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Add(blockListUrl);
                                    }
                                }
                            }
                        }
                    }

                    if (request.TryGetQueryOrForm("blockListUpdateIntervalHours", int.Parse, out int blockListUpdateIntervalHours))
                    {
                        if ((blockListUpdateIntervalHours < 0) || (blockListUpdateIntervalHours > 168))
                            throw new DnsWebServiceException("Parameter `blockListUpdateIntervalHours` must be between 1 hour and 168 hours (7 days) or 0 to disable automatic update.");

                        _blockListUpdateIntervalHours = blockListUpdateIntervalHours;
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
                                    throw new ArgumentException("Proxy username length cannot exceed 255 characters.", "proxyUsername");

                                string proxyPassword = request.QueryOrForm("proxyPassword");
                                if (proxyPassword?.Length > 255)
                                    throw new ArgumentException("Proxy password length cannot exceed 255 characters.", "proxyPassword");

                                credential = new NetworkCredential(proxyUsername, proxyPassword);
                            }

                            _dnsWebService._dnsServer.Proxy = NetProxy.CreateProxy(proxyType, request.QueryOrForm("proxyAddress"), int.Parse(request.QueryOrForm("proxyPort")), credential);

                            if (request.TryGetQueryOrFormArray("proxyBypass", delegate (string value) { return new NetProxyBypassItem(value); }, out NetProxyBypassItem[] proxyBypass))
                                _dnsWebService._dnsServer.Proxy.BypassList = proxyBypass;
                        }
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
                        }
                    }

                    if (request.TryGetQueryOrForm("concurrentForwarding", bool.Parse, out bool concurrentForwarding))
                        _dnsWebService._dnsServer.ConcurrentForwarding = concurrentForwarding;

                    if (request.TryGetQueryOrForm("forwarderRetries", int.Parse, out int forwarderRetries))
                        _dnsWebService._dnsServer.ForwarderRetries = forwarderRetries;

                    if (request.TryGetQueryOrForm("forwarderTimeout", int.Parse, out int forwarderTimeout))
                        _dnsWebService._dnsServer.ForwarderTimeout = forwarderTimeout;

                    if (request.TryGetQueryOrForm("forwarderConcurrency", int.Parse, out int forwarderConcurrency))
                        _dnsWebService._dnsServer.ForwarderConcurrency = forwarderConcurrency;

                    #endregion

                    #region logging

                    if (request.TryGetQueryOrForm("enableLogging", bool.Parse, out bool enableLogging))
                        _dnsWebService._log.EnableLogging = enableLogging;

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

                    //TLS actions
                    if ((_dnsWebService._webServiceTlsCertificatePath is null) && (_dnsWebService._dnsTlsCertificatePath is null))
                        _dnsWebService.StopTlsCertificateUpdateTimer();

                    _dnsWebService.SelfSignedCertCheck(serverDomainChanged || webServiceLocalAddressesChanged, true);

                    if (_dnsWebService._webServiceEnableTls && string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath) && !_dnsWebService._webServiceUseSelfSignedTlsCertificate)
                    {
                        //disable TLS
                        _dnsWebService._webServiceEnableTls = false;
                        restartWebService = true;
                    }

                    //blocklist timers
                    if ((_blockListUpdateIntervalHours > 0) && ((_dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Count) > 0))
                    {
                        if (_blockListUpdateTimer is null)
                            StartBlockListUpdateTimer(blockListUrlsUpdated);
                        else if (blockListUrlsUpdated)
                            ForceUpdateBlockLists(true);
                    }
                    else
                    {
                        StopBlockListUpdateTimer();
                    }

                    //save config
                    _dnsWebService.SaveConfigFile();
                    _dnsWebService._log.SaveConfig();
                }

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] DNS Settings were updated successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteDnsSettings(jsonWriter);

                RestartService(restartDnsService, restartWebService, oldWebServiceLocalAddresses, oldWebServiceHttpPort, oldWebServiceTlsPort);
            }

            public void GetTsigKeyNames(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.View) &&
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify)
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
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool blockLists = request.GetQueryOrForm("blockLists", bool.Parse, false);
                bool logs = request.GetQueryOrForm("logs", bool.Parse, false);
                bool scopes = request.GetQueryOrForm("scopes", bool.Parse, false);
                bool apps = request.GetQueryOrForm("apps", bool.Parse, false);
                bool stats = request.GetQueryOrForm("stats", bool.Parse, false);
                bool zones = request.GetQueryOrForm("zones", bool.Parse, false);
                bool allowedZones = request.GetQueryOrForm("allowedZones", bool.Parse, false);
                bool blockedZones = request.GetQueryOrForm("blockedZones", bool.Parse, false);
                bool dnsSettings = request.GetQueryOrForm("dnsSettings", bool.Parse, false);
                bool authConfig = request.GetQueryOrForm("authConfig", bool.Parse, false);
                bool logSettings = request.GetQueryOrForm("logSettings", bool.Parse, false);

                string tmpFile = Path.GetTempFileName();
                try
                {
                    using (FileStream backupZipStream = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        //create backup zip
                        using (ZipArchive backupZip = new ZipArchive(backupZipStream, ZipArchiveMode.Create, true, Encoding.UTF8))
                        {
                            if (blockLists)
                            {
                                string[] blockListFiles = Directory.GetFiles(Path.Combine(_dnsWebService._configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);
                                foreach (string blockListFile in blockListFiles)
                                {
                                    string entryName = "blocklists/" + Path.GetFileName(blockListFile);
                                    backupZip.CreateEntryFromFile(blockListFile, entryName);
                                }
                            }

                            if (logs)
                            {
                                string[] logFiles = Directory.GetFiles(_dnsWebService._log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);
                                foreach (string logFile in logFiles)
                                {
                                    string entryName = "logs/" + Path.GetFileName(logFile);

                                    if (logFile.Equals(_dnsWebService._log.CurrentLogFile, StringComparison.OrdinalIgnoreCase))
                                    {
                                        await CreateBackupEntryFromFileAsync(backupZip, logFile, entryName);
                                    }
                                    else
                                    {
                                        backupZip.CreateEntryFromFile(logFile, entryName);
                                    }
                                }
                            }

                            if (scopes)
                            {
                                string[] scopeFiles = Directory.GetFiles(Path.Combine(_dnsWebService._configFolder, "scopes"), "*.scope", SearchOption.TopDirectoryOnly);
                                foreach (string scopeFile in scopeFiles)
                                {
                                    string entryName = "scopes/" + Path.GetFileName(scopeFile);
                                    backupZip.CreateEntryFromFile(scopeFile, entryName);
                                }
                            }

                            if (apps)
                            {
                                string[] appFiles = Directory.GetFiles(Path.Combine(_dnsWebService._configFolder, "apps"), "*", SearchOption.AllDirectories);
                                foreach (string appFile in appFiles)
                                {
                                    string entryName = appFile.Substring(_dnsWebService._configFolder.Length);

                                    if (Path.DirectorySeparatorChar != '/')
                                        entryName = entryName.Replace(Path.DirectorySeparatorChar, '/');

                                    entryName = entryName.TrimStart('/');

                                    await CreateBackupEntryFromFileAsync(backupZip, appFile, entryName);
                                }
                            }

                            if (stats)
                            {
                                string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_dnsWebService._configFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);
                                foreach (string hourlyStatsFile in hourlyStatsFiles)
                                {
                                    string entryName = "stats/" + Path.GetFileName(hourlyStatsFile);
                                    backupZip.CreateEntryFromFile(hourlyStatsFile, entryName);
                                }

                                string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_dnsWebService._configFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);
                                foreach (string dailyStatsFile in dailyStatsFiles)
                                {
                                    string entryName = "stats/" + Path.GetFileName(dailyStatsFile);
                                    backupZip.CreateEntryFromFile(dailyStatsFile, entryName);
                                }
                            }

                            if (zones)
                            {
                                string[] zoneFiles = Directory.GetFiles(Path.Combine(_dnsWebService._configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);
                                foreach (string zoneFile in zoneFiles)
                                {
                                    string entryName = "zones/" + Path.GetFileName(zoneFile);
                                    backupZip.CreateEntryFromFile(zoneFile, entryName);
                                }
                            }

                            if (allowedZones)
                            {
                                string allowedZonesFile = Path.Combine(_dnsWebService._configFolder, "allowed.config");

                                if (File.Exists(allowedZonesFile))
                                    backupZip.CreateEntryFromFile(allowedZonesFile, "allowed.config");
                            }

                            if (blockedZones)
                            {
                                string blockedZonesFile = Path.Combine(_dnsWebService._configFolder, "blocked.config");

                                if (File.Exists(blockedZonesFile))
                                    backupZip.CreateEntryFromFile(blockedZonesFile, "blocked.config");
                            }

                            if (dnsSettings)
                            {
                                string dnsSettingsFile = Path.Combine(_dnsWebService._configFolder, "dns.config");

                                if (File.Exists(dnsSettingsFile))
                                    backupZip.CreateEntryFromFile(dnsSettingsFile, "dns.config");

                                //backup web service cert
                                if (!string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath))
                                {
                                    string webServiceTlsCertificatePath = _dnsWebService.ConvertToAbsolutePath(_dnsWebService._webServiceTlsCertificatePath);

                                    if (File.Exists(webServiceTlsCertificatePath) && webServiceTlsCertificatePath.StartsWith(_dnsWebService._configFolder, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                                    {
                                        string entryName = _dnsWebService.ConvertToRelativePath(webServiceTlsCertificatePath).Replace('\\', '/');
                                        backupZip.CreateEntryFromFile(webServiceTlsCertificatePath, entryName);
                                    }
                                }

                                //backup optional protocols cert
                                if (!string.IsNullOrEmpty(_dnsWebService._dnsTlsCertificatePath))
                                {
                                    string dnsTlsCertificatePath = _dnsWebService.ConvertToAbsolutePath(_dnsWebService._dnsTlsCertificatePath);

                                    if (File.Exists(dnsTlsCertificatePath) && dnsTlsCertificatePath.StartsWith(_dnsWebService._configFolder, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                                    {
                                        string entryName = _dnsWebService.ConvertToRelativePath(dnsTlsCertificatePath).Replace('\\', '/');
                                        backupZip.CreateEntryFromFile(dnsTlsCertificatePath, entryName);
                                    }
                                }
                            }

                            if (authConfig)
                            {
                                string authSettingsFile = Path.Combine(_dnsWebService._configFolder, "auth.config");

                                if (File.Exists(authSettingsFile))
                                    backupZip.CreateEntryFromFile(authSettingsFile, "auth.config");
                            }

                            if (logSettings)
                            {
                                string logSettingsFile = Path.Combine(_dnsWebService._configFolder, "log.config");

                                if (File.Exists(logSettingsFile))
                                    backupZip.CreateEntryFromFile(logSettingsFile, "log.config");
                            }
                        }

                        //send zip file
                        backupZipStream.Position = 0;

                        HttpResponse response = context.Response;

                        response.ContentType = "application/zip";
                        response.ContentLength = backupZipStream.Length;
                        response.Headers.ContentDisposition = "attachment;filename=" + _dnsWebService._dnsServer.ServerDomain + DateTime.UtcNow.ToString("_yyyy-MM-dd_HH-mm-ss") + "_backup.zip";

                        using (Stream output = response.Body)
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

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] Settings backup zip file was exported.");
            }

            public async Task RestoreSettingsAsync(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool blockLists = request.GetQueryOrForm("blockLists", bool.Parse, false);
                bool logs = request.GetQueryOrForm("logs", bool.Parse, false);
                bool scopes = request.GetQueryOrForm("scopes", bool.Parse, false);
                bool apps = request.GetQueryOrForm("apps", bool.Parse, false);
                bool stats = request.GetQueryOrForm("stats", bool.Parse, false);
                bool zones = request.GetQueryOrForm("zones", bool.Parse, false);
                bool allowedZones = request.GetQueryOrForm("allowedZones", bool.Parse, false);
                bool blockedZones = request.GetQueryOrForm("blockedZones", bool.Parse, false);
                bool dnsSettings = request.GetQueryOrForm("dnsSettings", bool.Parse, false);
                bool authConfig = request.GetQueryOrForm("authConfig", bool.Parse, false);
                bool logSettings = request.GetQueryOrForm("logSettings", bool.Parse, false);
                bool deleteExistingFiles = request.GetQueryOrForm("deleteExistingFiles", bool.Parse, false);

                if (!request.HasFormContentType || (request.Form.Files.Count == 0))
                    throw new DnsWebServiceException("DNS backup zip file is missing.");

                IReadOnlyList<IPAddress> oldWebServiceLocalAddresses = _dnsWebService._webServiceLocalAddresses;
                int oldWebServiceHttpPort = _dnsWebService._webServiceHttpPort;
                int oldWebServiceTlsPort = _dnsWebService._webServiceTlsPort;

                //write to temp file
                string tmpFile = Path.GetTempFileName();
                try
                {
                    using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        await request.Form.Files[0].CopyToAsync(fS);

                        fS.Position = 0;
                        using (ZipArchive backupZip = new ZipArchive(fS, ZipArchiveMode.Read, false, Encoding.UTF8))
                        {
                            if (logSettings || logs)
                            {
                                //stop logging
                                _dnsWebService._log.StopLogging();
                            }

                            try
                            {
                                if (logSettings)
                                {
                                    ZipArchiveEntry entry = backupZip.GetEntry("log.config");
                                    if (entry is not null)
                                        entry.ExtractToFile(Path.Combine(_dnsWebService._configFolder, entry.Name), true);

                                    //reload config
                                    _dnsWebService._log.LoadConfig();
                                }

                                if (logs)
                                {
                                    if (deleteExistingFiles)
                                    {
                                        //delete existing log files
                                        string[] logFiles = Directory.GetFiles(_dnsWebService._log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);
                                        foreach (string logFile in logFiles)
                                        {
                                            File.Delete(logFile);
                                        }
                                    }

                                    //extract log files from backup
                                    foreach (ZipArchiveEntry entry in backupZip.Entries)
                                    {
                                        if (entry.FullName.StartsWith("logs/"))
                                            entry.ExtractToFile(Path.Combine(_dnsWebService._log.LogFolderAbsolutePath, entry.Name), true);
                                    }
                                }
                            }
                            finally
                            {
                                if (logSettings || logs)
                                {
                                    //start logging
                                    if (_dnsWebService._log.EnableLogging)
                                        _dnsWebService._log.StartLogging();
                                }
                            }

                            if (authConfig)
                            {
                                ZipArchiveEntry entry = backupZip.GetEntry("auth.config");
                                if (entry is not null)
                                    entry.ExtractToFile(Path.Combine(_dnsWebService._configFolder, entry.Name), true);

                                //reload auth config
                                _dnsWebService._authManager.LoadConfigFile(session);
                            }

                            if (blockLists)
                            {
                                if (deleteExistingFiles)
                                {
                                    //delete existing block list files
                                    string[] blockListFiles = Directory.GetFiles(Path.Combine(_dnsWebService._configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);
                                    foreach (string blockListFile in blockListFiles)
                                    {
                                        File.Delete(blockListFile);
                                    }
                                }

                                //extract block list files from backup
                                foreach (ZipArchiveEntry entry in backupZip.Entries)
                                {
                                    if (entry.FullName.StartsWith("blocklists/"))
                                        entry.ExtractToFile(Path.Combine(_dnsWebService._configFolder, "blocklists", entry.Name), true);
                                }
                            }

                            if (dnsSettings)
                            {
                                ZipArchiveEntry entry = backupZip.GetEntry("dns.config");
                                if (entry is not null)
                                    entry.ExtractToFile(Path.Combine(_dnsWebService._configFolder, entry.Name), true);

                                //extract any certs
                                foreach (ZipArchiveEntry certEntry in backupZip.Entries)
                                {
                                    if (certEntry.FullName.StartsWith("apps/"))
                                        continue;

                                    if (certEntry.FullName.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase) || certEntry.FullName.EndsWith(".p12", StringComparison.OrdinalIgnoreCase))
                                    {
                                        string certFile = Path.Combine(_dnsWebService._configFolder, certEntry.FullName);
                                        Directory.CreateDirectory(Path.GetDirectoryName(certFile));

                                        certEntry.ExtractToFile(certFile, true);
                                    }
                                }

                                //flush zones to avoid UpdateServerDomain task for old zones and old allowed/blocked zones
                                if (zones)
                                    _dnsWebService._dnsServer.AuthZoneManager.Flush();

                                if (allowedZones)
                                    _dnsWebService._dnsServer.AllowedZoneManager.Flush();

                                if (blockedZones)
                                    _dnsWebService._dnsServer.BlockedZoneManager.Flush();

                                //reload settings and block list zone
                                _dnsWebService.LoadConfigFile();

                                if ((_dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Count) > 0)
                                {
                                    ThreadPool.QueueUserWorkItem(delegate (object state)
                                    {
                                        try
                                        {
                                            _dnsWebService._dnsServer.BlockListZoneManager.LoadBlockLists();
                                        }
                                        catch (Exception ex)
                                        {
                                            _dnsWebService._log.Write(ex);
                                        }
                                    });

                                    if (_blockListUpdateIntervalHours > 0)
                                        StartBlockListUpdateTimer(false);
                                    else
                                        StopBlockListUpdateTimer();
                                }
                                else
                                {
                                    _dnsWebService._dnsServer.BlockListZoneManager.Flush();

                                    StopBlockListUpdateTimer();
                                }
                            }

                            if (apps)
                            {
                                //unload apps
                                _dnsWebService._dnsServer.DnsApplicationManager.UnloadAllApplications();

                                if (deleteExistingFiles)
                                {
                                    //delete existing apps
                                    string appFolder = Path.Combine(_dnsWebService._configFolder, "apps");
                                    if (Directory.Exists(appFolder))
                                        Directory.Delete(appFolder, true);

                                    //create apps folder
                                    Directory.CreateDirectory(appFolder);
                                }

                                //extract apps files from backup
                                foreach (ZipArchiveEntry entry in backupZip.Entries)
                                {
                                    if (entry.FullName.StartsWith("apps/"))
                                    {
                                        string entryPath = entry.FullName;

                                        if (Path.DirectorySeparatorChar != '/')
                                            entryPath = entryPath.Replace('/', '\\');

                                        string filePath = Path.Combine(_dnsWebService._configFolder, entryPath);

                                        Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                                        entry.ExtractToFile(filePath, true);
                                    }
                                }

                                //reload apps
                                _dnsWebService._dnsServer.DnsApplicationManager.LoadAllApplications();
                            }

                            if (zones)
                            {
                                if (deleteExistingFiles)
                                {
                                    //delete existing zone files
                                    string[] zoneFiles = Directory.GetFiles(Path.Combine(_dnsWebService._configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);
                                    foreach (string zoneFile in zoneFiles)
                                    {
                                        File.Delete(zoneFile);
                                    }
                                }

                                //extract zone files from backup
                                foreach (ZipArchiveEntry entry in backupZip.Entries)
                                {
                                    if (entry.FullName.StartsWith("zones/"))
                                        entry.ExtractToFile(Path.Combine(_dnsWebService._configFolder, "zones", entry.Name), true);
                                }

                                //reload zones
                                _dnsWebService._dnsServer.AuthZoneManager.LoadAllZoneFiles();
                                _dnsWebService.InspectAndFixZonePermissions();
                            }

                            if (allowedZones)
                            {
                                ZipArchiveEntry entry = backupZip.GetEntry("allowed.config");
                                if (entry == null)
                                {
                                    string fileName = Path.Combine(_dnsWebService._configFolder, "allowed.config");
                                    if (File.Exists(fileName))
                                        File.Delete(fileName);
                                }
                                else
                                {
                                    entry.ExtractToFile(Path.Combine(_dnsWebService._configFolder, entry.Name), true);
                                }

                                //reload
                                _dnsWebService._dnsServer.AllowedZoneManager.LoadAllowedZoneFile();
                            }

                            if (blockedZones)
                            {
                                ZipArchiveEntry entry = backupZip.GetEntry("blocked.config");
                                if (entry == null)
                                {
                                    string fileName = Path.Combine(_dnsWebService._configFolder, "blocked.config");
                                    if (File.Exists(fileName))
                                        File.Delete(fileName);
                                }
                                else
                                {
                                    entry.ExtractToFile(Path.Combine(_dnsWebService._configFolder, entry.Name), true);
                                }

                                //reload
                                _dnsWebService._dnsServer.BlockedZoneManager.LoadBlockedZoneFile();
                            }

                            if (scopes)
                            {
                                //stop dhcp server
                                _dnsWebService._dhcpServer.Stop();

                                try
                                {
                                    if (deleteExistingFiles)
                                    {
                                        //delete existing scope files
                                        string[] scopeFiles = Directory.GetFiles(Path.Combine(_dnsWebService._configFolder, "scopes"), "*.scope", SearchOption.TopDirectoryOnly);
                                        foreach (string scopeFile in scopeFiles)
                                        {
                                            File.Delete(scopeFile);
                                        }
                                    }

                                    //extract scope files from backup
                                    foreach (ZipArchiveEntry entry in backupZip.Entries)
                                    {
                                        if (entry.FullName.StartsWith("scopes/"))
                                            entry.ExtractToFile(Path.Combine(_dnsWebService._configFolder, "scopes", entry.Name), true);
                                    }
                                }
                                finally
                                {
                                    //start dhcp server
                                    _dnsWebService._dhcpServer.Start();
                                }
                            }

                            if (stats)
                            {
                                if (deleteExistingFiles)
                                {
                                    //delete existing stats files
                                    string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_dnsWebService._configFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);
                                    foreach (string hourlyStatsFile in hourlyStatsFiles)
                                    {
                                        File.Delete(hourlyStatsFile);
                                    }

                                    string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_dnsWebService._configFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);
                                    foreach (string dailyStatsFile in dailyStatsFiles)
                                    {
                                        File.Delete(dailyStatsFile);
                                    }
                                }

                                //extract stats files from backup
                                foreach (ZipArchiveEntry entry in backupZip.Entries)
                                {
                                    if (entry.FullName.StartsWith("stats/"))
                                        entry.ExtractToFile(Path.Combine(_dnsWebService._configFolder, "stats", entry.Name), true);
                                }

                                //reload stats
                                _dnsWebService._dnsServer.StatsManager.ReloadStats();
                            }

                            _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] Settings backup zip file was restored.");
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

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteDnsSettings(jsonWriter);

                if (dnsSettings)
                    RestartService(true, true, oldWebServiceLocalAddresses, oldWebServiceHttpPort, oldWebServiceTlsPort);
            }

            public void ForceUpdateBlockLists(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                ForceUpdateBlockLists(false);
                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] Block list update was triggered.");
            }

            public void TemporaryDisableBlocking(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                int minutes = context.Request.GetQueryOrForm("minutes", int.Parse);

                Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
                if (temporaryDisableBlockingTimer is not null)
                    temporaryDisableBlockingTimer.Dispose();

                Timer newTemporaryDisableBlockingTimer = new Timer(delegate (object state)
                {
                    try
                    {
                        _dnsWebService._dnsServer.EnableBlocking = true;
                        _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] Blocking was enabled after " + minutes + " minute(s) being temporarily disabled.");
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService._log.Write(ex);
                    }
                });

                Timer originalTimer = Interlocked.CompareExchange(ref _temporaryDisableBlockingTimer, newTemporaryDisableBlockingTimer, temporaryDisableBlockingTimer);
                if (ReferenceEquals(originalTimer, temporaryDisableBlockingTimer))
                {
                    newTemporaryDisableBlockingTimer.Change(minutes * 60 * 1000, Timeout.Infinite);
                    _dnsWebService._dnsServer.EnableBlocking = false;
                    _temporaryDisableBlockingTill = DateTime.UtcNow.AddMinutes(minutes);

                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] Blocking was temporarily disabled for " + minutes + " minute(s).");
                }
                else
                {
                    newTemporaryDisableBlockingTimer.Dispose();
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteString("temporaryDisableBlockingTill", _temporaryDisableBlockingTill);
            }

            #endregion

            #region properties

            public DateTime BlockListLastUpdatedOn
            {
                get { return _blockListLastUpdatedOn; }
                set { _blockListLastUpdatedOn = value; }
            }

            public int BlockListUpdateIntervalHours
            {
                get { return _blockListUpdateIntervalHours; }
                set { _blockListUpdateIntervalHours = value; }
            }

            #endregion
        }
    }
}
