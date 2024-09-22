/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.Linq;
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
    sealed class WebServiceSettingsApi : IDisposable
    {
        #region variables

        static readonly char[] _commaSeparator = new char[] { ',' };

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
                if (await _dnsWebService.DnsServer.BlockListZoneManager.UpdateBlockListsAsync(forceReload))
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
                            if (await _dnsWebService.DnsServer.BlockListZoneManager.UpdateBlockListsAsync(_blockListLastUpdatedOn == default))
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
                        await _dnsWebService.DnsServer.StopAsync();
                        await _dnsWebService.DnsServer.StartAsync();

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
            jsonWriter.WriteString("dnsServerDomain", _dnsWebService.DnsServer.ServerDomain);

            jsonWriter.WriteStringArray("dnsServerLocalEndPoints", _dnsWebService.DnsServer.LocalEndPoints);

            jsonWriter.WriteStringArray("dnsServerIPv4SourceAddresses", DnsClientConnection.IPv4SourceAddresses);
            jsonWriter.WriteStringArray("dnsServerIPv6SourceAddresses", DnsClientConnection.IPv6SourceAddresses);

            jsonWriter.WriteNumber("defaultRecordTtl", _dnsWebService._zonesApi.DefaultRecordTtl);
            jsonWriter.WriteString("defaultResponsiblePerson", _dnsWebService.DnsServer.ResponsiblePersonInternal?.Address);
            jsonWriter.WriteBoolean("useSoaSerialDateScheme", _dnsWebService.DnsServer.AuthZoneManager.UseSoaSerialDateScheme);

            jsonWriter.WriteStringArray("zoneTransferAllowedNetworks", _dnsWebService.DnsServer.ZoneTransferAllowedNetworks);

            jsonWriter.WriteStringArray("notifyAllowedNetworks", _dnsWebService.DnsServer.NotifyAllowedNetworks);

            jsonWriter.WriteBoolean("dnsAppsEnableAutomaticUpdate", _dnsWebService._appsApi.EnableAutomaticUpdate);

            jsonWriter.WriteBoolean("preferIPv6", _dnsWebService.DnsServer.PreferIPv6);

            jsonWriter.WriteNumber("udpPayloadSize", _dnsWebService.DnsServer.UdpPayloadSize);

            jsonWriter.WriteBoolean("dnssecValidation", _dnsWebService.DnsServer.DnssecValidation);

            jsonWriter.WriteBoolean("eDnsClientSubnet", _dnsWebService.DnsServer.EDnsClientSubnet);
            jsonWriter.WriteNumber("eDnsClientSubnetIPv4PrefixLength", _dnsWebService.DnsServer.EDnsClientSubnetIPv4PrefixLength);
            jsonWriter.WriteNumber("eDnsClientSubnetIPv6PrefixLength", _dnsWebService.DnsServer.EDnsClientSubnetIPv6PrefixLength);
            jsonWriter.WriteString("eDnsClientSubnetIpv4Override", _dnsWebService.DnsServer.EDnsClientSubnetIpv4Override?.ToString());
            jsonWriter.WriteString("eDnsClientSubnetIpv6Override", _dnsWebService.DnsServer.EDnsClientSubnetIpv6Override?.ToString());

            jsonWriter.WriteNumber("qpmLimitRequests", _dnsWebService.DnsServer.QpmLimitRequests);
            jsonWriter.WriteNumber("qpmLimitErrors", _dnsWebService.DnsServer.QpmLimitErrors);
            jsonWriter.WriteNumber("qpmLimitSampleMinutes", _dnsWebService.DnsServer.QpmLimitSampleMinutes);
            jsonWriter.WriteNumber("qpmLimitIPv4PrefixLength", _dnsWebService.DnsServer.QpmLimitIPv4PrefixLength);
            jsonWriter.WriteNumber("qpmLimitIPv6PrefixLength", _dnsWebService.DnsServer.QpmLimitIPv6PrefixLength);

            jsonWriter.WritePropertyName("qpmLimitBypassList");
            jsonWriter.WriteStartArray();

            if (_dnsWebService.DnsServer.QpmLimitBypassList is not null)
            {
                foreach (NetworkAddress network in _dnsWebService.DnsServer.QpmLimitBypassList)
                    jsonWriter.WriteStringValue(network.ToString());
            }

            jsonWriter.WriteEndArray();

            jsonWriter.WriteNumber("clientTimeout", _dnsWebService.DnsServer.ClientTimeout);
            jsonWriter.WriteNumber("tcpSendTimeout", _dnsWebService.DnsServer.TcpSendTimeout);
            jsonWriter.WriteNumber("tcpReceiveTimeout", _dnsWebService.DnsServer.TcpReceiveTimeout);
            jsonWriter.WriteNumber("quicIdleTimeout", _dnsWebService.DnsServer.QuicIdleTimeout);
            jsonWriter.WriteNumber("quicMaxInboundStreams", _dnsWebService.DnsServer.QuicMaxInboundStreams);
            jsonWriter.WriteNumber("listenBacklog", _dnsWebService.DnsServer.ListenBacklog);

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

            //optional protocols
            jsonWriter.WriteBoolean("enableDnsOverUdpProxy", _dnsWebService.DnsServer.EnableDnsOverUdpProxy);
            jsonWriter.WriteBoolean("enableDnsOverTcpProxy", _dnsWebService.DnsServer.EnableDnsOverTcpProxy);
            jsonWriter.WriteBoolean("enableDnsOverHttp", _dnsWebService.DnsServer.EnableDnsOverHttp);
            jsonWriter.WriteBoolean("enableDnsOverTls", _dnsWebService.DnsServer.EnableDnsOverTls);
            jsonWriter.WriteBoolean("enableDnsOverHttps", _dnsWebService.DnsServer.EnableDnsOverHttps);
            jsonWriter.WriteBoolean("enableDnsOverHttp3", _dnsWebService.DnsServer.EnableDnsOverHttp3);
            jsonWriter.WriteBoolean("enableDnsOverQuic", _dnsWebService.DnsServer.EnableDnsOverQuic);
            jsonWriter.WriteNumber("dnsOverUdpProxyPort", _dnsWebService.DnsServer.DnsOverUdpProxyPort);
            jsonWriter.WriteNumber("dnsOverTcpProxyPort", _dnsWebService.DnsServer.DnsOverTcpProxyPort);
            jsonWriter.WriteNumber("dnsOverHttpPort", _dnsWebService.DnsServer.DnsOverHttpPort);
            jsonWriter.WriteNumber("dnsOverTlsPort", _dnsWebService.DnsServer.DnsOverTlsPort);
            jsonWriter.WriteNumber("dnsOverHttpsPort", _dnsWebService.DnsServer.DnsOverHttpsPort);
            jsonWriter.WriteNumber("dnsOverQuicPort", _dnsWebService.DnsServer.DnsOverQuicPort);
            jsonWriter.WriteString("dnsTlsCertificatePath", _dnsWebService._dnsTlsCertificatePath);
            jsonWriter.WriteString("dnsTlsCertificatePassword", "************");

            //tsig
            jsonWriter.WritePropertyName("tsigKeys");
            {
                jsonWriter.WriteStartArray();

                if (_dnsWebService.DnsServer.TsigKeys is not null)
                {
                    foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsWebService.DnsServer.TsigKeys.ToImmutableSortedDictionary())
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
            jsonWriter.WriteString("recursion", _dnsWebService.DnsServer.Recursion.ToString());

            jsonWriter.WritePropertyName("recursionNetworkACL");
            {
                jsonWriter.WriteStartArray();

                if (_dnsWebService.DnsServer.RecursionNetworkACL is not null)
                {
                    foreach (NetworkAccessControl nac in _dnsWebService.DnsServer.RecursionNetworkACL)
                        jsonWriter.WriteStringValue(nac.ToString());
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WriteBoolean("randomizeName", _dnsWebService.DnsServer.RandomizeName);
            jsonWriter.WriteBoolean("qnameMinimization", _dnsWebService.DnsServer.QnameMinimization);
            jsonWriter.WriteBoolean("nsRevalidation", _dnsWebService.DnsServer.NsRevalidation);

            jsonWriter.WriteNumber("resolverRetries", _dnsWebService.DnsServer.ResolverRetries);
            jsonWriter.WriteNumber("resolverTimeout", _dnsWebService.DnsServer.ResolverTimeout);
            jsonWriter.WriteNumber("resolverConcurrency", _dnsWebService.DnsServer.ResolverConcurrency);
            jsonWriter.WriteNumber("resolverMaxStackCount", _dnsWebService.DnsServer.ResolverMaxStackCount);

            //cache
            jsonWriter.WriteBoolean("saveCache", _dnsWebService._saveCache);
            jsonWriter.WriteBoolean("serveStale", _dnsWebService.DnsServer.ServeStale);
            jsonWriter.WriteNumber("serveStaleTtl", _dnsWebService.DnsServer.CacheZoneManager.ServeStaleTtl);
            jsonWriter.WriteNumber("serveStaleAnswerTtl", _dnsWebService.DnsServer.CacheZoneManager.ServeStaleAnswerTtl);
            jsonWriter.WriteNumber("serveStaleResetTtl", _dnsWebService.DnsServer.CacheZoneManager.ServeStaleResetTtl);
            jsonWriter.WriteNumber("serveStaleMaxWaitTime", _dnsWebService.DnsServer.ServeStaleMaxWaitTime);

            jsonWriter.WriteNumber("cacheMaximumEntries", _dnsWebService.DnsServer.CacheZoneManager.MaximumEntries);
            jsonWriter.WriteNumber("cacheMinimumRecordTtl", _dnsWebService.DnsServer.CacheZoneManager.MinimumRecordTtl);
            jsonWriter.WriteNumber("cacheMaximumRecordTtl", _dnsWebService.DnsServer.CacheZoneManager.MaximumRecordTtl);
            jsonWriter.WriteNumber("cacheNegativeRecordTtl", _dnsWebService.DnsServer.CacheZoneManager.NegativeRecordTtl);
            jsonWriter.WriteNumber("cacheFailureRecordTtl", _dnsWebService.DnsServer.CacheZoneManager.FailureRecordTtl);

            jsonWriter.WriteNumber("cachePrefetchEligibility", _dnsWebService.DnsServer.CachePrefetchEligibility);
            jsonWriter.WriteNumber("cachePrefetchTrigger", _dnsWebService.DnsServer.CachePrefetchTrigger);
            jsonWriter.WriteNumber("cachePrefetchSampleIntervalInMinutes", _dnsWebService.DnsServer.CachePrefetchSampleIntervalInMinutes);
            jsonWriter.WriteNumber("cachePrefetchSampleEligibilityHitsPerHour", _dnsWebService.DnsServer.CachePrefetchSampleEligibilityHitsPerHour);

            //blocking
            jsonWriter.WriteBoolean("enableBlocking", _dnsWebService.DnsServer.EnableBlocking);
            jsonWriter.WriteBoolean("allowTxtBlockingReport", _dnsWebService.DnsServer.AllowTxtBlockingReport);

            jsonWriter.WritePropertyName("blockingBypassList");
            jsonWriter.WriteStartArray();

            if (_dnsWebService.DnsServer.BlockingBypassList is not null)
            {
                foreach (NetworkAddress network in _dnsWebService.DnsServer.BlockingBypassList)
                    jsonWriter.WriteStringValue(network.ToString());
            }

            jsonWriter.WriteEndArray();

            if (!_dnsWebService.DnsServer.EnableBlocking && (DateTime.UtcNow < _temporaryDisableBlockingTill))
                jsonWriter.WriteString("temporaryDisableBlockingTill", _temporaryDisableBlockingTill);

            jsonWriter.WriteString("blockingType", _dnsWebService.DnsServer.BlockingType.ToString());

            jsonWriter.WritePropertyName("customBlockingAddresses");
            jsonWriter.WriteStartArray();

            foreach (DnsARecordData record in _dnsWebService.DnsServer.CustomBlockingARecords)
                jsonWriter.WriteStringValue(record.Address.ToString());

            foreach (DnsAAAARecordData record in _dnsWebService.DnsServer.CustomBlockingAAAARecords)
                jsonWriter.WriteStringValue(record.Address.ToString());

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("blockListUrls");

            if ((_dnsWebService.DnsServer.BlockListZoneManager.AllowListUrls.Count == 0) && (_dnsWebService.DnsServer.BlockListZoneManager.BlockListUrls.Count == 0))
            {
                jsonWriter.WriteNullValue();
            }
            else
            {
                jsonWriter.WriteStartArray();

                foreach (Uri allowListUrl in _dnsWebService.DnsServer.BlockListZoneManager.AllowListUrls)
                    jsonWriter.WriteStringValue("!" + allowListUrl.AbsoluteUri);

                foreach (Uri blockListUrl in _dnsWebService.DnsServer.BlockListZoneManager.BlockListUrls)
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
            if (_dnsWebService.DnsServer.Proxy == null)
            {
                jsonWriter.WriteNullValue();
            }
            else
            {
                jsonWriter.WriteStartObject();

                NetProxy proxy = _dnsWebService.DnsServer.Proxy;

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

            if (_dnsWebService.DnsServer.Forwarders == null)
            {
                jsonWriter.WriteNullValue();
            }
            else
            {
                forwarderProtocol = _dnsWebService.DnsServer.Forwarders[0].Protocol;

                jsonWriter.WriteStartArray();

                foreach (NameServerAddress forwarder in _dnsWebService.DnsServer.Forwarders)
                    jsonWriter.WriteStringValue(forwarder.OriginalAddress);

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WriteString("forwarderProtocol", forwarderProtocol.ToString());
            jsonWriter.WriteBoolean("concurrentForwarding", _dnsWebService.DnsServer.ConcurrentForwarding);

            jsonWriter.WriteNumber("forwarderRetries", _dnsWebService.DnsServer.ForwarderRetries);
            jsonWriter.WriteNumber("forwarderTimeout", _dnsWebService.DnsServer.ForwarderTimeout);
            jsonWriter.WriteNumber("forwarderConcurrency", _dnsWebService.DnsServer.ForwarderConcurrency);

            //logging
            jsonWriter.WriteBoolean("enableLogging", _dnsWebService._log.EnableLogging);
            jsonWriter.WriteBoolean("ignoreResolverLogs", _dnsWebService.DnsServer.ResolverLogManager == null);
            jsonWriter.WriteBoolean("logQueries", _dnsWebService.DnsServer.QueryLogManager != null);
            jsonWriter.WriteBoolean("useLocalTime", _dnsWebService._log.UseLocalTime);
            jsonWriter.WriteString("logFolder", _dnsWebService._log.LogFolder);
            jsonWriter.WriteNumber("maxLogFileDays", _dnsWebService._log.MaxLogFileDays);

            jsonWriter.WriteBoolean("enableInMemoryStats", _dnsWebService.DnsServer.StatsManager.EnableInMemoryStats);
            jsonWriter.WriteNumber("maxStatFileDays", _dnsWebService.DnsServer.StatsManager.MaxStatFileDays);
        }

        private static List<NetworkAddress> ParseNetworkAddresses(string networkAddresses)
        {
            if ((networkAddresses.Length == 0) || networkAddresses.Equals("false", StringComparison.OrdinalIgnoreCase))
                return null;

            string[] addresses = networkAddresses.Split(_commaSeparator, StringSplitOptions.RemoveEmptyEntries);

            List<NetworkAddress> networks = new List<NetworkAddress>(addresses.Length);

            foreach (string address in addresses)
            {
                if (NetworkAddress.TryParse(address, out NetworkAddress networkAddress))
                    networks.Add(networkAddress);
            }

            return networks;
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

        public void SetDnsSettings(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            bool serverDomainChanged = false;
            bool restartDnsService = false;
            bool restartWebService = false;
            bool blockListUrlsUpdated = false;
            IReadOnlyList<IPAddress> oldWebServiceLocalAddresses = _dnsWebService._webServiceLocalAddresses;
            int oldWebServiceHttpPort = _dnsWebService._webServiceHttpPort;
            int oldWebServiceTlsPort = _dnsWebService._webServiceTlsPort;
            bool _webServiceEnablingTls = false;

            HttpRequest request = context.Request;

            //general
            if (request.TryGetQueryOrForm("dnsServerDomain", out string dnsServerDomain))
            {
                dnsServerDomain = dnsServerDomain.TrimEnd('.');

                if (!_dnsWebService.DnsServer.ServerDomain.Equals(dnsServerDomain, StringComparison.OrdinalIgnoreCase))
                {
                    _dnsWebService.DnsServer.ServerDomain = dnsServerDomain;
                    serverDomainChanged = true;
                }
            }

            string dnsServerLocalEndPoints = request.QueryOrForm("dnsServerLocalEndPoints");
            if (dnsServerLocalEndPoints is not null)
            {
                if (dnsServerLocalEndPoints.Length == 0)
                    dnsServerLocalEndPoints = "0.0.0.0:53,[::]:53";

                IPEndPoint[] localEndPoints = dnsServerLocalEndPoints.Split(IPEndPoint.Parse, ',');
                if (localEndPoints.Length > 0)
                {
                    foreach (IPEndPoint localEndPoint in localEndPoints)
                    {
                        if (localEndPoint.Port == 0)
                            localEndPoint.Port = 53;
                    }

                    if (_dnsWebService.DnsServer.LocalEndPoints.Count != localEndPoints.Length)
                    {
                        restartDnsService = true;
                    }
                    else
                    {
                        foreach (IPEndPoint currentLocalEP in _dnsWebService.DnsServer.LocalEndPoints)
                        {
                            if (!localEndPoints.Contains(currentLocalEP))
                            {
                                restartDnsService = true;
                                break;
                            }
                        }
                    }

                    _dnsWebService.DnsServer.LocalEndPoints = localEndPoints;
                }
            }

            string dnsServerIPv4SourceAddresses = request.QueryOrForm("dnsServerIPv4SourceAddresses");
            if (dnsServerIPv4SourceAddresses is not null)
                DnsClientConnection.IPv4SourceAddresses = ParseNetworkAddresses(dnsServerIPv4SourceAddresses);

            string dnsServerIPv6SourceAddresses = request.QueryOrForm("dnsServerIPv6SourceAddresses");
            if (dnsServerIPv6SourceAddresses is not null)
                DnsClientConnection.IPv6SourceAddresses = ParseNetworkAddresses(dnsServerIPv6SourceAddresses);

            if (request.TryGetQueryOrForm("defaultRecordTtl", uint.Parse, out uint defaultRecordTtl))
                _dnsWebService._zonesApi.DefaultRecordTtl = defaultRecordTtl;

            string defaultResponsiblePerson = request.QueryOrForm("defaultResponsiblePerson");
            if (defaultResponsiblePerson is not null)
            {
                if (defaultResponsiblePerson.Length == 0)
                    _dnsWebService.DnsServer.ResponsiblePersonInternal = null;
                else
                    _dnsWebService.DnsServer.ResponsiblePersonInternal = new MailAddress(defaultResponsiblePerson);
            }

            if (request.TryGetQueryOrForm("useSoaSerialDateScheme", bool.Parse, out bool useSoaSerialDateScheme))
                _dnsWebService.DnsServer.AuthZoneManager.UseSoaSerialDateScheme = useSoaSerialDateScheme;

            string zoneTransferAllowedNetworks = request.QueryOrForm("zoneTransferAllowedNetworks");
            if (zoneTransferAllowedNetworks is not null)
                _dnsWebService.DnsServer.ZoneTransferAllowedNetworks = ParseNetworkAddresses(zoneTransferAllowedNetworks);

            string notifyAllowedNetworks = request.QueryOrForm("notifyAllowedNetworks");
            if (notifyAllowedNetworks is not null)
                _dnsWebService.DnsServer.NotifyAllowedNetworks = ParseNetworkAddresses(notifyAllowedNetworks);

            if (request.TryGetQueryOrForm("dnsAppsEnableAutomaticUpdate", bool.Parse, out bool dnsAppsEnableAutomaticUpdate))
                _dnsWebService._appsApi.EnableAutomaticUpdate = dnsAppsEnableAutomaticUpdate;

            if (request.TryGetQueryOrForm("preferIPv6", bool.Parse, out bool preferIPv6))
                _dnsWebService.DnsServer.PreferIPv6 = preferIPv6;

            if (request.TryGetQueryOrForm("udpPayloadSize", ushort.Parse, out ushort udpPayloadSize))
                _dnsWebService.DnsServer.UdpPayloadSize = udpPayloadSize;

            if (request.TryGetQueryOrForm("dnssecValidation", bool.Parse, out bool dnssecValidation))
                _dnsWebService.DnsServer.DnssecValidation = dnssecValidation;

            if (request.TryGetQueryOrForm("eDnsClientSubnet", bool.Parse, out bool eDnsClientSubnet))
                _dnsWebService.DnsServer.EDnsClientSubnet = eDnsClientSubnet;

            if (request.TryGetQueryOrForm("eDnsClientSubnetIPv4PrefixLength", byte.Parse, out byte eDnsClientSubnetIPv4PrefixLength))
                _dnsWebService.DnsServer.EDnsClientSubnetIPv4PrefixLength = eDnsClientSubnetIPv4PrefixLength;

            if (request.TryGetQueryOrForm("eDnsClientSubnetIPv6PrefixLength", byte.Parse, out byte eDnsClientSubnetIPv6PrefixLength))
                _dnsWebService.DnsServer.EDnsClientSubnetIPv6PrefixLength = eDnsClientSubnetIPv6PrefixLength;

            string eDnsClientSubnetIpv4Override = request.QueryOrForm("eDnsClientSubnetIpv4Override");
            if (eDnsClientSubnetIpv4Override is not null)
            {
                if (eDnsClientSubnetIpv4Override.Length == 0)
                    _dnsWebService.DnsServer.EDnsClientSubnetIpv4Override = null;
                else
                    _dnsWebService.DnsServer.EDnsClientSubnetIpv4Override = NetworkAddress.Parse(eDnsClientSubnetIpv4Override);
            }

            string eDnsClientSubnetIpv6Override = request.QueryOrForm("eDnsClientSubnetIpv6Override");
            if (eDnsClientSubnetIpv6Override is not null)
            {
                if (eDnsClientSubnetIpv6Override.Length == 0)
                    _dnsWebService.DnsServer.EDnsClientSubnetIpv6Override = null;
                else
                    _dnsWebService.DnsServer.EDnsClientSubnetIpv6Override = NetworkAddress.Parse(eDnsClientSubnetIpv6Override);
            }

            if (request.TryGetQueryOrForm("qpmLimitRequests", int.Parse, out int qpmLimitRequests))
                _dnsWebService.DnsServer.QpmLimitRequests = qpmLimitRequests;

            if (request.TryGetQueryOrForm("qpmLimitErrors", int.Parse, out int qpmLimitErrors))
                _dnsWebService.DnsServer.QpmLimitErrors = qpmLimitErrors;

            if (request.TryGetQueryOrForm("qpmLimitSampleMinutes", int.Parse, out int qpmLimitSampleMinutes))
                _dnsWebService.DnsServer.QpmLimitSampleMinutes = qpmLimitSampleMinutes;

            if (request.TryGetQueryOrForm("qpmLimitIPv4PrefixLength", int.Parse, out int qpmLimitIPv4PrefixLength))
                _dnsWebService.DnsServer.QpmLimitIPv4PrefixLength = qpmLimitIPv4PrefixLength;

            if (request.TryGetQueryOrForm("qpmLimitIPv6PrefixLength", int.Parse, out int qpmLimitIPv6PrefixLength))
                _dnsWebService.DnsServer.QpmLimitIPv6PrefixLength = qpmLimitIPv6PrefixLength;

            string qpmLimitBypassList = request.QueryOrForm("qpmLimitBypassList");
            if (qpmLimitBypassList is not null)
                _dnsWebService.DnsServer.QpmLimitBypassList = ParseNetworkAddresses(qpmLimitBypassList);

            if (request.TryGetQueryOrForm("clientTimeout", int.Parse, out int clientTimeout))
                _dnsWebService.DnsServer.ClientTimeout = clientTimeout;

            if (request.TryGetQueryOrForm("tcpSendTimeout", int.Parse, out int tcpSendTimeout))
                _dnsWebService.DnsServer.TcpSendTimeout = tcpSendTimeout;

            if (request.TryGetQueryOrForm("tcpReceiveTimeout", int.Parse, out int tcpReceiveTimeout))
                _dnsWebService.DnsServer.TcpReceiveTimeout = tcpReceiveTimeout;

            if (request.TryGetQueryOrForm("quicIdleTimeout", int.Parse, out int quicIdleTimeout))
                _dnsWebService.DnsServer.QuicIdleTimeout = quicIdleTimeout;

            if (request.TryGetQueryOrForm("quicMaxInboundStreams", int.Parse, out int quicMaxInboundStreams))
                _dnsWebService.DnsServer.QuicMaxInboundStreams = quicMaxInboundStreams;

            if (request.TryGetQueryOrForm("listenBacklog", int.Parse, out int listenBacklog))
                _dnsWebService.DnsServer.ListenBacklog = listenBacklog;

            //web service
            string webServiceLocalAddresses = request.QueryOrForm("webServiceLocalAddresses");
            if (webServiceLocalAddresses is not null)
            {
                if (webServiceLocalAddresses.Length == 0)
                    webServiceLocalAddresses = "0.0.0.0,[::]";

                IPAddress[] localAddresses = webServiceLocalAddresses.Split(IPAddress.Parse, ',');
                if (localAddresses.Length > 0)
                {
                    if (_dnsWebService._webServiceLocalAddresses.Count != localAddresses.Length)
                    {
                        restartWebService = true;
                    }
                    else
                    {
                        foreach (IPAddress currentlocalAddress in _dnsWebService._webServiceLocalAddresses)
                        {
                            if (!localAddresses.Contains(currentlocalAddress))
                            {
                                restartWebService = true;
                                break;
                            }
                        }
                    }

                    _dnsWebService._webServiceLocalAddresses = DnsServer.GetValidKestralLocalAddresses(localAddresses);
                }
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
                        _dnsWebService.LoadWebServiceTlsCertificate(_dnsWebService.ConvertToAbsolutePath(webServiceTlsCertificatePath), webServiceTlsCertificatePassword);

                        _dnsWebService._webServiceTlsCertificatePath = _dnsWebService.ConvertToRelativePath(webServiceTlsCertificatePath);
                        _dnsWebService._webServiceTlsCertificatePassword = webServiceTlsCertificatePassword;

                        _dnsWebService.StartTlsCertificateUpdateTimer();
                    }
                }
            }

            //optional protocols
            if (request.TryGetQueryOrForm("enableDnsOverUdpProxy", bool.Parse, out bool enableDnsOverUdpProxy))
            {
                if (_dnsWebService.DnsServer.EnableDnsOverUdpProxy != enableDnsOverUdpProxy)
                {
                    _dnsWebService.DnsServer.EnableDnsOverUdpProxy = enableDnsOverUdpProxy;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("enableDnsOverTcpProxy", bool.Parse, out bool enableDnsOverTcpProxy))
            {
                if (_dnsWebService.DnsServer.EnableDnsOverTcpProxy != enableDnsOverTcpProxy)
                {
                    _dnsWebService.DnsServer.EnableDnsOverTcpProxy = enableDnsOverTcpProxy;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("enableDnsOverHttp", bool.Parse, out bool enableDnsOverHttp))
            {
                if (_dnsWebService.DnsServer.EnableDnsOverHttp != enableDnsOverHttp)
                {
                    _dnsWebService.DnsServer.EnableDnsOverHttp = enableDnsOverHttp;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("enableDnsOverTls", bool.Parse, out bool enableDnsOverTls))
            {
                if (_dnsWebService.DnsServer.EnableDnsOverTls != enableDnsOverTls)
                {
                    _dnsWebService.DnsServer.EnableDnsOverTls = enableDnsOverTls;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("enableDnsOverHttps", bool.Parse, out bool enableDnsOverHttps))
            {
                if (_dnsWebService.DnsServer.EnableDnsOverHttps != enableDnsOverHttps)
                {
                    _dnsWebService.DnsServer.EnableDnsOverHttps = enableDnsOverHttps;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("enableDnsOverHttp3", bool.Parse, out bool enableDnsOverHttp3))
            {
                if (_dnsWebService.DnsServer.EnableDnsOverHttp3 != enableDnsOverHttp3)
                {
                    if (enableDnsOverHttp3)
                        DnsWebService.ValidateQuicSupport("DNS-over-HTTP/3");

                    _dnsWebService.DnsServer.EnableDnsOverHttp3 = enableDnsOverHttp3;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("enableDnsOverQuic", bool.Parse, out bool enableDnsOverQuic))
            {
                if (_dnsWebService.DnsServer.EnableDnsOverQuic != enableDnsOverQuic)
                {
                    if (enableDnsOverQuic)
                        DnsWebService.ValidateQuicSupport();

                    _dnsWebService.DnsServer.EnableDnsOverQuic = enableDnsOverQuic;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("dnsOverUdpProxyPort", int.Parse, out int dnsOverUdpProxyPort))
            {
                if (_dnsWebService.DnsServer.DnsOverUdpProxyPort != dnsOverUdpProxyPort)
                {
                    _dnsWebService.DnsServer.DnsOverUdpProxyPort = dnsOverUdpProxyPort;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("dnsOverTcpProxyPort", int.Parse, out int dnsOverTcpProxyPort))
            {
                if (_dnsWebService.DnsServer.DnsOverTcpProxyPort != dnsOverTcpProxyPort)
                {
                    _dnsWebService.DnsServer.DnsOverTcpProxyPort = dnsOverTcpProxyPort;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("dnsOverHttpPort", int.Parse, out int dnsOverHttpPort))
            {
                if (_dnsWebService.DnsServer.DnsOverHttpPort != dnsOverHttpPort)
                {
                    _dnsWebService.DnsServer.DnsOverHttpPort = dnsOverHttpPort;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("dnsOverTlsPort", int.Parse, out int dnsOverTlsPort))
            {
                if (_dnsWebService.DnsServer.DnsOverTlsPort != dnsOverTlsPort)
                {
                    _dnsWebService.DnsServer.DnsOverTlsPort = dnsOverTlsPort;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("dnsOverHttpsPort", int.Parse, out int dnsOverHttpsPort))
            {
                if (_dnsWebService.DnsServer.DnsOverHttpsPort != dnsOverHttpsPort)
                {
                    _dnsWebService.DnsServer.DnsOverHttpsPort = dnsOverHttpsPort;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQueryOrForm("dnsOverQuicPort", int.Parse, out int dnsOverQuicPort))
            {
                if (_dnsWebService.DnsServer.DnsOverQuicPort != dnsOverQuicPort)
                {
                    _dnsWebService.DnsServer.DnsOverQuicPort = dnsOverQuicPort;
                    restartDnsService = true;
                }
            }

            string dnsTlsCertificatePath = request.QueryOrForm("dnsTlsCertificatePath");
            if (dnsTlsCertificatePath is not null)
            {
                if (dnsTlsCertificatePath.Length == 0)
                {
                    if (!string.IsNullOrEmpty(_dnsWebService._dnsTlsCertificatePath) && (_dnsWebService.DnsServer.EnableDnsOverTls || _dnsWebService.DnsServer.EnableDnsOverHttps || _dnsWebService.DnsServer.EnableDnsOverQuic))
                        restartDnsService = true;

                    _dnsWebService.DnsServer.CertificateCollection = null;
                    _dnsWebService._dnsTlsCertificatePath = null;
                    _dnsWebService._dnsTlsCertificatePassword = "";
                }
                else
                {
                    string strDnsTlsCertificatePassword = request.QueryOrForm("dnsTlsCertificatePassword");

                    if ((strDnsTlsCertificatePassword is null) || (strDnsTlsCertificatePassword == "************"))
                        strDnsTlsCertificatePassword = _dnsWebService._dnsTlsCertificatePassword;

                    if ((dnsTlsCertificatePath != _dnsWebService._dnsTlsCertificatePath) || (strDnsTlsCertificatePassword != _dnsWebService._dnsTlsCertificatePassword))
                    {
                        _dnsWebService.LoadDnsTlsCertificate(_dnsWebService.ConvertToAbsolutePath(dnsTlsCertificatePath), strDnsTlsCertificatePassword);

                        if (string.IsNullOrEmpty(_dnsWebService._dnsTlsCertificatePath) && (_dnsWebService.DnsServer.EnableDnsOverTls || _dnsWebService.DnsServer.EnableDnsOverHttps || _dnsWebService.DnsServer.EnableDnsOverQuic))
                            restartDnsService = true;

                        _dnsWebService._dnsTlsCertificatePath = _dnsWebService.ConvertToRelativePath(dnsTlsCertificatePath);
                        _dnsWebService._dnsTlsCertificatePassword = strDnsTlsCertificatePassword;

                        _dnsWebService.StartTlsCertificateUpdateTimer();
                    }
                }
            }

            //tsig
            string strTsigKeys = request.QueryOrForm("tsigKeys");
            if (strTsigKeys is not null)
            {
                if ((strTsigKeys.Length == 0) || strTsigKeys.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    _dnsWebService.DnsServer.TsigKeys = null;
                }
                else
                {
                    string[] strTsigKeyParts = strTsigKeys.Split('|');
                    Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(strTsigKeyParts.Length);

                    for (int i = 0; i < strTsigKeyParts.Length; i += 3)
                    {
                        string keyName = strTsigKeyParts[i + 0].TrimEnd('.').ToLowerInvariant();
                        string sharedSecret = strTsigKeyParts[i + 1];
                        string algorithmName = strTsigKeyParts[i + 2];

                        if (DnsClient.IsDomainNameUnicode(keyName))
                            keyName = DnsClient.ConvertDomainNameToAscii(keyName);

                        DnsClient.IsDomainNameValid(keyName, true);

                        if (sharedSecret.Length == 0)
                            tsigKeys.Add(keyName, new TsigKey(keyName, algorithmName));
                        else
                            tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, algorithmName));
                    }

                    _dnsWebService.DnsServer.TsigKeys = tsigKeys;
                }
            }

            //recursion
            if (request.TryGetQueryOrFormEnum("recursion", out DnsServerRecursion recursion))
                _dnsWebService.DnsServer.Recursion = recursion;

            string recursionNetworkACL = request.QueryOrForm("recursionNetworkACL");
            if (recursionNetworkACL is not null)
            {
                if ((recursionNetworkACL.Length == 0) || recursionNetworkACL.Equals("false", StringComparison.OrdinalIgnoreCase))
                    _dnsWebService.DnsServer.RecursionNetworkACL = null;
                else
                    _dnsWebService.DnsServer.RecursionNetworkACL = recursionNetworkACL.Split(NetworkAccessControl.Parse, ',');
            }

            if (request.TryGetQueryOrForm("randomizeName", bool.Parse, out bool randomizeName))
                _dnsWebService.DnsServer.RandomizeName = randomizeName;

            if (request.TryGetQueryOrForm("qnameMinimization", bool.Parse, out bool qnameMinimization))
                _dnsWebService.DnsServer.QnameMinimization = qnameMinimization;

            if (request.TryGetQueryOrForm("nsRevalidation", bool.Parse, out bool nsRevalidation))
                _dnsWebService.DnsServer.NsRevalidation = nsRevalidation;

            if (request.TryGetQueryOrForm("resolverRetries", int.Parse, out int resolverRetries))
                _dnsWebService.DnsServer.ResolverRetries = resolverRetries;

            if (request.TryGetQueryOrForm("resolverTimeout", int.Parse, out int resolverTimeout))
                _dnsWebService.DnsServer.ResolverTimeout = resolverTimeout;

            if (request.TryGetQueryOrForm("resolverConcurrency", int.Parse, out int resolverConcurrency))
                _dnsWebService.DnsServer.ResolverConcurrency = resolverConcurrency;

            if (request.TryGetQueryOrForm("resolverMaxStackCount", int.Parse, out int resolverMaxStackCount))
                _dnsWebService.DnsServer.ResolverMaxStackCount = resolverMaxStackCount;

            //cache
            if (request.TryGetQueryOrForm("saveCache", bool.Parse, out bool saveCache))
            {
                if (!saveCache)
                    _dnsWebService.DnsServer.CacheZoneManager.DeleteCacheZoneFile();

                _dnsWebService._saveCache = saveCache;
            }

            if (request.TryGetQueryOrForm("serveStale", bool.Parse, out bool serveStale))
                _dnsWebService.DnsServer.ServeStale = serveStale;

            if (request.TryGetQueryOrForm("serveStaleTtl", uint.Parse, out uint serveStaleTtl))
                _dnsWebService.DnsServer.CacheZoneManager.ServeStaleTtl = serveStaleTtl;

            if (request.TryGetQueryOrForm("serveStaleAnswerTtl", uint.Parse, out uint serveStaleAnswerTtl))
                _dnsWebService.DnsServer.CacheZoneManager.ServeStaleAnswerTtl = serveStaleAnswerTtl;

            if (request.TryGetQueryOrForm("serveStaleResetTtl", uint.Parse, out uint serveStaleResetTtl))
                _dnsWebService.DnsServer.CacheZoneManager.ServeStaleResetTtl = serveStaleResetTtl;

            if (request.TryGetQueryOrForm("serveStaleMaxWaitTime", int.Parse, out int serveStaleMaxWaitTime))
                _dnsWebService.DnsServer.ServeStaleMaxWaitTime = serveStaleMaxWaitTime;

            if (request.TryGetQueryOrForm("cacheMaximumEntries", long.Parse, out long cacheMaximumEntries))
                _dnsWebService.DnsServer.CacheZoneManager.MaximumEntries = cacheMaximumEntries;

            if (request.TryGetQueryOrForm("cacheMinimumRecordTtl", uint.Parse, out uint cacheMinimumRecordTtl))
                _dnsWebService.DnsServer.CacheZoneManager.MinimumRecordTtl = cacheMinimumRecordTtl;

            if (request.TryGetQueryOrForm("cacheMaximumRecordTtl", uint.Parse, out uint cacheMaximumRecordTtl))
                _dnsWebService.DnsServer.CacheZoneManager.MaximumRecordTtl = cacheMaximumRecordTtl;

            if (request.TryGetQueryOrForm("cacheNegativeRecordTtl", uint.Parse, out uint cacheNegativeRecordTtl))
                _dnsWebService.DnsServer.CacheZoneManager.NegativeRecordTtl = cacheNegativeRecordTtl;

            if (request.TryGetQueryOrForm("cacheFailureRecordTtl", uint.Parse, out uint cacheFailureRecordTtl))
                _dnsWebService.DnsServer.CacheZoneManager.FailureRecordTtl = cacheFailureRecordTtl;

            if (request.TryGetQueryOrForm("cachePrefetchEligibility", int.Parse, out int cachePrefetchEligibility))
                _dnsWebService.DnsServer.CachePrefetchEligibility = cachePrefetchEligibility;

            if (request.TryGetQueryOrForm("cachePrefetchTrigger", int.Parse, out int cachePrefetchTrigger))
                _dnsWebService.DnsServer.CachePrefetchTrigger = cachePrefetchTrigger;

            if (request.TryGetQueryOrForm("cachePrefetchSampleIntervalInMinutes", int.Parse, out int cachePrefetchSampleIntervalInMinutes))
                _dnsWebService.DnsServer.CachePrefetchSampleIntervalInMinutes = cachePrefetchSampleIntervalInMinutes;

            if (request.TryGetQueryOrForm("cachePrefetchSampleEligibilityHitsPerHour", int.Parse, out int cachePrefetchSampleEligibilityHitsPerHour))
                _dnsWebService.DnsServer.CachePrefetchSampleEligibilityHitsPerHour = cachePrefetchSampleEligibilityHitsPerHour;

            //blocking
            if (request.TryGetQueryOrForm("enableBlocking", bool.Parse, out bool enableBlocking))
            {
                _dnsWebService.DnsServer.EnableBlocking = enableBlocking;
                if (_dnsWebService.DnsServer.EnableBlocking)
                {
                    if (_temporaryDisableBlockingTimer is not null)
                        _temporaryDisableBlockingTimer.Dispose();
                }
            }

            if (request.TryGetQueryOrForm("allowTxtBlockingReport", bool.Parse, out bool allowTxtBlockingReport))
                _dnsWebService.DnsServer.AllowTxtBlockingReport = allowTxtBlockingReport;

            string blockingBypassList = request.QueryOrForm("blockingBypassList");
            if (blockingBypassList is not null)
                _dnsWebService.DnsServer.BlockingBypassList = ParseNetworkAddresses(blockingBypassList);

            if (request.TryGetQueryOrFormEnum("blockingType", out DnsServerBlockingType blockingType))
                _dnsWebService.DnsServer.BlockingType = blockingType;

            string customBlockingAddresses = request.QueryOrForm("customBlockingAddresses");
            if (customBlockingAddresses is not null)
            {
                if ((customBlockingAddresses.Length == 0) || customBlockingAddresses.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    _dnsWebService.DnsServer.CustomBlockingARecords = null;
                    _dnsWebService.DnsServer.CustomBlockingAAAARecords = null;
                }
                else
                {
                    string[] strAddresses = customBlockingAddresses.Split(_commaSeparator, StringSplitOptions.RemoveEmptyEntries);

                    List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                    List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

                    foreach (string strAddress in strAddresses)
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

                    _dnsWebService.DnsServer.CustomBlockingARecords = dnsARecords;
                    _dnsWebService.DnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                }
            }

            string blockListUrls = request.QueryOrForm("blockListUrls");
            if (blockListUrls is not null)
            {
                if ((blockListUrls.Length == 0) || blockListUrls.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    _dnsWebService.DnsServer.BlockListZoneManager.AllowListUrls.Clear();
                    _dnsWebService.DnsServer.BlockListZoneManager.BlockListUrls.Clear();
                    _dnsWebService.DnsServer.BlockListZoneManager.Flush();
                }
                else
                {
                    string[] blockListUrlList = blockListUrls.Split(_commaSeparator, StringSplitOptions.RemoveEmptyEntries);

                    if (oldWebServiceHttpPort != _dnsWebService._webServiceHttpPort)
                    {
                        for (int i = 0; i < blockListUrlList.Length; i++)
                        {
                            if (blockListUrlList[i].Contains("http://localhost:" + oldWebServiceHttpPort + "/blocklist.txt"))
                            {
                                blockListUrlList[i] = "http://localhost:" + _dnsWebService._webServiceHttpPort + "/blocklist.txt";
                                blockListUrlsUpdated = true;
                                break;
                            }
                        }
                    }

                    if (!blockListUrlsUpdated)
                    {
                        if (blockListUrlList.Length != (_dnsWebService.DnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsWebService.DnsServer.BlockListZoneManager.BlockListUrls.Count))
                        {
                            blockListUrlsUpdated = true;
                        }
                        else
                        {
                            foreach (string strBlockListUrl in blockListUrlList)
                            {
                                if (strBlockListUrl.StartsWith('!'))
                                {
                                    string strAllowListUrl = strBlockListUrl.Substring(1);

                                    if (!_dnsWebService.DnsServer.BlockListZoneManager.AllowListUrls.Contains(new Uri(strAllowListUrl)))
                                    {
                                        blockListUrlsUpdated = true;
                                        break;
                                    }
                                }
                                else
                                {
                                    if (!_dnsWebService.DnsServer.BlockListZoneManager.BlockListUrls.Contains(new Uri(strBlockListUrl)))
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
                        _dnsWebService.DnsServer.BlockListZoneManager.AllowListUrls.Clear();
                        _dnsWebService.DnsServer.BlockListZoneManager.BlockListUrls.Clear();

                        foreach (string strBlockListUrl in blockListUrlList)
                        {
                            if (strBlockListUrl.StartsWith('!'))
                            {
                                Uri allowListUrl = new Uri(strBlockListUrl.Substring(1));

                                if (!_dnsWebService.DnsServer.BlockListZoneManager.AllowListUrls.Contains(allowListUrl))
                                    _dnsWebService.DnsServer.BlockListZoneManager.AllowListUrls.Add(allowListUrl);
                            }
                            else
                            {
                                Uri blockListUrl = new Uri(strBlockListUrl);

                                if (!_dnsWebService.DnsServer.BlockListZoneManager.BlockListUrls.Contains(blockListUrl))
                                    _dnsWebService.DnsServer.BlockListZoneManager.BlockListUrls.Add(blockListUrl);
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

            //proxy & forwarders
            if (request.TryGetQueryOrFormEnum("proxyType", out NetProxyType proxyType))
            {
                if (proxyType == NetProxyType.None)
                {
                    _dnsWebService.DnsServer.Proxy = null;
                }
                else
                {
                    NetworkCredential credential = null;

                    if (request.TryGetQueryOrForm("proxyUsername", out string proxyUsername))
                        credential = new NetworkCredential(proxyUsername, request.QueryOrForm("proxyPassword"));

                    _dnsWebService.DnsServer.Proxy = NetProxy.CreateProxy(proxyType, request.QueryOrForm("proxyAddress"), int.Parse(request.QueryOrForm("proxyPort")), credential);

                    if (request.TryGetQueryOrForm("proxyBypass", out string proxyBypass))
                        _dnsWebService.DnsServer.Proxy.BypassList = proxyBypass.Split(delegate (string value) { return new NetProxyBypassItem(value); }, ',');
                }
            }

            string strForwarders = request.QueryOrForm("forwarders");
            if (strForwarders is not null)
            {
                if ((strForwarders.Length == 0) || strForwarders.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    _dnsWebService.DnsServer.Forwarders = null;
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

                    NameServerAddress[] forwarders = strForwarders.Split(delegate (string value)
                    {
                        NameServerAddress forwarder = NameServerAddress.Parse(value);

                        if (forwarder.Protocol != forwarderProtocol)
                            forwarder = forwarder.ChangeProtocol(forwarderProtocol);

                        return forwarder;
                    }, ',');

                    if (!_dnsWebService.DnsServer.Forwarders.ListEquals(forwarders))
                        _dnsWebService.DnsServer.Forwarders = forwarders;
                }
            }

            if (request.TryGetQueryOrForm("concurrentForwarding", bool.Parse, out bool concurrentForwarding))
                _dnsWebService.DnsServer.ConcurrentForwarding = concurrentForwarding;

            if (request.TryGetQueryOrForm("forwarderRetries", int.Parse, out int forwarderRetries))
                _dnsWebService.DnsServer.ForwarderRetries = forwarderRetries;

            if (request.TryGetQueryOrForm("forwarderTimeout", int.Parse, out int forwarderTimeout))
                _dnsWebService.DnsServer.ForwarderTimeout = forwarderTimeout;

            if (request.TryGetQueryOrForm("forwarderConcurrency", int.Parse, out int forwarderConcurrency))
                _dnsWebService.DnsServer.ForwarderConcurrency = forwarderConcurrency;

            //logging
            if (request.TryGetQueryOrForm("enableLogging", bool.Parse, out bool enableLogging))
                _dnsWebService._log.EnableLogging = enableLogging;

            if (request.TryGetQueryOrForm("ignoreResolverLogs", bool.Parse, out bool ignoreResolverLogs))
                _dnsWebService.DnsServer.ResolverLogManager = ignoreResolverLogs ? null : _dnsWebService._log;

            if (request.TryGetQueryOrForm("logQueries", bool.Parse, out bool logQueries))
                _dnsWebService.DnsServer.QueryLogManager = logQueries ? _dnsWebService._log : null;

            if (request.TryGetQueryOrForm("useLocalTime", bool.Parse, out bool useLocalTime))
                _dnsWebService._log.UseLocalTime = useLocalTime;

            if (request.TryGetQueryOrForm("logFolder", out string logFolder))
                _dnsWebService._log.LogFolder = logFolder;

            if (request.TryGetQueryOrForm("maxLogFileDays", int.Parse, out int maxLogFileDays))
                _dnsWebService._log.MaxLogFileDays = maxLogFileDays;

            if (request.TryGetQueryOrForm("enableInMemoryStats", bool.Parse, out bool enableInMemoryStats))
                _dnsWebService.DnsServer.StatsManager.EnableInMemoryStats = enableInMemoryStats;

            if (request.TryGetQueryOrForm("maxStatFileDays", int.Parse, out int maxStatFileDays))
                _dnsWebService.DnsServer.StatsManager.MaxStatFileDays = maxStatFileDays;

            //TLS actions
            if ((_dnsWebService._webServiceTlsCertificatePath is null) && (_dnsWebService._dnsTlsCertificatePath is null))
                _dnsWebService.StopTlsCertificateUpdateTimer();

            _dnsWebService.SelfSignedCertCheck(serverDomainChanged, true);

            if (_dnsWebService._webServiceEnableTls && string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath) && !_dnsWebService._webServiceUseSelfSignedTlsCertificate)
            {
                //disable TLS
                _dnsWebService._webServiceEnableTls = false;
                restartWebService = true;
            }

            //blocklist timers
            if ((_blockListUpdateIntervalHours > 0) && ((_dnsWebService.DnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsWebService.DnsServer.BlockListZoneManager.BlockListUrls.Count) > 0))
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

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] DNS Settings were updated successfully.");

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

                if (_dnsWebService.DnsServer.TsigKeys is not null)
                {
                    foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsWebService.DnsServer.TsigKeys)
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
                    response.Headers.ContentDisposition = "attachment;filename=" + _dnsWebService.DnsServer.ServerDomain + DateTime.UtcNow.ToString("_yyyy-MM-dd_HH-mm-ss") + "_backup.zip";

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

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Settings backup zip file was exported.");
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
                                _dnsWebService.DnsServer.AuthZoneManager.Flush();

                            if (allowedZones)
                                _dnsWebService.DnsServer.AllowedZoneManager.Flush();

                            if (blockedZones)
                                _dnsWebService.DnsServer.BlockedZoneManager.Flush();

                            //reload settings and block list zone
                            _dnsWebService.LoadConfigFile();

                            if ((_dnsWebService.DnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsWebService.DnsServer.BlockListZoneManager.BlockListUrls.Count) > 0)
                            {
                                ThreadPool.QueueUserWorkItem(delegate (object state)
                                {
                                    try
                                    {
                                        _dnsWebService.DnsServer.BlockListZoneManager.LoadBlockLists();
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
                                _dnsWebService.DnsServer.BlockListZoneManager.Flush();

                                StopBlockListUpdateTimer();
                            }
                        }

                        if (apps)
                        {
                            //unload apps
                            _dnsWebService.DnsServer.DnsApplicationManager.UnloadAllApplications();

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
                            _dnsWebService.DnsServer.DnsApplicationManager.LoadAllApplications();
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
                            _dnsWebService.DnsServer.AuthZoneManager.LoadAllZoneFiles();
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
                            _dnsWebService.DnsServer.AllowedZoneManager.LoadAllowedZoneFile();
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
                            _dnsWebService.DnsServer.BlockedZoneManager.LoadBlockedZoneFile();
                        }

                        if (scopes)
                        {
                            //stop dhcp server
                            _dnsWebService.DhcpServer.Stop();

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
                                _dnsWebService.DhcpServer.Start();
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
                            _dnsWebService.DnsServer.StatsManager.ReloadStats();
                        }

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Settings backup zip file was restored.");
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
            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Block list update was triggered.");
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
                    _dnsWebService.DnsServer.EnableBlocking = true;
                    _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Blocking was enabled after " + minutes + " minute(s) being temporarily disabled.");
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
                _dnsWebService.DnsServer.EnableBlocking = false;
                _temporaryDisableBlockingTill = DateTime.UtcNow.AddMinutes(minutes);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Blocking was temporarily disabled for " + minutes + " minute(s).");
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
