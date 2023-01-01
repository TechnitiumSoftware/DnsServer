/*
Technitium DNS Server
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    sealed class WebServiceSettingsApi : IDisposable
    {
        #region variables

        readonly static RandomNumberGenerator _rng = RandomNumberGenerator.Create();

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

        private void ForceUpdateBlockLists()
        {
            Task.Run(async delegate ()
            {
                if (await _dnsWebService._dnsServer.BlockListZoneManager.UpdateBlockListsAsync())
                {
                    //block lists were updated
                    //save last updated on time
                    _blockListLastUpdatedOn = DateTime.UtcNow;
                    _dnsWebService.SaveConfigFile();
                }
            });
        }

        public void StartBlockListUpdateTimer()
        {
            if (_blockListUpdateTimer is null)
            {
                _blockListUpdateTimer = new Timer(async delegate (object state)
                {
                    try
                    {
                        if (DateTime.UtcNow > _blockListLastUpdatedOn.AddHours(_blockListUpdateIntervalHours))
                        {
                            if (await _dnsWebService._dnsServer.BlockListZoneManager.UpdateBlockListsAsync())
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

        private void RestartService(bool restartDnsService, bool restartWebService)
        {
            if (restartDnsService)
            {
                _ = Task.Run(delegate ()
                {
                    _dnsWebService._log.Write("Attempting to restart DNS service.");

                    try
                    {
                        _dnsWebService._dnsServer.Stop();
                        _dnsWebService._dnsServer.Start();

                        _dnsWebService._log.Write("DNS service was restarted successfully.");
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService._log.Write("Failed to restart DNS service.");
                        _dnsWebService._log.Write(ex);
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
                        await _dnsWebService.StartWebServiceAsync();

                        _dnsWebService._log.Write("Web service was restarted successfully.");
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService._log.Write("Failed to restart web service.");
                        _dnsWebService._log.Write(ex);
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
            jsonWriter.WriteString("dnsServerDomain", _dnsWebService._dnsServer.ServerDomain);

            jsonWriter.WritePropertyName("dnsServerLocalEndPoints");
            jsonWriter.WriteStartArray();

            foreach (IPEndPoint localEP in _dnsWebService._dnsServer.LocalEndPoints)
                jsonWriter.WriteStringValue(localEP.ToString());

            jsonWriter.WriteEndArray();

            jsonWriter.WriteNumber("defaultRecordTtl", _dnsWebService._zonesApi.DefaultRecordTtl);
            jsonWriter.WriteBoolean("dnsAppsEnableAutomaticUpdate", _dnsWebService._appsApi.EnableAutomaticUpdate);

            jsonWriter.WriteBoolean("preferIPv6", _dnsWebService._dnsServer.PreferIPv6);

            jsonWriter.WriteNumber("udpPayloadSize", _dnsWebService._dnsServer.UdpPayloadSize);

            jsonWriter.WriteBoolean("dnssecValidation", _dnsWebService._dnsServer.DnssecValidation);

            jsonWriter.WriteBoolean("eDnsClientSubnet", _dnsWebService._dnsServer.EDnsClientSubnet);
            jsonWriter.WriteNumber("eDnsClientSubnetIPv4PrefixLength", _dnsWebService._dnsServer.EDnsClientSubnetIPv4PrefixLength);
            jsonWriter.WriteNumber("eDnsClientSubnetIPv6PrefixLength", _dnsWebService._dnsServer.EDnsClientSubnetIPv6PrefixLength);

            jsonWriter.WriteNumber("qpmLimitRequests", _dnsWebService._dnsServer.QpmLimitRequests);
            jsonWriter.WriteNumber("qpmLimitErrors", _dnsWebService._dnsServer.QpmLimitErrors);
            jsonWriter.WriteNumber("qpmLimitSampleMinutes", _dnsWebService._dnsServer.QpmLimitSampleMinutes);
            jsonWriter.WriteNumber("qpmLimitIPv4PrefixLength", _dnsWebService._dnsServer.QpmLimitIPv4PrefixLength);
            jsonWriter.WriteNumber("qpmLimitIPv6PrefixLength", _dnsWebService._dnsServer.QpmLimitIPv6PrefixLength);

            jsonWriter.WriteNumber("clientTimeout", _dnsWebService._dnsServer.ClientTimeout);
            jsonWriter.WriteNumber("tcpSendTimeout", _dnsWebService._dnsServer.TcpSendTimeout);
            jsonWriter.WriteNumber("tcpReceiveTimeout", _dnsWebService._dnsServer.TcpReceiveTimeout);

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
            jsonWriter.WriteBoolean("webServiceHttpToTlsRedirect", _dnsWebService._webServiceHttpToTlsRedirect);
            jsonWriter.WriteBoolean("webServiceUseSelfSignedTlsCertificate", _dnsWebService._webServiceUseSelfSignedTlsCertificate);
            jsonWriter.WriteNumber("webServiceTlsPort", _dnsWebService._webServiceTlsPort);
            jsonWriter.WriteString("webServiceTlsCertificatePath", _dnsWebService._webServiceTlsCertificatePath);
            jsonWriter.WriteString("webServiceTlsCertificatePassword", "************");

            //optional protocols
            jsonWriter.WriteBoolean("enableDnsOverHttp", _dnsWebService._dnsServer.EnableDnsOverHttp);
            jsonWriter.WriteBoolean("enableDnsOverTls", _dnsWebService._dnsServer.EnableDnsOverTls);
            jsonWriter.WriteBoolean("enableDnsOverHttps", _dnsWebService._dnsServer.EnableDnsOverHttps);
            jsonWriter.WriteString("dnsTlsCertificatePath", _dnsWebService._dnsTlsCertificatePath);
            jsonWriter.WriteString("dnsTlsCertificatePassword", "************");

            //tsig
            jsonWriter.WritePropertyName("tsigKeys");
            {
                jsonWriter.WriteStartArray();

                if (_dnsWebService._dnsServer.TsigKeys is not null)
                {
                    foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsWebService._dnsServer.TsigKeys)
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

            jsonWriter.WritePropertyName("recursionDeniedNetworks");
            {
                jsonWriter.WriteStartArray();

                if (_dnsWebService._dnsServer.RecursionDeniedNetworks is not null)
                {
                    foreach (NetworkAddress networkAddress in _dnsWebService._dnsServer.RecursionDeniedNetworks)
                        jsonWriter.WriteStringValue(networkAddress.ToString());
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("recursionAllowedNetworks");
            {
                jsonWriter.WriteStartArray();

                if (_dnsWebService._dnsServer.RecursionAllowedNetworks is not null)
                {
                    foreach (NetworkAddress networkAddress in _dnsWebService._dnsServer.RecursionAllowedNetworks)
                        jsonWriter.WriteStringValue(networkAddress.ToString());
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WriteBoolean("randomizeName", _dnsWebService._dnsServer.RandomizeName);
            jsonWriter.WriteBoolean("qnameMinimization", _dnsWebService._dnsServer.QnameMinimization);
            jsonWriter.WriteBoolean("nsRevalidation", _dnsWebService._dnsServer.NsRevalidation);

            jsonWriter.WriteNumber("resolverRetries", _dnsWebService._dnsServer.ResolverRetries);
            jsonWriter.WriteNumber("resolverTimeout", _dnsWebService._dnsServer.ResolverTimeout);
            jsonWriter.WriteNumber("resolverMaxStackCount", _dnsWebService._dnsServer.ResolverMaxStackCount);

            //cache
            jsonWriter.WriteBoolean("serveStale", _dnsWebService._dnsServer.ServeStale);
            jsonWriter.WriteNumber("serveStaleTtl", _dnsWebService._dnsServer.CacheZoneManager.ServeStaleTtl);

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

            if (!_dnsWebService._dnsServer.EnableBlocking && (DateTime.UtcNow < _temporaryDisableBlockingTill))
                jsonWriter.WriteString("temporaryDisableBlockingTill", _temporaryDisableBlockingTill);

            jsonWriter.WriteString("blockingType", _dnsWebService._dnsServer.BlockingType.ToString());

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

            jsonWriter.WriteNumber("forwarderRetries", _dnsWebService._dnsServer.ForwarderRetries);
            jsonWriter.WriteNumber("forwarderTimeout", _dnsWebService._dnsServer.ForwarderTimeout);
            jsonWriter.WriteNumber("forwarderConcurrency", _dnsWebService._dnsServer.ForwarderConcurrency);

            //logging
            jsonWriter.WriteBoolean("enableLogging", _dnsWebService._log.EnableLogging);
            jsonWriter.WriteBoolean("logQueries", _dnsWebService._dnsServer.QueryLogManager != null);
            jsonWriter.WriteBoolean("useLocalTime", _dnsWebService._log.UseLocalTime);
            jsonWriter.WriteString("logFolder", _dnsWebService._log.LogFolder);
            jsonWriter.WriteNumber("maxLogFileDays", _dnsWebService._log.MaxLogFileDays);
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

        public void SetDnsSettings(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            bool serverDomainChanged = false;
            bool restartDnsService = false;
            bool restartWebService = false;
            bool blockListUrlsUpdated = false;
            int oldWebServiceHttpPort = _dnsWebService._webServiceHttpPort;

            HttpRequest request = context.Request;

            //general
            if (request.TryGetQuery("dnsServerDomain", out string dnsServerDomain))
            {
                if (!_dnsWebService._dnsServer.ServerDomain.Equals(dnsServerDomain, StringComparison.OrdinalIgnoreCase))
                {
                    _dnsWebService._dnsServer.ServerDomain = dnsServerDomain;
                    serverDomainChanged = true;
                }
            }

            string dnsServerLocalEndPoints = request.Query["dnsServerLocalEndPoints"];
            if (dnsServerLocalEndPoints is not null)
            {
                if (dnsServerLocalEndPoints.Length == 0)
                    dnsServerLocalEndPoints = "0.0.0.0:53,[::]:53";

                IPEndPoint[] localEndPoints = dnsServerLocalEndPoints.Split(IPEndPoint.Parse, ',');
                if (localEndPoints.Length > 0)
                {
                    if (_dnsWebService._dnsServer.LocalEndPoints.Count != localEndPoints.Length)
                    {
                        restartDnsService = true;
                    }
                    else
                    {
                        foreach (IPEndPoint currentLocalEP in _dnsWebService._dnsServer.LocalEndPoints)
                        {
                            if (!localEndPoints.Contains(currentLocalEP))
                            {
                                restartDnsService = true;
                                break;
                            }
                        }
                    }

                    _dnsWebService._dnsServer.LocalEndPoints = localEndPoints;
                }
            }

            if (request.TryGetQuery("defaultRecordTtl", uint.Parse, out uint defaultRecordTtl))
                _dnsWebService._zonesApi.DefaultRecordTtl = defaultRecordTtl;

            if (request.TryGetQuery("dnsAppsEnableAutomaticUpdate", bool.Parse, out bool dnsAppsEnableAutomaticUpdate))
                _dnsWebService._appsApi.EnableAutomaticUpdate = dnsAppsEnableAutomaticUpdate;

            if (request.TryGetQuery("preferIPv6", bool.Parse, out bool preferIPv6))
                _dnsWebService._dnsServer.PreferIPv6 = preferIPv6;

            if (request.TryGetQuery("udpPayloadSize", ushort.Parse, out ushort udpPayloadSize))
                _dnsWebService._dnsServer.UdpPayloadSize = udpPayloadSize;

            if (request.TryGetQuery("dnssecValidation", bool.Parse, out bool dnssecValidation))
                _dnsWebService._dnsServer.DnssecValidation = dnssecValidation;

            if (request.TryGetQuery("eDnsClientSubnet", bool.Parse, out bool eDnsClientSubnet))
                _dnsWebService._dnsServer.EDnsClientSubnet = eDnsClientSubnet;

            if (request.TryGetQuery("eDnsClientSubnetIPv4PrefixLength", byte.Parse, out byte eDnsClientSubnetIPv4PrefixLength))
                _dnsWebService._dnsServer.EDnsClientSubnetIPv4PrefixLength = eDnsClientSubnetIPv4PrefixLength;

            if (request.TryGetQuery("eDnsClientSubnetIPv6PrefixLength", byte.Parse, out byte eDnsClientSubnetIPv6PrefixLength))
                _dnsWebService._dnsServer.EDnsClientSubnetIPv6PrefixLength = eDnsClientSubnetIPv6PrefixLength;

            if (request.TryGetQuery("qpmLimitRequests", int.Parse, out int qpmLimitRequests))
                _dnsWebService._dnsServer.QpmLimitRequests = qpmLimitRequests;

            if (request.TryGetQuery("qpmLimitErrors", int.Parse, out int qpmLimitErrors))
                _dnsWebService._dnsServer.QpmLimitErrors = qpmLimitErrors;

            if (request.TryGetQuery("qpmLimitSampleMinutes", int.Parse, out int qpmLimitSampleMinutes))
                _dnsWebService._dnsServer.QpmLimitSampleMinutes = qpmLimitSampleMinutes;

            if (request.TryGetQuery("qpmLimitIPv4PrefixLength", int.Parse, out int qpmLimitIPv4PrefixLength))
                _dnsWebService._dnsServer.QpmLimitIPv4PrefixLength = qpmLimitIPv4PrefixLength;

            if (request.TryGetQuery("qpmLimitIPv6PrefixLength", int.Parse, out int qpmLimitIPv6PrefixLength))
                _dnsWebService._dnsServer.QpmLimitIPv6PrefixLength = qpmLimitIPv6PrefixLength;

            if (request.TryGetQuery("clientTimeout", int.Parse, out int clientTimeout))
                _dnsWebService._dnsServer.ClientTimeout = clientTimeout;

            if (request.TryGetQuery("tcpSendTimeout", int.Parse, out int tcpSendTimeout))
                _dnsWebService._dnsServer.TcpSendTimeout = tcpSendTimeout;

            if (request.TryGetQuery("tcpReceiveTimeout", int.Parse, out int tcpReceiveTimeout))
                _dnsWebService._dnsServer.TcpReceiveTimeout = tcpReceiveTimeout;

            //web service
            string webServiceLocalAddresses = request.Query["webServiceLocalAddresses"];
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

                    _dnsWebService._webServiceLocalAddresses = localAddresses;
                }
            }

            if (request.TryGetQuery("webServiceHttpPort", int.Parse, out int webServiceHttpPort))
            {
                if (_dnsWebService._webServiceHttpPort != webServiceHttpPort)
                {
                    _dnsWebService._webServiceHttpPort = webServiceHttpPort;
                    restartWebService = true;
                }
            }

            if (request.TryGetQuery("webServiceEnableTls", bool.Parse, out bool webServiceEnableTls))
            {
                if (_dnsWebService._webServiceEnableTls != webServiceEnableTls)
                {
                    _dnsWebService._webServiceEnableTls = webServiceEnableTls;
                    restartWebService = true;
                }
            }

            if (request.TryGetQuery("webServiceHttpToTlsRedirect", bool.Parse, out bool webServiceHttpToTlsRedirect))
            {
                if (_dnsWebService._webServiceHttpToTlsRedirect != webServiceHttpToTlsRedirect)
                {
                    _dnsWebService._webServiceHttpToTlsRedirect = webServiceHttpToTlsRedirect;
                    restartWebService = true;
                }
            }

            if (request.TryGetQuery("webServiceUseSelfSignedTlsCertificate", bool.Parse, out bool webServiceUseSelfSignedTlsCertificate))
                _dnsWebService._webServiceUseSelfSignedTlsCertificate = webServiceUseSelfSignedTlsCertificate;

            if (request.TryGetQuery("webServiceTlsPort", int.Parse, out int webServiceTlsPort))
            {
                if (_dnsWebService._webServiceTlsPort != webServiceTlsPort)
                {
                    _dnsWebService._webServiceTlsPort = webServiceTlsPort;
                    restartWebService = true;
                }
            }

            string webServiceTlsCertificatePath = request.Query["webServiceTlsCertificatePath"];
            if (webServiceTlsCertificatePath is not null)
            {
                if (webServiceTlsCertificatePath.Length == 0)
                {
                    _dnsWebService._webServiceTlsCertificatePath = null;
                    _dnsWebService._webServiceTlsCertificatePassword = "";
                }
                else
                {
                    string webServiceTlsCertificatePassword = request.Query["webServiceTlsCertificatePassword"];

                    if ((webServiceTlsCertificatePassword is null) || (webServiceTlsCertificatePassword == "************"))
                        webServiceTlsCertificatePassword = _dnsWebService._webServiceTlsCertificatePassword;

                    if ((webServiceTlsCertificatePath != _dnsWebService._webServiceTlsCertificatePath) || (webServiceTlsCertificatePassword != _dnsWebService._webServiceTlsCertificatePassword))
                    {
                        _dnsWebService.LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, webServiceTlsCertificatePassword);

                        _dnsWebService._webServiceTlsCertificatePath = webServiceTlsCertificatePath;
                        _dnsWebService._webServiceTlsCertificatePassword = webServiceTlsCertificatePassword;

                        _dnsWebService.StartTlsCertificateUpdateTimer();
                    }
                }
            }

            //optional protocols
            if (request.TryGetQuery("enableDnsOverHttp", bool.Parse, out bool enableDnsOverHttp))
            {
                if (_dnsWebService._dnsServer.EnableDnsOverHttp != enableDnsOverHttp)
                {
                    _dnsWebService._dnsServer.EnableDnsOverHttp = enableDnsOverHttp;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQuery("enableDnsOverTls", bool.Parse, out bool enableDnsOverTls))
            {
                if (_dnsWebService._dnsServer.EnableDnsOverTls != enableDnsOverTls)
                {
                    _dnsWebService._dnsServer.EnableDnsOverTls = enableDnsOverTls;
                    restartDnsService = true;
                }
            }

            if (request.TryGetQuery("enableDnsOverHttps", bool.Parse, out bool enableDnsOverHttps))
            {
                if (_dnsWebService._dnsServer.EnableDnsOverHttps != enableDnsOverHttps)
                {
                    _dnsWebService._dnsServer.EnableDnsOverHttps = enableDnsOverHttps;
                    restartDnsService = true;
                }
            }

            string dnsTlsCertificatePath = request.Query["dnsTlsCertificatePath"];
            if (dnsTlsCertificatePath is not null)
            {
                if (dnsTlsCertificatePath.Length == 0)
                {
                    _dnsWebService._dnsTlsCertificatePath = null;
                    _dnsWebService._dnsTlsCertificatePassword = "";
                }
                else
                {
                    string strDnsTlsCertificatePassword = request.Query["dnsTlsCertificatePassword"];

                    if ((strDnsTlsCertificatePassword is null) || (strDnsTlsCertificatePassword == "************"))
                        strDnsTlsCertificatePassword = _dnsWebService._dnsTlsCertificatePassword;

                    if ((dnsTlsCertificatePath != _dnsWebService._dnsTlsCertificatePath) || (strDnsTlsCertificatePassword != _dnsWebService._dnsTlsCertificatePassword))
                    {
                        _dnsWebService.LoadDnsTlsCertificate(dnsTlsCertificatePath, strDnsTlsCertificatePassword);

                        _dnsWebService._dnsTlsCertificatePath = dnsTlsCertificatePath;
                        _dnsWebService._dnsTlsCertificatePassword = strDnsTlsCertificatePassword;

                        _dnsWebService.StartTlsCertificateUpdateTimer();
                    }
                }
            }

            //tsig
            string strTsigKeys = request.Query["tsigKeys"];
            if (strTsigKeys is not null)
            {
                if ((strTsigKeys.Length == 0) || strTsigKeys.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    _dnsWebService._dnsServer.TsigKeys = null;
                }
                else
                {
                    string[] strTsigKeyParts = strTsigKeys.Split('|');
                    Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(strTsigKeyParts.Length);

                    for (int i = 0; i < strTsigKeyParts.Length; i += 3)
                    {
                        string keyName = strTsigKeyParts[i + 0].ToLower();
                        string sharedSecret = strTsigKeyParts[i + 1];
                        string algorithmName = strTsigKeyParts[i + 2];

                        if (sharedSecret.Length == 0)
                        {
                            byte[] key = new byte[32];
                            _rng.GetBytes(key);

                            tsigKeys.Add(keyName, new TsigKey(keyName, Convert.ToBase64String(key), algorithmName));
                        }
                        else
                        {
                            tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, algorithmName));
                        }
                    }

                    _dnsWebService._dnsServer.TsigKeys = tsigKeys;
                }
            }

            //recursion
            if (request.TryGetQuery("recursion", out DnsServerRecursion recursion))
                _dnsWebService._dnsServer.Recursion = recursion;

            string recursionDeniedNetworks = request.Query["recursionDeniedNetworks"];
            if (recursionDeniedNetworks is not null)
            {
                if ((recursionDeniedNetworks.Length == 0) || recursionDeniedNetworks.Equals("false", StringComparison.OrdinalIgnoreCase))
                    _dnsWebService._dnsServer.RecursionDeniedNetworks = null;
                else
                    _dnsWebService._dnsServer.RecursionDeniedNetworks = recursionDeniedNetworks.Split(NetworkAddress.Parse, ',');
            }

            string recursionAllowedNetworks = request.Query["recursionAllowedNetworks"];
            if (recursionAllowedNetworks is not null)
            {
                if ((recursionAllowedNetworks.Length == 0) || recursionAllowedNetworks.Equals("false", StringComparison.OrdinalIgnoreCase))
                    _dnsWebService._dnsServer.RecursionAllowedNetworks = null;
                else
                    _dnsWebService._dnsServer.RecursionAllowedNetworks = recursionAllowedNetworks.Split(NetworkAddress.Parse, ',');
            }

            if (request.TryGetQuery("randomizeName", bool.Parse, out bool randomizeName))
                _dnsWebService._dnsServer.RandomizeName = randomizeName;

            if (request.TryGetQuery("qnameMinimization", bool.Parse, out bool qnameMinimization))
                _dnsWebService._dnsServer.QnameMinimization = qnameMinimization;

            if (request.TryGetQuery("nsRevalidation", bool.Parse, out bool nsRevalidation))
                _dnsWebService._dnsServer.NsRevalidation = nsRevalidation;

            if (request.TryGetQuery("resolverRetries", int.Parse, out int resolverRetries))
                _dnsWebService._dnsServer.ResolverRetries = resolverRetries;

            if (request.TryGetQuery("resolverTimeout", int.Parse, out int resolverTimeout))
                _dnsWebService._dnsServer.ResolverTimeout = resolverTimeout;

            if (request.TryGetQuery("resolverMaxStackCount", int.Parse, out int resolverMaxStackCount))
                _dnsWebService._dnsServer.ResolverMaxStackCount = resolverMaxStackCount;

            //cache
            if (request.TryGetQuery("serveStale", bool.Parse, out bool serveStale))
                _dnsWebService._dnsServer.ServeStale = serveStale;

            if (request.TryGetQuery("serveStaleTtl", uint.Parse, out uint serveStaleTtl))
                _dnsWebService._dnsServer.CacheZoneManager.ServeStaleTtl = serveStaleTtl;

            if (request.TryGetQuery("cacheMaximumEntries", long.Parse, out long cacheMaximumEntries))
                _dnsWebService._dnsServer.CacheZoneManager.MaximumEntries = cacheMaximumEntries;

            if (request.TryGetQuery("cacheMinimumRecordTtl", uint.Parse, out uint cacheMinimumRecordTtl))
                _dnsWebService._dnsServer.CacheZoneManager.MinimumRecordTtl = cacheMinimumRecordTtl;

            if (request.TryGetQuery("cacheMaximumRecordTtl", uint.Parse, out uint cacheMaximumRecordTtl))
                _dnsWebService._dnsServer.CacheZoneManager.MaximumRecordTtl = cacheMaximumRecordTtl;

            if (request.TryGetQuery("cacheNegativeRecordTtl", uint.Parse, out uint cacheNegativeRecordTtl))
                _dnsWebService._dnsServer.CacheZoneManager.NegativeRecordTtl = cacheNegativeRecordTtl;

            if (request.TryGetQuery("cacheFailureRecordTtl", uint.Parse, out uint cacheFailureRecordTtl))
                _dnsWebService._dnsServer.CacheZoneManager.FailureRecordTtl = cacheFailureRecordTtl;

            if (request.TryGetQuery("cachePrefetchEligibility", int.Parse, out int cachePrefetchEligibility))
                _dnsWebService._dnsServer.CachePrefetchEligibility = cachePrefetchEligibility;

            if (request.TryGetQuery("cachePrefetchTrigger", int.Parse, out int cachePrefetchTrigger))
                _dnsWebService._dnsServer.CachePrefetchTrigger = cachePrefetchTrigger;

            if (request.TryGetQuery("cachePrefetchSampleIntervalInMinutes", int.Parse, out int cachePrefetchSampleIntervalInMinutes))
                _dnsWebService._dnsServer.CachePrefetchSampleIntervalInMinutes = cachePrefetchSampleIntervalInMinutes;

            if (request.TryGetQuery("cachePrefetchSampleEligibilityHitsPerHour", int.Parse, out int cachePrefetchSampleEligibilityHitsPerHour))
                _dnsWebService._dnsServer.CachePrefetchSampleEligibilityHitsPerHour = cachePrefetchSampleEligibilityHitsPerHour;

            //blocking
            if (request.TryGetQuery("enableBlocking", bool.Parse, out bool enableBlocking))
            {
                _dnsWebService._dnsServer.EnableBlocking = enableBlocking;
                if (_dnsWebService._dnsServer.EnableBlocking)
                {
                    if (_temporaryDisableBlockingTimer is not null)
                        _temporaryDisableBlockingTimer.Dispose();
                }
            }

            if (request.TryGetQuery("allowTxtBlockingReport", bool.Parse, out bool allowTxtBlockingReport))
                _dnsWebService._dnsServer.AllowTxtBlockingReport = allowTxtBlockingReport;

            if (request.TryGetQuery("blockingType", out DnsServerBlockingType blockingType))
                _dnsWebService._dnsServer.BlockingType = blockingType;

            string customBlockingAddresses = request.Query["customBlockingAddresses"];
            if (customBlockingAddresses is not null)
            {
                if ((customBlockingAddresses.Length == 0) || customBlockingAddresses.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    _dnsWebService._dnsServer.CustomBlockingARecords = null;
                    _dnsWebService._dnsServer.CustomBlockingAAAARecords = null;
                }
                else
                {
                    string[] strAddresses = customBlockingAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

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

                    _dnsWebService._dnsServer.CustomBlockingARecords = dnsARecords;
                    _dnsWebService._dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                }
            }

            string blockListUrls = request.Query["blockListUrls"];
            if (blockListUrls is not null)
            {
                if ((blockListUrls.Length == 0) || blockListUrls.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    _dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                    _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Clear();
                    _dnsWebService._dnsServer.BlockListZoneManager.Flush();
                }
                else
                {
                    string[] blockListUrlList = blockListUrls.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

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
                        if (blockListUrlList.Length != (_dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Count))
                        {
                            blockListUrlsUpdated = true;
                        }
                        else
                        {
                            foreach (string strBlockListUrl in blockListUrlList)
                            {
                                if (strBlockListUrl.StartsWith("!"))
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

                        foreach (string strBlockListUrl in blockListUrlList)
                        {
                            if (strBlockListUrl.StartsWith("!"))
                            {
                                Uri allowListUrl = new Uri(strBlockListUrl.Substring(1));

                                if (!_dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Contains(allowListUrl))
                                    _dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Add(allowListUrl);
                            }
                            else
                            {
                                Uri blockListUrl = new Uri(strBlockListUrl);

                                if (!_dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Contains(blockListUrl))
                                    _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Add(blockListUrl);
                            }
                        }
                    }
                }
            }

            if (request.TryGetQuery("blockListUpdateIntervalHours", int.Parse, out int blockListUpdateIntervalHours))
            {
                if ((blockListUpdateIntervalHours < 0) || (blockListUpdateIntervalHours > 168))
                    throw new DnsWebServiceException("Parameter `blockListUpdateIntervalHours` must be between 1 hour and 168 hours (7 days) or 0 to disable automatic update.");

                _blockListUpdateIntervalHours = blockListUpdateIntervalHours;
            }

            //proxy & forwarders
            if (request.TryGetQuery("proxyType", out NetProxyType proxyType))
            {
                if (proxyType == NetProxyType.None)
                {
                    _dnsWebService._dnsServer.Proxy = null;
                }
                else
                {
                    NetworkCredential credential = null;

                    if (request.TryGetQuery("proxyUsername", out string proxyUsername))
                        credential = new NetworkCredential(proxyUsername, request.Query["proxyPassword"]);

                    _dnsWebService._dnsServer.Proxy = NetProxy.CreateProxy(proxyType, request.Query["proxyAddress"], int.Parse(request.Query["proxyPort"]), credential);

                    if (request.TryGetQuery("proxyBypass", out string proxyBypass))
                        _dnsWebService._dnsServer.Proxy.BypassList = proxyBypass.Split(delegate (string value) { return new NetProxyBypassItem(value); }, ',');
                }
            }

            string strForwarders = request.Query["forwarders"];
            if (strForwarders is not null)
            {
                if ((strForwarders.Length == 0) || strForwarders.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    _dnsWebService._dnsServer.Forwarders = null;
                }
                else
                {
                    DnsTransportProtocol forwarderProtocol = request.GetQuery("forwarderProtocol", DnsTransportProtocol.Udp);
                    if (forwarderProtocol == DnsTransportProtocol.HttpsJson)
                        forwarderProtocol = DnsTransportProtocol.Https;

                    _dnsWebService._dnsServer.Forwarders = strForwarders.Split(delegate (string value)
                    {
                        NameServerAddress forwarder = NameServerAddress.Parse(value);

                        if (forwarder.Protocol != forwarderProtocol)
                            forwarder = forwarder.ChangeProtocol(forwarderProtocol);

                        return forwarder;
                    }, ',');
                }
            }

            if (request.TryGetQuery("forwarderRetries", int.Parse, out int forwarderRetries))
                _dnsWebService._dnsServer.ForwarderRetries = forwarderRetries;

            if (request.TryGetQuery("forwarderTimeout", int.Parse, out int forwarderTimeout))
                _dnsWebService._dnsServer.ForwarderTimeout = forwarderTimeout;

            if (request.TryGetQuery("forwarderConcurrency", int.Parse, out int forwarderConcurrency))
                _dnsWebService._dnsServer.ForwarderConcurrency = forwarderConcurrency;

            //logging
            if (request.TryGetQuery("enableLogging", bool.Parse, out bool enableLogging))
                _dnsWebService._log.EnableLogging = enableLogging;

            if (request.TryGetQuery("logQueries", bool.Parse, out bool logQueries))
                _dnsWebService._dnsServer.QueryLogManager = logQueries ? _dnsWebService._log : null;

            if (request.TryGetQuery("useLocalTime", bool.Parse, out bool useLocalTime))
                _dnsWebService._log.UseLocalTime = useLocalTime;

            if (request.TryGetQuery("logFolder", out string logFolder))
                _dnsWebService._log.LogFolder = logFolder;

            if (request.TryGetQuery("maxLogFileDays", int.Parse, out int maxLogFileDays))
                _dnsWebService._log.MaxLogFileDays = maxLogFileDays;

            if (request.TryGetQuery("maxStatFileDays", int.Parse, out int maxStatFileDays))
                _dnsWebService._dnsServer.StatsManager.MaxStatFileDays = maxStatFileDays;

            //TLS actions
            if ((_dnsWebService._webServiceTlsCertificatePath == null) && (_dnsWebService._dnsTlsCertificatePath == null))
                _dnsWebService.StopTlsCertificateUpdateTimer();

            _dnsWebService.SelfSignedCertCheck(serverDomainChanged, true);

            if (_dnsWebService._webServiceEnableTls && string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath) && !_dnsWebService._webServiceUseSelfSignedTlsCertificate)
            {
                //disable TLS
                _dnsWebService._webServiceEnableTls = false;
                restartWebService = true;
            }

            //blocklist timers
            if ((_blockListUpdateIntervalHours > 0) && ((_dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Count) > 0))
            {
                if (blockListUrlsUpdated || (_blockListUpdateTimer is null))
                    ForceUpdateBlockLists();

                StartBlockListUpdateTimer();
            }
            else
            {
                StopBlockListUpdateTimer();
            }

            //save config
            _dnsWebService.SaveConfigFile();
            _dnsWebService._log.Save();

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] DNS Settings were updated successfully.");

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
            WriteDnsSettings(jsonWriter);

            RestartService(restartDnsService, restartWebService);
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

            bool blockLists = request.GetQuery("blockLists", bool.Parse, false);
            bool logs = request.GetQuery("logs", bool.Parse, false);
            bool scopes = request.GetQuery("scopes", bool.Parse, false);
            bool apps = request.GetQuery("apps", bool.Parse, false);
            bool stats = request.GetQuery("stats", bool.Parse, false);
            bool zones = request.GetQuery("zones", bool.Parse, false);
            bool allowedZones = request.GetQuery("allowedZones", bool.Parse, false);
            bool blockedZones = request.GetQuery("blockedZones", bool.Parse, false);
            bool dnsSettings = request.GetQuery("dnsSettings", bool.Parse, false);
            bool authConfig = request.GetQuery("authConfig", bool.Parse, false);
            bool logSettings = request.GetQuery("logSettings", bool.Parse, false);

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
                    response.Headers.ContentDisposition = "attachment;filename=DnsServerBackup.zip";

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

            bool blockLists = request.GetQuery("blockLists", bool.Parse, false);
            bool logs = request.GetQuery("logs", bool.Parse, false);
            bool scopes = request.GetQuery("scopes", bool.Parse, false);
            bool apps = request.GetQuery("apps", bool.Parse, false);
            bool stats = request.GetQuery("stats", bool.Parse, false);
            bool zones = request.GetQuery("zones", bool.Parse, false);
            bool allowedZones = request.GetQuery("allowedZones", bool.Parse, false);
            bool blockedZones = request.GetQuery("blockedZones", bool.Parse, false);
            bool dnsSettings = request.GetQuery("dnsSettings", bool.Parse, false);
            bool authConfig = request.GetQuery("authConfig", bool.Parse, false);
            bool logSettings = request.GetQuery("logSettings", bool.Parse, false);
            bool deleteExistingFiles = request.GetQuery("deleteExistingFiles", bool.Parse, false);

            if (request.Form.Files.Count == 0)
                throw new DnsWebServiceException("DNS backup zip file is missing.");

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
                                if (entry != null)
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
                            if (entry != null)
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
                            if (entry != null)
                                entry.ExtractToFile(Path.Combine(_dnsWebService._configFolder, entry.Name), true);

                            //reload settings and block list zone
                            _dnsWebService.LoadConfigFile();

                            if ((_blockListUpdateIntervalHours > 0) && (_dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Count > 0))
                            {
                                ThreadPool.QueueUserWorkItem(delegate (object state)
                                {
                                    try
                                    {
                                        _dnsWebService._dnsServer.BlockListZoneManager.LoadBlockLists();
                                        StartBlockListUpdateTimer();
                                    }
                                    catch (Exception ex)
                                    {
                                        _dnsWebService._log.Write(ex);
                                    }
                                });
                            }
                            else
                            {
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
                                string fileName = Path.Combine(_dnsWebService._configFolder, "allowed.config");
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

            if (dnsSettings)
                RestartService(true, true);

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
            WriteDnsSettings(jsonWriter);
        }

        public void ForceUpdateBlockLists(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            ForceUpdateBlockLists();
            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Block list update was triggered.");
        }

        public void TemporaryDisableBlocking(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            int minutes = context.Request.GetQuery("minutes", int.Parse);

            Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
            if (temporaryDisableBlockingTimer is not null)
                temporaryDisableBlockingTimer.Dispose();

            Timer newTemporaryDisableBlockingTimer = new Timer(delegate (object state)
            {
                try
                {
                    _dnsWebService._dnsServer.EnableBlocking = true;
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
                _dnsWebService._dnsServer.EnableBlocking = false;
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
