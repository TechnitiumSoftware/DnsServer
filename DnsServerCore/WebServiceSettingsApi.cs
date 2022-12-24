/*
Technitium DNS Server
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
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
                        _dnsWebService.StopDnsWebService();
                        _dnsWebService.StartDnsWebService();

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

        #endregion

        #region public

        public void GetDnsSettings(Utf8JsonWriter jsonWriter)
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

        public void SetDnsSettings(HttpListenerRequest request, Utf8JsonWriter jsonWriter)
        {
            bool serverDomainChanged = false;
            bool restartDnsService = false;
            bool restartWebService = false;
            int oldWebServiceHttpPort = _dnsWebService._webServiceHttpPort;

            //general
            string strDnsServerDomain = request.QueryString["dnsServerDomain"];
            if (!string.IsNullOrEmpty(strDnsServerDomain))
            {
                serverDomainChanged = !_dnsWebService._dnsServer.ServerDomain.Equals(strDnsServerDomain, StringComparison.OrdinalIgnoreCase);
                _dnsWebService._dnsServer.ServerDomain = strDnsServerDomain;
            }

            string strDnsServerLocalEndPoints = request.QueryString["dnsServerLocalEndPoints"];
            if (strDnsServerLocalEndPoints != null)
            {
                if (string.IsNullOrEmpty(strDnsServerLocalEndPoints))
                    strDnsServerLocalEndPoints = "0.0.0.0:53,[::]:53";

                string[] strLocalEndPoints = strDnsServerLocalEndPoints.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                List<IPEndPoint> localEndPoints = new List<IPEndPoint>(strLocalEndPoints.Length);

                for (int i = 0; i < strLocalEndPoints.Length; i++)
                {
                    NameServerAddress nameServer = new NameServerAddress(strLocalEndPoints[i]);
                    if (nameServer.IPEndPoint != null)
                        localEndPoints.Add(nameServer.IPEndPoint);
                }

                if (localEndPoints.Count > 0)
                {
                    if (_dnsWebService._dnsServer.LocalEndPoints.Count != localEndPoints.Count)
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

            string strDefaultRecordTtl = request.QueryString["defaultRecordTtl"];
            if (!string.IsNullOrEmpty(strDefaultRecordTtl))
                _dnsWebService._zonesApi.DefaultRecordTtl = uint.Parse(strDefaultRecordTtl);

            string strDnsAppsEnableAutomaticUpdate = request.QueryString["dnsAppsEnableAutomaticUpdate"];
            if (!string.IsNullOrEmpty(strDnsAppsEnableAutomaticUpdate))
                _dnsWebService._appsApi.EnableAutomaticUpdate = bool.Parse(strDnsAppsEnableAutomaticUpdate);

            string strPreferIPv6 = request.QueryString["preferIPv6"];
            if (!string.IsNullOrEmpty(strPreferIPv6))
                _dnsWebService._dnsServer.PreferIPv6 = bool.Parse(strPreferIPv6);

            string strUdpPayloadSize = request.QueryString["udpPayloadSize"];
            if (!string.IsNullOrEmpty(strUdpPayloadSize))
                _dnsWebService._dnsServer.UdpPayloadSize = ushort.Parse(strUdpPayloadSize);

            string strDnssecValidation = request.QueryString["dnssecValidation"];
            if (!string.IsNullOrEmpty(strDnssecValidation))
                _dnsWebService._dnsServer.DnssecValidation = bool.Parse(strDnssecValidation);

            string strEDnsClientSubnet = request.QueryString["eDnsClientSubnet"];
            if (!string.IsNullOrEmpty(strEDnsClientSubnet))
                _dnsWebService._dnsServer.EDnsClientSubnet = bool.Parse(strEDnsClientSubnet);

            string strEDnsClientSubnetIPv4PrefixLength = request.QueryString["eDnsClientSubnetIPv4PrefixLength"];
            if (!string.IsNullOrEmpty(strEDnsClientSubnetIPv4PrefixLength))
                _dnsWebService._dnsServer.EDnsClientSubnetIPv4PrefixLength = byte.Parse(strEDnsClientSubnetIPv4PrefixLength);

            string strEDnsClientSubnetIPv6PrefixLength = request.QueryString["eDnsClientSubnetIPv6PrefixLength"];
            if (!string.IsNullOrEmpty(strEDnsClientSubnetIPv6PrefixLength))
                _dnsWebService._dnsServer.EDnsClientSubnetIPv6PrefixLength = byte.Parse(strEDnsClientSubnetIPv6PrefixLength);

            string strQpmLimitRequests = request.QueryString["qpmLimitRequests"];
            if (!string.IsNullOrEmpty(strQpmLimitRequests))
                _dnsWebService._dnsServer.QpmLimitRequests = int.Parse(strQpmLimitRequests);

            string strQpmLimitErrors = request.QueryString["qpmLimitErrors"];
            if (!string.IsNullOrEmpty(strQpmLimitErrors))
                _dnsWebService._dnsServer.QpmLimitErrors = int.Parse(strQpmLimitErrors);

            string strQpmLimitSampleMinutes = request.QueryString["qpmLimitSampleMinutes"];
            if (!string.IsNullOrEmpty(strQpmLimitSampleMinutes))
                _dnsWebService._dnsServer.QpmLimitSampleMinutes = int.Parse(strQpmLimitSampleMinutes);

            string strQpmLimitIPv4PrefixLength = request.QueryString["qpmLimitIPv4PrefixLength"];
            if (!string.IsNullOrEmpty(strQpmLimitIPv4PrefixLength))
                _dnsWebService._dnsServer.QpmLimitIPv4PrefixLength = int.Parse(strQpmLimitIPv4PrefixLength);

            string strQpmLimitIPv6PrefixLength = request.QueryString["qpmLimitIPv6PrefixLength"];
            if (!string.IsNullOrEmpty(strQpmLimitIPv6PrefixLength))
                _dnsWebService._dnsServer.QpmLimitIPv6PrefixLength = int.Parse(strQpmLimitIPv6PrefixLength);

            string strClientTimeout = request.QueryString["clientTimeout"];
            if (!string.IsNullOrEmpty(strClientTimeout))
                _dnsWebService._dnsServer.ClientTimeout = int.Parse(strClientTimeout);

            string strTcpSendTimeout = request.QueryString["tcpSendTimeout"];
            if (!string.IsNullOrEmpty(strTcpSendTimeout))
                _dnsWebService._dnsServer.TcpSendTimeout = int.Parse(strTcpSendTimeout);

            string strTcpReceiveTimeout = request.QueryString["tcpReceiveTimeout"];
            if (!string.IsNullOrEmpty(strTcpReceiveTimeout))
                _dnsWebService._dnsServer.TcpReceiveTimeout = int.Parse(strTcpReceiveTimeout);

            //web service
            string strWebServiceLocalAddresses = request.QueryString["webServiceLocalAddresses"];
            if (strWebServiceLocalAddresses != null)
            {
                if (string.IsNullOrEmpty(strWebServiceLocalAddresses))
                    strWebServiceLocalAddresses = "0.0.0.0,[::]";

                string[] strLocalAddresses = strWebServiceLocalAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                List<IPAddress> localAddresses = new List<IPAddress>(strLocalAddresses.Length);

                for (int i = 0; i < strLocalAddresses.Length; i++)
                {
                    if (IPAddress.TryParse(strLocalAddresses[i], out IPAddress localAddress))
                        localAddresses.Add(localAddress);
                }

                if (localAddresses.Count > 0)
                {
                    if (_dnsWebService._webServiceLocalAddresses.Count != localAddresses.Count)
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

            string strWebServiceHttpPort = request.QueryString["webServiceHttpPort"];
            if (!string.IsNullOrEmpty(strWebServiceHttpPort))
            {
                _dnsWebService._webServiceHttpPort = int.Parse(strWebServiceHttpPort);

                if (oldWebServiceHttpPort != _dnsWebService._webServiceHttpPort)
                    restartWebService = true;
            }

            string strWebServiceEnableTls = request.QueryString["webServiceEnableTls"];
            if (!string.IsNullOrEmpty(strWebServiceEnableTls))
            {
                bool oldWebServiceEnableTls = _dnsWebService._webServiceEnableTls;

                _dnsWebService._webServiceEnableTls = bool.Parse(strWebServiceEnableTls);

                if (oldWebServiceEnableTls != _dnsWebService._webServiceEnableTls)
                    restartWebService = true;
            }

            string strWebServiceHttpToTlsRedirect = request.QueryString["webServiceHttpToTlsRedirect"];
            if (!string.IsNullOrEmpty(strWebServiceHttpToTlsRedirect))
                _dnsWebService._webServiceHttpToTlsRedirect = bool.Parse(strWebServiceHttpToTlsRedirect);

            string strWebServiceUseSelfSignedTlsCertificate = request.QueryString["webServiceUseSelfSignedTlsCertificate"];
            if (!string.IsNullOrEmpty(strWebServiceUseSelfSignedTlsCertificate))
                _dnsWebService._webServiceUseSelfSignedTlsCertificate = bool.Parse(strWebServiceUseSelfSignedTlsCertificate);

            string strWebServiceTlsPort = request.QueryString["webServiceTlsPort"];
            if (!string.IsNullOrEmpty(strWebServiceTlsPort))
            {
                int oldWebServiceTlsPort = _dnsWebService._webServiceTlsPort;

                _dnsWebService._webServiceTlsPort = int.Parse(strWebServiceTlsPort);

                if (oldWebServiceTlsPort != _dnsWebService._webServiceTlsPort)
                    restartWebService = true;
            }

            string strWebServiceTlsCertificatePath = request.QueryString["webServiceTlsCertificatePath"];
            string strWebServiceTlsCertificatePassword = request.QueryString["webServiceTlsCertificatePassword"];
            if (string.IsNullOrEmpty(strWebServiceTlsCertificatePath))
            {
                _dnsWebService._webServiceTlsCertificatePath = null;
                _dnsWebService._webServiceTlsCertificatePassword = "";
            }
            else
            {
                if (strWebServiceTlsCertificatePassword == "************")
                    strWebServiceTlsCertificatePassword = _dnsWebService._webServiceTlsCertificatePassword;

                if ((strWebServiceTlsCertificatePath != _dnsWebService._webServiceTlsCertificatePath) || (strWebServiceTlsCertificatePassword != _dnsWebService._webServiceTlsCertificatePassword))
                {
                    _dnsWebService.LoadWebServiceTlsCertificate(strWebServiceTlsCertificatePath, strWebServiceTlsCertificatePassword);

                    _dnsWebService._webServiceTlsCertificatePath = strWebServiceTlsCertificatePath;
                    _dnsWebService._webServiceTlsCertificatePassword = strWebServiceTlsCertificatePassword;

                    _dnsWebService.StartTlsCertificateUpdateTimer();
                }
            }

            //optional protocols
            string enableDnsOverHttp = request.QueryString["enableDnsOverHttp"];
            if (!string.IsNullOrEmpty(enableDnsOverHttp))
            {
                bool oldEnableDnsOverHttp = _dnsWebService._dnsServer.EnableDnsOverHttp;

                _dnsWebService._dnsServer.EnableDnsOverHttp = bool.Parse(enableDnsOverHttp);

                if (oldEnableDnsOverHttp != _dnsWebService._dnsServer.EnableDnsOverHttp)
                    restartDnsService = true;
            }

            string strEnableDnsOverTls = request.QueryString["enableDnsOverTls"];
            if (!string.IsNullOrEmpty(strEnableDnsOverTls))
            {
                bool oldEnableDnsOverTls = _dnsWebService._dnsServer.EnableDnsOverTls;

                _dnsWebService._dnsServer.EnableDnsOverTls = bool.Parse(strEnableDnsOverTls);

                if (oldEnableDnsOverTls != _dnsWebService._dnsServer.EnableDnsOverTls)
                    restartDnsService = true;
            }

            string strEnableDnsOverHttps = request.QueryString["enableDnsOverHttps"];
            if (!string.IsNullOrEmpty(strEnableDnsOverHttps))
            {
                bool oldEnableDnsOverHttps = _dnsWebService._dnsServer.EnableDnsOverHttps;

                _dnsWebService._dnsServer.EnableDnsOverHttps = bool.Parse(strEnableDnsOverHttps);

                if (oldEnableDnsOverHttps != _dnsWebService._dnsServer.EnableDnsOverHttps)
                    restartDnsService = true;
            }

            string strDnsTlsCertificatePath = request.QueryString["dnsTlsCertificatePath"];
            string strDnsTlsCertificatePassword = request.QueryString["dnsTlsCertificatePassword"];
            if (string.IsNullOrEmpty(strDnsTlsCertificatePath))
            {
                _dnsWebService._dnsTlsCertificatePath = null;
                _dnsWebService._dnsTlsCertificatePassword = "";
            }
            else
            {
                if (strDnsTlsCertificatePassword == "************")
                    strDnsTlsCertificatePassword = _dnsWebService._dnsTlsCertificatePassword;

                if ((strDnsTlsCertificatePath != _dnsWebService._dnsTlsCertificatePath) || (strDnsTlsCertificatePassword != _dnsWebService._dnsTlsCertificatePassword))
                {
                    _dnsWebService.LoadDnsTlsCertificate(strDnsTlsCertificatePath, strDnsTlsCertificatePassword);

                    _dnsWebService._dnsTlsCertificatePath = strDnsTlsCertificatePath;
                    _dnsWebService._dnsTlsCertificatePassword = strDnsTlsCertificatePassword;

                    _dnsWebService.StartTlsCertificateUpdateTimer();
                }
            }

            //tsig
            string strTsigKeys = request.QueryString["tsigKeys"];
            if (!string.IsNullOrEmpty(strTsigKeys))
            {
                if (strTsigKeys == "false")
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
            string strRecursion = request.QueryString["recursion"];
            if (!string.IsNullOrEmpty(strRecursion))
                _dnsWebService._dnsServer.Recursion = Enum.Parse<DnsServerRecursion>(strRecursion, true);

            string strRecursionDeniedNetworks = request.QueryString["recursionDeniedNetworks"];
            if (!string.IsNullOrEmpty(strRecursionDeniedNetworks))
            {
                if (strRecursionDeniedNetworks == "false")
                {
                    _dnsWebService._dnsServer.RecursionDeniedNetworks = null;
                }
                else
                {
                    string[] strNetworks = strRecursionDeniedNetworks.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    NetworkAddress[] networks = new NetworkAddress[strNetworks.Length];

                    for (int i = 0; i < networks.Length; i++)
                        networks[i] = NetworkAddress.Parse(strNetworks[i]);

                    _dnsWebService._dnsServer.RecursionDeniedNetworks = networks;
                }
            }

            string strRecursionAllowedNetworks = request.QueryString["recursionAllowedNetworks"];
            if (!string.IsNullOrEmpty(strRecursionAllowedNetworks))
            {
                if (strRecursionAllowedNetworks == "false")
                {
                    _dnsWebService._dnsServer.RecursionAllowedNetworks = null;
                }
                else
                {
                    string[] strNetworks = strRecursionAllowedNetworks.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    NetworkAddress[] networks = new NetworkAddress[strNetworks.Length];

                    for (int i = 0; i < networks.Length; i++)
                        networks[i] = NetworkAddress.Parse(strNetworks[i]);

                    _dnsWebService._dnsServer.RecursionAllowedNetworks = networks;
                }
            }

            string strRandomizeName = request.QueryString["randomizeName"];
            if (!string.IsNullOrEmpty(strRandomizeName))
                _dnsWebService._dnsServer.RandomizeName = bool.Parse(strRandomizeName);

            string strQnameMinimization = request.QueryString["qnameMinimization"];
            if (!string.IsNullOrEmpty(strQnameMinimization))
                _dnsWebService._dnsServer.QnameMinimization = bool.Parse(strQnameMinimization);

            string strNsRevalidation = request.QueryString["nsRevalidation"];
            if (!string.IsNullOrEmpty(strNsRevalidation))
                _dnsWebService._dnsServer.NsRevalidation = bool.Parse(strNsRevalidation);

            string strResolverRetries = request.QueryString["resolverRetries"];
            if (!string.IsNullOrEmpty(strResolverRetries))
                _dnsWebService._dnsServer.ResolverRetries = int.Parse(strResolverRetries);

            string strResolverTimeout = request.QueryString["resolverTimeout"];
            if (!string.IsNullOrEmpty(strResolverTimeout))
                _dnsWebService._dnsServer.ResolverTimeout = int.Parse(strResolverTimeout);

            string strResolverMaxStackCount = request.QueryString["resolverMaxStackCount"];
            if (!string.IsNullOrEmpty(strResolverMaxStackCount))
                _dnsWebService._dnsServer.ResolverMaxStackCount = int.Parse(strResolverMaxStackCount);

            //cache
            string strServeStale = request.QueryString["serveStale"];
            if (!string.IsNullOrEmpty(strServeStale))
                _dnsWebService._dnsServer.ServeStale = bool.Parse(strServeStale);

            string strServeStaleTtl = request.QueryString["serveStaleTtl"];
            if (!string.IsNullOrEmpty(strServeStaleTtl))
                _dnsWebService._dnsServer.CacheZoneManager.ServeStaleTtl = uint.Parse(strServeStaleTtl);

            string strCacheMaximumEntries = request.QueryString["cacheMaximumEntries"];
            if (!string.IsNullOrEmpty(strCacheMaximumEntries))
                _dnsWebService._dnsServer.CacheZoneManager.MaximumEntries = long.Parse(strCacheMaximumEntries);

            string strCacheMinimumRecordTtl = request.QueryString["cacheMinimumRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheMinimumRecordTtl))
                _dnsWebService._dnsServer.CacheZoneManager.MinimumRecordTtl = uint.Parse(strCacheMinimumRecordTtl);

            string strCacheMaximumRecordTtl = request.QueryString["cacheMaximumRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheMaximumRecordTtl))
                _dnsWebService._dnsServer.CacheZoneManager.MaximumRecordTtl = uint.Parse(strCacheMaximumRecordTtl);

            string strCacheNegativeRecordTtl = request.QueryString["cacheNegativeRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheNegativeRecordTtl))
                _dnsWebService._dnsServer.CacheZoneManager.NegativeRecordTtl = uint.Parse(strCacheNegativeRecordTtl);

            string strCacheFailureRecordTtl = request.QueryString["cacheFailureRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheFailureRecordTtl))
                _dnsWebService._dnsServer.CacheZoneManager.FailureRecordTtl = uint.Parse(strCacheFailureRecordTtl);

            string strCachePrefetchEligibility = request.QueryString["cachePrefetchEligibility"];
            if (!string.IsNullOrEmpty(strCachePrefetchEligibility))
                _dnsWebService._dnsServer.CachePrefetchEligibility = int.Parse(strCachePrefetchEligibility);

            string strCachePrefetchTrigger = request.QueryString["cachePrefetchTrigger"];
            if (!string.IsNullOrEmpty(strCachePrefetchTrigger))
                _dnsWebService._dnsServer.CachePrefetchTrigger = int.Parse(strCachePrefetchTrigger);

            string strCachePrefetchSampleIntervalInMinutes = request.QueryString["cachePrefetchSampleIntervalInMinutes"];
            if (!string.IsNullOrEmpty(strCachePrefetchSampleIntervalInMinutes))
                _dnsWebService._dnsServer.CachePrefetchSampleIntervalInMinutes = int.Parse(strCachePrefetchSampleIntervalInMinutes);

            string strCachePrefetchSampleEligibilityHitsPerHour = request.QueryString["cachePrefetchSampleEligibilityHitsPerHour"];
            if (!string.IsNullOrEmpty(strCachePrefetchSampleEligibilityHitsPerHour))
                _dnsWebService._dnsServer.CachePrefetchSampleEligibilityHitsPerHour = int.Parse(strCachePrefetchSampleEligibilityHitsPerHour);

            //blocking
            string strEnableBlocking = request.QueryString["enableBlocking"];
            if (!string.IsNullOrEmpty(strEnableBlocking))
            {
                _dnsWebService._dnsServer.EnableBlocking = bool.Parse(strEnableBlocking);
                if (_dnsWebService._dnsServer.EnableBlocking)
                {
                    if (_temporaryDisableBlockingTimer is not null)
                        _temporaryDisableBlockingTimer.Dispose();
                }
            }

            string strAllowTxtBlockingReport = request.QueryString["allowTxtBlockingReport"];
            if (!string.IsNullOrEmpty(strAllowTxtBlockingReport))
                _dnsWebService._dnsServer.AllowTxtBlockingReport = bool.Parse(strAllowTxtBlockingReport);

            string strBlockingType = request.QueryString["blockingType"];
            if (!string.IsNullOrEmpty(strBlockingType))
                _dnsWebService._dnsServer.BlockingType = Enum.Parse<DnsServerBlockingType>(strBlockingType, true);

            string strCustomBlockingAddresses = request.QueryString["customBlockingAddresses"];
            if (!string.IsNullOrEmpty(strCustomBlockingAddresses))
            {
                if (strCustomBlockingAddresses == "false")
                {
                    _dnsWebService._dnsServer.CustomBlockingARecords = null;
                    _dnsWebService._dnsServer.CustomBlockingAAAARecords = null;
                }
                else
                {
                    string[] strAddresses = strCustomBlockingAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

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

            bool blockListUrlsUpdated = false;
            string strBlockListUrls = request.QueryString["blockListUrls"];
            if (!string.IsNullOrEmpty(strBlockListUrls))
            {
                if (strBlockListUrls == "false")
                {
                    _dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                    _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Clear();
                    _dnsWebService._dnsServer.BlockListZoneManager.Flush();
                }
                else
                {
                    string[] strBlockListUrlList = strBlockListUrls.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    if (oldWebServiceHttpPort != _dnsWebService._webServiceHttpPort)
                    {
                        for (int i = 0; i < strBlockListUrlList.Length; i++)
                        {
                            if (strBlockListUrlList[i].Contains("http://localhost:" + oldWebServiceHttpPort + "/blocklist.txt"))
                            {
                                strBlockListUrlList[i] = "http://localhost:" + _dnsWebService._webServiceHttpPort + "/blocklist.txt";
                                blockListUrlsUpdated = true;
                                break;
                            }
                        }
                    }

                    if (!blockListUrlsUpdated)
                    {
                        if (strBlockListUrlList.Length != (_dnsWebService._dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Count))
                        {
                            blockListUrlsUpdated = true;
                        }
                        else
                        {
                            foreach (string strBlockListUrl in strBlockListUrlList)
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

                        foreach (string strBlockListUrl in strBlockListUrlList)
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

            string strBlockListUpdateIntervalHours = request.QueryString["blockListUpdateIntervalHours"];
            if (!string.IsNullOrEmpty(strBlockListUpdateIntervalHours))
            {
                int blockListUpdateIntervalHours = int.Parse(strBlockListUpdateIntervalHours);

                if ((blockListUpdateIntervalHours < 0) || (blockListUpdateIntervalHours > 168))
                    throw new DnsWebServiceException("Parameter `blockListUpdateIntervalHours` must be between 1 hour and 168 hours (7 days) or 0 to disable automatic update.");

                _blockListUpdateIntervalHours = blockListUpdateIntervalHours;
            }

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

            //proxy & forwarders
            string strProxyType = request.QueryString["proxyType"];
            if (!string.IsNullOrEmpty(strProxyType))
            {
                NetProxyType proxyType = Enum.Parse<NetProxyType>(strProxyType, true);
                if (proxyType == NetProxyType.None)
                {
                    _dnsWebService._dnsServer.Proxy = null;
                }
                else
                {
                    NetworkCredential credential = null;

                    string strUsername = request.QueryString["proxyUsername"];
                    if (!string.IsNullOrEmpty(strUsername))
                        credential = new NetworkCredential(strUsername, request.QueryString["proxyPassword"]);

                    _dnsWebService._dnsServer.Proxy = NetProxy.CreateProxy(proxyType, request.QueryString["proxyAddress"], int.Parse(request.QueryString["proxyPort"]), credential);

                    string strProxyBypass = request.QueryString["proxyBypass"];
                    if (!string.IsNullOrEmpty(strProxyBypass))
                    {
                        string[] strBypassList = strProxyBypass.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                        List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(strBypassList.Length);

                        for (int i = 0; i < strBypassList.Length; i++)
                            bypassList.Add(new NetProxyBypassItem(strBypassList[i]));

                        _dnsWebService._dnsServer.Proxy.BypassList = bypassList;
                    }
                }
            }

            DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;
            string strForwarderProtocol = request.QueryString["forwarderProtocol"];
            if (!string.IsNullOrEmpty(strForwarderProtocol))
            {
                forwarderProtocol = Enum.Parse<DnsTransportProtocol>(strForwarderProtocol, true);
                if (forwarderProtocol == DnsTransportProtocol.HttpsJson)
                    forwarderProtocol = DnsTransportProtocol.Https;
            }

            string strForwarders = request.QueryString["forwarders"];
            if (!string.IsNullOrEmpty(strForwarders))
            {
                if (strForwarders == "false")
                {
                    _dnsWebService._dnsServer.Forwarders = null;
                }
                else
                {
                    string[] strForwardersList = strForwarders.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    NameServerAddress[] forwarders = new NameServerAddress[strForwardersList.Length];

                    for (int i = 0; i < strForwardersList.Length; i++)
                    {
                        NameServerAddress forwarder = new NameServerAddress(strForwardersList[i]);

                        if (forwarder.Protocol != forwarderProtocol)
                            forwarder = forwarder.ChangeProtocol(forwarderProtocol);

                        forwarders[i] = forwarder;
                    }

                    _dnsWebService._dnsServer.Forwarders = forwarders;
                }
            }

            string strForwarderRetries = request.QueryString["forwarderRetries"];
            if (!string.IsNullOrEmpty(strForwarderRetries))
                _dnsWebService._dnsServer.ForwarderRetries = int.Parse(strForwarderRetries);

            string strForwarderTimeout = request.QueryString["forwarderTimeout"];
            if (!string.IsNullOrEmpty(strForwarderTimeout))
                _dnsWebService._dnsServer.ForwarderTimeout = int.Parse(strForwarderTimeout);

            string strForwarderConcurrency = request.QueryString["forwarderConcurrency"];
            if (!string.IsNullOrEmpty(strForwarderConcurrency))
                _dnsWebService._dnsServer.ForwarderConcurrency = int.Parse(strForwarderConcurrency);

            //logging
            string strEnableLogging = request.QueryString["enableLogging"];
            if (!string.IsNullOrEmpty(strEnableLogging))
                _dnsWebService._log.EnableLogging = bool.Parse(strEnableLogging);

            string strLogQueries = request.QueryString["logQueries"];
            if (!string.IsNullOrEmpty(strLogQueries))
            {
                if (bool.Parse(strLogQueries))
                    _dnsWebService._dnsServer.QueryLogManager = _dnsWebService._log;
                else
                    _dnsWebService._dnsServer.QueryLogManager = null;
            }

            string strUseLocalTime = request.QueryString["useLocalTime"];
            if (!string.IsNullOrEmpty(strUseLocalTime))
                _dnsWebService._log.UseLocalTime = bool.Parse(strUseLocalTime);

            string strLogFolder = request.QueryString["logFolder"];
            if (!string.IsNullOrEmpty(strLogFolder))
                _dnsWebService._log.LogFolder = strLogFolder;

            string strMaxLogFileDays = request.QueryString["maxLogFileDays"];
            if (!string.IsNullOrEmpty(strMaxLogFileDays))
                _dnsWebService._log.MaxLogFileDays = int.Parse(strMaxLogFileDays);

            string strMaxStatFileDays = request.QueryString["maxStatFileDays"];
            if (!string.IsNullOrEmpty(strMaxStatFileDays))
                _dnsWebService._dnsServer.StatsManager.MaxStatFileDays = int.Parse(strMaxStatFileDays);

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

            //save config
            _dnsWebService.SaveConfigFile();
            _dnsWebService._log.Save();

            _dnsWebService._log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DNS Settings were updated successfully.");

            GetDnsSettings(jsonWriter);

            RestartService(restartDnsService, restartWebService);
        }

        public void GetTsigKeyNames(Utf8JsonWriter jsonWriter)
        {
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

        public async Task BackupSettingsAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            bool blockLists = false;
            bool logs = false;
            bool scopes = false;
            bool apps = false;
            bool stats = false;
            bool zones = false;
            bool allowedZones = false;
            bool blockedZones = false;
            bool dnsSettings = false;
            bool authConfig = false;
            bool logSettings = false;

            string strBlockLists = request.QueryString["blockLists"];
            if (!string.IsNullOrEmpty(strBlockLists))
                blockLists = bool.Parse(strBlockLists);

            string strLogs = request.QueryString["logs"];
            if (!string.IsNullOrEmpty(strLogs))
                logs = bool.Parse(strLogs);

            string strScopes = request.QueryString["scopes"];
            if (!string.IsNullOrEmpty(strScopes))
                scopes = bool.Parse(strScopes);

            string strApps = request.QueryString["apps"];
            if (!string.IsNullOrEmpty(strApps))
                apps = bool.Parse(strApps);

            string strStats = request.QueryString["stats"];
            if (!string.IsNullOrEmpty(strStats))
                stats = bool.Parse(strStats);

            string strZones = request.QueryString["zones"];
            if (!string.IsNullOrEmpty(strZones))
                zones = bool.Parse(strZones);

            string strAllowedZones = request.QueryString["allowedZones"];
            if (!string.IsNullOrEmpty(strAllowedZones))
                allowedZones = bool.Parse(strAllowedZones);

            string strBlockedZones = request.QueryString["blockedZones"];
            if (!string.IsNullOrEmpty(strBlockedZones))
                blockedZones = bool.Parse(strBlockedZones);

            string strDnsSettings = request.QueryString["dnsSettings"];
            if (!string.IsNullOrEmpty(strDnsSettings))
                dnsSettings = bool.Parse(strDnsSettings);

            string strAuthConfig = request.QueryString["authConfig"];
            if (!string.IsNullOrEmpty(strAuthConfig))
                authConfig = bool.Parse(strAuthConfig);

            string strLogSettings = request.QueryString["logSettings"];
            if (!string.IsNullOrEmpty(strLogSettings))
                logSettings = bool.Parse(strLogSettings);

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

                    response.ContentType = "application/zip";
                    response.ContentLength64 = backupZipStream.Length;
                    response.AddHeader("Content-Disposition", "attachment;filename=DnsServerBackup.zip");

                    using (Stream output = response.OutputStream)
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

            _dnsWebService._log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Settings backup zip file was exported.");
        }

        public async Task RestoreSettingsAsync(HttpListenerRequest request, Utf8JsonWriter jsonWriter)
        {
            bool blockLists = false;
            bool logs = false;
            bool scopes = false;
            bool apps = false;
            bool stats = false;
            bool zones = false;
            bool allowedZones = false;
            bool blockedZones = false;
            bool dnsSettings = false;
            bool authConfig = false;
            bool logSettings = false;

            bool deleteExistingFiles = false;

            string strBlockLists = request.QueryString["blockLists"];
            if (!string.IsNullOrEmpty(strBlockLists))
                blockLists = bool.Parse(strBlockLists);

            string strLogs = request.QueryString["logs"];
            if (!string.IsNullOrEmpty(strLogs))
                logs = bool.Parse(strLogs);

            string strScopes = request.QueryString["scopes"];
            if (!string.IsNullOrEmpty(strScopes))
                scopes = bool.Parse(strScopes);

            string strApps = request.QueryString["apps"];
            if (!string.IsNullOrEmpty(strApps))
                apps = bool.Parse(strApps);

            string strStats = request.QueryString["stats"];
            if (!string.IsNullOrEmpty(strStats))
                stats = bool.Parse(strStats);

            string strZones = request.QueryString["zones"];
            if (!string.IsNullOrEmpty(strZones))
                zones = bool.Parse(strZones);

            string strAllowedZones = request.QueryString["allowedZones"];
            if (!string.IsNullOrEmpty(strAllowedZones))
                allowedZones = bool.Parse(strAllowedZones);

            string strBlockedZones = request.QueryString["blockedZones"];
            if (!string.IsNullOrEmpty(strBlockedZones))
                blockedZones = bool.Parse(strBlockedZones);

            string strDnsSettings = request.QueryString["dnsSettings"];
            if (!string.IsNullOrEmpty(strDnsSettings))
                dnsSettings = bool.Parse(strDnsSettings);

            string strAuthConfig = request.QueryString["authConfig"];
            if (!string.IsNullOrEmpty(strAuthConfig))
                authConfig = bool.Parse(strAuthConfig);

            string strLogSettings = request.QueryString["logSettings"];
            if (!string.IsNullOrEmpty(strLogSettings))
                logSettings = bool.Parse(strLogSettings);

            string strDeleteExistingFiles = request.QueryString["deleteExistingFiles"];
            if (!string.IsNullOrEmpty(strDeleteExistingFiles))
                deleteExistingFiles = bool.Parse(strDeleteExistingFiles);

            #region skip to content

            int crlfCount = 0;
            int byteRead;

            while (crlfCount != 4)
            {
                byteRead = await request.InputStream.ReadByteValueAsync();
                switch (byteRead)
                {
                    case 13: //CR
                    case 10: //LF
                        crlfCount++;
                        break;

                    default:
                        crlfCount = 0;
                        break;
                }
            }

            #endregion

            //write to temp file
            string tmpFile = Path.GetTempFileName();
            try
            {
                using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    await request.InputStream.CopyToAsync(fS);

                    fS.Position = 0;
                    using (ZipArchive backupZip = new ZipArchive(fS, ZipArchiveMode.Read, false, Encoding.UTF8))
                    {
                        UserSession session = _dnsWebService.GetSession(request);

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

                        _dnsWebService._log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Settings backup zip file was restored.");
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

            GetDnsSettings(jsonWriter);
        }

        public void ForceUpdateBlockLists(HttpListenerRequest request)
        {
            ForceUpdateBlockLists();
            _dnsWebService._log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Block list update was triggered.");
        }

        public void TemporaryDisableBlocking(HttpListenerRequest request, Utf8JsonWriter jsonWriter)
        {
            string strMinutes = request.QueryString["minutes"];
            if (string.IsNullOrEmpty(strMinutes))
                throw new DnsWebServiceException("Parameter 'minutes' missing.");

            int minutes = int.Parse(strMinutes);

            Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
            if (temporaryDisableBlockingTimer is not null)
                temporaryDisableBlockingTimer.Dispose();

            Timer newTemporaryDisableBlockingTimer = new Timer(delegate (object state)
            {
                try
                {
                    _dnsWebService._dnsServer.EnableBlocking = true;
                    _dnsWebService._log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Blocking was enabled after " + minutes + " minute(s) being temporarily disabled.");
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

                _dnsWebService._log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Blocking was temporarily disabled for " + minutes + " minute(s).");
            }
            else
            {
                newTemporaryDisableBlockingTimer.Dispose();
            }

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
