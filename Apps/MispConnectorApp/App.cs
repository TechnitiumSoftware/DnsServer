/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)
Copyright (C) 2025  Zafer Balkan (zafer@zaferbalkan.com)

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
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;

namespace MispConnector
{
    public sealed class App : IDnsApplication, IDnsRequestBlockingHandler
    {
        #region variables

        readonly object _blocklistLock = new object();

        readonly HashSet<string> _globalBlocklist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        readonly Random _random = new Random();

        bool _allowTxtBlockingReport;

        string _cacheFilePath;

        IDnsServer _dnsServer;
        bool _enableBlocking;

        HttpClient _httpClient;

        string _maxIocAge;

        string _mispApiKey;

        Uri _mispApiUrl;

        DnsSOARecordData _soaRecord;
        TimeSpan _updateInterval;

        Timer _updateTimer;
        #endregion

        #region IDisposable

        public void Dispose()
        {
            _updateTimer?.Dispose();
            _httpClient?.Dispose();
        }

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            try
            {
                string configDir = _dnsServer.ApplicationFolder;
                Directory.CreateDirectory(configDir);
                _cacheFilePath = Path.Combine(configDir, "misp_domain_cache.txt");

                _soaRecord = new DnsSOARecordData(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, 60);

                using JsonDocument jsonDocument = JsonDocument.Parse(config);
                JsonElement jsonConfig = jsonDocument.RootElement;

                _enableBlocking = jsonConfig.GetProperty("enableBlocking").GetBoolean();
                _allowTxtBlockingReport = jsonConfig.GetProperty("allowTxtBlockingReport").GetBoolean();
                Uri mispServerUrl = new Uri(jsonConfig.GetProperty("mispServerUrl").GetString());
                _mispApiKey = jsonConfig.GetProperty("mispApiKey").GetString();
                bool disableTlsValidation = jsonConfig.GetProperty("disableTlsValidation").GetBoolean();

                string updateIntervalString = jsonConfig.GetProperty("updateInterval").GetString();
                _updateInterval = ParseUpdateInterval(updateIntervalString);

                _maxIocAge = jsonConfig.GetProperty("maxIocAge").GetString();

                _mispApiUrl = new Uri(mispServerUrl, "/attributes/restSearch");
                _httpClient = CreateHttpClient(mispServerUrl, disableTlsValidation);

                await LoadBlocklistFromCacheAsync();
                await using Timer _ = _updateTimer = new Timer(async _ =>
                {
                    await UpdateIocsAsync();
                }, null, TimeSpan.FromSeconds(10), Timeout.InfiniteTimeSpan);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog($"FATAL: MISP Connector failed to initialize. Check configuration. Error: {ex.Message}");
                _dnsServer.WriteLog(ex);
            }
        }

        #endregion

        #region public

        public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            return Task.FromResult(false);
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];
            if (!IsDomainBlocked(question.Name, out string blockedDomain))
            {
                return Task.FromResult<DnsDatagram>(null);
            }

            if (_allowTxtBlockingReport && question.Type == DnsResourceRecordType.TXT)
            {
                DnsResourceRecord[] answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecordData($"source=misp-connector;domain={blockedDomain}")) };
                return Task.FromResult(new DnsDatagram(
                                    ID: request.Identifier,
                                    isResponse: true,
                                    OPCODE: DnsOpcode.StandardQuery,
                                    authoritativeAnswer: false,
                                    truncation: false,
                                    recursionDesired: request.RecursionDesired,
                                    recursionAvailable: true,
                                    authenticData: false,
                                    checkingDisabled: false,
                                    RCODE: DnsResponseCode.NoError,
                                    question: request.Question,
                                    answer: answer,
                                    authority: null,
                                    additional: null
                                ));
            }

            DnsResourceRecord[] authority = new DnsResourceRecord[] { new DnsResourceRecord(GetParentZone(blockedDomain) ?? string.Empty, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) };
            return Task.FromResult(new DnsDatagram(
                            ID: request.Identifier,
                            isResponse: true,
                            OPCODE: DnsOpcode.StandardQuery,
                            authoritativeAnswer: true,
                            truncation: false,
                            recursionDesired: request.RecursionDesired,
                            recursionAvailable: true,
                            authenticData: false,
                            checkingDisabled: false,
                            RCODE: DnsResponseCode.NxDomain,
                            question: request.Question,
                            answer: null,
                            authority: authority,
                            additional: null
                        ));
        }

        #endregion

        #region private
        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            return (i > -1) ? domain.Substring(i + 1) : null;
        }

        private static TimeSpan ParseUpdateInterval(string interval)
        {
            if (string.IsNullOrWhiteSpace(interval) || interval.Length < 2)
            {
                throw new FormatException("Update interval is not in a valid format (e.g., '60m', '2h', '7d').");
            }

            string unit = interval.Substring(interval.Length - 1).ToLowerInvariant();
            string valueString = interval.Substring(0, interval.Length - 1);

            if (!int.TryParse(valueString, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value) || value <= 0)
            {
                throw new FormatException($"Invalid numeric value '{valueString}' in update interval.");
            }

            switch (unit)
            {
                case "m":
                    return TimeSpan.FromMinutes(value);
                case "h":
                    return TimeSpan.FromHours(value);
                case "d":
                    return TimeSpan.FromDays(value);
                default:
                    throw new FormatException($"Invalid unit '{unit}' in update interval. Allowed units are 'm', 'h', 'd'.");
            }
        }

        private HttpClient CreateHttpClient(Uri serverUrl, bool disableTlsValidation)
        {
            SocketsHttpHandler handler = new SocketsHttpHandler
            {
                Proxy = _dnsServer.Proxy,
                UseProxy = _dnsServer.Proxy != null,
                SslOptions = new SslClientAuthenticationOptions()
            };

            if (disableTlsValidation)
            {
                handler.SslOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
                {
                    return true;
                };
                _dnsServer.WriteLog($"WARNING: TLS certificate validation is DISABLED for MISP server: {serverUrl}");
            }

            return new HttpClient(new HttpClientNetworkHandler(handler, _dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default, _dnsServer));
        }

        private async Task<HashSet<string>> FetchDomainsFromMispAsync()
        {
            var requestBody = new
            {
                type = "domain",
                to_ids = true,
                deleted = false,
                last = _maxIocAge
            };

            StringContent requestContent = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");

            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, _mispApiUrl)
            {
                Content = requestContent
            };

            request.Headers.Add("Authorization", _mispApiKey);
            request.Headers.Add("Accept", "application/json");

            using HttpResponseMessage response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            using Stream responseStream = await response.Content.ReadAsStreamAsync();
            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(responseStream);

            HashSet<string> domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (jsonDoc.RootElement.TryGetProperty("response", out JsonElement responseElement) &&
                responseElement.TryGetProperty("Attribute", out JsonElement attributeArray) &&
                attributeArray.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement attributeElement in attributeArray.EnumerateArray())
                {
                    if (attributeElement.TryGetProperty("value", out JsonElement valueElement) && valueElement.ValueKind == JsonValueKind.String)
                    {
                        string domain = valueElement.GetString()?.Trim().ToLowerInvariant();
                        if (!string.IsNullOrEmpty(domain) && DnsClient.IsDomainNameValid(domain))
                        {
                            domains.Add(domain);
                        }
                    }
                }
            }
            return domains;
        }

        private bool IsDomainBlocked(string domain, out string foundZone)
        {
            lock (_blocklistLock)
            {
                string currentDomain = domain.ToLowerInvariant();
                do
                {
                    if (_globalBlocklist.Contains(currentDomain))
                    {
                        foundZone = currentDomain;
                        return true;
                    }
                    currentDomain = GetParentZone(currentDomain);
                } while (currentDomain != null);
            }
            foundZone = null;
            return false;
        }

        private async Task LoadBlocklistFromCacheAsync()
        {
            if (!File.Exists(_cacheFilePath)) return;
            try
            {
                HashSet<string> domains = (await File.ReadAllLinesAsync(_cacheFilePath)).ToHashSet(StringComparer.OrdinalIgnoreCase);
                ReloadBlocklist(domains);
                _dnsServer.WriteLog($"MISP Connector: Loaded {domains.Count} domains from cache.");
            }
            catch (IOException ex)
            {
                _dnsServer.WriteLog($"ERROR: Failed to read cache file '{_cacheFilePath}'. Error: {ex.Message}");
            }
        }

        private void ReloadBlocklist(HashSet<string> domains)
        {
            lock (_blocklistLock)
            {
                _globalBlocklist.Clear();
                foreach (string domain in domains)
                {
                    _globalBlocklist.Add(domain);
                }
            }
        }

        private async Task UpdateIocsAsync()
        {
            try
            {
                _dnsServer.WriteLog("MISP Connector: Starting IOC update...");
                HashSet<string> domains = await FetchDomainsFromMispAsync();
                await WriteDomainsToCacheAsync(domains);
                ReloadBlocklist(domains);
                _dnsServer.WriteLog($"MISP Connector: Successfully updated blocklist with {domains.Count} domains.");
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog($"ERROR: MISP Connector failed to update IOCs. Error: {ex.Message}");
            }
            finally
            {
                TimeSpan nextInterval = _updateInterval + TimeSpan.FromSeconds(_random.Next(0, 60));
                _updateTimer?.Change(nextInterval, Timeout.InfiniteTimeSpan);
            }
        }
        private async Task WriteDomainsToCacheAsync(HashSet<string> domains)
        {
            string tempPath = _cacheFilePath + ".tmp";
            await File.WriteAllLinesAsync(tempPath, domains);
            File.Move(tempPath, _cacheFilePath, true);
        }
        #endregion

        #region properties
        public string Description
        {
            get
            {
                return "A focused connector that imports domain IOCs from a MISP server to block malicious domains using direct REST API calls.";
            }
        }
        #endregion
    }
}
