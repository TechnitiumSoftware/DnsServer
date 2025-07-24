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
using System.Collections.Frozen;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;

namespace MispConnector
{
    public sealed class App : IDnsApplication, IDnsRequestBlockingHandler
    {
        #region variables

        readonly Random _random = new Random();
        string _cacheFilePath;
        Config _config;
        IDnsServer _dnsServer;
        private FrozenSet<string> _globalBlocklist = FrozenSet<string>.Empty;
        HttpClient _httpClient;

        Uri _mispApiUrl;

        DnsSOARecordData _soaRecord;
        TimeSpan _updateInterval;

        Timer _updateTimer;

        #endregion variables

        #region IDisposable

        public void Dispose()
        {
            _updateTimer?.Dispose();
            _httpClient?.Dispose();
        }

        #endregion IDisposable

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            try
            {
                string configDir = _dnsServer.ApplicationFolder;
                Directory.CreateDirectory(configDir);
                _cacheFilePath = Path.Combine(configDir, "misp_domain_cache.txt");

                _soaRecord = new DnsSOARecordData(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, 60);

                JsonSerializerOptions options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                _config = JsonSerializer.Deserialize<Config>(config, options);

                Validator.ValidateObject(_config, new ValidationContext(_config), validateAllProperties: true);

                _updateInterval = ParseUpdateInterval(_config.UpdateInterval);

                Uri mispServerUrl = new Uri(_config.MispServerUrl);
                _mispApiUrl = new Uri(mispServerUrl, "/attributes/restSearch");
                _httpClient = CreateHttpClient(mispServerUrl, _config.DisableTlsValidation);

                await LoadBlocklistFromCacheAsync();
                _updateTimer = new Timer(async _ =>
                {
                    try
                    {
                        await UpdateIocsAsync();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog($"FATAL: The MispConnector update task failed unexpectedly. Error: {ex.Message}");
                        _dnsServer.WriteLog(ex);
                    }
                }, null, TimeSpan.FromSeconds(_random.Next(5, 30)), Timeout.InfiniteTimeSpan);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog($"FATAL: MISP Connector failed to initialize. Check configuration. Error: {ex.Message}");
                _dnsServer.WriteLog(ex);
            }
        }

        public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            return Task.FromResult(false);
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (_config?.EnableBlocking != true)
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];
            if (!IsDomainBlocked(question.Name, out string blockedDomain))
            {
                return Task.FromResult<DnsDatagram>(null);
            }

            string blockingReport = $"source=misp-connector;domain={blockedDomain}";
            EDnsOption[] options = null;
            if (_config.AddExtendedDnsError && request.EDNS is not null)
            {
                options = new EDnsOption[] { new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, blockingReport)) };
            }

            if (_config.AllowTxtBlockingReport && question.Type == DnsResourceRecordType.TXT)
            {
                DnsResourceRecord[] answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecordData(blockingReport)) };
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
                                    additional: null,
                                    udpPayloadSize: request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize,
                                    ednsFlags: EDnsHeaderFlags.None,
                                    options: options
                                ));
            }

            DnsResourceRecord[] authority = { new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) };
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
                            additional: null,
                            udpPayloadSize: request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize,
                            ednsFlags: EDnsHeaderFlags.None,
                            options: options
                        ));
        }

        #endregion public

        #region private

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

        private async Task<bool> CheckTcpPortAsync(Uri serverUri)
        {
            string host = serverUri.DnsSafeHost;
            int port = serverUri.Port;
            TimeSpan timeout = TimeSpan.FromSeconds(5);

            _dnsServer.WriteLog($"Performing pre-flight TCP check for {host}:{port} with a {timeout.TotalSeconds}-second timeout...");

            try
            {
                using CancellationTokenSource cts = new CancellationTokenSource(timeout);
                using TcpClient client = new TcpClient();

                await client.ConnectAsync(host, port, cts.Token);

                _dnsServer.WriteLog($"Pre-flight TCP check successful for {host}:{port}.");
                return true;
            }
            catch (OperationCanceledException)
            {
                _dnsServer.WriteLog($"ERROR: Pre-flight TCP check failed: Connection to {host}:{port} timed out after {timeout.TotalSeconds} seconds. Check firewall rules or network route.");
                return false;
            }
            catch (SocketException ex)
            {
                _dnsServer.WriteLog($"ERROR: Pre-flight TCP check failed: A network error occurred for {host}:{port}. Error: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog($"ERROR: An unexpected error occurred during the pre-flight TCP check for {host}:{port}. Error: {ex.Message}");
                return false;
            }
        }

        private HttpClient CreateHttpClient(Uri serverUrl, bool disableTlsValidation)
        {
            SocketsHttpHandler handler = new SocketsHttpHandler
            {
                Proxy = _dnsServer.Proxy,
                UseProxy = _dnsServer.Proxy != null,
                SslOptions = new SslClientAuthenticationOptions(),
                ConnectTimeout = TimeSpan.FromSeconds(15)
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

        private async Task<FrozenSet<string>> FetchDomainsFromMispAsync()
        {
            HashSet<string> domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int page = 1;
            int limit = _config.PaginationLimit;
            bool hasMorePages = true;

            _dnsServer.WriteLog($"Starting paginated fetch from MISP API with a page size of {limit}...");
            const int maxRetries = 3;

            while (hasMorePages)
            {
                int attempt = 0;
                MispResponse mispResponse = null;

                while (attempt < maxRetries)
                {
                    attempt++;
                    try
                    {
                        MispRequestBody requestBody = new MispRequestBody
                        {
                            Type = "domain",
                            To_ids = true,
                            Deleted = false,
                            Last = _config.MaxIocAge,
                            Limit = limit,
                            Page = page
                        };
                        StringContent requestContent = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");

                        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, _mispApiUrl) { Content = requestContent };
                        request.Headers.Add("Authorization", _config.MispApiKey);
                        request.Headers.Add("Accept", "application/json");

                        _dnsServer.WriteLog($"Fetching page {page}, attempt {attempt}/{maxRetries}...");
                        using HttpResponseMessage response = await _httpClient.SendAsync(request);

                        if (!response.IsSuccessStatusCode)
                        {
                            // This is a definitive failure from the server (e.g., 403, 500).
                            // We should not retry this. Abort immediately.
                            string errorBody = await response.Content.ReadAsStringAsync();
                            throw new HttpRequestException($"MISP API returned a non-success status code: {(int)response.StatusCode}. Body: {errorBody}", null, response.StatusCode);
                        }

                        await using Stream responseStream = await response.Content.ReadAsStreamAsync();
                        mispResponse = await JsonSerializer.DeserializeAsync<MispResponse>(responseStream);

                        break;
                    }
                    catch (Exception ex) when (ex is HttpRequestException || ex is SocketException || ex is OperationCanceledException)
                    {
                        // These are likely transient network errors, so we should retry.
                        _dnsServer.WriteLog($"WARNING: A transient network error occurred on page {page}, attempt {attempt}/{maxRetries}. Error: {ex.Message}");
                        if (attempt < maxRetries)
                        {
                            TimeSpan delay = TimeSpan.FromSeconds(Math.Pow(2, attempt)) + TimeSpan.FromMilliseconds(Random.Shared.Next(0, 1000));
                            _dnsServer.WriteLog($"Waiting for {delay.TotalSeconds:F1} seconds before retrying...");
                            await Task.Delay(delay);
                        }
                        else
                        {
                            // All retries have failed for this page.
                            _dnsServer.WriteLog($"ERROR: Failed to fetch page {page} after {maxRetries} attempts. Aborting entire update cycle.");
                            throw;
                        }
                    }
                }

                List<MispAttribute> attributes = mispResponse?.Response?.Attribute;
                if (attributes == null || attributes.Count == 0)
                {
                    hasMorePages = false;
                    continue;
                }

                foreach (MispAttribute attribute in attributes)
                {
                    string domain = attribute.Value?.Trim().ToLowerInvariant();
                    if (!string.IsNullOrEmpty(domain) && DnsClient.IsDomainNameValid(domain))
                    {
                        domains.Add(domain);
                    }
                }

                // Assumption: If we received fewer items than our limit, it must be the last page.
                if (attributes.Count < limit)
                {
                    hasMorePages = false;
                }
                else
                {
                    page++;
                }
            }

            _dnsServer.WriteLog($"Finished paginated fetch. Freezing {domains.Count} domains for optimal read performance...");
            return domains.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
        }

        private bool IsDomainBlocked(string domain, out string foundZone)
        {
            FrozenSet<string> currentBlocklist = _globalBlocklist;

            ReadOnlySpan<char> currentSpan = domain.AsSpan();

            while (true)
            {
                // To look up in a HashSet<string>, we must provide a string.
                string key = new string(currentSpan);
                if (currentBlocklist.TryGetValue(key, out foundZone))
                {
                    return true;
                }

                int dotIndex = currentSpan.IndexOf('.');
                if (dotIndex == -1)
                {
                    break; // No more parent domains.
                }

                // Slice to the parent domain view. No allocation here.
                currentSpan = currentSpan.Slice(dotIndex + 1);
            }

            foundZone = null;
            return false;
        }

        private async Task LoadBlocklistFromCacheAsync()
        {
            if (!File.Exists(_cacheFilePath)) return;
            try
            {
                FrozenSet<string> domains = (await File.ReadAllLinesAsync(_cacheFilePath)).ToHashSet(StringComparer.OrdinalIgnoreCase).ToFrozenSet(StringComparer.OrdinalIgnoreCase);
                ReloadBlocklist(domains);
                _dnsServer.WriteLog($"MISP Connector: Loaded {domains.Count} domains from cache.");
            }
            catch (IOException ex)
            {
                _dnsServer.WriteLog($"ERROR: Failed to read cache file '{_cacheFilePath}'. Error: {ex.Message}");
            }
        }

        private void ReloadBlocklist(FrozenSet<string> newBlocklist)
        {
            Interlocked.Exchange(ref _globalBlocklist, newBlocklist);
        }

        private async Task UpdateIocsAsync()
        {
            try
            {
                if (!await CheckTcpPortAsync(new Uri(_config.MispServerUrl)))
                {
                    return;
                }

                _dnsServer.WriteLog("MISP Connector: Starting IOC update...");
                FrozenSet<string> domains = await FetchDomainsFromMispAsync();
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

        private async Task WriteDomainsToCacheAsync(FrozenSet<string> domains)
        {
            string tempPath = _cacheFilePath + ".tmp";
            await File.WriteAllLinesAsync(tempPath, domains);
            File.Move(tempPath, _cacheFilePath, true);
        }

        #endregion private

        #region properties

        public string Description
        {
            get
            {
                return "A focused connector that imports domain IOCs from a MISP server to block malicious domains using direct REST API calls.";
            }
        }

        #endregion properties

        private class Config
        {
            [JsonPropertyName("addExtendedDnsError")]
            public bool AddExtendedDnsError { get; set; } = true;

            [JsonPropertyName("allowTxtBlockingReport")]
            public bool AllowTxtBlockingReport { get; set; } = true;

            [JsonPropertyName("disableTlsValidation")]
            public bool DisableTlsValidation { get; set; } = false;

            [JsonPropertyName("enableBlocking")]
            public bool EnableBlocking { get; set; } = true;
            [JsonPropertyName("maxIocAge")]
            [Required(ErrorMessage = "maxIocAge is a required configuration property.")]
            [RegularExpression(@"^\d+[mhd]$", ErrorMessage = "Invalid interval format. Use a number followed by 'm', 'h', or 'd' (e.g., '90m', '2h', '7d').", MatchTimeoutInMilliseconds = 3000)]
            public string MaxIocAge { get; set; }

            [JsonPropertyName("mispApiKey")]
            [Required(ErrorMessage = "mispApiKey is a required configuration property.")]
            [MinLength(1, ErrorMessage = "mispApiKey cannot be empty.")]
            public string MispApiKey { get; set; }

            [JsonPropertyName("mispServerUrl")]
            [Required(ErrorMessage = "mispServerUrl is a required configuration property.")]
            [Url(ErrorMessage = "mispServerUrl must be a valid URL.")]
            public string MispServerUrl { get; set; }
            [JsonPropertyName("paginationLimit")]
            public int PaginationLimit { get; set; } = 5000;

            [JsonPropertyName("updateInterval")]
            [Required(ErrorMessage = "updateInterval is a required configuration property.")]
            [RegularExpression(@"^\d+[mhd]$", ErrorMessage = "Invalid interval format. Use a number followed by 'm', 'h', or 'd' (e.g., '90m', '2h', '7d').", MatchTimeoutInMilliseconds = 3000)]
            public string UpdateInterval { get; set; }
        }

        private class MispAttribute
        {
            [JsonPropertyName("value")]
            public string Value { get; set; }
        }

        private class MispRequestBody
        {
            [JsonPropertyName("deleted")]
            public bool Deleted { get; set; }

            [JsonPropertyName("last")]
            public string Last { get; set; }

            [JsonPropertyName("limit")]
            public int Limit { get; set; }

            [JsonPropertyName("page")]
            public int Page { get; set; }

            [JsonPropertyName("to_ids")]
            public bool To_ids { get; set; }

            [JsonPropertyName("type")]
            public string Type { get; set; }
        }

        private class MispResponse
        {
            [JsonPropertyName("response")]
            public MispResponseData Response { get; set; }
        }

        private class MispResponseData
        {
            [JsonPropertyName("Attribute")]
            public List<MispAttribute> Attribute { get; set; }
        }
    }
}