/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)
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
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;

namespace TyposquattingDetector
{
    public sealed partial class App : IDnsApplication, IDnsRequestBlockingHandler
    {
        #region variables

        private const string DefaultDomainListUrl = "https://downloads.majestic.com/majestic_million.csv";
        private CancellationTokenSource? _appShutdownCts;
        private Config? _config;
        private volatile TyposquattingDetector? _detector;
        private IDnsServer? _dnsServer;
        private string? _domainListFilePath;
        private HttpClient? _httpClient;
        private DnsSOARecordData? _soaRecord;
        private TimeSpan _updateInterval;
        private Task? _updateLoopTask;
        private static readonly JsonSerializerOptions _options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        private bool _changed = false;
        #endregion variables

        #region IDisposable

        public void Dispose()
        {
            _appShutdownCts?.Cancel();
            try
            {
                if (_updateLoopTask != null)
                {
                    _ = Task.WhenAny(_updateLoopTask, Task.Delay(TimeSpan.FromSeconds(2))).GetAwaiter().GetResult();
                }
            }
            catch
            {
            }
            finally
            {
                _appShutdownCts?.Dispose();
                _httpClient?.Dispose();
            }
        }

        #endregion IDisposable

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            try
            {
                _soaRecord = new DnsSOARecordData(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, 60);

                try
                {
                    _config = JsonSerializer.Deserialize<Config>(config, _options);
                }
                catch (Exception e)
                {
                    throw new AggregateException("Invalid configuration for TyposquattingDetector app.", e);
                }

                Validator.ValidateObject(_config!, new ValidationContext(_config!), validateAllProperties: true);
                _updateInterval = ParseUpdateInterval(_config!.UpdateInterval);
                _appShutdownCts = new CancellationTokenSource();

                string configDir = _dnsServer.ApplicationFolder;
                Directory.CreateDirectory(configDir);
                _domainListFilePath = Path.Combine(configDir, "majestic_million.csv");

                if (!Path.Exists(_domainListFilePath))
                {
                    _dnsServer.WriteLog($"Typosquatting Detector: Started downloading domain list to path: '{_domainListFilePath}'.");

                    try
                    {
                        Uri domainList = new Uri(DefaultDomainListUrl);
                        _httpClient = CreateHttpClient(domainList, _config.DisableTlsValidation);

                        using (Stream stream = await _httpClient.GetStreamAsync(domainList))
                        using (FileStream fs = new FileStream(_domainListFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                        {
                            await stream.CopyToAsync(fs, _appShutdownCts.Token);
                        }

                        _dnsServer.WriteLog($"Typosquatting Detector: Downloaded domain list from '{domainList}' to '{_domainListFilePath}'.");
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog($"FATAL: Failed to download domain list. Error: {ex.Message}");
                        _dnsServer.WriteLog(ex);
                    }
                }
                else
                {
                    _dnsServer.WriteLog($"Typosquatting Detector: Domain list exists at path: '{_domainListFilePath}'.");
                }


                // Re-read file to calculate hash (or use a CryptoStream during download)
                using (FileStream fs = new FileStream(_domainListFilePath, FileMode.Open, FileAccess.Read))
                {
                    string sha256 = Convert.ToHexString(await SHA256.HashDataAsync(fs));
                    _dnsServer.WriteLog($"Typosquatting Detector: SHA256 hash of downloaded domain list: {sha256}");

                    var hashPath = Path.Combine(configDir, "majestic_million.csv.sha256");
                    if (File.Exists(hashPath) && File.ReadLines(hashPath).ToArray()[0] == sha256)
                    {
                        _changed = false;
                        _dnsServer.WriteLog($"Typosquatting Detector: Downloaded domain list is identical to the previous one. No changes made.");
                    }
                    else
                    {
                        await File.WriteAllTextAsync(hashPath, sha256, _appShutdownCts.Token);
                        _changed = true;
                        _dnsServer.WriteLog($"Typosquatting Detector: Hash file is saved.");
                    }
                }


                // We await this so InitializeAsync doesn't finish until the detector is ready.
                await UpdateDomainListAsync(_appShutdownCts.Token);

                // Now that _detector is initiated, start the periodic update loop
                _updateLoopTask = StartUpdateLoopAsync(_appShutdownCts.Token);

                _ = _updateLoopTask.ContinueWith(t =>
                           {
                               if (t.IsFaulted)
                               {
                                   _dnsServer.WriteLog($"FATAL: Update loop terminated unexpectedly: {t.Exception?.GetBaseException().Message}");
                                   _dnsServer.WriteLog(t.Exception);
                               }
                           }, TaskContinuationOptions.OnlyOnFaulted);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog($"FATAL: Typosquatting Detector failed to initialize. Check configuration. Error: {ex.Message}");
                _dnsServer.WriteLog(ex);
            }
        }

        public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            return Task.FromResult(false);
        }

        public Task<DnsDatagram?> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (_config?.Enable != true)
            {
                return Task.FromResult<DnsDatagram?>(null);
            }

            // Download takes time. Let's not break the app.
            if (_detector is null)
            {
                return Task.FromResult<DnsDatagram?>(null);
            }

            DnsQuestionRecord question = request.Question[0];
            var res = _detector.Check(question.Name);
            if (res.Status == DetectionStatus.Clean)
            {
                return Task.FromResult<DnsDatagram?>(null);
            }

            string blockingReport = $"source=typosquatting-detector;domain={res.Query};severity={res.Severity};reason={res.Reason}";

            EDnsOption[]? options = null;
            if (_config.AddExtendedDnsError && request.EDNS is not null)
            {
                options = new EDnsOption[] { new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, blockingReport)) };
            }

            if (_config.AllowTxtBlockingReport && question.Type == DnsResourceRecordType.TXT)
            {
                DnsResourceRecord[] answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecordData(blockingReport)) };
                return Task.FromResult<DnsDatagram?>(new DnsDatagram(
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
                                    udpPayloadSize: request.EDNS is null ? ushort.MinValue : _dnsServer!.UdpPayloadSize,
                                    ednsFlags: EDnsHeaderFlags.None,
                                    options: options
                                ));
            }

            DnsResourceRecord[] authority = { new DnsResourceRecord(question.Name, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) };
            return Task.FromResult<DnsDatagram?>(new DnsDatagram(
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
                            udpPayloadSize: request.EDNS is null ? ushort.MinValue : _dnsServer!.UdpPayloadSize,
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
                throw new FormatException("Update interval is not in a valid format (e.g., '30m', '12h', '1d', '2w').");
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

                case "w":
                    return TimeSpan.FromDays(value * 7);

                default:
                    throw new FormatException($"Invalid unit '{unit}' in update interval. Allowed units are 'm', 'h', 'd'. 'w'.");
            }
        }

        private HttpClient CreateHttpClient(Uri serverUrl, bool disableTlsValidation)
        {
            HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
            handler.Proxy = _dnsServer!.Proxy;
            handler.NetworkType = _dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
            handler.DnsClient = _dnsServer;

            if (disableTlsValidation)
            {
                handler.InnerHandler.SslOptions.RemoteCertificateValidationCallback = delegate (object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
                {
                    return true;
                };

                _dnsServer.WriteLog($"WARNING: TLS certificate validation is DISABLED for server: {serverUrl}");
            }

            return new HttpClient(handler);
        }

        private async Task StartUpdateLoopAsync(CancellationToken cancellationToken)
        {
            using PeriodicTimer timer = new PeriodicTimer(_updateInterval);

            if (!_changed)
            {
                // Nothing changed, skip first update
            }
            else
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    bool flowControl = await TryUpdate(cancellationToken);
                    if (!flowControl)
                    {
                        break;
                    }

                    await timer.WaitForNextTickAsync(cancellationToken);
                }
            }
            await Task.Delay(TimeSpan.FromSeconds(Random.Shared.Next(0, 60)), cancellationToken);
        }

        private async Task<bool> TryUpdate(CancellationToken cancellationToken)
        {
            try
            {
                await UpdateDomainListAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _dnsServer!.WriteLog("Update loop is shutting down gracefully.");
                return false;
            }
            catch (Exception ex)
            {
                _dnsServer!.WriteLog($"FATAL: The Typosquatting Detector update task failed unexpectedly. Error: {ex.Message}");
                _dnsServer.WriteLog(ex);
            }

            return true;
        }

        private async Task UpdateDomainListAsync(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested) return;

            try
            {
                _dnsServer!.WriteLog($"Typosquatting Detector: Processing domain list...");
                string safePath = string.Empty;
                safePath = Path.GetFullPath(_domainListFilePath!);
                if (!safePath.StartsWith(_dnsServer.ApplicationFolder)) throw new SecurityException("Access Denied");

                var oldDetector = _detector;
                _detector = new TyposquattingDetector(_domainListFilePath!, safePath, _config!.FuzzyMatchThreshold);
                oldDetector?.Dispose();
                _dnsServer.WriteLog($"Typosquatting Detector: Processing completed.");
            }
            catch (IOException ex)
            {
                _dnsServer!.WriteLog($"ERROR: Failed to read cache file '{_domainListFilePath}'. Error: {ex.Message}");
            }
        }

        #endregion private

        #region properties

        public string Description
        {
            get
            {
                return "Downloads Alexa toip 1 million domains, runs a fuzzy logic, and if the match is high but not 100, it may be a typosquatting attempt.";
            }
        }

        #endregion properties
    }
}