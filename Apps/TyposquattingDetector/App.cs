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
                        using HttpClient httpClient = CreateHttpClient(domainList, _config.DisableTlsValidation);
                        using Stream stream = await httpClient.GetStreamAsync(domainList);
                        using FileStream fs = new FileStream(_domainListFilePath, FileMode.Create, FileAccess.Write, FileShare.None);
                        await stream.CopyToAsync(fs, _appShutdownCts.Token);

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

                    string hashPath = Path.Combine(configDir, "majestic_million.csv.sha256");
                    string? previousHash = null;
                    if (File.Exists(hashPath))
                    {
                        // Safely read the first line; handle empty or corrupted hash file
                        previousHash = File.ReadLines(hashPath).FirstOrDefault()?.Trim();
                    }
                    if (!string.IsNullOrEmpty(previousHash) && string.Equals(previousHash, sha256, StringComparison.OrdinalIgnoreCase))
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
            Result res = _detector.Check(question.Name);
            if (res.IsSuspicious == false)
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
                    throw new FormatException($"Invalid unit '{unit}' in update interval. Allowed units are 'm', 'h', 'd', 'w'.");
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

            // If init already checked hash and found no change, you can skip the *first* interval check.
            bool skipFirst = !Volatile.Read(ref _changed);

            // Jitter to avoid stampede after restart
            await Task.Delay(TimeSpan.FromSeconds(Random.Shared.Next(0, 60)), cancellationToken);

            while (!cancellationToken.IsCancellationRequested)
            {
                if (skipFirst)
                {
                    skipFirst = false;
                }
                else
                {
                    bool flowControl = await TryUpdate(cancellationToken);
                    if (!flowControl)
                        break;
                }

                await timer.WaitForNextTickAsync(cancellationToken);
            }
        }

        private async Task<bool> TryUpdate(CancellationToken cancellationToken)
        {
            try
            {
                bool changed = await DownloadIfChangedAndReloadAsync(cancellationToken);
                if (changed)
                    _dnsServer!.WriteLog("Typosquatting Detector: Domain list updated and detector reloaded.");
            }
            catch (OperationCanceledException)
            {
                _dnsServer!.WriteLog("Typosquatting Detector: Update loop is shutting down gracefully.");
                return false;
            }
            catch (Exception ex)
            {
                _dnsServer!.WriteLog($"ERROR: Typosquatting Detector update failed. {ex.Message}");
                _dnsServer!.WriteLog(ex);
            }

            return true;
        }

        private async Task<bool> DownloadIfChangedAndReloadAsync(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested) return false;

            string configDir = _dnsServer!.ApplicationFolder;
            string majesticPath = Path.GetFullPath(_domainListFilePath!);

            if (!majesticPath.StartsWith(configDir, StringComparison.OrdinalIgnoreCase))
                throw new SecurityException("Access Denied");

            string hashPath = Path.Combine(configDir, "majestic_million.csv.sha256");
            string tempPath = Path.Combine(configDir, "majestic_million.csv.tmp");

            // Avoid concurrent temp collisions (paranoia)
            if (File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { /* ignore */ }
            }

            _dnsServer.WriteLog("Typosquatting Detector: Checking for updated domain list...");

            // Download to temp and compute hash while writing (single pass)
            string newHash;
            Uri domainList = new Uri(DefaultDomainListUrl);

            using (HttpClient httpClient = CreateHttpClient(domainList, _config!.DisableTlsValidation))
            using (Stream netStream = await httpClient.GetStreamAsync(domainList, cancellationToken))
            using (FileStream fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 128 * 1024, useAsync: true))
            using (SHA256 sha = SHA256.Create())
            using (CryptoStream crypto = new CryptoStream(fs, sha, CryptoStreamMode.Write, leaveOpen: true))
            {
                await netStream.CopyToAsync(crypto, 128 * 1024, cancellationToken);
                await crypto.FlushAsync(cancellationToken);
                crypto.FlushFinalBlock();

                newHash = Convert.ToHexString(sha.Hash!);
            }

            // Read old hash (if any)
            string? oldHash = null;
            if (File.Exists(hashPath))
                oldHash = File.ReadLines(hashPath).FirstOrDefault()?.Trim();

            if (!string.IsNullOrEmpty(oldHash) && string.Equals(oldHash, newHash, StringComparison.OrdinalIgnoreCase))
            {
                // No change → delete temp
                try { File.Delete(tempPath); } catch { /* ignore */ }
                Volatile.Write(ref _changed, false);
                _dnsServer.WriteLog("Typosquatting Detector: No change in domain list.");
                return false;
            }

            // Changed → replace live file atomically (temp is in same directory)
            // File.Move(tempPath, majesticPath, overwrite: true) is supported on modern .NET.
            File.Move(tempPath, majesticPath, overwrite: true);

            await File.WriteAllTextAsync(hashPath, newHash, cancellationToken);
            Volatile.Write(ref _changed, true);

            // Reload detector from the updated file
            await UpdateDomainListAsync(cancellationToken);

            return true;
        }

        private Task UpdateDomainListAsync(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested) return Task.CompletedTask;

            try
            {
                _dnsServer!.WriteLog("Typosquatting Detector: Processing domain list...");

                string configDirFullPath = Path.GetFullPath(_dnsServer.ApplicationFolder);

                string majesticPath = Path.GetFullPath(_domainListFilePath!);
                EnsureUnderBaseSymlinkSafe(configDirFullPath, majesticPath);

                string customListPath = string.Empty;
                if (!string.IsNullOrWhiteSpace(_config!.Path))
                {
                    customListPath = Path.GetFullPath(_config.Path);
                    EnsureUnderBaseSymlinkSafe(configDirFullPath, customListPath);
                }

                TyposquattingDetector newDetector = new TyposquattingDetector(majesticPath, customListPath, _config.FuzzyMatchThreshold);
                TyposquattingDetector? oldDetector = Interlocked.Exchange(ref _detector, newDetector);
                oldDetector?.Dispose();

                _dnsServer.WriteLog("Typosquatting Detector: Processing completed.");
            }
            catch (IOException ex)
            {
                _dnsServer!.WriteLog($"ERROR: Failed to read cache file '{_domainListFilePath}'. Error: {ex.Message}");
            }

            return Task.CompletedTask;
        }

        private static void EnsureUnderBaseSymlinkSafe(string baseDirFullPath, string candidateFullPath)
        {
            baseDirFullPath = Path.GetFullPath(baseDirFullPath);
            candidateFullPath = Path.GetFullPath(candidateFullPath);

            // First: lexical traversal guard
            string rel = Path.GetRelativePath(baseDirFullPath, candidateFullPath);
            if (rel == ".." ||
                rel.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
                rel.StartsWith(".." + Path.AltDirectorySeparatorChar, StringComparison.Ordinal))
                throw new SecurityException("Access Denied");

            // Second: resolve each component and block symlink escape
            var current = new DirectoryInfo(candidateFullPath);
            while (current != null &&
                   !current.FullName.Equals(baseDirFullPath, StringComparison.OrdinalIgnoreCase))
            {
                // If any component is a symlink → reject
                if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                    throw new SecurityException("Access Denied");

                current = current.Parent;
            }

            // If we walked to filesystem root without hitting base folder → reject
            if (current == null)
                throw new SecurityException("Access Denied");
        }

        #endregion private

        #region properties

        public string Description
        {
            get
            {
                return "Evaluates queried domains against a trusted corpus and flags visually similar near-matches as potential typosquatting. Allows blocking of suspicious queries and exposes structured detection details. The fuzzy-match threshold and optional custom domain list are operator-tunable; adjust cautiously to reduce false-positive impact.";
            }
        }

        #endregion properties
    }
}