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
using LogExporter.Strategy;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace LogExporter
{
    public sealed class App : IDnsApplication, IDnsQueryLogger, IDisposable
    {
        #region variables

        private const int BULK_INSERT_COUNT = 1000;
        private readonly ExportManager _exportManager = new ExportManager();
        private Task? _backgroundTask;
        private Channel<LogEntry> _channel = default!;
        private AppConfig? _config;
        private CancellationTokenSource? _cts;
        private bool _disposed;
        private IDnsServer? _dnsServer;
        private bool _enableLogging;

        #endregion variables

        #region constructor

        public App()
        { }

        #endregion constructor

        #region IDisposable

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            try
            {
                _cts?.Cancel();
            }
            catch { }

            try
            {
                _backgroundTask?.GetAwaiter().GetResult();
            }
            catch { }

            _exportManager.Dispose();
            GC.SuppressFinalize(this);
        }

        #endregion IDisposable

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            _config = AppConfig.Deserialize(config)
                      ?? throw new DnsClientException("Invalid application configuration.");

            ConfigureStrategies();

            _enableLogging = _exportManager.HasStrategy();
            if (!_enableLogging)
                return Task.CompletedTask;

            // Create bounded channel to avoid memory explosion
            _channel = Channel.CreateBounded<LogEntry>(
                new BoundedChannelOptions(_config!.MaxQueueSize)
                {
                    SingleReader = true,
                    SingleWriter = false,
                    FullMode = BoundedChannelFullMode.DropWrite
                });

            // Start background worker
            _cts = new CancellationTokenSource();
            _backgroundTask = Task.Run(() => BackgroundWorkerAsync(_cts.Token));

            return Task.CompletedTask;
        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request,
                                   IPEndPoint remoteEP, DnsTransportProtocol protocol,
                                   DnsDatagram response)
        {
            if (_enableLogging)
            {
                var entry = new LogEntry(timestamp, remoteEP, protocol, request, response, _config!.EnableEdnsLogging);

                if (!_channel.Writer.TryWrite(entry))
                {
                    _dnsServer?.WriteLog("Log export queue full; dropping entry.");
                }
            }

            // No async, no warning, no overhead
            return Task.CompletedTask;
        }

        #endregion public

        #region private

        private async Task BackgroundWorkerAsync(CancellationToken token)
        {
            var batch = new List<LogEntry>(BULK_INSERT_COUNT);

            try
            {
                // Single-consumer continuous processing
                while (await _channel.Reader.WaitToReadAsync(token))
                {
                    while (batch.Count < BULK_INSERT_COUNT &&
                           _channel.Reader.TryRead(out var entry))
                    {
                        batch.Add(entry);
                    }

                    if (batch.Count > 0)
                    {
                        // Clone for safety
                        var safeBatch = new List<LogEntry>(batch);

                        await _exportManager.ImplementStrategyAsync(safeBatch);

                        batch.Clear();
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Drain channel on cancellation
                await DrainRemainingLogs(batch);
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
        }

        private void ConfigureStrategies()
        {
            // FILE
            _exportManager.RemoveStrategy(typeof(FileExportStrategy));
            if (_config!.FileTarget!.Enabled)
                _exportManager.AddStrategy(new FileExportStrategy(_config.FileTarget.Path));

            // HTTP
            _exportManager.RemoveStrategy(typeof(HttpExportStrategy));
            if (_config.HttpTarget!.Enabled)
                _exportManager.AddStrategy(
                    new HttpExportStrategy(_config.HttpTarget.Endpoint, _config.HttpTarget.Headers));

            // SYSLOG
            _exportManager.RemoveStrategy(typeof(SyslogExportStrategy));
            if (_config.SyslogTarget!.Enabled)
                _exportManager.AddStrategy(
                    new SyslogExportStrategy(_config.SyslogTarget.Address,
                                             _config.SyslogTarget.Port,
                                             _config.SyslogTarget.Protocol));
        }

        private async Task DrainRemainingLogs(List<LogEntry> batch)
        {
            try
            {
                while (_channel.Reader.TryRead(out var entry))
                {
                    batch.Add(entry);

                    if (batch.Count >= BULK_INSERT_COUNT)
                    {
                        await _exportManager.ImplementStrategyAsync(new List<LogEntry>(batch));
                        batch.Clear();
                    }
                }

                if (batch.Count > 0)
                {
                    await _exportManager.ImplementStrategyAsync(batch);
                    batch.Clear();
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
        }

        #endregion private

        #region properties

        public string Description =>
            "Allows exporting query logs to third party sinks. Supports exporting to File, HTTP endpoint, and Syslog.";

        #endregion properties
    }
}