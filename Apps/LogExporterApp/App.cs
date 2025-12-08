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
using LogExporter.Sinks;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace LogExporter
{
    public sealed class App : IDnsApplication, IDnsQueryLogger
    {
        #region variables

        const int BULK_INSERT_COUNT = 1000;
        readonly SinkDispatcher _sinkDispatcher;
        Task? _backgroundTask;
        Channel<LogEntry> _channel = default!;
        AppConfig? _config;
        CancellationTokenSource? _cts;
        bool _disposed;
        IDnsServer? _dnsServer;
        volatile bool _enableLogging; // volatile to improve cross-thread visibility
        long _droppedCount;
        DateTime _lastDropLog = DateTime.UtcNow;
        static readonly TimeSpan DropLogInterval = TimeSpan.FromSeconds(5);
        long _lastDropTicks;
        #endregion variables

        #region constructor
        public App()
        {
            _sinkDispatcher = new SinkDispatcher();
        }
        #endregion constructor

        #region IDisposable
        ~App() => Dispose();

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            // Stop accepting new entries immediately; cannot throw.
            _enableLogging = false;

            // ADR: Previously Dispose swallowed all exceptions, hiding exporter or
            // shutdown failures and making diagnosis impossible. We now log every
            // unexpected exception without rethrowing, preserving best-effort teardown
            // while ensuring operational visibility.
            try
            {
                try
                {
                    _channel?.Writer.TryComplete();
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(ex);
                }

                try
                {
                    _cts?.Cancel();
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(ex);
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }

            try
            {
                _backgroundTask?.GetAwaiter().GetResult();
            }
            catch (OperationCanceledException)
            {
                // Expected; no log needed.
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
            _cts?.Dispose();
            _sinkDispatcher.Dispose();
            GC.SuppressFinalize(this);
        }

        #endregion IDisposable

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            _dnsServer = dnsServer;
            _config = AppConfig.Deserialize(config)
                      ?? throw new DnsClientException("Invalid application configuration.");

            ConfigureSinks();

            // If no sinks exist, never enable logging.
            if (!_sinkDispatcher.Any())
            {
                _enableLogging = false;
                return Task.CompletedTask;
            }

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

            // ADR: _enableLogging is intentionally set last so that any caller observing
            // _enableLogging is true can rely on the entire logging pipeline being fully
            // constructed (channel, CTS, background worker). This prevents subtle race
            // conditions where concurrent InsertLogAsync calls see "enabled" before internal
            // structures are ready.
            _enableLogging = true;

            return Task.CompletedTask;
        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request,
            IPEndPoint remoteEP, DnsTransportProtocol protocol,
            DnsDatagram response)
        {
            if (_enableLogging)
            {
                LogEntry entry = new LogEntry(timestamp, remoteEP, protocol, request, response, _config!.EnableEdnsLogging);

                if (!_channel.Writer.TryWrite(entry))
                {
                    Interlocked.Increment(ref _droppedCount);

                    long nowTicks = DateTime.UtcNow.Ticks;
                    long lastTicks = Volatile.Read(ref _lastDropTicks);
                    if (new TimeSpan(nowTicks - lastTicks) >= DropLogInterval && Interlocked.CompareExchange(ref _lastDropTicks, nowTicks, lastTicks) == lastTicks)
                    {
                        long dropped = Interlocked.Exchange(ref _droppedCount, 0);
                        _dnsServer?.WriteLog($"Log export queue full; dropped {dropped} entries over last {DropLogInterval.TotalSeconds:F0}s.");
                    }
                }
            }

            return Task.CompletedTask;
        }

        #endregion public

        #region private

        private async Task BackgroundWorkerAsync(CancellationToken token)
        {
            // ADR: Reuse this list buffer to avoid GC churn during high-volume logging.
            List<LogEntry> batch = new List<LogEntry>(BULK_INSERT_COUNT);

            try
            {
                while (await _channel.Reader.WaitToReadAsync(token).ConfigureAwait(false))
                {
                    while (batch.Count < BULK_INSERT_COUNT &&
                           _channel.Reader.TryRead(out LogEntry? entry))
                    {
                        if (token.IsCancellationRequested)
                            break;

                        batch.Add(entry);
                    }

                    if (batch.Count > 0)
                    {
                        await _sinkDispatcher.DispatchAsync(batch, token).ConfigureAwait(false);
                        batch.Clear(); // REUSE — do not reassign
                    }
                }
            }
            catch (OperationCanceledException)
            {
                await DrainRemainingLogs(batch, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
                await DrainRemainingLogs(batch, token).ConfigureAwait(false);
            }
        }

        private void ConfigureSinks()
        {
            _sinkDispatcher.Remove(typeof(ConsoleSink));
            if (_config!.ConsoleSinkConfig != null && _config.ConsoleSinkConfig.Enabled)
                _sinkDispatcher.Add(new ConsoleSink());

            _sinkDispatcher.Remove(typeof(FileSink));
            if (_config.FileSinkConfig?.Enabled is true)
                _sinkDispatcher.Add(new FileSink(_config.FileSinkConfig.Path));

            _sinkDispatcher.Remove(typeof(HttpSink));
            if (_config.HttpSinkConfig?.Enabled is true)
            {
                _sinkDispatcher.Add(
                    new HttpSink(_config.HttpSinkConfig.Endpoint, _config.HttpSinkConfig.Headers));
            }

            _sinkDispatcher.Remove(typeof(SyslogSink));
            if (_config.SyslogSinkConfig?.Enabled is true)
            {
                _sinkDispatcher.Add(
                    new SyslogSink(_config.SyslogSinkConfig.Address,
                                             _config.SyslogSinkConfig.Port!.Value,
                                             _config.SyslogSinkConfig.Protocol));
            }
        }

        private async Task DrainRemainingLogs(List<LogEntry> batch, CancellationToken token)
        {
            try
            {
                while (_channel!.Reader.TryRead(out LogEntry? item))
                {
                    batch.Add(item);

                    if (batch.Count >= BULK_INSERT_COUNT)
                    {
                        await _sinkDispatcher.DispatchAsync(batch, CancellationToken.None).ConfigureAwait(false);
                        batch.Clear();  // reuse instead of creating new list
                    }
                }

                if (batch.Count > 0)
                {
                    await _sinkDispatcher.DispatchAsync(batch, CancellationToken.None).ConfigureAwait(false);
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