/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare
Copyright (C) 2025  Zafer Balkan

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
using LogExporter.Pipeline;
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

        private const int BULK_INSERT_COUNT = 1000;

        private readonly SinkDispatcher _sinkDispatcher;
        private readonly PipelineDispatcher _enrichmentDispatcher;

        // Stage 1 buffer: transformed LogEntry waiting for enrichment
        private Channel<LogEntry> _transformChannel = default!;

        // Stage 2 buffer: enriched LogEntry waiting for dispatch
        private Channel<LogEntry> _enrichedChannel = default!;

        private Task? _backgroundTask;
        private AppConfig? _config;
        private bool _disposed;
        private IDnsServer? _dnsServer;
        private volatile bool _enableLogging; // volatile to improve cross-thread visibility

        private long _droppedCount;
        private static readonly TimeSpan DropLogInterval = TimeSpan.FromSeconds(5);
        private long _lastDropTicks;

        #endregion variables

        #region constructor

        public App()
        {
            _sinkDispatcher = new SinkDispatcher();
            _enrichmentDispatcher = new PipelineDispatcher();
            _lastDropTicks = DateTime.UtcNow.Ticks;
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

            // Best-effort shutdown: complete input channel so workers drain and exit.
            try
            {
                try
                {
                    _transformChannel?.Writer.TryComplete();
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

            // Wait for background pipeline to finish.
            try
            {
                _backgroundTask?.GetAwaiter().GetResult();
            }
            catch (OperationCanceledException)
            {
                // Not expected without explicit cancellation, but safe to ignore.
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }

            // Dispose sinks and enrichment dispatcher defensively.
            try
            {
                _sinkDispatcher.Dispose();
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }

            try
            {
                _enrichmentDispatcher.Dispose();
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }

            GC.SuppressFinalize(this);
        }

        #endregion IDisposable

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            _dnsServer = dnsServer;

            try
            {
                _config = AppConfig.Deserialize(config)
                          ?? throw new DnsClientException("Invalid application configuration.");

                ConfigurePipeline();

                ConfigureSinks();
            }
            catch (Exception ex)
            {
                // Fail fast but log with context; do not partially initialize pipeline.
                _dnsServer?.WriteLog(ex);
                _enableLogging = false;
                throw;
            }

            // If no sinks exist, never enable logging.
            if (!_sinkDispatcher.Any())
            {
                _enableLogging = false;
                return Task.CompletedTask;
            }

            // Stage 1: transform buffer – InsertLogAsync pushes LogEntry here.
            _transformChannel = Channel.CreateBounded<LogEntry>(
                new BoundedChannelOptions(_config!.Sinks.MaxQueueSize)
                {
                    SingleReader = true,
                    SingleWriter = false, // InsertLogAsync may be called concurrently
                    FullMode = BoundedChannelFullMode.DropWrite
                });

            // Stage 2: enriched buffer – EnrichLogsAsync pushes here, ExportLogsAsync consumes.
            _enrichedChannel = Channel.CreateBounded<LogEntry>(
                new BoundedChannelOptions(_config.Sinks.MaxQueueSize)
                {
                    SingleReader = true,
                    SingleWriter = true, // only enrichment stage writes
                    FullMode = BoundedChannelFullMode.DropWrite
                });

            // Start pipeline workers:
            //  - EnrichLogsAsync: transform -> enrich
            //  - ExportLogsAsync: enrich -> output
            _backgroundTask = Task.WhenAll(
                Task.Run(EnrichLogsAsync),
                Task.Run(ExportLogsAsync));

            // ADR: _enableLogging is intentionally set last so that any caller observing
            // _enableLogging is true can rely on the entire logging pipeline being fully
            // constructed (channels and background workers). This prevents subtle race
            // conditions where concurrent InsertLogAsync calls see "enabled" before internal
            // structures are ready.
            _enableLogging = true;

            return Task.CompletedTask;
        }

        // Step 1: input
        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request,
            IPEndPoint remoteEP, DnsTransportProtocol protocol,
            DnsDatagram response)
        {
            if (_enableLogging)
            {
                LogEntry entry;

                try
                {
                    // input -> transform: build LogEntry
                    entry = new LogEntry(timestamp, remoteEP, protocol, request, response, _config!.Sinks.EnableEdnsLogging);
                }
                catch (Exception ex)
                {
                    // Malformed packet or unexpected data should not crash the server.
                    _dnsServer?.WriteLog(ex);
                    return Task.CompletedTask;
                }

                try
                {
                    if (!_transformChannel.Writer.TryWrite(entry))
                    {
                        IncrementDropAndMaybeLog();
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(ex);
                }
            }

            return Task.CompletedTask;
        }

        #endregion public

        #region private

        // Step 2: EnrichLogsAsync – transform -> enrich
        private async Task EnrichLogsAsync()
        {
            try
            {
                while (await _transformChannel.Reader.WaitToReadAsync().ConfigureAwait(false))
                {
                    while (_transformChannel.Reader.TryRead(out LogEntry? entry))
                    {
                        // If there is no question, most enrichers cannot do anything.
                        if (entry.Question != null && _enrichmentDispatcher.Any())
                        {
                            try
                            {
                                _enrichmentDispatcher.Run(entry, ex => _dnsServer?.WriteLog(ex));
                            }
                            catch (Exception ex)
                            {
                                // Extra guard: dispatcher itself should not tear down the loop.
                                _dnsServer?.WriteLog(ex);
                            }
                        }

                        try
                        {
                            if (!_enrichedChannel.Writer.TryWrite(entry))
                            {
                                IncrementDropAndMaybeLog();
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsServer?.WriteLog(ex);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
            finally
            {
                // Signal no more enriched entries will be produced.
                try
                {
                    _enrichedChannel.Writer.TryComplete();
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(ex);
                }
            }
        }

        // Step 3: ExportLogsAsync – pipeline -> output
        private async Task ExportLogsAsync()
        {
            // ADR: Reuse this list buffer to avoid GC churn during high-volume logging.
            List<LogEntry> batch = new List<LogEntry>(BULK_INSERT_COUNT);

            try
            {
                while (await _enrichedChannel.Reader.WaitToReadAsync().ConfigureAwait(false))
                {
                    while (batch.Count < BULK_INSERT_COUNT &&
                           _enrichedChannel.Reader.TryRead(out LogEntry? entry))
                    {
                        batch.Add(entry);
                    }

                    if (batch.Count > 0)
                    {
                        try
                        {
                            await _sinkDispatcher
                                .DispatchAsync(batch, CancellationToken.None)
                                .ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            // Sink failures must be logged but must not crash the server.
                            _dnsServer?.WriteLog(ex);
                        }
                        finally
                        {
                            batch.Clear(); // REUSE — do not reassign
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
        }

        private void ConfigureSinks()
        {
            var sinks = _config!.Sinks;
            _sinkDispatcher.Remove(typeof(ConsoleSink));
            if (sinks.ConsoleSinkConfig != null && sinks.ConsoleSinkConfig.Enabled)
                _sinkDispatcher.Add(new ConsoleSink());

            _sinkDispatcher.Remove(typeof(FileSink));
            if (sinks.FileSinkConfig?.Enabled is true)
                _sinkDispatcher.Add(new FileSink(sinks.FileSinkConfig.Path));

            _sinkDispatcher.Remove(typeof(HttpSink));
            if (sinks.HttpSinkConfig?.Enabled is true)
            {
                _sinkDispatcher.Add(
                    new HttpSink(sinks.HttpSinkConfig.Endpoint, sinks.HttpSinkConfig.Headers));
            }

            _sinkDispatcher.Remove(typeof(SyslogSink));
            if (sinks.SyslogSinkConfig?.Enabled is true)
            {
                _sinkDispatcher.Add(
                    new SyslogSink(sinks.SyslogSinkConfig.Address,
                                   sinks.SyslogSinkConfig.Port!.Value,
                                   sinks.SyslogSinkConfig.Protocol));
            }
        }

        private void ConfigurePipeline()
        {
            // Remove any existing enricher types first to avoid duplicate registration.
            _enrichmentDispatcher.Remove(typeof(Normalize));
            if (_config!.Pipeline.NormalizeProcessConfig?.Enabled is true)
            {
                _enrichmentDispatcher.Add(new Normalize());
            }
        }

        private void IncrementDropAndMaybeLog()
        {
            Interlocked.Increment(ref _droppedCount);

            long nowTicks = DateTime.UtcNow.Ticks;
            long lastTicks = Volatile.Read(ref _lastDropTicks);

            if (new TimeSpan(nowTicks - lastTicks) >= DropLogInterval &&
                Interlocked.CompareExchange(ref _lastDropTicks, nowTicks, lastTicks) == lastTicks)
            {
                long dropped = Interlocked.Exchange(ref _droppedCount, 0);
                _dnsServer?.WriteLog(
                    $"Log export queue full; dropped {dropped} entries over last {DropLogInterval.TotalSeconds:F0}s.");
            }
        }

        #endregion private

        #region properties

        public string Description =>
            "Allows exporting query logs to third party sinks. Supports exporting to FileSink, HTTP endpoint, and SyslogSink.";

        #endregion properties
    }
}
