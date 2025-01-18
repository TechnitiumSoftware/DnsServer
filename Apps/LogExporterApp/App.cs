/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;

namespace LogExporter
{
    public sealed class App : IDnsApplication, IDnsQueryLogger
    {
        #region variables

        IDnsServer? _dnsServer;
        BufferManagementConfig? _config;

        readonly ExportManager _exportManager = new ExportManager();

        bool _enableLogging;

        readonly ConcurrentQueue<LogEntry> _queuedLogs = new ConcurrentQueue<LogEntry>();
        readonly Timer _queueTimer;
        const int QUEUE_TIMER_INTERVAL = 10000;
        const int BULK_INSERT_COUNT = 1000;

        bool _disposed;

        #endregion

        #region constructor

        public App()
        {
            _queueTimer = new Timer(HandleExportLogCallback);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _queueTimer?.Dispose();

                    ExportLogsAsync().Sync(); //flush any pending logs

                    _exportManager.Dispose();
                }

                _disposed = true;
            }
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            _config = BufferManagementConfig.Deserialize(config);

            if (_config is null)
                throw new DnsClientException("Invalid application configuration.");

            if (_config.FileTarget!.Enabled)
            {
                _exportManager.RemoveStrategy(typeof(FileExportStrategy));
                _exportManager.AddStrategy(new FileExportStrategy(_config.FileTarget!.Path));
            }
            else
            {
                _exportManager.RemoveStrategy(typeof(FileExportStrategy));
            }

            if (_config.HttpTarget!.Enabled)
            {
                _exportManager.RemoveStrategy(typeof(HttpExportStrategy));
                _exportManager.AddStrategy(new HttpExportStrategy(_config.HttpTarget.Endpoint, _config.HttpTarget.Headers));
            }
            else
            {
                _exportManager.RemoveStrategy(typeof(HttpExportStrategy));
            }

            if (_config.SyslogTarget!.Enabled)
            {
                _exportManager.RemoveStrategy(typeof(SyslogExportStrategy));
                _exportManager.AddStrategy(new SyslogExportStrategy(_config.SyslogTarget.Address, _config.SyslogTarget.Port, _config.SyslogTarget.Protocol));
            }
            else
            {
                _exportManager.RemoveStrategy(typeof(SyslogExportStrategy));
            }

            _enableLogging = _exportManager.HasStrategy();

            if (_enableLogging)
                _queueTimer.Change(QUEUE_TIMER_INTERVAL, Timeout.Infinite);
            else
                _queueTimer.Change(Timeout.Infinite, Timeout.Infinite);

            return Task.CompletedTask;
        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (_enableLogging)
            {
                if (_queuedLogs.Count < _config!.MaxQueueSize)
                    _queuedLogs.Enqueue(new LogEntry(timestamp, remoteEP, protocol, request, response));
            }

            return Task.CompletedTask;
        }

        #endregion

        #region private

        private async Task ExportLogsAsync()
        {
            try
            {
                List<LogEntry> logs = new List<LogEntry>(BULK_INSERT_COUNT);

                while (true)
                {
                    while (logs.Count < BULK_INSERT_COUNT && _queuedLogs.TryDequeue(out LogEntry? log))
                    {
                        logs.Add(log);
                    }

                    if (logs.Count < 1)
                        break;

                    await _exportManager.ImplementStrategyAsync(logs);

                    logs.Clear();
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
        }

        private async void HandleExportLogCallback(object? state)
        {
            try
            {
                // Process logs within the timer interval, then let the timer reschedule
                await ExportLogsAsync();
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
            finally
            {
                try
                {
                    _queueTimer?.Change(QUEUE_TIMER_INTERVAL, Timeout.Infinite);
                }
                catch (ObjectDisposedException)
                { }
            }
        }

        #endregion

        #region properties

        public string Description
        {
            get { return "Allows exporting query logs to third party sinks. It supports exporting to File, HTTP endpoint, and Syslog (UDP, TCP, TLS, and Local protocols)."; }
        }

        #endregion
    }
}
