/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace LogExporter
{
    public sealed class App : IDnsApplication, IDnsQueryLogger
    {
        #region variables

        private const int BULK_INSERT_COUNT = 1000;

        private const int DEFAULT_QUEUE_CAPACITY = 1000;

        private const int QUEUE_TIMER_INTERVAL = 10000;

        private readonly ExportManager _exportManager = new ExportManager();

        private BlockingCollection<LogEntry> _logBuffer;

        private readonly object _queueTimerLock = new object();

        private BufferManagementConfig _config;

        private IDnsServer _dnsServer;

        private Timer _queueTimer;

        private bool disposedValue;

        private readonly IReadOnlyList<DnsLogEntry> _emptyList = [];

        #endregion variables

        #region constructor

        public App()
        {
        }

        #endregion constructor

        #region IDisposable

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    lock (_queueTimerLock)
                    {
                        _queueTimer?.Dispose();
                    }

                    ExportLogsAsync().Sync(); //flush any pending logs

                    _logBuffer.Dispose();
                }

                disposedValue = true;
            }
        }

        #endregion IDisposable

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            _config = BufferManagementConfig.Deserialize(config);

            if (_config == null)
            {
                throw new DnsClientException("Invalid application configuration.");
            }

            if (_config.MaxLogEntries != null)
            {
                _logBuffer = new BlockingCollection<LogEntry>(_config.MaxLogEntries.Value);
            }
            else
            {
                _logBuffer = new BlockingCollection<LogEntry>(DEFAULT_QUEUE_CAPACITY);
            }

            RegisterExportTargets();

            lock (_queueTimerLock)
            {
                _queueTimer = new Timer(async (object _) =>
                {
                    try
                    {
                        await ExportLogsAsync();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog(ex);
                    }
                }, null, QUEUE_TIMER_INTERVAL, Timeout.Infinite);
            }

            return Task.CompletedTask;
        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            _logBuffer.Add(new LogEntry(timestamp, remoteEP, protocol, request, response));

            return Task.CompletedTask;
        }

        public async Task<DnsLogPage> QueryLogsAsync(long pageNumber, int entriesPerPage, bool descendingOrder, DateTime? start, DateTime? end, IPAddress clientIpAddress, DnsTransportProtocol? protocol, DnsServerResponseType? responseType, DnsResponseCode? rcode, string qname, DnsResourceRecordType? qtype, DnsClass? qclass)
        {
            return await Task.FromResult(new DnsLogPage(0, 0, 0, _emptyList));
        }

        #endregion public

        #region private

        private async Task ExportLogsAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var logs = new List<LogEntry>(BULK_INSERT_COUNT);

                while (!cancellationToken.IsCancellationRequested)
                {
                    while ((logs.Count < BULK_INSERT_COUNT) && _logBuffer.TryTake(out LogEntry? log))
                    {
                        if (log != null)
                            logs.Add(log);
                    }

                    if (logs.Count > 0)
                    {
                        await _exportManager.ImplementStrategyForAsync(logs, cancellationToken);

                        logs.Clear();
                    }
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
        }

        private void RegisterExportTargets()
        {
            // Helper function to register an export strategy if the target is enabled
            void RegisterIfEnabled<TTarget, TStrategy>(TTarget target, Func<TTarget, TStrategy> strategyFactory)
                where TTarget : TargetBase
                where TStrategy : IExportStrategy
            {
                if (target?.Enabled == true)
                {
                    var strategy = strategyFactory(target);
                    _exportManager.AddOrReplaceStrategy(strategy);
                }
            }

            // Register the different strategies using the helper
            RegisterIfEnabled(_config.FileTarget, target => new FileExportStrategy(target.Path));
            RegisterIfEnabled(_config.HttpTarget, target => new HttpExportStrategy(target.Endpoint, target.Method, target.Headers));
            RegisterIfEnabled(_config.SyslogTarget, target => new SyslogExportStrategy(target.Address, target.Port, target.Protocol));
        }

        #endregion private

        #region properties

        public string Description
        {
            get { return "The app allows exporting logs to a third party sink using an internal buffer."; }
        }

        #endregion properties
    }
}