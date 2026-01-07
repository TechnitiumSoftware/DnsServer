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

using Microsoft.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace LogExporter.Sinks
{
    public sealed class ConsoleSink : IOutputSink
    {
        private readonly RecyclableMemoryStreamManager _memoryManager =
            new RecyclableMemoryStreamManager();

        private readonly Stream _stdout;
        private bool _disposed;

        public ConsoleSink()
        {
            _stdout = Console.OpenStandardOutput();
        }

        public void Dispose()
        {
            // ADR: We intentionally do NOT dispose _stdout. The standard output stream is
            // owned by the process, not by this strategy. Disposing it here would break
            // all console output for the entire DNS server. Dispose only flips the flag
            // so that subsequent ExportAsync calls become no-ops during shutdown.
            _disposed = true;
        }

        public async Task ExportAsync(IReadOnlyList<LogEntry> logs, CancellationToken token)
        {
            if (_disposed || logs.Count == 0 || token.IsCancellationRequested)
                return;

            using RecyclableMemoryStream ms = _memoryManager.GetStream("ConsoleExport-Batch");
            NdjsonSerializer.WriteBatch(ms, logs);

            ms.Position = 0;

            await ms.CopyToAsync(_stdout, token).ConfigureAwait(false);
            await _stdout.FlushAsync(token).ConfigureAwait(false);
        }
    }
}