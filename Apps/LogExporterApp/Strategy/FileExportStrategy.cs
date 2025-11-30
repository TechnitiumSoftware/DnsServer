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
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public sealed class FileExportStrategy : IExportStrategy
    {
        #region variables

        private readonly FileStream _fileStream;
        private readonly RecyclableMemoryStreamManager _memoryManager = new();
        private readonly StreamWriter _writer;
        private bool _disposed;

        #endregion variables

        #region constructor

        public FileExportStrategy(string filePath)
        {
            _fileStream = new FileStream(
                filePath,
                FileMode.Append,
                FileAccess.Write,
                FileShare.Read,
                bufferSize: 64 * 1024,
                useAsync: true);

            _writer = new StreamWriter(_fileStream);
        }

        #endregion constructor

        #region IDisposable

        public void Dispose()
        {
            if (_disposed)
                return;

            _writer.Dispose();
            _fileStream.Dispose();
            _disposed = true;
        }

        #endregion IDisposable

        #region public

        public async Task ExportAsync(IReadOnlyList<LogEntry> logs, CancellationToken token)
        {
            // ADR: Once disposed, this strategy must not attempt any I/O. The background
            // worker may still flush a few batches while shutdown is in progress. Treating
            // late calls as no-ops avoids spurious ObjectDisposedExceptions during normal
            // teardown.
            if (_disposed || logs.Count == 0 || token.IsCancellationRequested)
                return;

            // Per-batch pooled buffer ("arena")
            using var ms = _memoryManager.GetStream("FileExport-Batch");
            NdjsonSerializer.WriteBatch(ms, logs);

            // Reset to beginning for output
            ms.Position = 0;

            // Copy to the actual file stream
            await ms.CopyToAsync(_writer.BaseStream, token);
            await _writer.BaseStream.FlushAsync();
        }

        #endregion public
    }
}