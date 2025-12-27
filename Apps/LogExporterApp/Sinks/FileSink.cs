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
using System.Threading;
using System.Threading.Tasks;

namespace LogExporter.Sinks
{
    public sealed class FileSink : IOutputSink
    {
        #region variables

        private readonly FileStream _fileStream;
        private readonly RecyclableMemoryStreamManager _memoryManager = new();
        private readonly StreamWriter _writer;
        private bool _disposed;

        #endregion variables

        #region constructor

        public FileSink(string filePath)
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
            // ADR: FileSink writes must honor cancellation so server shutdown cannot block
            // on slow disks or large flush operations. Previously FlushAsync() was not
            // cancellable, allowing shutdown to hang indefinitely under I/O pressure.
            // All I/O operations now respect the provided token.
            if (_disposed || logs.Count == 0 || token.IsCancellationRequested)
                return;

            using RecyclableMemoryStream ms = _memoryManager.GetStream("FileExport-Batch");
            NdjsonSerializer.WriteBatch(ms, logs);
            ms.Position = 0;

            await ms.CopyToAsync(_writer.BaseStream, token).ConfigureAwait(false);
            await _writer.BaseStream.FlushAsync(token).ConfigureAwait(false);
        }

        #endregion public
    }
}