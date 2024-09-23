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

using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public class FileExportStrategy : IExportStrategy
    {
        private readonly string _filePath;
        private static readonly SemaphoreSlim _fileSemaphore = new SemaphoreSlim(1, 1);
        private bool disposedValue;

        public FileExportStrategy(string filePath)
        {
            _filePath = filePath;
        }

        public async Task ExportLogsAsync(List<LogEntry> logs, CancellationToken cancellationToken = default)
        {
            var jsonLogs = new StringBuilder(logs.Count);
            foreach (var log in logs)
            {
                jsonLogs.AppendLine(log.ToString());
            }

            // Wait to enter the semaphore
            await _fileSemaphore.WaitAsync(cancellationToken);
            try
            {
                // Use a FileStream with exclusive access
                using var fileStream = new FileStream(_filePath, FileMode.Append, FileAccess.Write, FileShare.None);
                using var writer = new StreamWriter(fileStream);
                await writer.WriteAsync(jsonLogs.ToString());
            }
            finally
            {
                // Release the semaphore
                _fileSemaphore.Release();
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _fileSemaphore.Release();
                    _fileSemaphore.Dispose();
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            System.GC.SuppressFinalize(this);
        }
    }
}
