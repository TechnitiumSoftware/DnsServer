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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public partial class FileExportStrategy : IExportStrategy
    {

        #region variables

        private static readonly SemaphoreSlim _fileSemaphore = new SemaphoreSlim(1, 1);

        private readonly string _filePath;

        private bool disposedValue;


        #endregion variables

        #region constructor

        public FileExportStrategy(string filePath)
        {
            _filePath = filePath;

        }

        #endregion constructor

        #region public

        public Task ExportAsync(List<LogEntry> logs)
        {
            var buffer = new GrowableBuffer<char>();
            foreach (var log in logs)
            {
                buffer.Append(log.AsSpan());
                buffer.Append('\n');
            }
            Flush(buffer.ToSpan());
            return Task.CompletedTask;
        }

        private void Flush(ReadOnlySpan<char> jsonLogs)
        {
            // Wait to enter the semaphore
            _fileSemaphore.Wait();
            try
            {
                // Use a FileStream with exclusive access
                var fileStream = new FileStream(_filePath, FileMode.Append, FileAccess.Write, FileShare.Write);
                var writer = new StreamWriter(fileStream);
                writer.Write(jsonLogs);
                writer.Close();
                fileStream.Dispose();
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }
            finally
            {
                // Release the semaphore
                _ = _fileSemaphore.Release();
            }
        }

        #endregion public

        #region IDisposable

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            System.GC.SuppressFinalize(this);
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

        #endregion IDisposable
    }
}