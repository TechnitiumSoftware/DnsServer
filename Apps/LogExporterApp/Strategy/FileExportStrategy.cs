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
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public class FileExportStrategy : IExportStrategy
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
            var jsonLogs = new StringBuilder(logs.Count * 250);
            foreach (var log in logs)
            {
                jsonLogs.AppendLine(log.ToString());
            }
            return FlushAsync(jsonLogs.ToString());
        }

        private async Task FlushAsync(string jsonLogs)
        {
            // Wait to enter the semaphore
            await _fileSemaphore.WaitAsync();
            try
            {
                // Use a FileStream with exclusive access
                using (var fileStream = new FileStream(_filePath, FileMode.Append, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(fileStream))
                {
                    await writer.WriteAsync(jsonLogs);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }
            finally
            {
                // Ensure semaphore is released only if it was successfully acquired
                if (_fileSemaphore.CurrentCount == 0)
                {
                    _fileSemaphore.Release();
                }
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
                    // Ensure semaphore is released only if it was successfully acquired
                    if (_fileSemaphore.CurrentCount == 0)
                    {
                        _fileSemaphore.Release();
                    }
                    _fileSemaphore.Dispose();
                }

                disposedValue = true;
            }
        }

        #endregion IDisposable
    }
}