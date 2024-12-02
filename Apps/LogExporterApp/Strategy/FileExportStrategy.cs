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

using Serilog;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public class FileExportStrategy : IExportStrategy
    {
        #region variables

        private readonly Serilog.Core.Logger _sender;

        private bool disposedValue;

        #endregion variables

        #region constructor

        public FileExportStrategy(string filePath)
        {
            _sender = new LoggerConfiguration().WriteTo.File(filePath, outputTemplate: "{Message:lj}{NewLine}{Exception}").CreateLogger();
        }

        #endregion constructor

        #region public

        public Task ExportAsync(List<LogEntry> logs)
        {
            return Task.Run(() =>
            {
                foreach (LogEntry logEntry in logs)
            {
                _sender.Information(logEntry.ToString());
            }
            });
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
                    _sender.Dispose();
                }

                disposedValue = true;
            }
        }

        #endregion IDisposable
    }
}