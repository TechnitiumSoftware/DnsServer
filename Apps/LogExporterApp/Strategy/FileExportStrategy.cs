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

using Serilog;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public sealed class FileExportStrategy : IExportStrategy
    {
        #region variables

        readonly Serilog.Core.Logger _sender;

        bool _disposed;

        #endregion

        #region constructor

        public FileExportStrategy(string filePath)
        {
            _sender = new LoggerConfiguration().WriteTo.File(filePath, outputTemplate: "{Message:lj}{NewLine}{Exception}").CreateLogger();
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (!_disposed)
            {
                _sender.Dispose();

                _disposed = true;
            }
        }

        #endregion

        #region public

        public Task ExportAsync(IReadOnlyList<LogEntry> logs)
        {
            foreach (LogEntry logEntry in logs)
                _sender.Information(logEntry.ToString());

            return Task.CompletedTask;
        }

        #endregion
    }
}
