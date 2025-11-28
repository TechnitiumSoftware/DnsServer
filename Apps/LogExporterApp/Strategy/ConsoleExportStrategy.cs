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
using System.Text.Json;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public sealed class ConsoleExportStrategy : IExportStrategy
    {
        private readonly RecyclableMemoryStreamManager _memoryManager =
            new RecyclableMemoryStreamManager();

        private readonly Stream _stdout;
        private bool _disposed;

        public ConsoleExportStrategy()
        {
            _stdout = Console.OpenStandardOutput();
        }

        public void Dispose()
        {
            _disposed = true;
        }

        public async Task ExportAsync(IReadOnlyList<LogEntry> logs)
        {
            if (_disposed || logs.Count == 0)
                return;

            using var ms = _memoryManager.GetStream("ConsoleExport-Batch");

            using (var jsonWriter = new Utf8JsonWriter(
               (Stream)ms,
                new JsonWriterOptions
                {
                    Indented = false,
                    SkipValidation = true
                }))
            {
                for (int i = 0; i < logs.Count; i++)
                {
                    JsonSerializer.Serialize(
                        jsonWriter,
                        logs[i],
                        LogEntry.DnsLogSerializerOptions.Default);

                    jsonWriter.WriteRawValue("\n"u8, skipInputValidation: true);
                }
            }

            ms.Position = 0;

            await ms.CopyToAsync(_stdout).ConfigureAwait(false);
            await _stdout.FlushAsync().ConfigureAwait(false);
        }
    }
}