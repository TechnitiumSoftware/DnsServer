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
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public sealed class HttpExportStrategy : IExportStrategy
    {
        #region variables

        private readonly Uri _endpoint;
        private readonly HttpClient _httpClient;
        private readonly RecyclableMemoryStreamManager _memoryManager = new();
        private bool _disposed;

        #endregion variables

        #region constructor

        public HttpExportStrategy(string endpoint, Dictionary<string, string?>? headers = null)
        {
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
                throw new ArgumentException("Invalid HTTP endpoint.", nameof(endpoint));

            _endpoint = uri;
            _httpClient = new HttpClient();

            if (headers != null)
            {
                foreach (var kv in headers)
                {
                    if (!_httpClient.DefaultRequestHeaders.TryAddWithoutValidation(kv.Key, kv.Value))
                        throw new FormatException($"Failed to add HTTP header '{kv.Key}'.");
                }
            }
        }

        #endregion constructor

        #region IDisposable

        public void Dispose()
        {
            if (_disposed)
                return;

            _httpClient.Dispose();
            _disposed = true;
        }

        #endregion IDisposable

        #region public

        public async Task ExportAsync(IReadOnlyList<LogEntry> logs)
        {
            // ADR: Once disposed, this strategy must not attempt any I/O. The background
            // worker may still flush a few batches while shutdown is in progress. Treating
            // late calls as no-ops avoids spurious ObjectDisposedExceptions during normal
            // teardown.
            if (_disposed || logs.Count == 0)
                return;

            using var ms = _memoryManager.GetStream("HttpExport-Batch");

            // Use Stream overload explicitly to avoid ambiguity
            NdjsonSerializer.WriteBatch(ms, logs);

            ms.Position = 0;

            using var content = new StreamContent(ms);
            content.Headers.Add("Content-Type", "application/x-ndjson");

            using HttpResponseMessage response = await _httpClient
                .PostAsync(_endpoint, content, CancellationToken.None)
                .ConfigureAwait(false);

            // Fail if server rejects logs
            response.EnsureSuccessStatusCode();
        }

        #endregion public
    }
}