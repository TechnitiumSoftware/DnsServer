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
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using HttpSinkConfig = LogExporter.SinkConfig.HttpSink;

namespace LogExporter.Sinks
{
    public sealed class HttpSink : IOutputSink
    {
        #region variables

        private readonly Uri _endpoint;
        private readonly HttpClient _httpClient;
        private readonly RecyclableMemoryStreamManager _memoryManager = new();
        private readonly bool _ndJson;
        private bool _disposed;

        #endregion variables

        #region constructor

        public HttpSink(HttpSinkConfig config)
        {
            if (!Uri.TryCreate(config.Endpoint, UriKind.Absolute, out Uri? uri))
                throw new ArgumentException("Invalid HTTP endpoint.", nameof(config));

            _endpoint = uri;
            _ndJson = config.NdJson;
            _httpClient = new HttpClient();

            if (config.Headers == null)
            {
                return;
            }

            foreach (var kv in config.Headers.Where(kv => !_httpClient.DefaultRequestHeaders.TryAddWithoutValidation(kv.Key, kv.Value)))
            {
                throw new FormatException($"Failed to add HTTP header '{kv.Key}'.");
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

        public async Task ExportAsync(IReadOnlyList<LogEntry> logs, CancellationToken token)
        {
            if (_disposed || logs.Count == 0 || token.IsCancellationRequested)
            {
                return;
            }

            using RecyclableMemoryStream ms = _memoryManager.GetStream("HttpExport-Batch");

            if (_ndJson)
            {
                LogBatchSerializer.WriteNdjson(ms, logs);
            }
            else
            {
                LogBatchSerializer.WriteJsonArray(ms, logs);
            }

            ms.Position = 0;

            using StreamContent content = new StreamContent(ms);
            content.Headers.ContentType = new MediaTypeHeaderValue(
                _ndJson ? "application/x-ndjson" : "application/json");

            using HttpResponseMessage response = await _httpClient
                .PostAsync(_endpoint, content, token)
                .ConfigureAwait(false);

            response.EnsureSuccessStatusCode();
        }

        #endregion public
    }

    public static class LogBatchSerializer
    {
        private static readonly JsonWriterOptions WriterOptions = new JsonWriterOptions
        {
            Indented = false
        };

        public static void WriteNdjson(Stream target, IReadOnlyList<LogEntry> logs)
        {
            ArgumentNullException.ThrowIfNull(target);
            ArgumentNullException.ThrowIfNull(logs);

            if (logs.Count == 0)
            {
                return;
            }

            ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(4096);
            using Utf8JsonWriter writer = new Utf8JsonWriter(buffer, WriterOptions);

            for (int i = 0; i < logs.Count; i++)
            {
                JsonSerializer.Serialize(writer, logs[i]);
                writer.Flush();

                target.Write(buffer.WrittenSpan);
                target.WriteByte((byte)'\n');

                buffer.Clear();

                if (i < logs.Count - 1)
                {
                    writer.Reset(buffer);
                }
            }
        }

        public static void WriteJsonArray(Stream target, IReadOnlyList<LogEntry> logs)
        {
            ArgumentNullException.ThrowIfNull(target);
            ArgumentNullException.ThrowIfNull(logs);

            using Utf8JsonWriter writer = new Utf8JsonWriter(target, WriterOptions);

            writer.WriteStartArray();

            for (int i = 0; i < logs.Count; i++)
            {
                JsonSerializer.Serialize(writer, logs[i]);
            }

            writer.WriteEndArray();
            writer.Flush();
        }
    }
}