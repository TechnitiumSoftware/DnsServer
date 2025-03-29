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

using Microsoft.Extensions.Configuration;
using Serilog;
using Serilog.Sinks.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public sealed class HttpExportStrategy : IExportStrategy
    {
        #region variables

        readonly Serilog.Core.Logger _sender;

        bool _disposed;

        #endregion

        #region constructor

        public HttpExportStrategy(string endpoint, Dictionary<string, string?>? headers = null)
        {
            IConfigurationRoot? configuration = null;
            if (headers != null)
            {
                configuration = new ConfigurationBuilder()
               .AddInMemoryCollection(headers)
               .Build();
            }

            _sender = new LoggerConfiguration().WriteTo.Http(endpoint, null, httpClient: new CustomHttpClient(), configuration: configuration).Enrich.FromLogContext().CreateLogger();
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

        public class CustomHttpClient : IHttpClient
        {
            readonly HttpClient _httpClient;

            public CustomHttpClient()
            {
                _httpClient = new HttpClient();
            }

            public void Configure(IConfiguration configuration)
            {
                foreach (IConfigurationSection pair in configuration.GetChildren())
                {
                    if (!_httpClient.DefaultRequestHeaders.TryAddWithoutValidation(pair.Key, pair.Value))
                        throw new FormatException($"Failed to add header '{pair.Key}'.");
                }
            }

            public void Dispose()
            {
                _httpClient?.Dispose();
                GC.SuppressFinalize(this);
            }

            public async Task<HttpResponseMessage> PostAsync(string requestUri, Stream contentStream, CancellationToken cancellationToken)
            {
                StreamContent content = new StreamContent(contentStream);
                content.Headers.Add("Content-Type", "application/json");

                return await _httpClient
                    .PostAsync(requestUri, content, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }
}
