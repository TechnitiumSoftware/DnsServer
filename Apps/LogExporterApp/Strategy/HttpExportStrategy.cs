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
    public class HttpExportStrategy : IExportStrategy
    {
        #region variables

        private readonly Serilog.Core.Logger _sender;

        private bool disposedValue;

        #endregion variables

        #region constructor

        public HttpExportStrategy(string endpoint, Dictionary<string, string>? headers = null)
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
            GC.SuppressFinalize(this);
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

        #region Classes

        public class CustomHttpClient : IHttpClient
        {
            private readonly HttpClient httpClient;

            public CustomHttpClient() => httpClient = new HttpClient();

            public void Configure(IConfiguration configuration)
            {
                foreach (var pair in configuration.GetChildren())
                {
                    httpClient.DefaultRequestHeaders.Add(pair.Key, pair.Value);
                }
            }

            public void Dispose()
            {
                httpClient?.Dispose();
            }

            public async Task<HttpResponseMessage> PostAsync(string requestUri, Stream contentStream, CancellationToken cancellationToken)
            {
                using var content = new StreamContent(contentStream);
                content.Headers.Add("Content-Type", "application/json");

                return await httpClient
                    .PostAsync(requestUri, content, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        #endregion Classes
    }
}