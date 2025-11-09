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

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;
using TechnitiumLibrary.Net.Proxy;

namespace Failover
{
    class WebHook : IDisposable
    {
        #region variables

        readonly HealthService _service;

        readonly string _name;
        bool _enabled;
        Uri[] _urls;

        HttpClientNetworkHandler _httpHandler;
        HttpClient _httpClient;

        #endregion

        #region constructor

        public WebHook(HealthService service, JsonElement jsonWebHook)
        {
            _service = service;

            _name = jsonWebHook.GetPropertyValue("name", "default");

            Reload(jsonWebHook);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_httpClient != null)
                {
                    _httpClient.Dispose();
                    _httpClient = null;
                }

                if (_httpHandler != null)
                {
                    _httpHandler.Dispose();
                    _httpHandler = null;
                }
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region private

        private void ConditionalHttpReload()
        {
            bool handlerChanged = false;
            NetProxy proxy = _service.DnsServer.Proxy;

            if (_httpHandler is null)
            {
                HttpClientNetworkHandler httpHandler = new HttpClientNetworkHandler();
                httpHandler.Proxy = proxy;
                httpHandler.NetworkType = _service.DnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
                httpHandler.DnsClient = _service.DnsServer;

                httpHandler.InnerHandler.AllowAutoRedirect = true;
                httpHandler.InnerHandler.MaxAutomaticRedirections = 10;

                _httpHandler = httpHandler;
                handlerChanged = true;
            }
            else
            {
                if (_httpHandler.Proxy != proxy)
                {
                    HttpClientNetworkHandler httpHandler = new HttpClientNetworkHandler();
                    httpHandler.Proxy = proxy;
                    httpHandler.NetworkType = _service.DnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
                    httpHandler.DnsClient = _service.DnsServer;

                    httpHandler.InnerHandler.AllowAutoRedirect = true;
                    httpHandler.InnerHandler.MaxAutomaticRedirections = 10;

                    HttpClientNetworkHandler oldHttpHandler = _httpHandler;
                    _httpHandler = httpHandler;
                    handlerChanged = true;

                    oldHttpHandler.Dispose();
                }
            }

            if (_httpClient is null)
            {
                HttpClient httpClient = new HttpClient(_httpHandler);

                _httpClient = httpClient;
            }
            else
            {
                if (handlerChanged)
                {
                    HttpClient httpClient = new HttpClient(_httpHandler);

                    HttpClient oldHttpClient = _httpClient;
                    _httpClient = httpClient;

                    oldHttpClient.Dispose();
                }
            }
        }

        private async Task CallAsync(HttpContent content)
        {
            ConditionalHttpReload();

            async Task CallWebHook(Uri url)
            {
                try
                {
                    HttpResponseMessage response = await _httpClient.PostAsync(url, content);
                    response.EnsureSuccessStatusCode();
                }
                catch (Exception ex)
                {
                    _service.DnsServer.WriteLog("Webhook call failed for URL: " + url.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            List<Task> tasks = new List<Task>();

            foreach (Uri url in _urls)
                tasks.Add(CallWebHook(url));

            await Task.WhenAll(tasks);
        }

        #endregion

        #region public

        public void Reload(JsonElement jsonWebHook)
        {
            _enabled = jsonWebHook.GetPropertyValue("enabled", false);

            if (jsonWebHook.TryReadArray("urls", delegate (string uri) { return new Uri(uri); }, out Uri[] urls))
                _urls = urls;
            else
                _urls = null;

            ConditionalHttpReload();
        }

        public Task CallAsync(IPAddress address, string healthCheck, HealthCheckResponse healthCheckResponse)
        {
            if (!_enabled)
                return Task.CompletedTask;

            HttpContent content;
            {
                using (MemoryStream mS = new MemoryStream())
                {
                    Utf8JsonWriter jsonWriter = new Utf8JsonWriter(mS);
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteString("address", address.ToString());
                    jsonWriter.WriteString("healthCheck", healthCheck);
                    jsonWriter.WriteString("status", healthCheckResponse.Status.ToString());

                    if (healthCheckResponse.Status == HealthStatus.Failed)
                        jsonWriter.WriteString("failureReason", healthCheckResponse.FailureReason);

                    jsonWriter.WriteString("dateTime", healthCheckResponse.DateTime);

                    jsonWriter.WriteEndObject();
                    jsonWriter.Flush();

                    content = new ByteArrayContent(mS.ToArray());
                    content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                }
            }

            return CallAsync(content);
        }

        public Task CallAsync(IPAddress address, string healthCheck, Exception ex)
        {
            if (!_enabled)
                return Task.CompletedTask;

            HttpContent content;
            {
                using (MemoryStream mS = new MemoryStream())
                {
                    Utf8JsonWriter jsonWriter = new Utf8JsonWriter(mS);
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteString("address", address.ToString());
                    jsonWriter.WriteString("healthCheck", healthCheck);
                    jsonWriter.WriteString("status", "Error");
                    jsonWriter.WriteString("failureReason", ex.ToString());
                    jsonWriter.WriteString("dateTime", DateTime.UtcNow);

                    jsonWriter.WriteEndObject();
                    jsonWriter.Flush();

                    content = new ByteArrayContent(mS.ToArray());
                    content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                }
            }

            return CallAsync(content);
        }

        public Task CallAsync(string domain, DnsResourceRecordType type, string healthCheck, HealthCheckResponse healthCheckResponse)
        {
            if (!_enabled)
                return Task.CompletedTask;

            HttpContent content;
            {
                using (MemoryStream mS = new MemoryStream())
                {
                    Utf8JsonWriter jsonWriter = new Utf8JsonWriter(mS);
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteString("domain", domain);
                    jsonWriter.WriteString("recordType", type.ToString());
                    jsonWriter.WriteString("healthCheck", healthCheck);
                    jsonWriter.WriteString("status", healthCheckResponse.Status.ToString());

                    if (healthCheckResponse.Status == HealthStatus.Failed)
                        jsonWriter.WriteString("failureReason", healthCheckResponse.FailureReason);

                    jsonWriter.WriteString("dateTime", healthCheckResponse.DateTime);

                    jsonWriter.WriteEndObject();
                    jsonWriter.Flush();

                    content = new ByteArrayContent(mS.ToArray());
                    content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                }
            }

            return CallAsync(content);
        }

        public Task CallAsync(string domain, DnsResourceRecordType type, string healthCheck, Exception ex)
        {
            if (!_enabled)
                return Task.CompletedTask;

            HttpContent content;
            {
                using (MemoryStream mS = new MemoryStream())
                {
                    Utf8JsonWriter jsonWriter = new Utf8JsonWriter(mS);
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteString("domain", domain);
                    jsonWriter.WriteString("recordType", type.ToString());
                    jsonWriter.WriteString("healthCheck", healthCheck);
                    jsonWriter.WriteString("status", "Error");
                    jsonWriter.WriteString("failureReason", ex.ToString());
                    jsonWriter.WriteString("dateTime", DateTime.UtcNow);

                    jsonWriter.WriteEndObject();
                    jsonWriter.Flush();

                    content = new ByteArrayContent(mS.ToArray());
                    content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                }
            }

            return CallAsync(content);
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public bool Enabled
        { get { return _enabled; } }

        public Uri[] Urls
        { get { return _urls; } }

        #endregion
    }
}
