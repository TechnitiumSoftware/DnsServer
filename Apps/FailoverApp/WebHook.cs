/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

namespace Failover
{
    class WebHook : IDisposable
    {
        #region variables

        readonly HealthService _service;

        string _name;
        bool _enabled;
        Uri[] _urls;

        SocketsHttpHandler _httpHandler;
        HttpClient _httpClient;

        #endregion

        #region constructor

        public WebHook(HealthService service, dynamic jsonWebHook)
        {
            _service = service;

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
                SocketsHttpHandler httpHandler = new SocketsHttpHandler();
                httpHandler.Proxy = proxy;
                httpHandler.AllowAutoRedirect = true;
                httpHandler.MaxAutomaticRedirections = 10;

                _httpHandler = httpHandler;
                handlerChanged = true;
            }
            else
            {
                if (_httpHandler.Proxy != proxy)
                {
                    SocketsHttpHandler httpHandler = new SocketsHttpHandler();
                    httpHandler.Proxy = proxy;
                    httpHandler.AllowAutoRedirect = true;
                    httpHandler.MaxAutomaticRedirections = 10;

                    SocketsHttpHandler oldHttpHandler = _httpHandler;
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
                    _service.DnsServer.WriteLog(ex);
                }
            }

            List<Task> tasks = new List<Task>();

            foreach (Uri url in _urls)
                tasks.Add(CallWebHook(url));

            await Task.WhenAll(tasks);
        }

        #endregion

        #region public

        public void Reload(dynamic jsonWebHook)
        {
            if (jsonWebHook.name is null)
                _name = "default";
            else
                _name = jsonWebHook.name.Value;

            if (jsonWebHook.enabled is null)
                _enabled = false;
            else
                _enabled = jsonWebHook.enabled.Value;

            if (jsonWebHook.urls is null)
            {
                _urls = null;
            }
            else
            {
                _urls = new Uri[jsonWebHook.urls.Count];

                for (int i = 0; i < _urls.Length; i++)
                    _urls[i] = new Uri(jsonWebHook.urls[i].Value);
            }

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
                    JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("address");
                    jsonWriter.WriteValue(address.ToString());

                    jsonWriter.WritePropertyName("healthCheck");
                    jsonWriter.WriteValue(healthCheck);

                    jsonWriter.WritePropertyName("status");
                    jsonWriter.WriteValue(healthCheckResponse.Status.ToString());

                    if (healthCheckResponse.Status == HealthStatus.Failed)
                    {
                        jsonWriter.WritePropertyName("failureReason");
                        jsonWriter.WriteValue(healthCheckResponse.FailureReason);
                    }

                    jsonWriter.WritePropertyName("dateTime");
                    jsonWriter.WriteValue(healthCheckResponse.DateTime);

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
                    JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("address");
                    jsonWriter.WriteValue(address.ToString());

                    jsonWriter.WritePropertyName("healthCheck");
                    jsonWriter.WriteValue(healthCheck);

                    jsonWriter.WritePropertyName("status");
                    jsonWriter.WriteValue("Error");

                    jsonWriter.WritePropertyName("failureReason");
                    jsonWriter.WriteValue(ex.ToString());

                    jsonWriter.WritePropertyName("dateTime");
                    jsonWriter.WriteValue(DateTime.UtcNow);

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
                    JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("domain");
                    jsonWriter.WriteValue(domain);

                    jsonWriter.WritePropertyName("recordType");
                    jsonWriter.WriteValue(type.ToString());

                    jsonWriter.WritePropertyName("healthCheck");
                    jsonWriter.WriteValue(healthCheck);

                    jsonWriter.WritePropertyName("status");
                    jsonWriter.WriteValue(healthCheckResponse.Status.ToString());

                    if (healthCheckResponse.Status == HealthStatus.Failed)
                    {
                        jsonWriter.WritePropertyName("failureReason");
                        jsonWriter.WriteValue(healthCheckResponse.FailureReason);
                    }

                    jsonWriter.WritePropertyName("dateTime");
                    jsonWriter.WriteValue(healthCheckResponse.DateTime);

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
                    JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("domain");
                    jsonWriter.WriteValue(domain);

                    jsonWriter.WritePropertyName("recordType");
                    jsonWriter.WriteValue(type.ToString());

                    jsonWriter.WritePropertyName("healthCheck");
                    jsonWriter.WriteValue(healthCheck);

                    jsonWriter.WritePropertyName("status");
                    jsonWriter.WriteValue("Error");

                    jsonWriter.WritePropertyName("failureReason");
                    jsonWriter.WriteValue(ex.ToString());

                    jsonWriter.WritePropertyName("dateTime");
                    jsonWriter.WriteValue(DateTime.UtcNow);

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

        public IReadOnlyList<Uri> Urls
        { get { return _urls; } }

        #endregion
    }
}
