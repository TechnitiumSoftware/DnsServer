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
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;
using TechnitiumLibrary.Net.Proxy;

namespace Failover
{
    enum HealthCheckType
    {
        Unknown = 0,
        Ping = 1,
        Tcp = 2,
        Http = 3,
        Https = 4
    }

    class HealthCheck : IDisposable
    {
        #region variables

        const string HTTP_HEALTH_CHECK_USER_AGENT = "DNS Failover App (Technitium DNS Server)";

        readonly HealthService _service;

        readonly string _name;
        HealthCheckType _type;
        int _interval;
        int _retries;
        int _timeout;
        int _port;
        Uri _url;
        EmailAlert _emailAlert;
        WebHook _webHook;

        HttpClientNetworkHandler _httpHandler;
        HttpClient _httpClient;

        #endregion

        #region constructor

        public HealthCheck(HealthService service, JsonElement jsonHealthCheck)
        {
            _service = service;

            _name = jsonHealthCheck.GetPropertyValue("name", "default");

            Reload(jsonHealthCheck);
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
            switch (_type)
            {
                case HealthCheckType.Http:
                case HealthCheckType.Https:
                    bool handlerChanged = false;
                    NetProxy proxy = _service.DnsServer.Proxy;

                    if (_httpHandler is null)
                    {
                        HttpClientNetworkHandler httpHandler = new HttpClientNetworkHandler();
                        httpHandler.Proxy = proxy;
                        httpHandler.NetworkType = _service.DnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
                        httpHandler.DnsClient = _service.DnsServer;

                        httpHandler.InnerHandler.ConnectTimeout = TimeSpan.FromMilliseconds(_timeout);
                        httpHandler.InnerHandler.PooledConnectionIdleTimeout = TimeSpan.FromMilliseconds(Math.Max(10000, _timeout));
                        httpHandler.InnerHandler.AllowAutoRedirect = false;

                        _httpHandler = httpHandler;
                        handlerChanged = true;
                    }
                    else
                    {
                        if ((_httpHandler.InnerHandler.ConnectTimeout.TotalMilliseconds != _timeout) || (_httpHandler.Proxy != proxy))
                        {
                            HttpClientNetworkHandler httpHandler = new HttpClientNetworkHandler();
                            httpHandler.Proxy = proxy;
                            httpHandler.NetworkType = _service.DnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
                            httpHandler.DnsClient = _service.DnsServer;

                            httpHandler.InnerHandler.ConnectTimeout = TimeSpan.FromMilliseconds(_timeout);
                            httpHandler.InnerHandler.PooledConnectionIdleTimeout = TimeSpan.FromMilliseconds(Math.Max(10000, _timeout));
                            httpHandler.InnerHandler.AllowAutoRedirect = false;

                            HttpClientNetworkHandler oldHttpHandler = _httpHandler;
                            _httpHandler = httpHandler;
                            handlerChanged = true;

                            oldHttpHandler.Dispose();
                        }
                    }

                    if (_httpClient is null)
                    {
                        HttpClient httpClient = new HttpClient(_httpHandler);
                        httpClient.Timeout = TimeSpan.FromMilliseconds(_timeout);
                        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(HTTP_HEALTH_CHECK_USER_AGENT);
                        httpClient.DefaultRequestHeaders.ConnectionClose = true;

                        _httpClient = httpClient;
                    }
                    else
                    {
                        if (handlerChanged || (_httpClient.Timeout.TotalMilliseconds != _timeout))
                        {
                            HttpClient httpClient = new HttpClient(_httpHandler);
                            httpClient.Timeout = TimeSpan.FromMilliseconds(_timeout);
                            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(HTTP_HEALTH_CHECK_USER_AGENT);
                            httpClient.DefaultRequestHeaders.ConnectionClose = true;

                            HttpClient oldHttpClient = _httpClient;
                            _httpClient = httpClient;

                            oldHttpClient.Dispose();
                        }
                    }
                    break;

                default:
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
                    break;
            }
        }

        #endregion

        #region public

        public void Reload(JsonElement jsonHealthCheck)
        {
            _type = Enum.Parse<HealthCheckType>(jsonHealthCheck.GetPropertyValue("type", "Tcp"), true);
            _interval = jsonHealthCheck.GetPropertyValue("interval", 60) * 1000;
            _retries = jsonHealthCheck.GetPropertyValue("retries", 3);
            _timeout = jsonHealthCheck.GetPropertyValue("timeout", 10) * 1000;
            _port = jsonHealthCheck.GetPropertyValue("port", 80);

            if (jsonHealthCheck.TryGetProperty("url", out JsonElement jsonUrl) && (jsonUrl.ValueKind != JsonValueKind.Null))
                _url = new Uri(jsonUrl.GetString());
            else
                _url = null;

            if (jsonHealthCheck.TryGetProperty("emailAlert", out JsonElement jsonEmailAlert) && _service.EmailAlerts.TryGetValue(jsonEmailAlert.GetString(), out EmailAlert emailAlert))
                _emailAlert = emailAlert;
            else
                _emailAlert = null;

            if (jsonHealthCheck.TryGetProperty("webHook", out JsonElement jsonWebHook) && _service.WebHooks.TryGetValue(jsonWebHook.GetString(), out WebHook webHook))
                _webHook = webHook;
            else
                _webHook = null;

            ConditionalHttpReload();
        }

        public async Task<HealthCheckResponse> IsHealthyAsync(string domain, DnsResourceRecordType type, Uri healthCheckUrl)
        {
            switch (type)
            {
                case DnsResourceRecordType.A:
                    {
                        DnsDatagram response = await _service.DnsServer.DirectQueryAsync(new DnsQuestionRecord(domain, type, DnsClass.IN));
                        if ((response is null) || (response.Answer.Count == 0))
                            return new HealthCheckResponse(HealthStatus.Failed, "Failed to resolve address.");

                        IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseA(response);
                        if (addresses.Count > 0)
                        {
                            HealthCheckResponse lastResponse = null;

                            foreach (IPAddress address in addresses)
                            {
                                lastResponse = await IsHealthyAsync(address, healthCheckUrl);
                                if (lastResponse.Status == HealthStatus.Healthy)
                                    return lastResponse;
                            }

                            return lastResponse;
                        }

                        return new HealthCheckResponse(HealthStatus.Failed, "Failed to resolve address.");
                    }

                case DnsResourceRecordType.AAAA:
                    {
                        DnsDatagram response = await _service.DnsServer.DirectQueryAsync(new DnsQuestionRecord(domain, type, DnsClass.IN));
                        if ((response is null) || (response.Answer.Count == 0))
                            return new HealthCheckResponse(HealthStatus.Failed, "Failed to resolve address.");

                        IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseAAAA(response);
                        if (addresses.Count > 0)
                        {
                            HealthCheckResponse lastResponse = null;

                            foreach (IPAddress address in addresses)
                            {
                                lastResponse = await IsHealthyAsync(address, healthCheckUrl);
                                if (lastResponse.Status == HealthStatus.Healthy)
                                    return lastResponse;
                            }

                            return lastResponse;
                        }

                        return new HealthCheckResponse(HealthStatus.Failed, "Failed to resolve address.");
                    }

                default:
                    return new HealthCheckResponse(HealthStatus.Failed, "Not supported.");
            }
        }

        public async Task<HealthCheckResponse> IsHealthyAsync(IPAddress address, Uri healthCheckUrl)
        {
            foreach (KeyValuePair<NetworkAddress, bool> network in _service.UnderMaintenance)
            {
                if (network.Key.Contains(address))
                {
                    if (network.Value)
                        return new HealthCheckResponse(HealthStatus.Maintenance);

                    break;
                }
            }

            switch (_type)
            {
                case HealthCheckType.Ping:
                    {
                        if (_service.DnsServer.Proxy != null)
                            throw new NotSupportedException("Health check type 'ping' is not supported over proxy.");

                        using (Ping ping = new Ping())
                        {
                            string lastReason;
                            int retry = 0;
                            do
                            {
                                PingReply reply = await ping.SendPingAsync(address, _timeout);
                                if (reply.Status == IPStatus.Success)
                                    return new HealthCheckResponse(HealthStatus.Healthy);

                                lastReason = reply.Status.ToString();
                            }
                            while (++retry < _retries);

                            return new HealthCheckResponse(HealthStatus.Failed, lastReason);
                        }
                    }

                case HealthCheckType.Tcp:
                    {
                        Exception lastException;
                        string lastReason = null;
                        int retry = 0;
                        do
                        {
                            try
                            {
                                NetProxy proxy = _service.DnsServer.Proxy;

                                if (proxy is null)
                                {
                                    using (Socket socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
                                    {
                                        await TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                                        {
                                            return socket.ConnectAsync(address, _port, cancellationToken1).AsTask();
                                        }, _timeout);
                                    }
                                }
                                else
                                {
                                    using (Socket socket = await TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                                        {
                                            return proxy.ConnectAsync(new IPEndPoint(address, _port), cancellationToken1);
                                        }, _timeout))
                                    {
                                        //do nothing
                                    }
                                }

                                return new HealthCheckResponse(HealthStatus.Healthy);
                            }
                            catch (TimeoutException ex)
                            {
                                lastReason = "Connection timed out.";
                                lastException = ex;
                            }
                            catch (SocketException ex)
                            {
                                lastReason = ex.Message;
                                lastException = ex;
                            }
                            catch (Exception ex)
                            {
                                lastException = ex;
                            }
                        }
                        while (++retry < _retries);

                        return new HealthCheckResponse(HealthStatus.Failed, lastReason, lastException);
                    }

                case HealthCheckType.Http:
                case HealthCheckType.Https:
                    {
                        ConditionalHttpReload();

                        Exception lastException;
                        string lastReason = null;
                        int retry = 0;
                        do
                        {
                            try
                            {
                                Uri url;

                                if (_url is null)
                                    url = healthCheckUrl;
                                else
                                    url = _url;

                                if (url is null)
                                    return new HealthCheckResponse(HealthStatus.Failed, "Missing health check URL in APP record as well as in app config.");

                                if (_type == HealthCheckType.Http)
                                {
                                    if (url.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                                        url = new Uri("http://" + url.Host + (url.IsDefaultPort ? "" : ":" + url.Port) + url.PathAndQuery);
                                }
                                else
                                {
                                    if (url.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase))
                                        url = new Uri("https://" + url.Host + (url.IsDefaultPort ? "" : ":" + url.Port) + url.PathAndQuery);
                                }

                                IPEndPoint ep = new IPEndPoint(address, url.Port);
                                Uri queryUri = new Uri(url.Scheme + "://" + ep.ToString() + url.PathAndQuery);
                                HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Get, queryUri);

                                if (url.IsDefaultPort)
                                    httpRequest.Headers.Host = url.Host;
                                else
                                    httpRequest.Headers.Host = url.Host + ":" + url.Port;

                                HttpResponseMessage httpResponse = await _httpClient.SendAsync(httpRequest);
                                if (httpResponse.IsSuccessStatusCode)
                                    return new HealthCheckResponse(HealthStatus.Healthy);

                                return new HealthCheckResponse(HealthStatus.Failed, "Received HTTP status code: " + (int)httpResponse.StatusCode + " " + httpResponse.StatusCode.ToString() + "; URL: " + url.AbsoluteUri);
                            }
                            catch (OperationCanceledException ex)
                            {
                                lastReason = "Connection timed out.";
                                lastException = ex;
                            }
                            catch (HttpRequestException ex)
                            {
                                lastReason = ex.Message;
                                lastException = ex;
                            }
                            catch (Exception ex)
                            {
                                lastException = ex;
                            }
                        }
                        while (++retry < _retries);

                        return new HealthCheckResponse(HealthStatus.Failed, lastReason, lastException);
                    }

                default:
                    throw new NotSupportedException();
            }
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public HealthCheckType Type
        { get { return _type; } }

        public int Interval
        { get { return _interval; } }

        public int Retries
        { get { return _retries; } }

        public int Timeout
        { get { return _timeout; } }

        public int Port
        { get { return _port; } }

        public Uri Url
        { get { return _url; } }

        public EmailAlert EmailAlert
        { get { return _emailAlert; } }

        public WebHook WebHook
        { get { return _webHook; } }

        #endregion
    }
}
