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

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
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

        readonly HealthMonitoringService _service;

        string _name;
        HealthCheckType _type;
        int _interval;
        int _retries;
        int _timeout;
        int _port;
        Uri _url;
        EmailAlert _emailAlert;
        WebHook _webHook;

        SocketsHttpHandler _httpHandler;
        HttpClient _httpClient;

        #endregion

        #region constructor

        public HealthCheck(HealthMonitoringService service, dynamic jsonHealthCheck)
        {
            _service = service;

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
                        SocketsHttpHandler httpHandler = new SocketsHttpHandler();
                        httpHandler.ConnectTimeout = TimeSpan.FromMilliseconds(_timeout);
                        httpHandler.Proxy = proxy;
                        httpHandler.AllowAutoRedirect = true;
                        httpHandler.MaxAutomaticRedirections = 10;

                        _httpHandler = httpHandler;
                        handlerChanged = true;
                    }
                    else
                    {
                        if ((_httpHandler.ConnectTimeout.TotalMilliseconds != _timeout) || (_httpHandler.Proxy != proxy))
                        {
                            SocketsHttpHandler httpHandler = new SocketsHttpHandler();
                            httpHandler.ConnectTimeout = TimeSpan.FromMilliseconds(_timeout);
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
                        httpClient.Timeout = TimeSpan.FromMilliseconds(_timeout);
                        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(HTTP_HEALTH_CHECK_USER_AGENT);

                        _httpClient = httpClient;
                    }
                    else
                    {
                        if (handlerChanged || (_httpClient.Timeout.TotalMilliseconds != _timeout))
                        {
                            HttpClient httpClient = new HttpClient(_httpHandler);
                            httpClient.Timeout = TimeSpan.FromMilliseconds(_timeout);
                            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(HTTP_HEALTH_CHECK_USER_AGENT);

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

        public void Reload(dynamic jsonHealthCheck)
        {
            if (jsonHealthCheck.name is null)
                _name = "default";
            else
                _name = jsonHealthCheck.name.Value;

            if (jsonHealthCheck.type == null)
                _type = HealthCheckType.Tcp;
            else
                _type = Enum.Parse<HealthCheckType>(jsonHealthCheck.type.Value, true);

            if (jsonHealthCheck.interval is null)
                _interval = 60000;
            else
                _interval = Convert.ToInt32(jsonHealthCheck.interval.Value) * 1000;

            if (jsonHealthCheck.retries is null)
                _retries = 3;
            else
                _retries = Convert.ToInt32(jsonHealthCheck.retries.Value);

            if (jsonHealthCheck.timeout is null)
                _timeout = 10000;
            else
                _timeout = Convert.ToInt32(jsonHealthCheck.timeout.Value) * 1000;

            if (jsonHealthCheck.port is null)
                _port = 80;
            else
                _port = Convert.ToInt32(jsonHealthCheck.port.Value);

            if ((jsonHealthCheck.url is null) || (jsonHealthCheck.url.Value is null))
                _url = null;
            else
                _url = new Uri(jsonHealthCheck.url.Value);

            string emailAlertName;

            if (jsonHealthCheck.emailAlert is null)
                emailAlertName = null;
            else
                emailAlertName = jsonHealthCheck.emailAlert.Value;

            if ((emailAlertName is not null) && _service.EmailAlerts.TryGetValue(emailAlertName, out EmailAlert emailAlert))
                _emailAlert = emailAlert;
            else
                _emailAlert = null;

            string webHookName;

            if (jsonHealthCheck.webHook is null)
                webHookName = null;
            else
                webHookName = jsonHealthCheck.webHook.Value;

            if ((webHookName is not null) && _service.WebHooks.TryGetValue(webHookName, out WebHook webHook))
                _webHook = webHook;
            else
                _webHook = null;

            ConditionalHttpReload();
        }

        public async Task<HealthCheckStatus> IsHealthyAsync(string domain, DnsResourceRecordType type, Uri healthCheckUrl)
        {
            switch (type)
            {
                case DnsResourceRecordType.A:
                    {
                        DnsDatagram response = await _service.DnsServer.DirectQueryAsync(new DnsQuestionRecord(domain, type, DnsClass.IN));
                        if ((response is null) || (response.Answer.Count == 0))
                            return HealthCheckStatus.FailedToResolve();

                        IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseA(response);
                        if (addresses.Count > 0)
                        {
                            HealthCheckStatus lastStatus = null;

                            foreach (IPAddress address in addresses)
                            {
                                lastStatus = await IsHealthyAsync(address, healthCheckUrl);
                                if (lastStatus.IsHealthy)
                                    return lastStatus;
                            }

                            return lastStatus;
                        }

                        return HealthCheckStatus.FailedToResolve();
                    }

                case DnsResourceRecordType.AAAA:
                    {
                        DnsDatagram response = await _service.DnsServer.DirectQueryAsync(new DnsQuestionRecord(domain, type, DnsClass.IN));
                        if ((response is null) || (response.Answer.Count == 0))
                            return HealthCheckStatus.FailedToResolve();

                        IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseAAAA(response);
                        if (addresses.Count > 0)
                        {
                            HealthCheckStatus lastStatus = null;

                            foreach (IPAddress address in addresses)
                            {
                                lastStatus = await IsHealthyAsync(address, healthCheckUrl);
                                if (lastStatus.IsHealthy)
                                    return lastStatus;
                            }

                            return lastStatus;
                        }

                        return HealthCheckStatus.FailedToResolve();
                    }

                default:
                    return HealthCheckStatus.NotSupported();
            }
        }

        public async Task<HealthCheckStatus> IsHealthyAsync(IPAddress address, Uri healthCheckUrl)
        {
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
                                    return HealthCheckStatus.Success();

                                lastReason = reply.Status.ToString();
                            }
                            while (++retry < _retries);

                            return new HealthCheckStatus(false, lastReason);
                        }
                    }

                case HealthCheckType.Tcp:
                    {
                        Exception lastException = null;
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
                                        await socket.ConnectAsync(address, _port).WithTimeout(_timeout);
                                    }
                                }
                                else
                                {
                                    using (Socket socket = await proxy.ConnectAsync(new IPEndPoint(address, _port)).WithTimeout(_timeout))
                                    {
                                        //do nothing
                                    }
                                }

                                return HealthCheckStatus.Success();
                            }
                            catch (TimeoutException)
                            {
                                lastReason = "Connection timed out.";
                            }
                            catch (SocketException ex)
                            {
                                lastReason = ex.Message;
                            }
                            catch (Exception ex)
                            {
                                lastException = ex;
                            }
                        }
                        while (++retry < _retries);

                        if (lastException is not null)
                            throw lastException;

                        return new HealthCheckStatus(false, lastReason);
                    }

                case HealthCheckType.Http:
                case HealthCheckType.Https:
                    {
                        ConditionalHttpReload();

                        Exception lastException = null;
                        string lastReason = null;
                        int retry = 0;
                        do
                        {
                            try
                            {
                                Uri url = healthCheckUrl;
                                if (url is null)
                                {
                                    url = _url;
                                    if (url is null)
                                        return new HealthCheckStatus(false, "Missing health check URL in APP record as well as in app config.");
                                }

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
                                    return HealthCheckStatus.Success();

                                lastReason = "Received HTTP status code: " + (int)httpResponse.StatusCode + " " + httpResponse.StatusCode.ToString() + "; URL: " + url.AbsoluteUri;
                                break;
                            }
                            catch (TaskCanceledException)
                            {
                                lastReason = "Connection timed out.";
                            }
                            catch (Exception ex)
                            {
                                lastException = ex;
                            }
                        }
                        while (++retry < _retries);

                        if (lastException is not null)
                            throw lastException;

                        return new HealthCheckStatus(false, lastReason);
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
