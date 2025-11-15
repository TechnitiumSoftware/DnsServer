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

using DnsServerCore.HttpApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Http.Client;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore.HttpApi
{
    public sealed class HttpApiClient : IDisposable
    {
        #region variables

        readonly static JsonSerializerOptions _serializerOptions;

        readonly Uri _serverUrl;
        string? _username;
        string? _token;

        readonly HttpClient _httpClient;
        bool _loggedIn;

        #endregion

        #region constructor

        static HttpApiClient()
        {
            _serializerOptions = new JsonSerializerOptions();
            _serializerOptions.PropertyNameCaseInsensitive = true;
        }

        public HttpApiClient(string serverUrl, NetProxy? proxy = null, bool preferIPv6 = false, bool ignoreCertificateErrors = false, IDnsClient? dnsClient = null)
            : this(new Uri(serverUrl), proxy, preferIPv6, ignoreCertificateErrors, dnsClient)
        { }

        public HttpApiClient(Uri serverUrl, NetProxy? proxy = null, bool preferIPv6 = false, bool ignoreCertificateErrors = false, IDnsClient? dnsClient = null)
        {
            _serverUrl = serverUrl;

            HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
            handler.Proxy = proxy;
            handler.NetworkType = preferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
            handler.DnsClient = dnsClient;

            if (ignoreCertificateErrors)
            {
                handler.InnerHandler.SslOptions.RemoteCertificateValidationCallback = delegate (object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
                {
                    return true;
                };
            }
            else
            {
                handler.EnableDANE = true;
            }

            _httpClient = new HttpClient(handler);
            _httpClient.BaseAddress = _serverUrl;
            _httpClient.DefaultRequestHeaders.Add("user-agent", "Technitium DNS Server HTTP API Client");
            _httpClient.Timeout = TimeSpan.FromSeconds(30);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _httpClient?.Dispose();

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        #endregion

        #region private

        private static void CheckResponseStatus(JsonElement rootElement)
        {
            if (!rootElement.TryGetProperty("status", out JsonElement jsonStatus))
                throw new HttpApiClientException("Invalid JSON response was received.");

            string? status = jsonStatus.GetString()?.ToLowerInvariant();
            switch (status)
            {
                case "ok":
                    return;

                case "error":
                    {
                        Exception? innerException = null;

                        if (rootElement.TryGetProperty("innerErrorMessage", out JsonElement jsonInnerErrorMessage))
                            innerException = new HttpApiClientException(jsonInnerErrorMessage.GetString()!);

                        if (rootElement.TryGetProperty("errorMessage", out JsonElement jsonErrorMessage))
                        {
                            if (innerException is null)
                                throw new HttpApiClientException(jsonErrorMessage.GetString()!);

                            throw new HttpApiClientException(jsonErrorMessage.GetString()!, innerException);
                        }

                        throw new HttpApiClientException();
                    }

                case "invalid-token":
                    {
                        if (rootElement.TryGetProperty("errorMessage", out JsonElement jsonErrorMessage))
                            throw new InvalidTokenHttpApiClientException(jsonErrorMessage.GetString()!);

                        throw new InvalidTokenHttpApiClientException();
                    }

                case "2fa-required":
                    {
                        if (rootElement.TryGetProperty("errorMessage", out JsonElement jsonErrorMessage))
                            throw new TwoFactorAuthRequiredHttpApiClientException(jsonErrorMessage.GetString()!);

                        throw new TwoFactorAuthRequiredHttpApiClientException();
                    }

                default:
                    throw new HttpApiClientException("Unknown status value was received: " + status);
            }
        }

        #endregion

        #region public

        public async Task<SessionInfo> LoginAsync(string username, string password, string? totp = null, bool includeInfo = false, CancellationToken cancellationToken = default)
        {
            if (_loggedIn)
                throw new HttpApiClientException("Already logged in.");

            Stream stream = await _httpClient.GetStreamAsync($"api/user/login?user={HttpUtility.UrlEncode(username)}&pass={HttpUtility.UrlEncode(password)}&totp={(totp is null ? "" : HttpUtility.UrlEncode(totp))}&includeInfo={includeInfo}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            SessionInfo? sessionInfo = rootElement.Deserialize<SessionInfo>(_serializerOptions);
            if (sessionInfo is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            _username = sessionInfo.Username;
            _token = sessionInfo.Token;
            _loggedIn = true;

            return sessionInfo;
        }

        public async Task LogoutAsync(CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exist to logout.");

            Stream stream = await _httpClient.GetStreamAsync($"api/user/logout?token={_token}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            _username = null;
            _token = null;
            _loggedIn = false;
        }

        public void UseApiToken(string username, string token)
        {
            if (_loggedIn)
                throw new HttpApiClientException("Already logged in. Please logout before using a different API token.");

            _username = username;
            _token = token;
            _loggedIn = true;
        }

        public async Task<DashboardStats> GetDashboardStatsAsync(DashboardStatsType type = DashboardStatsType.LastHour, bool utcFormat = false, string acceptLanguage = "en-US,en;q=0.5", bool dontTrimQueryTypeData = false, DateTime startDate = default, DateTime endDate = default, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            string path = $"api/dashboard/stats/get?token={_token}&user={HttpUtility.UrlEncode(_username)}&type={type}&utc={utcFormat}&dontTrimQueryTypeData={dontTrimQueryTypeData}";

            if (type == DashboardStatsType.Custom)
                path += $"&start={startDate:O}&end={endDate:O}";

            HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Get, new Uri(_serverUrl, path));
            httpRequest.Headers.Add("Accept-Language", acceptLanguage);

            HttpResponseMessage httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(httpResponse.Content.ReadAsStream(cancellationToken), cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            DashboardStats? stats = rootElement.GetProperty("response").Deserialize<DashboardStats>(_serializerOptions);
            if (stats is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            return stats;
        }

        public async Task<DashboardStats> GetDashboardTopStatsAsync(DashboardTopStatsType statsType, int limit = 1000, DashboardStatsType type = DashboardStatsType.LastHour, DateTime startDate = default, DateTime endDate = default, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            string path = $"api/dashboard/stats/getTop?token={_token}&user={HttpUtility.UrlEncode(_username)}&type={type}&statsType={statsType}&limit={limit}";

            if (type == DashboardStatsType.Custom)
                path += $"&start={startDate:O}&end={endDate:O}";

            HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Get, new Uri(_serverUrl, path));

            HttpResponseMessage httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(httpResponse.Content.ReadAsStream(cancellationToken), cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            DashboardStats? stats = rootElement.GetProperty("response").Deserialize<DashboardStats>(_serializerOptions);
            if (stats is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            return stats;
        }

        public async Task SetClusterSettingsAsync(IReadOnlyDictionary<string, string> clusterParameters, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            if (clusterParameters.Count == 0)
                throw new ArgumentException("At least one parameter must be provided.", nameof(clusterParameters));

            foreach (KeyValuePair<string, string> parameter in clusterParameters)
            {
                switch (parameter.Key)
                {
                    case "token":
                    case "node":
                        throw new ArgumentException($"The '{parameter.Key}' is an invalid Settings parameter.", nameof(clusterParameters));
                }
            }

            HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Post, new Uri(_serverUrl, $"api/settings/set?token={_token}&user={HttpUtility.UrlEncode(_username)}"));

            httpRequest.Content = new FormUrlEncodedContent(clusterParameters);

            HttpResponseMessage httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(httpResponse.Content.ReadAsStream(cancellationToken), cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task ForceUpdateBlockListsAsync(CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/settings/forceUpdateBlockLists?token={_token}&user={HttpUtility.UrlEncode(_username)}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task TemporaryDisableBlockingAsync(int minutes, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/settings/temporaryDisableBlocking?token={_token}&user={HttpUtility.UrlEncode(_username)}&minutes={minutes}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task<ClusterInfo> GetClusterStateAsync(bool includeServerIpAddresses = false, bool includeNodeCertificates = false, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/state?token={_token}&user={HttpUtility.UrlEncode(_username)}&includeServerIpAddresses={includeServerIpAddresses}&includeNodeCertificates={includeNodeCertificates}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            ClusterInfo? clusterInfo = rootElement.GetProperty("response").Deserialize<ClusterInfo>(_serializerOptions);
            if (clusterInfo is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            return clusterInfo;
        }

        public async Task<ClusterInfo> DeleteClusterAsync(bool forceDelete = false, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/delete?token={_token}&user={HttpUtility.UrlEncode(_username)}&forceDelete={forceDelete}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            ClusterInfo? clusterInfo = rootElement.GetProperty("response").Deserialize<ClusterInfo>(_serializerOptions);
            if (clusterInfo is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            return clusterInfo;
        }

        public async Task<ClusterInfo> JoinClusterAsync(int secondaryNodeId, Uri secondaryNodeUrl, IReadOnlyCollection<IPAddress> secondaryNodeIpAddresses, X509Certificate2 secondaryNodeCertificate, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/join?token={_token}&user={HttpUtility.UrlEncode(_username)}&secondaryNodeId={secondaryNodeId}&secondaryNodeUrl={HttpUtility.UrlEncode(secondaryNodeUrl.OriginalString)}&secondaryNodeIpAddresses={HttpUtility.UrlEncode(secondaryNodeIpAddresses.Join())}&secondaryNodeCertificate={Base64Url.EncodeToString(secondaryNodeCertificate.Export(X509ContentType.Cert))}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            ClusterInfo? clusterInfo = rootElement.GetProperty("response").Deserialize<ClusterInfo>(_serializerOptions);
            if (clusterInfo is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            return clusterInfo;
        }

        public async Task<ClusterInfo> DeleteSecondaryNodeAsync(int secondaryNodeId, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/deleteSecondary?token={_token}&user={HttpUtility.UrlEncode(_username)}&secondaryNodeId={secondaryNodeId}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            ClusterInfo? clusterInfo = rootElement.GetProperty("response").Deserialize<ClusterInfo>(_serializerOptions);
            if (clusterInfo is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            return clusterInfo;
        }

        public async Task<ClusterInfo> UpdateSecondaryNodeAsync(int secondaryNodeId, Uri secondaryNodeUrl, IReadOnlyCollection<IPAddress> secondaryNodeIpAddresses, X509Certificate2 secondaryNodeCertificate, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/updateSecondary?token={_token}&user={HttpUtility.UrlEncode(_username)}&secondaryNodeId={secondaryNodeId}&secondaryNodeUrl={HttpUtility.UrlEncode(secondaryNodeUrl.OriginalString)}&secondaryNodeIpAddresses={HttpUtility.UrlEncode(secondaryNodeIpAddresses.Join())}&secondaryNodeCertificate={Base64Url.EncodeToString(secondaryNodeCertificate.Export(X509ContentType.Cert))}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            ClusterInfo? clusterInfo = rootElement.GetProperty("response").Deserialize<ClusterInfo>(_serializerOptions);
            if (clusterInfo is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            return clusterInfo;
        }

        public async Task<(Stream, DateTime)> TransferConfigFromPrimaryNodeAsync(DateTime ifModifiedSince = default, IReadOnlyCollection<string>? includeZones = null, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Get, $"api/admin/cluster/primary/transferConfig?token={_token}&user={HttpUtility.UrlEncode(_username)}&includeZones={(includeZones is null ? "" : includeZones.Join(','))}");
            httpRequest.Headers.IfModifiedSince = ifModifiedSince;

            HttpResponseMessage httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);

            return (httpResponse.Content.ReadAsStream(cancellationToken), httpResponse.Content.Headers.LastModified?.UtcDateTime ?? DateTime.UtcNow);
        }

        public async Task<ClusterInfo> LeaveClusterAsync(bool forceLeave = false, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/secondary/leave?token={_token}&user={HttpUtility.UrlEncode(_username)}&forceLeave={forceLeave}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            ClusterInfo? clusterInfo = rootElement.GetProperty("response").Deserialize<ClusterInfo>(_serializerOptions);
            if (clusterInfo is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            return clusterInfo;
        }

        public async Task NotifySecondaryNodeAsync(int primaryNodeId, Uri primaryNodeUrl, IReadOnlyCollection<IPAddress> primaryNodeIpAddresses, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/secondary/notify?token={_token}&user={HttpUtility.UrlEncode(_username)}&primaryNodeId={primaryNodeId}&primaryNodeUrl={HttpUtility.UrlEncode(primaryNodeUrl.OriginalString)}&primaryNodeIpAddresses={HttpUtility.UrlEncode(primaryNodeIpAddresses.Join())}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task ResyncClusterFromPrimaryNodeAsync(CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/secondary/resync?token={_token}&user={HttpUtility.UrlEncode(_username)}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task ProxyRequest(HttpContext context, string username, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            //read input http request and send http response to node
            HttpRequest inHttpRequest = context.Request;

            StringBuilder queryString = new StringBuilder();

            queryString.Append("?user=").Append(HttpUtility.UrlEncode(username));

            foreach (KeyValuePair<string, StringValues> query in inHttpRequest.Query)
            {
                string key = query.Key;
                string value = query.Value.ToString();

                switch (key)
                {
                    case "token":
                        //use http client token
                        value = _token!;
                        break;

                    case "node":
                        //skip node name
                        continue;
                }

                queryString.Append('&').Append(key).Append('=').Append(HttpUtility.UrlEncode(value));
            }

            HttpRequestMessage httpRequest = new HttpRequestMessage(new HttpMethod(inHttpRequest.Method), new Uri(_serverUrl, inHttpRequest.Path + queryString.ToString()));

            if (inHttpRequest.HasFormContentType)
            {
                if (inHttpRequest.Form.Keys.Count > 0)
                {
                    Dictionary<string, string> formParams = new Dictionary<string, string>(inHttpRequest.Form.Count);

                    foreach (KeyValuePair<string, StringValues> formParam in inHttpRequest.Form)
                    {
                        string key = formParam.Key;
                        string value = formParam.Value.ToString();

                        switch (key)
                        {
                            case "token":
                                //use http client token
                                value = _token!;
                                break;

                            case "node":
                                //skip node name
                                continue;
                        }

                        formParams[key] = value;
                    }

                    httpRequest.Content = new FormUrlEncodedContent(formParams);
                }
                else if (inHttpRequest.Form.Files.Count > 0)
                {
                    MultipartFormDataContent formData = new MultipartFormDataContent();

                    foreach (IFormFile file in inHttpRequest.Form.Files)
                        formData.Add(new StreamContent(file.OpenReadStream()), file.Name, file.FileName);

                    httpRequest.Content = formData;
                }
                else
                {
                    throw new InvalidOperationException();
                }
            }
            else
            {
                httpRequest.Content = new StreamContent(inHttpRequest.Body);
            }

            foreach (KeyValuePair<string, StringValues> inHeader in inHttpRequest.Headers)
            {
                if (!httpRequest.Headers.TryAddWithoutValidation(inHeader.Key, inHeader.Value.ToString()))
                {
                    if (!inHttpRequest.HasFormContentType)
                    {
                        //add content headers only when there is no form data
                        if (!httpRequest.Content.Headers.TryAddWithoutValidation(inHeader.Key, inHeader.Value.ToString()))
                            throw new InvalidOperationException();
                    }
                }
            }

            HttpResponseMessage httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);

            //receive http response and write to output http response
            HttpResponse outHttpResponse = context.Response;

            foreach (KeyValuePair<string, IEnumerable<string>> header in httpResponse.Headers)
            {
                if (header.Key.Equals("transfer-encoding", StringComparison.OrdinalIgnoreCase) && (httpResponse.Headers.TransferEncodingChunked == true))
                    continue; //skip chunked header to allow kestrel to do the chunking

                if (!outHttpResponse.Headers.TryAdd(header.Key, header.Value.Join()))
                    throw new InvalidOperationException();
            }

            foreach (KeyValuePair<string, IEnumerable<string>> header in httpResponse.Content.Headers)
            {
                if (header.Key.Equals("content-length", StringComparison.OrdinalIgnoreCase) && (httpResponse.Headers.TransferEncodingChunked == true))
                    continue; //skip content length when data is chunked

                if (!outHttpResponse.Headers.TryAdd(header.Key, header.Value.Join()))
                    throw new InvalidOperationException();
            }

            await httpResponse.Content.CopyToAsync(outHttpResponse.Body, cancellationToken);
        }

        #endregion

        #region properties

        public Uri ServerUrl
        { get { return _serverUrl; } }

        #endregion
    }
}
