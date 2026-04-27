/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
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

        readonly HttpClient _httpClient;
        bool _loggedIn;

        #endregion

        #region constructor

        static HttpApiClient()
        {
            _serializerOptions = new JsonSerializerOptions();
            _serializerOptions.PropertyNameCaseInsensitive = true;
        }

        public HttpApiClient(Uri serverUrl, NetProxy? proxy = null, IPv6Mode ipv6Mode = IPv6Mode.Disabled, bool ignoreCertificateErrors = false, IDnsClient? dnsClient = null, TimeSpan? timeout = null)
            : this(serverUrl, proxy, HttpClientNetworkHandler.GetNetworkType(ipv6Mode), ignoreCertificateErrors, dnsClient, timeout)
        { }

        public HttpApiClient(Uri serverUrl, NetProxy? proxy = null, HttpClientNetworkType networkType = HttpClientNetworkType.Default, bool ignoreCertificateErrors = false, IDnsClient? dnsClient = null, TimeSpan? timeout = null)
        {
            _serverUrl = serverUrl;

            HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
            handler.Proxy = proxy;
            handler.NetworkType = networkType;
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
            _httpClient.Timeout = timeout ?? TimeSpan.FromSeconds(30);
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

            HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Post, new Uri(_serverUrl, $"api/user/login"));

            Dictionary<string, string> parameters = new Dictionary<string, string>
            {
                { "user", username },
                { "pass", password },
                { "includeInfo", includeInfo.ToString() }
            };

            if (totp is not null)
                parameters.Add("totp", totp);

            httpRequest.Content = new FormUrlEncodedContent(parameters);

            HttpResponseMessage httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(httpResponse.Content.ReadAsStream(cancellationToken), cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            SessionInfo? sessionInfo = rootElement.Deserialize<SessionInfo>(_serializerOptions);
            if (sessionInfo is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            _httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + sessionInfo.Token);
            _loggedIn = true;

            return sessionInfo;
        }

        public async Task LogoutAsync(CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exist to logout.");

            Stream stream = await _httpClient.GetStreamAsync($"api/user/logout", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            _httpClient.DefaultRequestHeaders.Remove("Authorization");
            _loggedIn = false;
        }

        public void UseApiToken(string token)
        {
            if (_loggedIn)
                throw new HttpApiClientException("Already logged in. Please logout before using a different API token.");

            _httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + token);
            _loggedIn = true;
        }

        public async Task<DashboardStats> GetDashboardStatsAsync(string actingUsername, DashboardStatsType type = DashboardStatsType.LastHour, bool utcFormat = false, string acceptLanguage = "en-US,en;q=0.5", bool dontTrimQueryTypeData = false, DateTime startDate = default, DateTime endDate = default, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            string path = $"api/dashboard/stats/get?actingUser={Uri.EscapeDataString(actingUsername)}&type={type}&utc={utcFormat}&dontTrimQueryTypeData={dontTrimQueryTypeData}";

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

        public async Task<DashboardStats> GetDashboardTopStatsAsync(string actingUsername, DashboardTopStatsType statsType, int limit = 1000, DashboardStatsType type = DashboardStatsType.LastHour, DateTime startDate = default, DateTime endDate = default, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            string path = $"api/dashboard/stats/getTop?actingUser={Uri.EscapeDataString(actingUsername)}&type={type}&statsType={statsType}&limit={limit}";

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

        public async Task SetClusterSettingsAsync(string actingUsername, IReadOnlyDictionary<string, string> clusterParameters, CancellationToken cancellationToken = default)
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

            HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Post, new Uri(_serverUrl, $"api/settings/set?actingUser={Uri.EscapeDataString(actingUsername)}"));

            httpRequest.Content = new FormUrlEncodedContent(clusterParameters);

            HttpResponseMessage httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(httpResponse.Content.ReadAsStream(cancellationToken), cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task ForceUpdateBlockListsAsync(string actingUsername, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/settings/forceUpdateBlockLists?actingUser={Uri.EscapeDataString(actingUsername)}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task TemporaryDisableBlockingAsync(string actingUsername, int minutes, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/settings/temporaryDisableBlocking?actingUser={Uri.EscapeDataString(actingUsername)}&minutes={minutes}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task CreateSsoUserAsync(string ssoIdentifier, string username, string? displayName, IReadOnlyCollection<string>? memberOfGroups, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            string path = $"api/admin/sso/users/create?ssoIdentifier={ssoIdentifier}&user={username}";

            if (displayName is not null)
                path += $"&displayName={displayName}";

            if (memberOfGroups is not null)
                path += $"&memberOfGroups={memberOfGroups.Join()}";

            Stream stream = await _httpClient.GetStreamAsync(path, cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task SetSsoUserAsync(string username, string? newUsername, string? displayName, IReadOnlyCollection<string>? memberOfGroups, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            string path = $"api/admin/sso/users/set?user={username}";

            if (newUsername is not null)
                path += $"&newUser={newUsername}";

            if (displayName is not null)
                path += $"&displayName={displayName}";

            if (memberOfGroups is not null)
                path += $"&memberOfGroups={memberOfGroups.Join()}";

            Stream stream = await _httpClient.GetStreamAsync(path, cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task<ClusterInfo> GetClusterStateAsync(bool includeServerIpAddresses = false, bool includeNodeCertificates = false, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/state?includeServerIpAddresses={includeServerIpAddresses}&includeNodeCertificates={includeNodeCertificates}", cancellationToken);

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

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/delete?forceDelete={forceDelete}", cancellationToken);

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

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/join?secondaryNodeId={secondaryNodeId}&secondaryNodeUrl={Uri.EscapeDataString(secondaryNodeUrl.OriginalString)}&secondaryNodeIpAddresses={Uri.EscapeDataString(secondaryNodeIpAddresses.Join())}&secondaryNodeCertificate={Base64Url.EncodeToString(secondaryNodeCertificate.Export(X509ContentType.Cert))}", cancellationToken);

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

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/deleteSecondary?secondaryNodeId={secondaryNodeId}", cancellationToken);

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

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/updateSecondary?secondaryNodeId={secondaryNodeId}&secondaryNodeUrl={Uri.EscapeDataString(secondaryNodeUrl.OriginalString)}&secondaryNodeIpAddresses={Uri.EscapeDataString(secondaryNodeIpAddresses.Join())}&secondaryNodeCertificate={Base64Url.EncodeToString(secondaryNodeCertificate.Export(X509ContentType.Cert))}", cancellationToken);

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

            HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Get, $"api/admin/cluster/primary/transferConfig?includeZones={(includeZones is null ? "" : includeZones.Join(','))}");
            httpRequest.Headers.IfModifiedSince = ifModifiedSince;

            HttpResponseMessage httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);

            return (httpResponse.Content.ReadAsStream(cancellationToken), httpResponse.Content.Headers.LastModified?.UtcDateTime ?? DateTime.UtcNow);
        }

        public async Task<ClusterInfo> LeaveClusterAsync(bool forceLeave = false, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/secondary/leave?forceLeave={forceLeave}", cancellationToken);

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

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/secondary/notify?primaryNodeId={primaryNodeId}&primaryNodeUrl={Uri.EscapeDataString(primaryNodeUrl.OriginalString)}&primaryNodeIpAddresses={Uri.EscapeDataString(primaryNodeIpAddresses.Join())}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task ProxyRequest(HttpContext context, string actingUsername, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            //read input http request and send http response to node
            HttpRequest inHttpRequest = context.Request;

            StringBuilder queryString = new StringBuilder();

            queryString.Append("?actingUser=").Append(Uri.EscapeDataString(actingUsername));

            foreach (KeyValuePair<string, StringValues> query in inHttpRequest.Query)
            {
                string key = query.Key;
                string value = query.Value.ToString();

                switch (key)
                {
                    case "token":
                    case "node":
                        //skip params
                        continue;
                }

                queryString.Append('&').Append(key).Append('=').Append(Uri.EscapeDataString(value));
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
                            case "node":
                                //skip params
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
                if (inHeader.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                    continue; //skip client header

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
