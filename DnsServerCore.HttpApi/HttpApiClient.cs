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
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
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

        public HttpApiClient(string serverUrl, NetProxy? proxy = null, bool preferIPv6 = false, bool ignoreCertErrors = false, IDnsClient? dnsClient = null)
            : this(new Uri(serverUrl), proxy, preferIPv6, ignoreCertErrors, dnsClient)
        { }

        public HttpApiClient(Uri serverUrl, NetProxy? proxy = null, bool preferIPv6 = false, bool ignoreCertErrors = false, IDnsClient? dnsClient = null)
        {
            _serverUrl = serverUrl;

            HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
            handler.Proxy = proxy;
            handler.NetworkType = preferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
            handler.DnsClient = dnsClient;

            if (ignoreCertErrors)
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

        private static string ToBase64UrlString(byte[] data)
        {
            return Convert.ToBase64String(data).Replace('+', '-').Replace('/', '_').TrimEnd('=');
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

            _token = null;
            _loggedIn = false;
        }

        public void UseApiToken(string token)
        {
            if (_loggedIn)
                throw new HttpApiClientException("Already logged in. Please logout before using a different API token.");

            _token = token;
            _loggedIn = true;
        }

        public async Task<ClusterInfo> GetClusterStateAsync(bool includeServerIpAddresses = false, bool includeNodeCertificates = false, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/state?token={_token}&includeServerIpAddresses={includeServerIpAddresses}&includeNodeCertificates={includeNodeCertificates}", cancellationToken);

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

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/delete?token={_token}&forceDelete={forceDelete}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            ClusterInfo? clusterInfo = rootElement.GetProperty("response").Deserialize<ClusterInfo>(_serializerOptions);
            if (clusterInfo is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            return clusterInfo;
        }

        public async Task<ClusterInfo> JoinClusterAsync(int secondaryNodeId, Uri secondaryNodeUrl, IPAddress secondaryNodeIpAddress, X509Certificate2 secondaryNodeCertificate, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/join?token={_token}&secondaryNodeId={secondaryNodeId}&secondaryNodeUrl={HttpUtility.UrlEncode(secondaryNodeUrl.OriginalString)}&secondaryNodeIpAddress={HttpUtility.UrlEncode(secondaryNodeIpAddress.ToString())}&secondaryNodeCertificate={ToBase64UrlString(secondaryNodeCertificate.Export(X509ContentType.Cert))}", cancellationToken);

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

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/deleteSecondary?token={_token}&secondaryNodeId={secondaryNodeId}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            ClusterInfo? clusterInfo = rootElement.GetProperty("response").Deserialize<ClusterInfo>(_serializerOptions);
            if (clusterInfo is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            return clusterInfo;
        }

        public async Task<ClusterInfo> UpdateSecondaryNodeAsync(int secondaryNodeId, Uri secondaryNodeUrl, IPAddress secondaryNodeIpAddress, X509Certificate2 secondaryNodeCertificate, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/primary/updateSecondary?token={_token}&secondaryNodeId={secondaryNodeId}&secondaryNodeUrl={HttpUtility.UrlEncode(secondaryNodeUrl.OriginalString)}&secondaryNodeIpAddress={HttpUtility.UrlEncode(secondaryNodeIpAddress.ToString())}&secondaryNodeCertificate={ToBase64UrlString(secondaryNodeCertificate.Export(X509ContentType.Cert))}", cancellationToken);

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

            HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Get, $"api/admin/cluster/primary/transferConfig?token={_token}&includeZones={(includeZones is null ? "" : includeZones.Join(','))}");
            httpRequest.Headers.IfModifiedSince = ifModifiedSince;

            HttpResponseMessage httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);

            return (httpResponse.Content.ReadAsStream(cancellationToken), httpResponse.Content.Headers.LastModified?.UtcDateTime ?? DateTime.UtcNow);
        }

        public async Task<ClusterInfo> LeaveClusterAsync(bool forceLeave = false, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/secondary/leave?token={_token}&forceLeave={forceLeave}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);

            ClusterInfo? clusterInfo = rootElement.GetProperty("response").Deserialize<ClusterInfo>(_serializerOptions);
            if (clusterInfo is null)
                throw new HttpApiClientException("Invalid JSON response was received.");

            return clusterInfo;
        }

        public async Task NotifySecondaryNodeAsync(int primaryNodeId, Uri primaryNodeUrl, IPAddress primaryNodeIpAddress, CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/secondary/notify?token={_token}&primaryNodeId={primaryNodeId}&primaryNodeUrl={HttpUtility.UrlEncode(primaryNodeUrl.OriginalString)}&primaryNodeIpAddress={HttpUtility.UrlEncode(primaryNodeIpAddress.ToString())}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        public async Task ResyncClusterFromPrimaryNodeAsync(CancellationToken cancellationToken = default)
        {
            if (!_loggedIn)
                throw new HttpApiClientException("No active session exists. Please login and try again.");

            Stream stream = await _httpClient.GetStreamAsync($"api/admin/cluster/secondary/resync?token={_token}", cancellationToken);

            using JsonDocument jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement rootElement = jsonDoc.RootElement;

            CheckResponseStatus(rootElement);
        }

        #endregion

        #region properties

        public Uri ServerUrl
        { get { return _serverUrl; } }

        #endregion
    }
}
