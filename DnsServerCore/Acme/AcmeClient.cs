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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore.Acme
{
    //Automatic Certificate Management Environment (ACME)
    //https://datatracker.ietf.org/doc/html/rfc8555

    class AcmeException : Exception
    {
        public AcmeException(string message, string problemType = null)
            : base(message)
        {
            ProblemType = problemType;
        }

        public string ProblemType { get; }
    }

    sealed class AcmeChallenge
    {
        public required string Url { get; init; }
        public required string Token { get; init; }
        public required string Status { get; init; }
    }

    sealed class AcmeAuthorization
    {
        public required string Url { get; init; }
        public required string Identifier { get; init; }
        public required string Status { get; init; }
        public required bool Wildcard { get; init; }
        public required AcmeChallenge Dns01Challenge { get; init; }
    }

    sealed class AcmeOrder
    {
        public required string Url { get; init; }
        public required string Status { get; init; }
        public required IReadOnlyList<string> AuthorizationUrls { get; init; }
        public required string FinalizeUrl { get; init; }
        public string CertificateUrl { get; init; }
    }

    //Minimal ACME v2 client: account, order, dns-01 challenge, finalize, download.
    //Account keys are ECDSA P-256 (ES256). Every request is a JWS signed POST (RFC 8555 section 6.2).
    sealed class AcmeClient : IDisposable
    {
        #region variables

        const int MAX_BAD_NONCE_RETRIES = 3;

        readonly HttpClient _http;
        readonly Uri _directoryUrl;
        readonly ECDsa _accountKey;

        JsonElement _directory;
        bool _directoryLoaded;
        string _nonce;
        string _accountUrl;

        #endregion

        #region constructor

        public AcmeClient(HttpMessageHandler handler, Uri directoryUrl, ECDsa accountKey, string accountUrl = null)
        {
            if (accountKey.KeySize != 256)
                throw new ArgumentException("ACME account key must be an ECDSA P-256 key.", nameof(accountKey));

            _http = new HttpClient(handler, false);
            _http.Timeout = TimeSpan.FromSeconds(60);
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("TechnitiumDnsServer-ACME/1.0");

            _directoryUrl = directoryUrl;
            _accountKey = accountKey;
            _accountUrl = accountUrl;
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _http.Dispose();
        }

        #endregion

        #region static

        public static string Base64Url(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        static byte[] Base64UrlDecode(string data)
        {
            string s = data.Replace('-', '+').Replace('_', '/');

            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }

            return Convert.FromBase64String(s);
        }

        #endregion

        #region private

        private string GetJwkJson()
        {
            ECParameters p = _accountKey.ExportParameters(false);

            //members in lexicographic order as required for the thumbprint (RFC 7638)
            return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + Base64Url(p.Q.X) + "\",\"y\":\"" + Base64Url(p.Q.Y) + "\"}";
        }

        private async Task LoadDirectoryAsync(CancellationToken cancellationToken)
        {
            if (_directoryLoaded)
                return;

            using (HttpResponseMessage response = await _http.GetAsync(_directoryUrl, cancellationToken))
            {
                string body = await response.Content.ReadAsStringAsync(cancellationToken);

                if (!response.IsSuccessStatusCode)
                    throw new AcmeException("Failed to load ACME directory (" + (int)response.StatusCode + "): " + _directoryUrl);

                _directory = JsonDocument.Parse(body).RootElement.Clone();
                _directoryLoaded = true;
            }
        }

        private string GetDirectoryUrl(string name)
        {
            if (!_directory.TryGetProperty(name, out JsonElement value))
                throw new AcmeException("ACME directory does not provide '" + name + "'.");

            return value.GetString();
        }

        private async Task<string> GetNonceAsync(CancellationToken cancellationToken)
        {
            if (_nonce is not null)
            {
                string nonce = _nonce;
                _nonce = null;
                return nonce;
            }

            using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Head, GetDirectoryUrl("newNonce")))
            using (HttpResponseMessage response = await _http.SendAsync(request, cancellationToken))
            {
                if (!response.Headers.TryGetValues("Replay-Nonce", out IEnumerable<string> values))
                    throw new AcmeException("ACME server did not return a nonce.");

                return values.First();
            }
        }

        private string CreateJws(string url, string payloadJson, string nonce, bool useJwk)
        {
            string protectedHeader = "{\"alg\":\"ES256\"," +
                (useJwk ? "\"jwk\":" + GetJwkJson() : "\"kid\":" + JsonSerializer.Serialize(_accountUrl)) +
                ",\"nonce\":" + JsonSerializer.Serialize(nonce) +
                ",\"url\":" + JsonSerializer.Serialize(url) + "}";

            string protectedB64 = Base64Url(Encoding.UTF8.GetBytes(protectedHeader));
            string payloadB64 = payloadJson is null ? "" : Base64Url(Encoding.UTF8.GetBytes(payloadJson)); //empty payload = POST-as-GET

            //ES256 signature is r||s (IEEE P1363), which is .NET's default ECDsa signature format
            byte[] signature = _accountKey.SignData(Encoding.ASCII.GetBytes(protectedB64 + "." + payloadB64), HashAlgorithmName.SHA256);

            return "{\"protected\":\"" + protectedB64 + "\",\"payload\":\"" + payloadB64 + "\",\"signature\":\"" + Base64Url(signature) + "\"}";
        }

        private async Task<(HttpResponseMessage, JsonElement, string)> PostAsync(string url, string payloadJson, bool useJwk, CancellationToken cancellationToken, string accept = null)
        {
            await LoadDirectoryAsync(cancellationToken);

            for (int attempt = 0; ; attempt++)
            {
                string nonce = await GetNonceAsync(cancellationToken);
                string jws = CreateJws(url, payloadJson, nonce, useJwk);

                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Content = new StringContent(jws, Encoding.UTF8);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");

                if (accept is not null)
                    request.Headers.Accept.ParseAdd(accept);

                HttpResponseMessage response = await _http.SendAsync(request, cancellationToken);

                if (response.Headers.TryGetValues("Replay-Nonce", out IEnumerable<string> nonces))
                    _nonce = nonces.First();

                string body = await response.Content.ReadAsStringAsync(cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    JsonElement json = default;

                    if ((body.Length > 0) && ((response.Content.Headers.ContentType?.MediaType ?? "").Contains("json")))
                        json = JsonDocument.Parse(body).RootElement.Clone();

                    return (response, json, body);
                }

                string problemType = null;
                string detail = body;

                try
                {
                    JsonElement problem = JsonDocument.Parse(body).RootElement;

                    if (problem.TryGetProperty("type", out JsonElement type))
                        problemType = type.GetString();

                    if (problem.TryGetProperty("detail", out JsonElement detailElement))
                        detail = detailElement.GetString();
                }
                catch (JsonException)
                { }

                response.Dispose();

                //badNonce: retry with the fresh nonce from this response (RFC 8555 section 6.5)
                if ((problemType == "urn:ietf:params:acme:error:badNonce") && (attempt < MAX_BAD_NONCE_RETRIES))
                    continue;

                throw new AcmeException("ACME request failed (" + (int)response.StatusCode + " " + problemType + "): " + detail, problemType);
            }
        }

        private static TimeSpan GetRetryAfter(HttpResponseMessage response, TimeSpan fallback)
        {
            if (response.Headers.RetryAfter?.Delta is TimeSpan delta)
                return delta < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : (delta > TimeSpan.FromSeconds(30) ? TimeSpan.FromSeconds(30) : delta);

            return fallback;
        }

        private static AcmeOrder ParseOrder(string url, JsonElement json)
        {
            return new AcmeOrder()
            {
                Url = url,
                Status = json.GetProperty("status").GetString(),
                AuthorizationUrls = json.GetProperty("authorizations").EnumerateArray().Select(e => e.GetString()).ToArray(),
                FinalizeUrl = json.GetProperty("finalize").GetString(),
                CertificateUrl = json.TryGetProperty("certificate", out JsonElement certificate) ? certificate.GetString() : null
            };
        }

        #endregion

        #region public

        public async Task<(string termsOfServiceUrl, bool externalAccountRequired)> GetDirectoryMetaAsync(CancellationToken cancellationToken = default)
        {
            await LoadDirectoryAsync(cancellationToken);

            string tos = null;
            bool eabRequired = false;

            if (_directory.TryGetProperty("meta", out JsonElement meta))
            {
                if (meta.TryGetProperty("termsOfService", out JsonElement tosElement))
                    tos = tosElement.GetString();

                if (meta.TryGetProperty("externalAccountRequired", out JsonElement eabElement))
                    eabRequired = eabElement.GetBoolean();
            }

            return (tos, eabRequired);
        }

        //Creates the account, or finds the existing one for this key. Returns the account URL.
        //termsOfServiceAgreed must come from an explicit agreement by the administrator.
        public async Task<string> CreateOrFindAccountAsync(string email, bool termsOfServiceAgreed, string eabKeyId = null, string eabHmacKeyBase64Url = null, CancellationToken cancellationToken = default)
        {
            await LoadDirectoryAsync(cancellationToken);

            string newAccountUrl = GetDirectoryUrl("newAccount");

            StringBuilder payload = new StringBuilder();
            payload.Append("{\"termsOfServiceAgreed\":").Append(termsOfServiceAgreed ? "true" : "false");

            if (!string.IsNullOrWhiteSpace(email))
                payload.Append(",\"contact\":[").Append(JsonSerializer.Serialize("mailto:" + email.Trim())).Append(']');

            if (!string.IsNullOrEmpty(eabKeyId) && !string.IsNullOrEmpty(eabHmacKeyBase64Url))
            {
                //External Account Binding (RFC 8555 section 7.3.4): HS256 JWS over the account JWK
                string eabProtected = Base64Url(Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"kid\":" + JsonSerializer.Serialize(eabKeyId) + ",\"url\":" + JsonSerializer.Serialize(newAccountUrl) + "}"));
                string eabPayload = Base64Url(Encoding.UTF8.GetBytes(GetJwkJson()));
                byte[] eabSignature = HMACSHA256.HashData(Base64UrlDecode(eabHmacKeyBase64Url), Encoding.ASCII.GetBytes(eabProtected + "." + eabPayload));

                payload.Append(",\"externalAccountBinding\":{\"protected\":\"").Append(eabProtected).Append("\",\"payload\":\"").Append(eabPayload).Append("\",\"signature\":\"").Append(Base64Url(eabSignature)).Append("\"}");
            }

            payload.Append('}');

            (HttpResponseMessage response, JsonElement json, string _) = await PostAsync(newAccountUrl, payload.ToString(), true, cancellationToken);
            using (response)
            {
                _accountUrl = response.Headers.Location?.ToString() ?? throw new AcmeException("ACME server did not return an account URL.");

                if (json.ValueKind == JsonValueKind.Object && json.TryGetProperty("status", out JsonElement status) && (status.GetString() != "valid"))
                    throw new AcmeException("ACME account status is '" + status.GetString() + "'.");

                return _accountUrl;
            }
        }

        public async Task<AcmeOrder> NewOrderAsync(IReadOnlyList<string> domains, CancellationToken cancellationToken = default)
        {
            //an existing account skips registration, so the directory may not be loaded yet
            await LoadDirectoryAsync(cancellationToken);

            string identifiers = string.Join(",", domains.Select(d => "{\"type\":\"dns\",\"value\":" + JsonSerializer.Serialize(d) + "}"));

            (HttpResponseMessage response, JsonElement json, string _) = await PostAsync(GetDirectoryUrl("newOrder"), "{\"identifiers\":[" + identifiers + "]}", false, cancellationToken);
            using (response)
            {
                string orderUrl = response.Headers.Location?.ToString() ?? throw new AcmeException("ACME server did not return an order URL.");
                return ParseOrder(orderUrl, json);
            }
        }

        public async Task<AcmeOrder> GetOrderAsync(string orderUrl, CancellationToken cancellationToken = default)
        {
            (HttpResponseMessage response, JsonElement json, string _) = await PostAsync(orderUrl, null, false, cancellationToken);
            using (response)
                return ParseOrder(orderUrl, json);
        }

        public async Task<AcmeAuthorization> GetAuthorizationAsync(string authorizationUrl, CancellationToken cancellationToken = default)
        {
            (HttpResponseMessage response, JsonElement json, string _) = await PostAsync(authorizationUrl, null, false, cancellationToken);
            using (response)
            {
                AcmeChallenge dns01 = null;

                foreach (JsonElement challenge in json.GetProperty("challenges").EnumerateArray())
                {
                    if (challenge.GetProperty("type").GetString() == "dns-01")
                    {
                        dns01 = new AcmeChallenge()
                        {
                            Url = challenge.GetProperty("url").GetString(),
                            Token = challenge.GetProperty("token").GetString(),
                            Status = challenge.GetProperty("status").GetString()
                        };
                        break;
                    }
                }

                return new AcmeAuthorization()
                {
                    Url = authorizationUrl,
                    Identifier = json.GetProperty("identifier").GetProperty("value").GetString(),
                    Status = json.GetProperty("status").GetString(),
                    Wildcard = json.TryGetProperty("wildcard", out JsonElement wildcard) && wildcard.GetBoolean(),
                    Dns01Challenge = dns01
                };
            }
        }

        //TXT record value for a dns-01 challenge (RFC 8555 section 8.4)
        public string GetDns01TxtValue(string token)
        {
            byte[] thumbprint = SHA256.HashData(Encoding.UTF8.GetBytes(GetJwkJson()));
            string keyAuthorization = token + "." + Base64Url(thumbprint);

            return Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(keyAuthorization)));
        }

        public async Task RespondToChallengeAsync(string challengeUrl, CancellationToken cancellationToken = default)
        {
            (HttpResponseMessage response, JsonElement _, string _) = await PostAsync(challengeUrl, "{}", false, cancellationToken);
            response.Dispose();
        }

        public async Task<AcmeAuthorization> WaitForAuthorizationAsync(string authorizationUrl, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            DateTime deadline = DateTime.UtcNow.Add(timeout);

            while (true)
            {
                AcmeAuthorization authorization = await GetAuthorizationAsync(authorizationUrl, cancellationToken);

                switch (authorization.Status)
                {
                    case "valid":
                        return authorization;

                    case "pending":
                        break;

                    default:
                        throw new AcmeException(await GetAuthorizationErrorAsync(authorizationUrl, authorization.Status, cancellationToken));
                }

                if (DateTime.UtcNow > deadline)
                    throw new AcmeException("Timed out waiting for the ACME server to validate " + authorization.Identifier + ".");

                await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken);
            }
        }

        private async Task<string> GetAuthorizationErrorAsync(string authorizationUrl, string status, CancellationToken cancellationToken)
        {
            (HttpResponseMessage response, JsonElement json, string _) = await PostAsync(authorizationUrl, null, false, cancellationToken);
            using (response)
            {
                string identifier = json.GetProperty("identifier").GetProperty("value").GetString();

                foreach (JsonElement challenge in json.GetProperty("challenges").EnumerateArray())
                {
                    if (challenge.TryGetProperty("error", out JsonElement error) && error.TryGetProperty("detail", out JsonElement detail))
                        return "Validation of " + identifier + " failed (" + status + "): " + detail.GetString();
                }

                return "Validation of " + identifier + " failed (" + status + ").";
            }
        }

        public async Task<AcmeOrder> FinalizeAsync(AcmeOrder order, byte[] csrDer, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            (HttpResponseMessage response, JsonElement json, string _) = await PostAsync(order.FinalizeUrl, "{\"csr\":\"" + Base64Url(csrDer) + "\"}", false, cancellationToken);

            AcmeOrder current = ParseOrder(order.Url, json);
            TimeSpan retryAfter = GetRetryAfter(response, TimeSpan.FromSeconds(2));
            response.Dispose();

            DateTime deadline = DateTime.UtcNow.Add(timeout);

            while (current.Status == "processing")
            {
                if (DateTime.UtcNow > deadline)
                    throw new AcmeException("Timed out waiting for the ACME server to issue the certificate.");

                await Task.Delay(retryAfter, cancellationToken);
                current = await GetOrderAsync(order.Url, cancellationToken);
            }

            if (current.Status != "valid")
                throw new AcmeException("ACME order status is '" + current.Status + "' after finalize.");

            return current;
        }

        public async Task<string> DownloadCertificateChainPemAsync(AcmeOrder order, CancellationToken cancellationToken = default)
        {
            if (order.CertificateUrl is null)
                throw new AcmeException("ACME order has no certificate URL.");

            (HttpResponseMessage response, JsonElement _, string body) = await PostAsync(order.CertificateUrl, null, false, cancellationToken, "application/pem-certificate-chain");
            response.Dispose();

            if (!body.Contains("-----BEGIN CERTIFICATE-----"))
                throw new AcmeException("ACME server returned an invalid certificate chain.");

            return body;
        }

        #endregion

        #region properties

        public string AccountUrl
        { get { return _accountUrl; } }

        #endregion
    }
}
