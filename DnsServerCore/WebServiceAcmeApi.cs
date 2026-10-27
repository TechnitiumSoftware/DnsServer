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

using DnsServerCore.Acme;
using DnsServerCore.Auth;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Http.Client;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        sealed class WebServiceAcmeApi
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceAcmeApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            private void CheckPermission(HttpContext context, PermissionFlag flag)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, flag))
                    throw new DnsWebServiceException("Access was denied.");
            }

            private void WriteAcme(Utf8JsonWriter jsonWriter)
            {
                AcmeManager acme = _dnsWebService._acmeManager;

                jsonWriter.WriteBoolean("enabled", acme.Enabled);
                jsonWriter.WriteString("directoryUrl", acme.DirectoryUrl);
                jsonWriter.WriteString("email", acme.Email);
                jsonWriter.WriteBoolean("termsOfServiceAgreed", acme.TermsOfServiceAgreed);
                jsonWriter.WriteString("eabKeyId", acme.EabKeyId);
                jsonWriter.WriteBoolean("eabHmacKeySet", acme.EabHmacKeySet); //secret is never returned

                jsonWriter.WriteStartArray("domains");
                foreach (string domain in acme.Domains)
                    jsonWriter.WriteStringValue(domain);
                jsonWriter.WriteEndArray();

                jsonWriter.WriteString("keyType", acme.KeyType.ToString());
                jsonWriter.WriteNumber("renewDaysBeforeExpiry", acme.RenewDaysBeforeExpiry);
                jsonWriter.WriteBoolean("useForWebService", acme.UseForWebService);
                jsonWriter.WriteBoolean("useForDnsTls", acme.UseForDnsTls);

                jsonWriter.WriteString("dns01Provider", acme.ProviderType.ToString());
                jsonWriter.WriteString("rfc2136Server", acme.Rfc2136Server);
                jsonWriter.WriteString("rfc2136TsigKeyName", acme.Rfc2136TsigKeyName);
                jsonWriter.WriteBoolean("cloudflareApiTokenSet", acme.CloudflareApiTokenSet); //secret is never returned
                jsonWriter.WriteNumber("propagationTimeoutSeconds", acme.PropagationTimeoutSeconds);

                jsonWriter.WriteStartArray("publicResolvers");
                foreach (IPAddress resolver in acme.PublicResolvers)
                    jsonWriter.WriteStringValue(resolver.ToString());
                jsonWriter.WriteEndArray();

                jsonWriter.WriteStartArray("tsigKeyNames");
                if (_dnsWebService._dnsServer.TsigKeys is not null)
                {
                    foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsWebService._dnsServer.TsigKeys)
                        jsonWriter.WriteStringValue(tsigKey.Key);
                }
                jsonWriter.WriteEndArray();

                jsonWriter.WriteString("serverDomain", _dnsWebService._dnsServer.ServerDomain);
                jsonWriter.WriteBoolean("webServiceTlsEnabled", _dnsWebService.WebServiceTlsEnabled);
                jsonWriter.WriteNumber("webServiceTlsPort", _dnsWebService._webServiceTlsPort);

                //status
                jsonWriter.WriteBoolean("running", acme.Running);
                jsonWriter.WriteBoolean("accountRegistered", acme.AccountUrl is not null);

                if (acme.LastAttempt != default)
                    jsonWriter.WriteString("lastAttempt", acme.LastAttempt);

                if (acme.LastSuccess != default)
                    jsonWriter.WriteString("lastSuccess", acme.LastSuccess);

                jsonWriter.WriteString("lastError", acme.LastError);

                X509Certificate2 certificate = acme.GetCurrentCertificate();
                if (certificate is null)
                {
                    jsonWriter.WriteNull("certificate");
                }
                else
                {
                    jsonWriter.WriteStartObject("certificate");
                    jsonWriter.WriteString("subject", certificate.Subject);
                    jsonWriter.WriteString("issuer", certificate.Issuer);
                    jsonWriter.WriteString("notBefore", certificate.NotBefore.ToUniversalTime());
                    jsonWriter.WriteString("notAfter", certificate.NotAfter.ToUniversalTime());
                    jsonWriter.WriteString("thumbprint", certificate.Thumbprint);

                    jsonWriter.WriteStartArray("dnsNames");
                    foreach (X509Extension extension in certificate.Extensions)
                    {
                        if (extension is X509SubjectAlternativeNameExtension san)
                        {
                            foreach (string name in san.EnumerateDnsNames())
                                jsonWriter.WriteStringValue(name);
                        }
                    }
                    jsonWriter.WriteEndArray();

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteStartArray("log");
                foreach (string line in acme.GetLog())
                    jsonWriter.WriteStringValue(line);
                jsonWriter.WriteEndArray();
            }

            #endregion

            #region public

            public void GetAcme(HttpContext context)
            {
                CheckPermission(context, PermissionFlag.View);

                WriteAcme(context.GetCurrentJsonWriter());
            }

            public void SetAcme(HttpContext context)
            {
                CheckPermission(context, PermissionFlag.Modify);

                HttpRequest request = context.Request;
                AcmeManager acme = _dnsWebService._acmeManager;

                bool enabled = request.GetQueryOrForm("enabled", bool.Parse, acme.Enabled);
                string directoryUrl = request.GetQueryOrForm("directoryUrl", acme.DirectoryUrl);

                //agreement belongs to one CA: switching CA without explicitly agreeing again means not agreed
                bool directoryChanged = directoryUrl != acme.DirectoryUrl;
                bool termsOfServiceAgreed = request.GetQueryOrForm("termsOfServiceAgreed", bool.Parse, directoryChanged ? false : acme.TermsOfServiceAgreed);

                //plain fields: missing keeps the saved value, empty clears it
                string email = request.QueryOrForm("email");
                string eabKeyId = request.QueryOrForm("eabKeyId");
                string eabHmacKey = request.QueryOrForm("eabHmacKey");

                IReadOnlyList<string> domains = acme.Domains;
                string domainsValue = request.QueryOrForm("domains");
                if (domainsValue is not null)
                    domains = domainsValue.Split([',', ' ', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

                AcmeKeyType keyType = request.GetQueryOrFormEnum("keyType", acme.KeyType);
                ushort renewDaysBeforeExpiry = request.GetQueryOrForm("renewDaysBeforeExpiry", ushort.Parse, acme.RenewDaysBeforeExpiry);
                bool useForWebService = request.GetQueryOrForm("useForWebService", bool.Parse, acme.UseForWebService);
                bool useForDnsTls = request.GetQueryOrForm("useForDnsTls", bool.Parse, acme.UseForDnsTls);

                Dns01ProviderType providerType = request.GetQueryOrFormEnum("dns01Provider", acme.ProviderType);
                string rfc2136Server = request.QueryOrForm("rfc2136Server");
                string rfc2136TsigKeyName = request.QueryOrForm("rfc2136TsigKeyName");
                string cloudflareApiToken = request.QueryOrForm("cloudflareApiToken");
                ushort propagationTimeoutSeconds = request.GetQueryOrForm("propagationTimeoutSeconds", ushort.Parse, acme.PropagationTimeoutSeconds);

                IReadOnlyList<IPAddress> publicResolvers = acme.PublicResolvers;
                if (request.TryQueryOrFormArray("publicResolvers", IPAddress.Parse, out IPAddress[] resolvers))
                    publicResolvers = resolvers;

                //secrets are never sent to the UI, so an empty secret field means "keep the saved secret"
                if (eabHmacKey == "")
                    eabHmacKey = null;

                if (cloudflareApiToken == "")
                    cloudflareApiToken = null;

                try
                {
                    acme.SetConfig(enabled, directoryUrl, email, termsOfServiceAgreed, eabKeyId, eabHmacKey, domains, keyType, renewDaysBeforeExpiry, useForWebService, useForDnsTls, providerType, rfc2136Server, rfc2136TsigKeyName, cloudflareApiToken, propagationTimeoutSeconds, publicResolvers);
                }
                catch (AcmeException ex)
                {
                    throw new DnsWebServiceException(ex.Message);
                }

                //HTTPS may now rely on ACME; start it with a temporary self signed certificate until one is issued
                _dnsWebService.RefreshWebServiceTlsCertificateFallback();

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + _dnsWebService.GetSessionUser(context).Username + "] ACME settings were updated (enabled: " + enabled + ", directory: " + directoryUrl + ", provider: " + providerType + ").");

                WriteAcme(context.GetCurrentJsonWriter());
            }

            //terms of service URL and whether External Account Binding is required, shown before the admin agrees
            public async Task GetDirectoryInfoAsync(HttpContext context)
            {
                //makes the server fetch an admin-supplied URL, so it needs the same permission as changing it
                CheckPermission(context, PermissionFlag.Modify);

                string directoryUrl = context.Request.GetQueryOrForm("directoryUrl");

                if (!Uri.TryCreate(directoryUrl, UriKind.Absolute, out Uri directoryUri) || (directoryUri.Scheme != Uri.UriSchemeHttps))
                    throw new DnsWebServiceException("The ACME directory URL must be an absolute https:// URL.");

                using HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                handler.Proxy = _dnsWebService._dnsServer.Proxy;
                handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsWebService._dnsServer.IPv6Mode);
                handler.DnsClient = _dnsWebService._dnsServer;

                using ECDsa unusedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                using AcmeClient client = new AcmeClient(handler, directoryUri, unusedKey);

                (string termsOfServiceUrl, bool externalAccountRequired) = await client.GetDirectoryMetaAsync();

                //only pass on a web link; the UI renders it as an href
                if ((termsOfServiceUrl is not null) && (!Uri.TryCreate(termsOfServiceUrl, UriKind.Absolute, out Uri termsUri) || ((termsUri.Scheme != Uri.UriSchemeHttps) && (termsUri.Scheme != Uri.UriSchemeHttp))))
                    termsOfServiceUrl = null;

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteString("termsOfServiceUrl", termsOfServiceUrl);
                jsonWriter.WriteBoolean("externalAccountRequired", externalAccountRequired);
            }

            public void RequestCertificate(HttpContext context)
            {
                CheckPermission(context, PermissionFlag.Modify);

                AcmeManager acme = _dnsWebService._acmeManager;

                if (!acme.Enabled)
                    throw new DnsWebServiceException("Enable ACME and save the settings first.");

                if (acme.Running)
                    throw new DnsWebServiceException("A certificate request is already in progress.");

                _ = acme.RunAsync(); //progress is reported through get (status and log)

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + _dnsWebService.GetSessionUser(context).Username + "] ACME certificate request was started.");

                WriteAcme(context.GetCurrentJsonWriter());
            }

            public void EnableHttps(HttpContext context)
            {
                CheckPermission(context, PermissionFlag.Modify);

                if (!_dnsWebService.AcmeManagesWebServiceTlsCertificate)
                    throw new DnsWebServiceException("Enable ACME for the web service and save the ACME settings first.");

                _dnsWebService.EnableWebServiceTlsForAcme();

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + _dnsWebService.GetSessionUser(context).Username + "] HTTPS was enabled for the web service from the ACME settings.");

                WriteAcme(context.GetCurrentJsonWriter());
            }

            public async Task TestDns01Async(HttpContext context)
            {
                CheckPermission(context, PermissionFlag.Modify);

                string result;

                try
                {
                    //propagation wait plus time for the provider calls
                    using (CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(_dnsWebService._acmeManager.PropagationTimeoutSeconds + 180)))
                    {
                        result = await _dnsWebService._acmeManager.TestDns01Async(cts.Token);
                    }
                }
                catch (AcmeException ex)
                {
                    throw new DnsWebServiceException("DNS-01 test failed: " + ex.Message);
                }
                catch (OperationCanceledException)
                {
                    throw new DnsWebServiceException("DNS-01 test failed: timed out.");
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteString("result", result);
            }

            #endregion
        }
    }
}
