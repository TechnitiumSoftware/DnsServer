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

using DnsServerCore.ApplicationCommon;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace BlockPage
{
    public sealed class App : IDnsApplication
    {
        #region variables

        readonly static JsonDocumentOptions _jsonParseOptions = new JsonDocumentOptions() { CommentHandling = JsonCommentHandling.Skip };

        IReadOnlyDictionary<string, WebServer>? _webServers;

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            StopAllWebServersAsync().Sync();

            _disposed = true;
        }

        #endregion

        #region private

        private async Task StopAllWebServersAsync()
        {
            if (_webServers is not null)
            {
                foreach (KeyValuePair<string, WebServer> webServerEntry in _webServers)
                    await webServerEntry.Value.DisposeAsync();

                _webServers = null;
            }
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string? config)
        {
            if (config is null)
                throw new InvalidOperationException();

            using JsonDocument jsonDocument = JsonDocument.Parse(config, _jsonParseOptions);
            JsonElement jsonConfig = jsonDocument.RootElement;

            await StopAllWebServersAsync();

            Dictionary<string, WebServer> webServers = new Dictionary<string, WebServer>(3);
            _webServers = webServers;

            if (jsonConfig.ValueKind == JsonValueKind.Array)
            {
                bool foundWebServerEnableOnlineCertificateSigning = false;

                foreach (JsonElement jsonWebServerConfig in jsonConfig.EnumerateArray())
                {
                    string name = jsonWebServerConfig.GetPropertyValue("name", "default");

                    if (!webServers.TryGetValue(name, out WebServer? webServer))
                    {
                        webServer = new WebServer(dnsServer, name);

                        if (!webServers.TryAdd(webServer.Name, webServer))
                            throw new InvalidOperationException("Failed to update web server config. Please try again.");
                    }

                    await webServer.InitializeAsync(jsonWebServerConfig);

                    foundWebServerEnableOnlineCertificateSigning = jsonWebServerConfig.TryGetProperty("webServerEnableOnlineCertificateSigning", out _);
                }

                if (!foundWebServerEnableOnlineCertificateSigning)
                {
                    config = config.Replace("\"webServerRootPath\"", "\"webServerEnableOnlineCertificateSigning\": false,\r\n    \"webServerRootPath\"");
                    await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
                }
            }
            else
            {
                WebServer webServer = new WebServer(dnsServer, "default");
                webServers.Add(webServer.Name, webServer);

                await webServer.InitializeAsync(jsonConfig);

                if (!jsonConfig.TryGetProperty("webServerEnableOnlineCertificateSigning", out _))
                    config = config.Replace("\"webServerRootPath\"", "\"webServerEnableOnlineCertificateSigning\": false,\r\n    \"webServerRootPath\"");

                if (!jsonConfig.TryGetProperty("webServerUseSelfSignedTlsCertificate", out _))
                    config = config.Replace("\"webServerTlsCertificateFilePath\"", "\"webServerUseSelfSignedTlsCertificate\": true,\r\n  \"webServerTlsCertificateFilePath\"");

                if (!jsonConfig.TryGetProperty("enableWebServer", out _))
                    config = config.Replace("\"webServerLocalAddresses\"", "\"enableWebServer\": true,\r\n  \"webServerLocalAddresses\"");

                if (!jsonConfig.TryGetProperty("name", out _))
                    config = config.Replace("\"enableWebServer\"", "\"name\": \"default\",\r\n  \"enableWebServer\"");

                config = "[\r\n  " + config.Replace("\n", "\n  ").TrimEnd() + "\r\n]";
                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Serves a block page from a built-in web server that can be displayed to the end user when a website is blocked by the DNS server.\n\nNote: You need to manually set the Blocking Type as Custom Address in the blocking settings and configure the current server's IP address as Custom Blocking Addresses for the block page to be served to the users. Use a PKCS #12 certificate (.pfx or .p12) for enabling HTTPS support. Enabling HTTPS support will show certificate error to the user which is expected and the user will have to proceed ignoring the certificate error to be able to see the block page."; } }

        #endregion

        class WebServer : IAsyncDisposable
        {
            #region variables

            readonly IDnsServer _dnsServer;
            readonly string _name;

            IReadOnlyList<IPAddress> _webServerLocalAddresses = [];
            bool _webServerUseSelfSignedTlsCertificate;
            string? _webServerTlsCertificateFilePath;
            string? _webServerTlsCertificatePassword;
            bool _webServerEnableOnlineCertificateSigning;
            string? _webServerRootPath;
            bool _serveBlockPageFromWebServerRoot;
            bool _includeBlockingInfo;

            string? _blockPageContent;

            WebApplication? _webServer;

            SslServerAuthenticationOptions? _sslServerAuthenticationOptions;
            DateTime _webServerTlsCertificateLastModifiedOn;

            readonly ConcurrentDictionary<string, SslServerAuthenticationOptions> _certCache = new ConcurrentDictionary<string, SslServerAuthenticationOptions>();
            readonly ConcurrentDictionary<string, Task<SslServerAuthenticationOptions>> _certSigningTasks = new ConcurrentDictionary<string, Task<SslServerAuthenticationOptions>>();

            Timer? _tlsCertificateUpdateTimer;
            const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
            const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

            //self-contained style for the default block page; no external resources are loaded
            const string DEFAULT_BLOCK_PAGE_STYLE = @"
    :root { color-scheme: light dark; --bg: #f4f6fb; --card: #ffffff; --text: #1f2937; --muted: #5b6475; --border: #e3e7ef; --accent: #d9480f; --accent-bg: #fff1e8; --code-bg: #f6f8fb; }
    @media (prefers-color-scheme: dark) { :root { --bg: #121417; --card: #1c1f24; --text: #e8eaed; --muted: #a3aab5; --border: #2e333b; --accent: #ff8a4c; --accent-bg: #2d1f17; --code-bg: #15171b; } }
    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body { margin: 0; display: flex; align-items: center; justify-content: center; padding: 24px 16px; background: var(--bg); color: var(--text); font: 16px/1.6 system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }
    main { width: 100%; max-width: 560px; padding: 40px 32px; background: var(--card); border: 1px solid var(--border); border-radius: 16px; box-shadow: 0 1px 2px rgba(0,0,0,.04), 0 12px 32px rgba(0,0,0,.08); text-align: center; }
    .icon { display: inline-flex; align-items: center; justify-content: center; width: 72px; height: 72px; margin-bottom: 16px; border-radius: 50%; background: var(--accent-bg); color: var(--accent); }
    h1 { margin: 0 0 8px; font-size: 1.6rem; line-height: 1.25; font-weight: 700; }
    main > p { margin: 0; color: var(--muted); }
    .details p { margin: 24px 0 0; padding: 12px 16px; text-align: left; font: 13px/1.6 ui-monospace, SFMono-Regular, Consolas, 'Liberation Mono', monospace; color: var(--muted); background: var(--code-bg); border: 1px solid var(--border); border-radius: 10px; overflow-wrap: anywhere; }
    .details b { display: block; margin-bottom: 4px; font: 600 11px/1.4 system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif; letter-spacing: .06em; text-transform: uppercase; color: var(--text); }
    .details br:first-of-type { display: none; }
    @media (max-width: 480px) { main { padding: 32px 20px; } h1 { font-size: 1.35rem; } }
  ";

            string? _cachedIndexPage;
            DateTime? _cachedIndexPageLastModified;

            #endregion

            #region constructor

            public WebServer(IDnsServer dnsServer, string name)
            {
                _dnsServer = dnsServer;
                _name = name;
            }

            #endregion

            #region IDisposable

            bool _disposed;

            public async ValueTask DisposeAsync()
            {
                if (_disposed)
                    return;

                await StopTlsCertificateUpdateTimerAsync();
                await StopWebServerAsync();

                _disposed = true;
            }

            #endregion

            #region private

            private async Task StartWebServerAsync()
            {
                WebApplicationBuilder builder = WebApplication.CreateBuilder();

                if (_serveBlockPageFromWebServerRoot)
                {
                    builder.Environment.ContentRootFileProvider = new PhysicalFileProvider(_dnsServer.ApplicationFolder)
                    {
                        UseActivePolling = true,
                        UsePollingFileWatcher = true
                    };

                    builder.Environment.WebRootFileProvider = new PhysicalFileProvider(_webServerRootPath!)
                    {
                        UseActivePolling = true,
                        UsePollingFileWatcher = true
                    };
                }

                builder.Services.AddResponseCompression(delegate (ResponseCompressionOptions options)
                {
                    options.EnableForHttps = true;
                });

                builder.WebHost.ConfigureKestrel(delegate (WebHostBuilderContext context, KestrelServerOptions serverOptions)
                {
                    //http
                    foreach (IPAddress webServiceLocalAddress in _webServerLocalAddresses)
                        serverOptions.Listen(webServiceLocalAddress, 80);

                    //https
                    if (_sslServerAuthenticationOptions is not null)
                    {
                        foreach (IPAddress webServiceLocalAddress in _webServerLocalAddresses)
                        {
                            serverOptions.Listen(webServiceLocalAddress, 443, delegate (ListenOptions listenOptions)
                            {
                                listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
                                listenOptions.UseHttps(async delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object? state, CancellationToken cancellationToken)
                                {
                                    if (_webServerEnableOnlineCertificateSigning)
                                    {
                                        try
                                        {
                                            string sniDomain = clientHelloInfo.ServerName.ToLowerInvariant();
                                            if (sniDomain is not null)
                                            {
                                                DateTimeOffset utcNow = DateTimeOffset.UtcNow;

                                                if (_certCache.TryGetValue(sniDomain, out SslServerAuthenticationOptions? sslServerAuthenticationOptions) && (utcNow.AddMinutes(30) < sslServerAuthenticationOptions!.ServerCertificateContext!.TargetCertificate.NotAfter))
                                                    return sslServerAuthenticationOptions;

                                                TaskCompletionSource<SslServerAuthenticationOptions> signingTaskCompletionSource = new TaskCompletionSource<SslServerAuthenticationOptions>();
                                                Task<SslServerAuthenticationOptions> signingTask = _certSigningTasks.GetOrAdd(sniDomain, signingTaskCompletionSource.Task);

                                                if (!signingTask.Equals(signingTaskCompletionSource.Task))
                                                    return await signingTask; //await existing task

                                                //got new signing task added; do the task
                                                try
                                                {
                                                    X509Certificate2 caCert = _sslServerAuthenticationOptions!.ServerCertificateContext!.TargetCertificate;

                                                    ECDsa? ecdsa = null;
                                                    RSA? rsa = null;
                                                    CertificateRequest req;
                                                    X509SignatureGenerator generator;

                                                    ECDsa? caECDsaPrivateKey = caCert.GetECDsaPrivateKey();
                                                    if (caECDsaPrivateKey is not null)
                                                    {
                                                        ECCurve caCurve = caECDsaPrivateKey.ExportParameters(false).Curve;
                                                        ecdsa = ECDsa.Create(caCurve);
                                                        req = new CertificateRequest("cn=" + sniDomain, ecdsa, HashAlgorithmName.SHA256);
                                                        generator = X509SignatureGenerator.CreateForECDsa(caECDsaPrivateKey);
                                                    }
                                                    else
                                                    {
                                                        RSA? caRsaPrivateKey = caCert.GetRSAPrivateKey();
                                                        if (caRsaPrivateKey is not null)
                                                        {
                                                            rsa = RSA.Create(2048);
                                                            req = new CertificateRequest("cn=" + sniDomain, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                                                            generator = X509SignatureGenerator.CreateForRSA(caRsaPrivateKey, RSASignaturePadding.Pkcs1);
                                                        }
                                                        else
                                                        {
                                                            //algorithm not supported; return ca cert directly
                                                            _certCache[sniDomain] = _sslServerAuthenticationOptions;

                                                            //release any awaiting task
                                                            signingTaskCompletionSource.SetResult(_sslServerAuthenticationOptions);

                                                            return _sslServerAuthenticationOptions;
                                                        }
                                                    }

                                                    req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                                                    req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
                                                    req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

                                                    SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
                                                    san.AddDnsName(sniDomain);

                                                    req.CertificateExtensions.Add(san.Build());

                                                    DateTimeOffset certNotBefore = utcNow.AddMinutes(-30);
                                                    if (certNotBefore < caCert.NotBefore)
                                                        certNotBefore = caCert.NotBefore;

                                                    Span<byte> serial = stackalloc byte[16];
                                                    RandomNumberGenerator.Fill(serial);

                                                    X509Certificate2 newCert = req.Create(caCert.SubjectName, generator, certNotBefore, utcNow.AddDays(7), serial);

                                                    if (ecdsa is not null)
                                                        newCert = newCert.CopyWithPrivateKey(ecdsa);
                                                    else if (rsa is not null)
                                                        newCert = newCert.CopyWithPrivateKey(rsa);

                                                    newCert = X509CertificateLoader.LoadPkcs12(newCert.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.PersistKeySet);

                                                    sslServerAuthenticationOptions = new SslServerAuthenticationOptions()
                                                    {
                                                        ServerCertificateContext = SslStreamCertificateContext.Create(newCert, new X509Certificate2Collection(caCert), false)
                                                    };

                                                    _certCache[sniDomain] = sslServerAuthenticationOptions;

                                                    //release any awaiting task
                                                    signingTaskCompletionSource.SetResult(sslServerAuthenticationOptions);

                                                    return sslServerAuthenticationOptions;
                                                }
                                                catch (Exception ex)
                                                {
                                                    //release any awaiting task with exception
                                                    signingTaskCompletionSource.SetException(ex);

                                                    throw;
                                                }
                                                finally
                                                {
                                                    //ensure removal of signing task
                                                    _certSigningTasks.TryRemove(sniDomain, out _);
                                                }
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            _dnsServer.WriteLog(ex);
                                        }
                                    }

                                    return _sslServerAuthenticationOptions;
                                }, null!);
                            });
                        }
                    }

                    serverOptions.AddServerHeader = false;
                    serverOptions.Limits.MaxRequestBodySize = int.MaxValue;
                });

                builder.Logging.ClearProviders();

                _webServer = builder.Build();

                _webServer.UseResponseCompression();

                _webServer.UseDefaultFiles();

                if (_serveBlockPageFromWebServerRoot)
                {
                    _webServer.Use(async delegate (HttpContext context, RequestDelegate next)
                    {
                        if (HttpMethods.IsGet(context.Request.Method) && (context.Request.Path.Equals("/") || context.Request.Path.Equals("/index.html", StringComparison.OrdinalIgnoreCase)))
                            await ServeDefaultPageAsync(context, next);
                        else
                            await next(context);
                    });
                }

                _webServer.UseStaticFiles(new StaticFileOptions()
                {
                    OnPrepareResponse = delegate (StaticFileResponseContext ctx)
                    {
                        ctx.Context.Response.Headers["X-Robots-Tag"] = "noindex, nofollow";
                        ctx.Context.Response.Headers.CacheControl = "no-cache";
                    },
                    ServeUnknownFileTypes = true
                });

                if (_serveBlockPageFromWebServerRoot)
                    _webServer.Use(RedirectToDefaultPageAsync);
                else
                    _webServer.Use(ServeDefaultPageAsync);

                try
                {
                    await _webServer.StartAsync();

                    foreach (IPAddress webServiceLocalAddress in _webServerLocalAddresses)
                    {
                        _dnsServer.WriteLog("Web server '" + _name + "' was bound successfully: " + new IPEndPoint(webServiceLocalAddress, 80).ToString());

                        if (_sslServerAuthenticationOptions is not null)
                            _dnsServer.WriteLog("Web server '" + _name + "' was bound successfully: " + new IPEndPoint(webServiceLocalAddress, 443).ToString());
                    }
                }
                catch (Exception ex)
                {
                    await StopWebServerAsync();

                    foreach (IPAddress webServiceLocalAddress in _webServerLocalAddresses)
                    {
                        _dnsServer.WriteLog("Web server '" + _name + "' failed to bind: " + new IPEndPoint(webServiceLocalAddress, 80).ToString());

                        if (_sslServerAuthenticationOptions is not null)
                            _dnsServer.WriteLog("Web server '" + _name + "' failed to bind: " + new IPEndPoint(webServiceLocalAddress, 443).ToString());
                    }

                    _dnsServer.WriteLog(ex);
                }
            }

            private async Task StopWebServerAsync()
            {
                if (_webServer is not null)
                {
                    await _webServer.DisposeAsync();
                    _webServer = null;
                }
            }

            private void LoadWebServiceTlsCertificate(string webServerTlsCertificateFilePath, string? webServerTlsCertificatePassword)
            {
                FileInfo fileInfo = new FileInfo(webServerTlsCertificateFilePath);

                if (!fileInfo.Exists)
                    throw new ArgumentException("Web server '" + _name + "' TLS certificate file does not exists: " + webServerTlsCertificateFilePath);

                switch (Path.GetExtension(webServerTlsCertificateFilePath).ToLowerInvariant())
                {
                    case ".pfx":
                    case ".p12":
                        break;

                    default:
                        throw new ArgumentException("Web server '" + _name + "' TLS certificate file must be PKCS #12 formatted with .pfx or .p12 extension: " + webServerTlsCertificateFilePath);
                }

                X509Certificate2Collection webServerTlsCertificateCollection = X509CertificateLoader.LoadPkcs12CollectionFromFile(webServerTlsCertificateFilePath, webServerTlsCertificatePassword, X509KeyStorageFlags.PersistKeySet);
                X509Certificate2? serverCertificate = null;

                foreach (X509Certificate2 certificate in webServerTlsCertificateCollection)
                {
                    if (certificate.HasPrivateKey)
                    {
                        serverCertificate = certificate;
                        break;
                    }
                }

                if (serverCertificate is null)
                    throw new ArgumentException("Web server '" + _name + "' TLS certificate file must contain a certificate with private key.");

                _sslServerAuthenticationOptions = new SslServerAuthenticationOptions()
                {
                    ServerCertificateContext = SslStreamCertificateContext.Create(serverCertificate, webServerTlsCertificateCollection, false)
                };

                _webServerTlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

                _dnsServer.WriteLog("Web server '" + _name + "' TLS certificate was loaded: " + webServerTlsCertificateFilePath);
            }

            private void StartTlsCertificateUpdateTimer()
            {
                if (_tlsCertificateUpdateTimer is null)
                {
                    _tlsCertificateUpdateTimer = new Timer(delegate (object? state)
                    {
                        if (!string.IsNullOrEmpty(_webServerTlsCertificateFilePath))
                        {
                            try
                            {
                                FileInfo fileInfo = new FileInfo(_webServerTlsCertificateFilePath);

                                if (fileInfo.Exists && (fileInfo.LastWriteTimeUtc != _webServerTlsCertificateLastModifiedOn))
                                    LoadWebServiceTlsCertificate(_webServerTlsCertificateFilePath, _webServerTlsCertificatePassword);
                            }
                            catch (Exception ex)
                            {
                                _dnsServer.WriteLog("Web server '" + _name + "' encountered an error while updating TLS Certificate: " + _webServerTlsCertificateFilePath, ex);
                            }
                        }

                    }, null, TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL, TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL);
                }
            }

            private async Task StopTlsCertificateUpdateTimerAsync()
            {
                if (_tlsCertificateUpdateTimer is not null)
                {
                    await _tlsCertificateUpdateTimer.DisposeAsync();
                    _tlsCertificateUpdateTimer = null;
                }
            }

            private Task RedirectToDefaultPageAsync(HttpContext context, RequestDelegate next)
            {
                context.Response.Redirect("/", false, true);

                return Task.CompletedTask;
            }

            private async Task ServeDefaultPageAsync(HttpContext context, RequestDelegate next)
            {
                string blockPageContent;

                if (_serveBlockPageFromWebServerRoot)
                {
                    string indexFilePath = Path.Combine(_webServerRootPath!, "index.html");
                    FileInfo fileInfo = new FileInfo(indexFilePath);

                    if (fileInfo.Exists)
                    {
                        DateTime lastModified = fileInfo.LastWriteTimeUtc;

                        if ((_cachedIndexPage is null) || (lastModified > _cachedIndexPageLastModified))
                        {
                            _cachedIndexPage = await File.ReadAllTextAsync(indexFilePath);
                            _cachedIndexPageLastModified = lastModified;
                        }

                        blockPageContent = _cachedIndexPage;
                    }
                    else
                    {
                        blockPageContent = _blockPageContent!;
                    }
                }
                else
                {
                    blockPageContent = _blockPageContent!;
                }

                if (_includeBlockingInfo)
                {
                    string? blockingInfoHtmlContent = null;

                    try
                    {
                        string host = context.Request.Host.Host;
                        if (host is not null)
                        {
                            DnsDatagram dnsRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN)], udpPayloadSize: DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE);

                            IPEndPoint clientEP;
                            {
                                try
                                {
                                    IPAddress? remoteIP = context.Connection.RemoteIpAddress;
                                    if (remoteIP is not null)
                                    {
                                        if (remoteIP.IsIPv4MappedToIPv6)
                                            remoteIP = remoteIP.MapToIPv4();

                                        clientEP = new IPEndPoint(remoteIP, context.Connection.RemotePort);
                                    }
                                    else
                                    {
                                        clientEP = new IPEndPoint(IPAddress.Any, 0);
                                    }
                                }
                                catch
                                {
                                    clientEP = new IPEndPoint(IPAddress.Any, 0);
                                }
                            }

                            DnsDatagram dnsResponse = await _dnsServer.DirectQueryAsync(dnsRequest, clientEP, 500);

                            List<EDnsExtendedDnsErrorOptionData> options = new List<EDnsExtendedDnsErrorOptionData>();

                            if (dnsResponse.EDNS is not null)
                            {
                                foreach (EDnsOption option in dnsResponse.EDNS.Options)
                                {
                                    if (option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR)
                                    {
                                        EDnsExtendedDnsErrorOptionData? ede = option.Data as EDnsExtendedDnsErrorOptionData;
                                        options.Add(ede!);
                                    }
                                }
                            }

                            options.AddRange(dnsResponse.DnsClientExtendedErrors);

                            foreach (EDnsExtendedDnsErrorOptionData option in options)
                            {
                                //extra text may originate from upstream servers or block lists; encode it to prevent HTML injection
                                string infoText = WebUtility.HtmlEncode(option.InfoCode.ToString() + (option.ExtraText is null ? "" : ": " + option.ExtraText));

                                if (blockingInfoHtmlContent is null)
                                    blockingInfoHtmlContent = "  <p class=\"blocking-info\"><b>Detailed Info</b><br>" + infoText;
                                else
                                    blockingInfoHtmlContent += "<br>" + infoText;
                            }

                            if (blockingInfoHtmlContent is not null)
                                blockingInfoHtmlContent += "</p>";
                        }
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog(ex);
                    }

                    if (blockingInfoHtmlContent is null)
                        blockPageContent = blockPageContent.Replace("{BLOCKING-INFO}", "");
                    else
                        blockPageContent = blockPageContent.Replace("{BLOCKING-INFO}", blockingInfoHtmlContent);
                }

                byte[] finalBlockPageContent = Encoding.UTF8.GetBytes(blockPageContent);

                HttpResponse response = context.Response;

                response.StatusCode = StatusCodes.Status200OK;
                response.ContentType = "text/html; charset=utf-8";
                response.ContentLength = finalBlockPageContent.Length;

                using (Stream s = context.Response.Body)
                {
                    await s.WriteAsync(finalBlockPageContent);
                }
            }

            #endregion

            #region public

            public async Task InitializeAsync(JsonElement jsonWebServerConfig)
            {
                bool enableWebServer = jsonWebServerConfig.GetPropertyValue("enableWebServer", true);
                if (!enableWebServer)
                {
                    await StopWebServerAsync();
                    return;
                }

                _webServerLocalAddresses = WebUtilities.GetValidKestrelLocalAddresses(jsonWebServerConfig.ReadArray("webServerLocalAddresses", IPAddress.Parse));
                _webServerUseSelfSignedTlsCertificate = jsonWebServerConfig.GetPropertyValue("webServerUseSelfSignedTlsCertificate", true);
                _webServerTlsCertificateFilePath = jsonWebServerConfig.GetProperty("webServerTlsCertificateFilePath").GetString();
                _webServerTlsCertificatePassword = jsonWebServerConfig.GetProperty("webServerTlsCertificatePassword").GetString();
                _webServerEnableOnlineCertificateSigning = jsonWebServerConfig.GetPropertyValue("webServerEnableOnlineCertificateSigning", false);

                _webServerRootPath = jsonWebServerConfig.GetProperty("webServerRootPath").GetString();

                if (!Path.IsPathRooted(_webServerRootPath))
                    _webServerRootPath = Path.Combine(_dnsServer.ApplicationFolder, _webServerRootPath!);

                _serveBlockPageFromWebServerRoot = jsonWebServerConfig.GetProperty("serveBlockPageFromWebServerRoot").GetBoolean();

                string blockPageTitle = jsonWebServerConfig.GetProperty("blockPageTitle").GetString()!;
                string blockPageHeading = jsonWebServerConfig.GetProperty("blockPageHeading").GetString()!;
                string blockPageMessage = jsonWebServerConfig.GetProperty("blockPageMessage").GetString()!;

                _includeBlockingInfo = jsonWebServerConfig.GetPropertyValue("includeBlockingInfo", true);

                _blockPageContent = @"<!DOCTYPE html>
<html lang=""en"">
<head>
  <meta charset=""utf-8"">
  <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
  <meta name=""robots"" content=""noindex, nofollow"">
  <meta name=""referrer"" content=""no-referrer"">
  <meta http-equiv=""Content-Security-Policy"" content=""default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'"">
  <title>" + (blockPageTitle is null ? "" : blockPageTitle) + @"</title>
  <style>" + DEFAULT_BLOCK_PAGE_STYLE + @"</style>
</head>
<body>
  <main>
    <div class=""icon"" aria-hidden=""true""><svg width=""36"" height=""36"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round""><path d=""M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z""/><line x1=""9"" y1=""9"" x2=""15"" y2=""15""/><line x1=""15"" y1=""9"" x2=""9"" y2=""15""/></svg></div>
" + (blockPageHeading is null ? "" : "    <h1>" + blockPageHeading + "</h1>") + @"
" + (blockPageMessage is null ? "" : "    <p>" + blockPageMessage + "</p>") + @"
" + (_includeBlockingInfo ? "    <div class=\"details\">{BLOCKING-INFO}</div>" : "") + @"
  </main>
</body>
</html>";

                try
                {
                    await StopWebServerAsync();

                    string selfSignedCertificateFilePath = Path.Combine(_dnsServer.ApplicationFolder, "self-signed-cert.pfx");

                    if (_webServerUseSelfSignedTlsCertificate)
                    {
                        string oldSelfSignedCertificateFilePath = Path.Combine(_dnsServer.ApplicationFolder, "cert.pfx");

                        if (!oldSelfSignedCertificateFilePath.Equals(_webServerTlsCertificateFilePath, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) && File.Exists(oldSelfSignedCertificateFilePath) && !File.Exists(selfSignedCertificateFilePath))
                            File.Move(oldSelfSignedCertificateFilePath, selfSignedCertificateFilePath);

                        if (!File.Exists(selfSignedCertificateFilePath))
                        {
                            RSA rsa = RSA.Create(2048);
                            CertificateRequest req = new CertificateRequest("cn=" + _dnsServer.ServerDomain, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

                            X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

                            await File.WriteAllBytesAsync(selfSignedCertificateFilePath, cert.Export(X509ContentType.Pkcs12, null as string));
                        }
                    }
                    else
                    {
                        File.Delete(selfSignedCertificateFilePath);
                    }

                    if (string.IsNullOrEmpty(_webServerTlsCertificateFilePath))
                    {
                        await StopTlsCertificateUpdateTimerAsync();

                        if (_webServerUseSelfSignedTlsCertificate)
                        {
                            LoadWebServiceTlsCertificate(selfSignedCertificateFilePath, null);
                        }
                        else
                        {
                            //disable HTTPS
                            _sslServerAuthenticationOptions = null;
                        }
                    }
                    else
                    {
                        LoadWebServiceTlsCertificate(_webServerTlsCertificateFilePath, _webServerTlsCertificatePassword);
                        StartTlsCertificateUpdateTimer();
                    }

                    await StartWebServerAsync();
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);
                }
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            #endregion
        }
    }
}
