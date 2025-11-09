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

using DnsServerCore.ApplicationCommon;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using System;
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

        IReadOnlyDictionary<string, WebServer> _webServers;

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

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            await StopAllWebServersAsync();

            Dictionary<string, WebServer> webServers = new Dictionary<string, WebServer>(3);
            _webServers = webServers;

            if (jsonConfig.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement jsonWebServerConfig in jsonConfig.EnumerateArray())
                {
                    string name = jsonWebServerConfig.GetPropertyValue("name", "default");

                    if (!webServers.TryGetValue(name, out WebServer webServer))
                    {
                        webServer = new WebServer(dnsServer, name);

                        if (!webServers.TryAdd(webServer.Name, webServer))
                            throw new InvalidOperationException("Failed to update web server config. Please try again.");
                    }

                    await webServer.InitializeAsync(jsonWebServerConfig);
                }
            }
            else
            {
                WebServer webServer = new WebServer(dnsServer, "default");
                webServers.Add(webServer.Name, webServer);

                await webServer.InitializeAsync(jsonConfig);

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

            IReadOnlyList<IPAddress> _webServerLocalAddresses = Array.Empty<IPAddress>();
            bool _webServerUseSelfSignedTlsCertificate;
            string _webServerTlsCertificateFilePath;
            string _webServerTlsCertificatePassword;
            string _webServerRootPath;
            bool _serveBlockPageFromWebServerRoot;
            bool _includeBlockingInfo;

            string _blockPageContent;

            WebApplication _webServer;

            SslServerAuthenticationOptions _sslServerAuthenticationOptions;
            DateTime _webServerTlsCertificateLastModifiedOn;

            Timer _tlsCertificateUpdateTimer;
            const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
            const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

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

                    builder.Environment.WebRootFileProvider = new PhysicalFileProvider(_webServerRootPath)
                    {
                        UseActivePolling = true,
                        UsePollingFileWatcher = true
                    };
                }

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
                                listenOptions.UseHttps(delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object state, CancellationToken cancellationToken)
                                {
                                    return ValueTask.FromResult(_sslServerAuthenticationOptions);
                                }, null);
                            });
                        }
                    }

                    serverOptions.AddServerHeader = false;
                    serverOptions.Limits.MaxRequestBodySize = int.MaxValue;
                });

                builder.Logging.ClearProviders();

                _webServer = builder.Build();

                _webServer.UseDefaultFiles();
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

            private void LoadWebServiceTlsCertificate(string webServerTlsCertificateFilePath, string webServerTlsCertificatePassword)
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
                X509Certificate2 serverCertificate = null;

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
                    _tlsCertificateUpdateTimer = new Timer(delegate (object state)
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
                                _dnsServer.WriteLog("Web server '" + _name + "' encountered an error while updating TLS Certificate: " + _webServerTlsCertificateFilePath + "\r\n" + ex.ToString());
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
                string blockPageContent = _blockPageContent;

                if (_includeBlockingInfo)
                {
                    string blockingInfoHtmlContent = null;

                    try
                    {
                        string host = context.Request.Host.Host;
                        if (host is not null)
                        {
                            DnsDatagram dnsRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN)], udpPayloadSize: DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE);
                            DnsDatagram dnsResponse = await _dnsServer.DirectQueryAsync(dnsRequest, 500);

                            List<EDnsExtendedDnsErrorOptionData> options = new List<EDnsExtendedDnsErrorOptionData>();

                            if (dnsResponse.EDNS is not null)
                            {
                                foreach (EDnsOption option in dnsResponse.EDNS.Options)
                                {
                                    if (option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR)
                                    {
                                        EDnsExtendedDnsErrorOptionData ede = option.Data as EDnsExtendedDnsErrorOptionData;
                                        options.Add(ede);
                                    }
                                }
                            }

                            options.AddRange(dnsResponse.DnsClientExtendedErrors);

                            foreach (EDnsExtendedDnsErrorOptionData option in options)
                            {
                                if (blockingInfoHtmlContent is null)
                                    blockingInfoHtmlContent = "  <p><b>Detailed Info</b><br>" + option.InfoCode.ToString() + (option.ExtraText is null ? "" : ": " + option.ExtraText);
                                else
                                    blockingInfoHtmlContent += "<br>" + option.InfoCode.ToString() + (option.ExtraText is null ? "" : ": " + option.ExtraText);
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

                if (jsonWebServerConfig.TryGetProperty("webServerUseSelfSignedTlsCertificate", out JsonElement jsonWebServerUseSelfSignedTlsCertificate))
                    _webServerUseSelfSignedTlsCertificate = jsonWebServerUseSelfSignedTlsCertificate.GetBoolean();
                else
                    _webServerUseSelfSignedTlsCertificate = true;

                _webServerTlsCertificateFilePath = jsonWebServerConfig.GetProperty("webServerTlsCertificateFilePath").GetString();
                _webServerTlsCertificatePassword = jsonWebServerConfig.GetProperty("webServerTlsCertificatePassword").GetString();

                _webServerRootPath = jsonWebServerConfig.GetProperty("webServerRootPath").GetString();

                if (!Path.IsPathRooted(_webServerRootPath))
                    _webServerRootPath = Path.Combine(_dnsServer.ApplicationFolder, _webServerRootPath);

                _serveBlockPageFromWebServerRoot = jsonWebServerConfig.GetProperty("serveBlockPageFromWebServerRoot").GetBoolean();

                string blockPageTitle = jsonWebServerConfig.GetProperty("blockPageTitle").GetString();
                string blockPageHeading = jsonWebServerConfig.GetProperty("blockPageHeading").GetString();
                string blockPageMessage = jsonWebServerConfig.GetProperty("blockPageMessage").GetString();

                _includeBlockingInfo = jsonWebServerConfig.GetPropertyValue("includeBlockingInfo", true);

                _blockPageContent = @"<html>
<head>
  <title>" + (blockPageTitle is null ? "" : blockPageTitle) + @"</title>
</head>
<body>
" + (blockPageHeading is null ? "" : "  <h1>" + blockPageHeading + "</h1>") + @"
" + (blockPageMessage is null ? "" : "  <p>" + blockPageMessage + "</p>") + @"
" + (_includeBlockingInfo ? "{BLOCKING-INFO}" : "") + @"
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
                            X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(5));

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
