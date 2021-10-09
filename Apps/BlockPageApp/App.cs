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

using DnsServerCore.ApplicationCommon;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Http;

namespace BlockPage
{
    public class App : IDnsApplication
    {
        #region enum

        enum ServiceState
        {
            Stopped = 0,
            Starting = 1,
            Running = 2,
            Stopping = 3
        }

        #endregion

        #region variables

        const int TCP_SEND_TIMEOUT = 10000;
        const int TCP_RECV_TIMEOUT = 10000;

        IDnsServer _dnsServer;

        IReadOnlyList<IPAddress> _webServerLocalAddresses = Array.Empty<IPAddress>();
        bool _webServerUseSelfSignedTlsCertificate;
        string _webServerTlsCertificateFilePath;
        string _webServerTlsCertificatePassword;
        string _webServerRootPath;
        bool _serveBlockPageFromWebServerRoot;

        byte[] _blockPageContent;

        readonly List<Socket> _httpListeners = new List<Socket>();
        readonly List<Socket> _httpsListeners = new List<Socket>();

        X509Certificate2 _webServerTlsCertificate;
        DateTime _webServerTlsCertificateLastModifiedOn;

        Timer _tlsCertificateUpdateTimer;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

        volatile ServiceState _state = ServiceState.Stopped;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            StopTlsCertificateUpdateTimer();
            StopWebServer();
        }

        #endregion

        #region private

        private void StartWebServer()
        {
            if (_state != ServiceState.Stopped)
                throw new InvalidOperationException("Web server is already running.");

            _state = ServiceState.Starting;

            //bind to local addresses
            foreach (IPAddress localAddress in _webServerLocalAddresses)
            {
                //bind to HTTP port 80
                {
                    IPEndPoint httpEP = new IPEndPoint(localAddress, 80);
                    Socket httpListener = null;

                    try
                    {
                        httpListener = new Socket(httpEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        httpListener.Bind(httpEP);
                        httpListener.Listen(100);

                        _httpListeners.Add(httpListener);

                        _dnsServer.WriteLog("Web server was bound successfully: " + httpEP.ToString());
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog(ex);

                        if (httpListener is not null)
                            httpListener.Dispose();
                    }
                }

                //bind to HTTPS port 443
                if (_webServerTlsCertificate is not null)
                {
                    IPEndPoint httpsEP = new IPEndPoint(localAddress, 443);
                    Socket httpsListener = null;

                    try
                    {
                        httpsListener = new Socket(httpsEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        httpsListener.Bind(httpsEP);
                        httpsListener.Listen(100);

                        _httpsListeners.Add(httpsListener);

                        _dnsServer.WriteLog("Web server was bound successfully: " + httpsEP.ToString());
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog(ex);

                        if (httpsListener is not null)
                            httpsListener.Dispose();
                    }
                }
            }

            //start reading requests
            int listenerTaskCount = Math.Max(1, Environment.ProcessorCount);

            foreach (Socket httpListener in _httpListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(httpListener, false);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
                }
            }

            foreach (Socket httpsListener in _httpsListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(httpsListener, true);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
                }
            }

            _state = ServiceState.Running;
        }

        private void StopWebServer()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            foreach (Socket httpListener in _httpListeners)
                httpListener.Dispose();

            foreach (Socket httpsListener in _httpsListeners)
                httpsListener.Dispose();

            _httpListeners.Clear();
            _httpsListeners.Clear();

            _state = ServiceState.Stopped;
        }

        private void LoadWebServiceTlsCertificate(string webServerTlsCertificateFilePath, string webServerTlsCertificatePassword)
        {
            FileInfo fileInfo = new FileInfo(webServerTlsCertificateFilePath);

            if (!fileInfo.Exists)
                throw new ArgumentException("Web server TLS certificate file does not exists: " + webServerTlsCertificateFilePath);

            if (Path.GetExtension(webServerTlsCertificateFilePath) != ".pfx")
                throw new ArgumentException("Web server TLS certificate file must be PKCS #12 formatted with .pfx extension: " + webServerTlsCertificateFilePath);

            _webServerTlsCertificate = new X509Certificate2(webServerTlsCertificateFilePath, webServerTlsCertificatePassword);
            _webServerTlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

            _dnsServer.WriteLog("Web server TLS certificate was loaded: " + webServerTlsCertificateFilePath);
        }

        private void StartTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer == null)
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
                            _dnsServer.WriteLog("Web server encountered an error while updating TLS Certificate: " + _webServerTlsCertificateFilePath + "\r\n" + ex.ToString());
                        }
                    }

                }, null, TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL, TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL);
            }
        }

        private void StopTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer != null)
            {
                _tlsCertificateUpdateTimer.Dispose();
                _tlsCertificateUpdateTimer = null;
            }
        }

        private async Task AcceptConnectionAsync(Socket tcpListener, bool usingHttps)
        {
            try
            {
                tcpListener.SendTimeout = TCP_SEND_TIMEOUT;
                tcpListener.ReceiveTimeout = TCP_RECV_TIMEOUT;
                tcpListener.NoDelay = true;

                while (true)
                {
                    Socket socket = await tcpListener.AcceptAsync();

                    _ = ProcessConnectionAsync(socket, usingHttps);
                }
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.OperationAborted)
                    return; //server stopping

                _dnsServer.WriteLog(ex);
            }
            catch (ObjectDisposedException)
            {
                //server stopped
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                _dnsServer.WriteLog(ex);
            }
        }

        private async Task ProcessConnectionAsync(Socket socket, bool usingHttps)
        {
            try
            {
                IPEndPoint remoteEP = socket.RemoteEndPoint as IPEndPoint;
                Stream stream = new NetworkStream(socket);

                if (usingHttps)
                {
                    SslStream httpsStream = new SslStream(stream);
                    await httpsStream.AuthenticateAsServerAsync(_webServerTlsCertificate);

                    stream = httpsStream;
                }

                await ProcessHttpRequestAsync(stream, remoteEP, usingHttps);
            }
            catch (IOException)
            {
                //ignore IO exceptions
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog(ex);
            }
            finally
            {
                if (socket is not null)
                    socket.Dispose();
            }
        }

        private async Task ProcessHttpRequestAsync(Stream stream, IPEndPoint remoteEP, bool usingHttps)
        {
            try
            {
                while (true)
                {
                    bool isSocketRemoteIpPrivate = NetUtilities.IsPrivateIP(remoteEP.Address);
                    HttpRequest httpRequest = await HttpRequest.ReadRequestAsync(stream, 512).WithTimeout(TCP_RECV_TIMEOUT);
                    if (httpRequest is null)
                        return; //connection closed gracefully by client

                    string requestConnection = httpRequest.Headers[HttpRequestHeader.Connection];
                    if (string.IsNullOrEmpty(requestConnection))
                        requestConnection = "close";

                    string path = httpRequest.RequestPath;

                    if (!path.StartsWith("/") || path.Contains("/../") || path.Contains("/.../"))
                    {
                        await SendErrorAsync(stream, requestConnection, 404);
                        break;
                    }

                    if (path == "/")
                        path = "/index.html";

                    string accept = httpRequest.Headers[HttpRequestHeader.Accept];
                    if (string.IsNullOrEmpty(accept) || accept.Contains("text/html", StringComparison.OrdinalIgnoreCase))
                    {
                        if (path.Equals("/index.html", StringComparison.OrdinalIgnoreCase))
                        {
                            //send block page
                            if (_serveBlockPageFromWebServerRoot)
                            {
                                path = Path.GetFullPath(_webServerRootPath + path.Replace('/', Path.DirectorySeparatorChar));

                                if (!path.StartsWith(_webServerRootPath) || !File.Exists(path))
                                    await SendErrorAsync(stream, requestConnection, 404);
                                else
                                    await SendFileAsync(stream, requestConnection, path);
                            }
                            else
                            {
                                await SendContentAsync(stream, requestConnection, "text/html", _blockPageContent);
                            }
                        }
                        else
                        {
                            //redirect to block page
                            await RedirectAsync(stream, httpRequest.Protocol, requestConnection, (usingHttps ? "https://" : "http://") + httpRequest.Headers[HttpRequestHeader.Host]);
                        }
                    }
                    else
                    {
                        if (_serveBlockPageFromWebServerRoot)
                        {
                            //serve files
                            path = Path.GetFullPath(_webServerRootPath + path.Replace('/', Path.DirectorySeparatorChar));

                            if (!path.StartsWith(_webServerRootPath) || !File.Exists(path))
                                await SendErrorAsync(stream, requestConnection, 404);
                            else
                                await SendFileAsync(stream, requestConnection, path);
                        }
                        else
                        {
                            await SendErrorAsync(stream, requestConnection, 404);
                        }
                    }
                }
            }
            catch (TimeoutException)
            {
                //ignore timeout exception
            }
            catch (IOException)
            {
                //ignore IO exceptions
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog(ex);
            }
        }

        private static async Task SendContentAsync(Stream outputStream, string connection, string contentType, byte[] content)
        {
            byte[] bufferHeader = Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nContent-Type: " + contentType + "\r\nContent-Length: " + content.Length + "\r\nX-Robots-Tag: noindex, nofollow\r\nConnection: " + connection + "\r\n\r\n");

            await outputStream.WriteAsync(bufferHeader);
            await outputStream.WriteAsync(content);
            await outputStream.FlushAsync();
        }

        private static async Task SendErrorAsync(Stream outputStream, string connection, int statusCode, string message = null)
        {
            try
            {
                string statusString = statusCode + " " + GetHttpStatusString((HttpStatusCode)statusCode);
                byte[] bufferContent = Encoding.UTF8.GetBytes("<html><head><title>" + statusString + "</title></head><body><h1>" + statusString + "</h1>" + (message is null ? "" : "<p>" + message + "</p>") + "</body></html>");
                byte[] bufferHeader = Encoding.UTF8.GetBytes("HTTP/1.1 " + statusString + "\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + bufferContent.Length + "\r\nX-Robots-Tag: noindex, nofollow\r\nConnection: " + connection + "\r\n\r\n");

                await outputStream.WriteAsync(bufferHeader);
                await outputStream.WriteAsync(bufferContent);
                await outputStream.FlushAsync();
            }
            catch
            { }
        }

        private static async Task RedirectAsync(Stream outputStream, string protocol, string connection, string location)
        {
            try
            {
                string statusString = "302 Found";
                byte[] bufferContent = Encoding.UTF8.GetBytes("<html><head><title>" + statusString + "</title></head><body><h1>" + statusString + "</h1><p>Location: <a href=\"" + location + "\">" + location + "</a></p></body></html>");
                byte[] bufferHeader = Encoding.UTF8.GetBytes(protocol + " " + statusString + "\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nLocation: " + location + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + bufferContent.Length + "\r\nX-Robots-Tag: noindex, nofollow\r\nConnection: " + connection + "\r\n\r\n");

                await outputStream.WriteAsync(bufferHeader);
                await outputStream.WriteAsync(bufferContent);
                await outputStream.FlushAsync();
            }
            catch
            { }
        }

        private static async Task SendFileAsync(Stream outputStream, string connection, string filePath)
        {
            using (FileStream fS = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                byte[] bufferHeader = Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nDate: " + DateTime.UtcNow.ToString("r") + "\r\nContent-Type: " + WebUtilities.GetContentType(filePath).MediaType + "\r\nContent-Length: " + fS.Length + "\r\nCache-Control: private, max-age=300\r\nX-Robots-Tag: noindex, nofollow\r\nConnection: " + connection + "\r\n\r\n");

                await outputStream.WriteAsync(bufferHeader);
                await fS.CopyToAsync(outputStream);
                await outputStream.FlushAsync();
            }
        }

        private static string GetHttpStatusString(HttpStatusCode statusCode)
        {
            StringBuilder sb = new StringBuilder();

            foreach (char c in statusCode.ToString().ToCharArray())
            {
                if (char.IsUpper(c) && sb.Length > 0)
                    sb.Append(' ');

                sb.Append(c);
            }

            return sb.ToString();
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            dynamic jsonConfig = JsonConvert.DeserializeObject(config);

            {
                List<IPAddress> webServerLocalAddresses = new List<IPAddress>();

                foreach (dynamic jsonAddress in jsonConfig.webServerLocalAddresses)
                    webServerLocalAddresses.Add(IPAddress.Parse(jsonAddress.Value));

                _webServerLocalAddresses = webServerLocalAddresses;
            }

            if (jsonConfig.webServerUseSelfSignedTlsCertificate is null)
                _webServerUseSelfSignedTlsCertificate = true;
            else
                _webServerUseSelfSignedTlsCertificate = jsonConfig.webServerUseSelfSignedTlsCertificate.Value;

            _webServerTlsCertificateFilePath = jsonConfig.webServerTlsCertificateFilePath.Value;
            _webServerTlsCertificatePassword = jsonConfig.webServerTlsCertificatePassword.Value;

            _webServerRootPath = jsonConfig.webServerRootPath.Value;

            if (!Path.IsPathRooted(_webServerRootPath))
                _webServerRootPath = Path.Combine(_dnsServer.ApplicationFolder, _webServerRootPath);

            _serveBlockPageFromWebServerRoot = jsonConfig.serveBlockPageFromWebServerRoot.Value;

            string blockPageTitle = jsonConfig.blockPageTitle.Value;
            string blockPageHeading = jsonConfig.blockPageHeading.Value;
            string blockPageMessage = jsonConfig.blockPageMessage.Value;

            string blockPageContent = @"<html>
<head>
  <title>" + (blockPageTitle is null ? "" : blockPageTitle) + @"</title>
</head>
<body>
" + (blockPageHeading is null ? "" : "  <h1>" + blockPageHeading + "</h1>") + @"
" + (blockPageMessage is null ? "" : "  <p>" + blockPageMessage + "</p>") + @"
</body>
</html>";

            _blockPageContent = Encoding.UTF8.GetBytes(blockPageContent);

            try
            {
                StopWebServer();

                string selfSignedCertificateFilePath = Path.Combine(_dnsServer.ApplicationFolder, "cert.pfx");

                if (_webServerUseSelfSignedTlsCertificate)
                {
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
                    StopTlsCertificateUpdateTimer();

                    if (_webServerUseSelfSignedTlsCertificate)
                    {
                        LoadWebServiceTlsCertificate(selfSignedCertificateFilePath, null);
                    }
                    else
                    {
                        //disable HTTPS
                        _webServerTlsCertificate = null;
                    }
                }
                else
                {
                    LoadWebServiceTlsCertificate(_webServerTlsCertificateFilePath, _webServerTlsCertificatePassword);
                    StartTlsCertificateUpdateTimer();
                }

                StartWebServer();
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog(ex);
            }

            if (jsonConfig.webServerUseSelfSignedTlsCertificate is null)
            {
                config = config.Replace("\"webServerTlsCertificateFilePath\"", "\"webServerUseSelfSignedTlsCertificate\": true,\r\n  \"webServerTlsCertificateFilePath\"");

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Serves a block page from a built-in web server that can be displayed to the end user when a website is blocked by the DNS server.\n\nNote: You need to manually set the Blocking Type as Custom Address in the blocking settings and configure the current server's IP address as Custom Blocking Addresses for the block page to be served to the users. Use a PKCS #12 certificate (.pfx) for enabling HTTPS support. Enabling HTTPS support will show certificate error to the user which is expected and the user will have to proceed ignoring the certificate error to be able to see the block page."; } }

        #endregion
    }
}
