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

using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using DnsServerCore.Dns;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    public class WebService : IDisposable
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

        readonly Version _currentVersion;
        readonly string _appFolder;
        readonly string _configFolder;
        readonly Uri _updateCheckUri;

        readonly LogManager _log;

        DnsServer _dnsServer;
        DhcpServer _dhcpServer;

        IReadOnlyList<IPAddress> _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };
        int _webServiceHttpPort = 5380;
        int _webServiceTlsPort = 53443;
        bool _webServiceEnableTls;
        bool _webServiceHttpToTlsRedirect;
        string _webServiceTlsCertificatePath;
        string _webServiceTlsCertificatePassword;
        DateTime _webServiceTlsCertificateLastModifiedOn;

        HttpListener _webService;
        IReadOnlyList<Socket> _webServiceTlsListeners;
        X509Certificate2 _webServiceTlsCertificate;
        readonly IndependentTaskScheduler _webServiceTaskScheduler = new IndependentTaskScheduler(ThreadPriority.AboveNormal);
        string _webServiceHostname;

        string _dnsTlsCertificatePath;
        string _dnsTlsCertificatePassword;
        DateTime _dnsTlsCertificateLastModifiedOn;

        Timer _tlsCertificateUpdateTimer;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

        const int MAX_LOGIN_ATTEMPTS = 5;
        const int BLOCK_ADDRESS_INTERVAL = 5 * 60 * 1000;
        readonly ConcurrentDictionary<IPAddress, int> _failedLoginAttempts = new ConcurrentDictionary<IPAddress, int>();
        readonly ConcurrentDictionary<IPAddress, DateTime> _blockedAddresses = new ConcurrentDictionary<IPAddress, DateTime>();
        readonly ConcurrentDictionary<string, string> _credentials = new ConcurrentDictionary<string, string>();
        readonly ConcurrentDictionary<string, UserSession> _sessions = new ConcurrentDictionary<string, UserSession>();

        volatile ServiceState _state = ServiceState.Stopped;

        Timer _blockListUpdateTimer;
        DateTime _blockListLastUpdatedOn;
        int _blockListUpdateIntervalHours = 24;
        const int BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL = 5000;
        const int BLOCK_LIST_UPDATE_TIMER_INTERVAL = 900000;

        List<string> _configDisabledZones;

        #endregion

        #region constructor

        public WebService(string configFolder = null, Uri updateCheckUri = null)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            AssemblyName assemblyName = assembly.GetName();

            _currentVersion = assemblyName.Version;
            _appFolder = Path.GetDirectoryName(assembly.Location);

            if (configFolder == null)
                _configFolder = Path.Combine(_appFolder, "config");
            else
                _configFolder = configFolder;

            if (!Directory.Exists(_configFolder))
                Directory.CreateDirectory(_configFolder);

            _updateCheckUri = updateCheckUri;

            _log = new LogManager(_configFolder);

            string blockListsFolder = Path.Combine(_configFolder, "blocklists");

            if (!Directory.Exists(blockListsFolder))
                Directory.CreateDirectory(blockListsFolder);
        }

        #endregion

        #region IDisposable

        private bool _disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                Stop();

                if (_webService != null)
                    _webService.Close();

                if (_dnsServer != null)
                    _dnsServer.Dispose();

                if (_dhcpServer != null)
                    _dhcpServer.Dispose();

                if (_log != null)
                    _log.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private async Task AcceptWebRequestAsync()
        {
            try
            {
                while (true)
                {
                    HttpListenerContext context = await _webService.GetContextAsync();

                    if ((_webServiceTlsListeners != null) && (_webServiceTlsListeners.Count > 0) && _webServiceHttpToTlsRedirect)
                    {
                        IPEndPoint remoteEP = context.Request.RemoteEndPoint;

                        if ((remoteEP != null) && !IPAddress.IsLoopback(remoteEP.Address))
                        {
                            string domain = _webServiceTlsCertificate.GetNameInfo(X509NameType.DnsName, false);
                            string redirectUri = "https://" + domain + ":" + _webServiceTlsPort + context.Request.Url.PathAndQuery;

                            context.Response.Redirect(redirectUri);
                            context.Response.Close();

                            continue;
                        }
                    }

                    _ = ProcessRequestAsync(context.Request, context.Response);
                }
            }
            catch (HttpListenerException ex)
            {
                if (ex.ErrorCode == 995)
                    return; //web service stopping

                _log.Write(ex);
            }
            catch (ObjectDisposedException)
            {
                //web service stopped
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //web service stopping

                _log.Write(ex);
            }
        }

        private async Task AcceptTlsWebRequestAsync(Socket tlsListener)
        {
            try
            {
                while (true)
                {
                    Socket socket = await tlsListener.AcceptAsync();

                    _ = TlsToHttpTunnelAsync(socket);
                }
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.OperationAborted)
                    return; //web service stopping

                _log.Write(ex);
            }
            catch (ObjectDisposedException)
            {
                //web service stopped
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //web service stopping

                _log.Write(ex);
            }
        }

        private async Task TlsToHttpTunnelAsync(Socket socket)
        {
            bool dispose = true;
            Socket tunnel = null;

            try
            {
                if (_webServiceLocalAddresses.Count < 1)
                    return;

                SslStream sslStream = new SslStream(new NetworkStream(socket, true));

                await sslStream.AuthenticateAsServerAsync(_webServiceTlsCertificate);

                IPEndPoint httpEP;

                if (_webServiceLocalAddresses[0].Equals(IPAddress.Any))
                    httpEP = new IPEndPoint(IPAddress.Loopback, _webServiceHttpPort);
                else if (_webServiceLocalAddresses[0].Equals(IPAddress.IPv6Any))
                    httpEP = new IPEndPoint(IPAddress.IPv6Loopback, _webServiceHttpPort);
                else
                    httpEP = new IPEndPoint(_webServiceLocalAddresses[0], _webServiceHttpPort);

                tunnel = new Socket(httpEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                tunnel.Connect(httpEP);

                NetworkStream tunnelStream = new NetworkStream(tunnel, true);

                _ = sslStream.CopyToAsync(tunnelStream).ContinueWith(delegate (Task prevTask) { sslStream.Dispose(); tunnelStream.Dispose(); });
                _ = tunnelStream.CopyToAsync(sslStream).ContinueWith(delegate (Task prevTask) { sslStream.Dispose(); tunnelStream.Dispose(); });

                dispose = false;
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
            finally
            {
                if (dispose)
                {
                    socket.Dispose();

                    if (tunnel != null)
                        tunnel.Dispose();
                }
            }
        }

        private async Task ProcessRequestAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            response.AddHeader("Server", "");
            response.AddHeader("X-Robots-Tag", "noindex, nofollow");

            try
            {
                Uri url = request.Url;
                string path = url.AbsolutePath;

                if (!path.StartsWith("/") || path.Contains("/../") || path.Contains("/.../"))
                {
                    await SendErrorAsync(response, 404);
                    return;
                }

                if (path.StartsWith("/api/"))
                {
                    using (MemoryStream mS = new MemoryStream())
                    {
                        try
                        {
                            JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                            jsonWriter.WriteStartObject();

                            switch (path)
                            {
                                case "/api/login":
                                    await LoginAsync(request, jsonWriter);
                                    break;

                                case "/api/logout":
                                    Logout(request);
                                    break;

                                default:
                                    if (!IsSessionValid(request))
                                        throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                                    jsonWriter.WritePropertyName("response");
                                    jsonWriter.WriteStartObject();

                                    try
                                    {
                                        switch (path)
                                        {
                                            case "/api/changePassword":
                                                ChangePassword(request);
                                                break;

                                            case "/api/checkForUpdate":
                                                await CheckForUpdateAsync(request, jsonWriter);
                                                break;

                                            case "/api/getDnsSettings":
                                                GetDnsSettings(jsonWriter);
                                                break;

                                            case "/api/setDnsSettings":
                                                SetDnsSettings(request, jsonWriter);
                                                break;

                                            case "/api/forceUpdateBlockLists":
                                                ForceUpdateBlockLists(request);
                                                break;

                                            case "/api/backupSettings":
                                                await BackupSettingsAsync(request, response);
                                                return;

                                            case "/api/restoreSettings":
                                                await RestoreSettingsAsync(request, jsonWriter);
                                                break;

                                            case "/api/getStats":
                                                await GetStats(request, jsonWriter);
                                                break;

                                            case "/api/getTopStats":
                                                await GetTopStats(request, jsonWriter);
                                                break;

                                            case "/api/flushDnsCache":
                                                FlushCache(request);
                                                break;

                                            case "/api/listCachedZones":
                                                ListCachedZones(request, jsonWriter);
                                                break;

                                            case "/api/deleteCachedZone":
                                                DeleteCachedZone(request);
                                                break;

                                            case "/api/listAllowedZones":
                                                ListAllowedZones(request, jsonWriter);
                                                break;

                                            case "/api/importAllowedZones":
                                                ImportAllowedZones(request);
                                                break;

                                            case "/api/exportAllowedZones":
                                                ExportAllowedZones(response);
                                                return;

                                            case "/api/deleteAllowedZone":
                                                DeleteAllowedZone(request);
                                                break;

                                            case "/api/allowZone":
                                                AllowZone(request);
                                                break;

                                            case "/api/listBlockedZones":
                                                ListBlockedZones(request, jsonWriter);
                                                break;

                                            case "/api/importBlockedZones":
                                                ImportBlockedZones(request);
                                                break;

                                            case "/api/exportBlockedZones":
                                                ExportBlockedZones(response);
                                                return;

                                            case "/api/deleteBlockedZone":
                                                DeleteBlockedZone(request);
                                                break;

                                            case "/api/blockZone":
                                                BlockZone(request);
                                                break;

                                            case "/api/listZones":
                                                ListZones(jsonWriter);
                                                break;

                                            case "/api/createZone":
                                                await CreateZoneAsync(request, jsonWriter);
                                                break;

                                            case "/api/deleteZone":
                                                DeleteZone(request);
                                                break;

                                            case "/api/enableZone":
                                                EnableZone(request);
                                                break;

                                            case "/api/disableZone":
                                                DisableZone(request);
                                                break;

                                            case "/api/addRecord":
                                                AddRecord(request);
                                                break;

                                            case "/api/getRecords":
                                                GetRecords(request, jsonWriter);
                                                break;

                                            case "/api/deleteRecord":
                                                DeleteRecord(request);
                                                break;

                                            case "/api/updateRecord":
                                                UpdateRecord(request);
                                                break;

                                            case "/api/resolveQuery":
                                                await ResolveQuery(request, jsonWriter);
                                                break;

                                            case "/api/listLogs":
                                                ListLogs(jsonWriter);
                                                break;

                                            case "/api/deleteLog":
                                                DeleteLog(request);
                                                break;

                                            case "/api/deleteAllLogs":
                                                DeleteAllLogs(request);
                                                break;

                                            case "/api/deleteAllStats":
                                                DeleteAllStats(request);
                                                break;

                                            case "/api/listDhcpScopes":
                                                ListDhcpScopes(jsonWriter);
                                                break;

                                            case "/api/listDhcpLeases":
                                                ListDhcpLeases(jsonWriter);
                                                break;

                                            case "/api/getDhcpScope":
                                                GetDhcpScope(request, jsonWriter);
                                                break;

                                            case "/api/setDhcpScope":
                                                await SetDhcpScopeAsync(request);
                                                break;

                                            case "/api/enableDhcpScope":
                                                await EnableDhcpScopeAsync(request);
                                                break;

                                            case "/api/disableDhcpScope":
                                                DisableDhcpScope(request);
                                                break;

                                            case "/api/deleteDhcpScope":
                                                DeleteDhcpScope(request);
                                                break;

                                            default:
                                                await SendErrorAsync(response, 404);
                                                return;
                                        }
                                    }
                                    finally
                                    {
                                        jsonWriter.WriteEndObject();
                                    }
                                    break;
                            }

                            jsonWriter.WritePropertyName("status");
                            jsonWriter.WriteValue("ok");

                            jsonWriter.WriteEndObject();
                            jsonWriter.Flush();
                        }
                        catch (InvalidTokenWebServiceException ex)
                        {
                            mS.SetLength(0);
                            JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                            jsonWriter.WriteStartObject();

                            jsonWriter.WritePropertyName("status");
                            jsonWriter.WriteValue("invalid-token");

                            jsonWriter.WritePropertyName("errorMessage");
                            jsonWriter.WriteValue(ex.Message);

                            jsonWriter.WriteEndObject();
                            jsonWriter.Flush();
                        }
                        catch (Exception ex)
                        {
                            _log.Write(GetRequestRemoteEndPoint(request), ex);

                            mS.SetLength(0);
                            JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                            jsonWriter.WriteStartObject();

                            jsonWriter.WritePropertyName("status");
                            jsonWriter.WriteValue("error");

                            jsonWriter.WritePropertyName("errorMessage");
                            jsonWriter.WriteValue(ex.Message);

                            jsonWriter.WritePropertyName("stackTrace");
                            jsonWriter.WriteValue(ex.StackTrace);

                            if (ex.InnerException != null)
                            {
                                jsonWriter.WritePropertyName("innerErrorMessage");
                                jsonWriter.WriteValue(ex.InnerException.Message);
                            }

                            jsonWriter.WriteEndObject();
                            jsonWriter.Flush();
                        }

                        response.ContentType = "application/json; charset=utf-8";
                        response.ContentEncoding = Encoding.UTF8;
                        response.ContentLength64 = mS.Length;

                        using (Stream stream = response.OutputStream)
                        {
                            mS.WriteTo(response.OutputStream);
                        }
                    }
                }
                else if (path.StartsWith("/log/"))
                {
                    if (!IsSessionValid(request))
                    {
                        await SendErrorAsync(response, 403, "Invalid token or session expired.");
                        return;
                    }

                    string[] pathParts = path.Split('/');
                    string logFileName = pathParts[2];

                    int limit = 0;
                    string strLimit = request.QueryString["limit"];
                    if (!string.IsNullOrEmpty(strLimit))
                        limit = int.Parse(strLimit);

                    await _log.DownloadLogAsync(request, response, logFileName, limit * 1024 * 1024);
                }
                else
                {
                    if (path == "/")
                    {
                        path = "/index.html";
                    }
                    else if ((path == "/blocklist.txt") && !IPAddress.IsLoopback(GetRequestRemoteEndPoint(request).Address))
                    {
                        await SendErrorAsync(response, 403);
                        return;
                    }

                    string wwwroot = Path.Combine(_appFolder, "www");
                    path = Path.GetFullPath(wwwroot + path.Replace('/', Path.DirectorySeparatorChar));

                    if (!path.StartsWith(wwwroot) || !File.Exists(path))
                    {
                        await SendErrorAsync(response, 404);
                        return;
                    }

                    await SendFileAsync(request, response, path);
                }
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //web service stopping

                _log.Write(GetRequestRemoteEndPoint(request), ex);

                await SendError(response, ex);
            }
        }

        private static IPEndPoint GetRequestRemoteEndPoint(HttpListenerRequest request)
        {
            try
            {
                if (request.RemoteEndPoint == null)
                    return new IPEndPoint(IPAddress.Any, 0);

                if (NetUtilities.IsPrivateIP(request.RemoteEndPoint.Address))
                {
                    string xRealIp = request.Headers["X-Real-IP"];
                    if (IPAddress.TryParse(xRealIp, out IPAddress address))
                    {
                        //get the real IP address of the requesting client from X-Real-IP header set in nginx proxy_pass block
                        return new IPEndPoint(address, 0);
                    }
                }

                return request.RemoteEndPoint;
            }
            catch
            {
                return new IPEndPoint(IPAddress.Any, 0);
            }
        }

        public static Stream GetOutputStream(HttpListenerRequest request, HttpListenerResponse response)
        {
            string strAcceptEncoding = request.Headers["Accept-Encoding"];
            if (string.IsNullOrEmpty(strAcceptEncoding))
            {
                return response.OutputStream;
            }
            else
            {
                if (strAcceptEncoding.Contains("gzip"))
                {
                    response.AddHeader("Content-Encoding", "gzip");
                    return new GZipStream(response.OutputStream, CompressionMode.Compress);
                }
                else if (strAcceptEncoding.Contains("deflate"))
                {
                    response.AddHeader("Content-Encoding", "deflate");
                    return new DeflateStream(response.OutputStream, CompressionMode.Compress);
                }
                else
                {
                    return response.OutputStream;
                }
            }
        }

        private static Task SendError(HttpListenerResponse response, Exception ex)
        {
            return SendErrorAsync(response, 500, ex.ToString());
        }

        private static async Task SendErrorAsync(HttpListenerResponse response, int statusCode, string message = null)
        {
            try
            {
                string statusString = statusCode + " " + DnsServer.GetHttpStatusString((HttpStatusCode)statusCode);
                byte[] buffer = Encoding.UTF8.GetBytes("<html><head><title>" + statusString + "</title></head><body><h1>" + statusString + "</h1>" + (message == null ? "" : "<p>" + message + "</p>") + "</body></html>");

                response.StatusCode = statusCode;
                response.ContentType = "text/html";
                response.ContentLength64 = buffer.Length;

                using (Stream stream = response.OutputStream)
                {
                    await stream.WriteAsync(buffer, 0, buffer.Length);
                }
            }
            catch
            { }
        }

        private static async Task SendFileAsync(HttpListenerRequest request, HttpListenerResponse response, string filePath)
        {
            using (FileStream fS = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                response.ContentType = WebUtilities.GetContentType(filePath).MediaType;
                response.AddHeader("Cache-Control", "private, max-age=300");

                using (Stream stream = GetOutputStream(request, response))
                {
                    try
                    {
                        await fS.CopyToAsync(stream);
                    }
                    catch (HttpListenerException)
                    {
                        //ignore this error
                    }
                }
            }
        }

        private string CreateSession(string username)
        {
            string token = BinaryNumber.GenerateRandomNumber256().ToString();

            if (!_sessions.TryAdd(token, new UserSession(username)))
                throw new WebServiceException("Error while creating session. Please try again.");

            return token;
        }

        private UserSession GetSession(string token)
        {
            if (_sessions.TryGetValue(token, out UserSession session))
                return session;

            return null;
        }

        private UserSession GetSession(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new WebServiceException("Parameter 'token' missing.");

            return GetSession(strToken);
        }

        private UserSession DeleteSession(string token)
        {
            if (_sessions.TryRemove(token, out UserSession session))
                return session;

            return null;
        }

        private UserSession DeleteSession(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new WebServiceException("Parameter 'token' missing.");

            return DeleteSession(strToken);
        }

        private void FailedLoginAttempt(IPAddress address)
        {
            _failedLoginAttempts.AddOrUpdate(address, 1, delegate (IPAddress key, int attempts)
            {
                return attempts + 1;
            });
        }

        private bool LoginAttemptsExceedLimit(IPAddress address, int limit)
        {
            if (!_failedLoginAttempts.TryGetValue(address, out int attempts))
                return false;

            return attempts >= limit;
        }

        private void ResetFailedLoginAttempt(IPAddress address)
        {
            _failedLoginAttempts.TryRemove(address, out _);
        }

        private void BlockAddress(IPAddress address, int interval)
        {
            _blockedAddresses.TryAdd(address, DateTime.UtcNow.AddMilliseconds(interval));
        }

        private bool IsAddressBlocked(IPAddress address)
        {
            if (!_blockedAddresses.TryGetValue(address, out DateTime expiry))
                return false;

            if (expiry > DateTime.UtcNow)
            {
                return true;
            }
            else
            {
                UnblockAddress(address);
                ResetFailedLoginAttempt(address);

                return false;
            }
        }

        private void UnblockAddress(IPAddress address)
        {
            _blockedAddresses.TryRemove(address, out _);
        }

        private async Task LoginAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strUsername = request.QueryString["user"];
            if (string.IsNullOrEmpty(strUsername))
                throw new WebServiceException("Parameter 'user' missing.");

            string strPassword = request.QueryString["pass"];
            if (string.IsNullOrEmpty(strPassword))
                throw new WebServiceException("Parameter 'pass' missing.");

            IPEndPoint remoteEP = GetRequestRemoteEndPoint(request);

            if (IsAddressBlocked(remoteEP.Address))
                throw new WebServiceException("Max limit of " + MAX_LOGIN_ATTEMPTS + " attempts exceeded. Access blocked for " + (BLOCK_ADDRESS_INTERVAL / 1000) + " seconds.");

            strUsername = strUsername.ToLower();
            string strPasswordHash = GetPasswordHash(strUsername, strPassword);

            if (!_credentials.TryGetValue(strUsername, out string passwordHash) || (passwordHash != strPasswordHash))
            {
                if (strPassword != "admin") //exception for default password
                {
                    FailedLoginAttempt(remoteEP.Address);

                    if (LoginAttemptsExceedLimit(remoteEP.Address, MAX_LOGIN_ATTEMPTS))
                        BlockAddress(remoteEP.Address, BLOCK_ADDRESS_INTERVAL);

                    await Task.Delay(1000);
                }

                throw new WebServiceException("Invalid username or password: " + strUsername);
            }

            ResetFailedLoginAttempt(remoteEP.Address);

            _log.Write(remoteEP, "[" + strUsername + "] User logged in.");

            string token = CreateSession(strUsername);

            jsonWriter.WritePropertyName("token");
            jsonWriter.WriteValue(token);
        }

        private bool IsSessionValid(HttpListenerRequest request)
        {
            UserSession session = GetSession(request);
            if (session == null)
                return false;

            if (session.HasExpired())
            {
                DeleteSession(request);
                return false;
            }

            session.UpdateLastSeen();
            return true;
        }

        private void ChangePassword(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new WebServiceException("Parameter 'token' missing.");

            string strPassword = request.QueryString["pass"];
            if (string.IsNullOrEmpty(strPassword))
                throw new WebServiceException("Parameter 'pass' missing.");

            UserSession session = GetSession(strToken);
            if (session == null)
                throw new WebServiceException("User session does not exists.");

            SetCredentials(session.Username, strPassword);
            SaveConfigFile();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + session.Username + "] Password was changed for user.");
        }

        private void Logout(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new WebServiceException("Parameter 'token' missing.");

            UserSession session = DeleteSession(strToken);

            if (session != null)
                _log.Write(GetRequestRemoteEndPoint(request), "[" + session.Username + "] User logged out.");
        }

        public static void CreateUpdateInfo(Stream s, string version, string displayText, string downloadLink)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("DU")); //format
            bW.Write((byte)2); //version

            bW.WriteShortString(version);
            bW.WriteShortString(displayText);
            bW.WriteShortString(downloadLink);
        }

        private async Task CheckForUpdateAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            Version updateVersion = null;
            string displayText = null;
            string downloadLink = null;

            bool updateAvailable = false;

            if (_updateCheckUri != null)
            {
                try
                {
                    HttpClientHandler handler = new HttpClientHandler();
                    handler.Proxy = _dnsServer.Proxy;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        byte[] response = await http.GetByteArrayAsync(_updateCheckUri);

                        using (MemoryStream mS = new MemoryStream(response, false))
                        {
                            BinaryReader bR = new BinaryReader(mS);

                            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DU") //format
                                throw new InvalidDataException("DNS Server update info format is invalid.");

                            switch (bR.ReadByte()) //version
                            {
                                case 2:
                                    updateVersion = new Version(bR.ReadShortString());
                                    displayText = bR.ReadShortString();
                                    downloadLink = bR.ReadShortString();
                                    break;

                                default:
                                    throw new InvalidDataException("DNS Server update info version not supported.");
                            }

                            updateAvailable = updateVersion > _currentVersion;
                        }
                    }

                    _log.Write(GetRequestRemoteEndPoint(request), "Check for update was done {updateAvailable: " + updateAvailable + "; updateVersion: " + updateVersion + "; displayText: " + displayText + "; downloadLink: " + downloadLink + ";}");
                }
                catch (Exception ex)
                {
                    _log.Write(GetRequestRemoteEndPoint(request), "Check for update was done {updateAvailable: False;}\r\n" + ex.ToString());
                }
            }

            jsonWriter.WritePropertyName("updateAvailable");
            jsonWriter.WriteValue(updateAvailable);

            if (updateAvailable)
            {
                if (!string.IsNullOrEmpty(displayText))
                {
                    jsonWriter.WritePropertyName("displayText");
                    jsonWriter.WriteValue(displayText);
                }

                jsonWriter.WritePropertyName("downloadLink");
                jsonWriter.WriteValue(downloadLink);
            }
        }

        private static string GetCleanVersion(Version version)
        {
            string strVersion = version.Major + "." + version.Minor;

            if (version.Build > 0)
                strVersion += "." + version.Build;

            if (version.Revision > 0)
                strVersion += "." + version.Revision;

            return strVersion;
        }

        private void GetDnsSettings(JsonTextWriter jsonWriter)
        {
            jsonWriter.WritePropertyName("version");
            jsonWriter.WriteValue(GetCleanVersion(_currentVersion));

            jsonWriter.WritePropertyName("dnsServerDomain");
            jsonWriter.WriteValue(_dnsServer.ServerDomain);

            jsonWriter.WritePropertyName("dnsServerLocalEndPoints");
            jsonWriter.WriteStartArray();

            foreach (IPEndPoint localEP in _dnsServer.LocalEndPoints)
                jsonWriter.WriteValue(localEP.ToString());

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("webServiceLocalAddresses");
            jsonWriter.WriteStartArray();

            foreach (IPAddress localAddress in _webServiceLocalAddresses)
                jsonWriter.WriteValue(localAddress.ToString());

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("webServiceHttpPort");
            jsonWriter.WriteValue(_webServiceHttpPort);

            jsonWriter.WritePropertyName("webServiceEnableTls");
            jsonWriter.WriteValue(_webServiceEnableTls);

            jsonWriter.WritePropertyName("webServiceHttpToTlsRedirect");
            jsonWriter.WriteValue(_webServiceHttpToTlsRedirect);

            jsonWriter.WritePropertyName("webServiceTlsPort");
            jsonWriter.WriteValue(_webServiceTlsPort);

            jsonWriter.WritePropertyName("webServiceTlsCertificatePath");
            jsonWriter.WriteValue(_webServiceTlsCertificatePath);

            jsonWriter.WritePropertyName("webServiceTlsCertificatePassword");
            jsonWriter.WriteValue("************");

            jsonWriter.WritePropertyName("enableDnsOverHttp");
            jsonWriter.WriteValue(_dnsServer.EnableDnsOverHttp);

            jsonWriter.WritePropertyName("enableDnsOverTls");
            jsonWriter.WriteValue(_dnsServer.EnableDnsOverTls);

            jsonWriter.WritePropertyName("enableDnsOverHttps");
            jsonWriter.WriteValue(_dnsServer.EnableDnsOverHttps);

            jsonWriter.WritePropertyName("dnsTlsCertificatePath");
            jsonWriter.WriteValue(_dnsTlsCertificatePath);

            jsonWriter.WritePropertyName("dnsTlsCertificatePassword");
            jsonWriter.WriteValue("************");

            jsonWriter.WritePropertyName("preferIPv6");
            jsonWriter.WriteValue(_dnsServer.PreferIPv6);

            jsonWriter.WritePropertyName("enableLogging");
            jsonWriter.WriteValue(_log.EnableLogging);

            jsonWriter.WritePropertyName("logQueries");
            jsonWriter.WriteValue(_dnsServer.QueryLogManager != null);

            jsonWriter.WritePropertyName("useLocalTime");
            jsonWriter.WriteValue(_log.UseLocalTime);

            jsonWriter.WritePropertyName("logFolder");
            jsonWriter.WriteValue(_log.LogFolder);

            jsonWriter.WritePropertyName("maxLogFileDays");
            jsonWriter.WriteValue(_log.MaxLogFileDays);

            jsonWriter.WritePropertyName("maxStatFileDays");
            jsonWriter.WriteValue(_dnsServer.StatsManager.MaxStatFileDays);

            jsonWriter.WritePropertyName("allowRecursion");
            jsonWriter.WriteValue(_dnsServer.AllowRecursion);

            jsonWriter.WritePropertyName("allowRecursionOnlyForPrivateNetworks");
            jsonWriter.WriteValue(_dnsServer.AllowRecursionOnlyForPrivateNetworks);

            jsonWriter.WritePropertyName("randomizeName");
            jsonWriter.WriteValue(_dnsServer.RandomizeName);

            jsonWriter.WritePropertyName("serveStale");
            jsonWriter.WriteValue(_dnsServer.ServeStale);

            jsonWriter.WritePropertyName("serveStaleTtl");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.ServeStaleTtl);

            jsonWriter.WritePropertyName("cachePrefetchEligibility");
            jsonWriter.WriteValue(_dnsServer.CachePrefetchEligibility);

            jsonWriter.WritePropertyName("cachePrefetchTrigger");
            jsonWriter.WriteValue(_dnsServer.CachePrefetchTrigger);

            jsonWriter.WritePropertyName("cachePrefetchSampleIntervalInMinutes");
            jsonWriter.WriteValue(_dnsServer.CachePrefetchSampleIntervalInMinutes);

            jsonWriter.WritePropertyName("cachePrefetchSampleEligibilityHitsPerHour");
            jsonWriter.WriteValue(_dnsServer.CachePrefetchSampleEligibilityHitsPerHour);

            jsonWriter.WritePropertyName("proxy");
            if (_dnsServer.Proxy == null)
            {
                jsonWriter.WriteNull();
            }
            else
            {
                jsonWriter.WriteStartObject();

                NetProxy proxy = _dnsServer.Proxy;

                jsonWriter.WritePropertyName("type");
                jsonWriter.WriteValue(proxy.Type.ToString());

                jsonWriter.WritePropertyName("address");
                jsonWriter.WriteValue(proxy.Address);

                jsonWriter.WritePropertyName("port");
                jsonWriter.WriteValue(proxy.Port);

                NetworkCredential credential = proxy.Credential;

                if (credential != null)
                {
                    jsonWriter.WritePropertyName("username");
                    jsonWriter.WriteValue(credential.UserName);

                    jsonWriter.WritePropertyName("password");
                    jsonWriter.WriteValue(credential.Password);
                }

                jsonWriter.WritePropertyName("bypass");
                jsonWriter.WriteStartArray();

                foreach (NetProxyBypassItem item in proxy.BypassList)
                    jsonWriter.WriteValue(item.Value);

                jsonWriter.WriteEndArray();

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WritePropertyName("forwarders");

            DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;

            if (_dnsServer.Forwarders == null)
            {
                jsonWriter.WriteNull();
            }
            else
            {
                forwarderProtocol = _dnsServer.Forwarders[0].Protocol;

                jsonWriter.WriteStartArray();

                foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                    jsonWriter.WriteValue(forwarder.OriginalAddress);

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("forwarderProtocol");
            jsonWriter.WriteValue(forwarderProtocol.ToString());


            jsonWriter.WritePropertyName("blockListUrls");

            if (_dnsServer.BlockListZoneManager.BlockListUrls.Count == 0)
            {
                jsonWriter.WriteNull();
            }
            else
            {
                jsonWriter.WriteStartArray();

                foreach (Uri blockListUrl in _dnsServer.BlockListZoneManager.BlockListUrls)
                    jsonWriter.WriteValue(blockListUrl.AbsoluteUri);

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("blockListUpdateIntervalHours");
            jsonWriter.WriteValue(_blockListUpdateIntervalHours);

            jsonWriter.WritePropertyName("blockListNextUpdatedOn");
            jsonWriter.WriteValue(_blockListLastUpdatedOn.AddHours(_blockListUpdateIntervalHours).ToLocalTime().ToString());
        }

        private void SetDnsSettings(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            bool restartDnsService = false;
            bool restartWebService = false;

            string strDnsServerDomain = request.QueryString["dnsServerDomain"];
            if (!string.IsNullOrEmpty(strDnsServerDomain))
                _dnsServer.ServerDomain = strDnsServerDomain;

            string strDnsServerLocalEndPoints = request.QueryString["dnsServerLocalEndPoints"];
            if (strDnsServerLocalEndPoints != null)
            {
                if (string.IsNullOrEmpty(strDnsServerLocalEndPoints))
                    strDnsServerLocalEndPoints = "0.0.0.0:53,[::]:53";

                string[] strLocalEndPoints = strDnsServerLocalEndPoints.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                List<IPEndPoint> localEndPoints = new List<IPEndPoint>(strLocalEndPoints.Length);

                for (int i = 0; i < strLocalEndPoints.Length; i++)
                {
                    NameServerAddress nameServer = new NameServerAddress(strLocalEndPoints[i]);
                    if (nameServer.IPEndPoint != null)
                        localEndPoints.Add(nameServer.IPEndPoint);
                }

                if (localEndPoints.Count > 0)
                {
                    if (_dnsServer.LocalEndPoints.Count != localEndPoints.Count)
                    {
                        restartDnsService = true;
                    }
                    else
                    {
                        foreach (IPEndPoint currentLocalEP in _dnsServer.LocalEndPoints)
                        {
                            if (!localEndPoints.Contains(currentLocalEP))
                            {
                                restartDnsService = true;
                                break;
                            }
                        }
                    }

                    _dnsServer.LocalEndPoints = localEndPoints;
                }
            }

            string strWebServiceLocalAddresses = request.QueryString["webServiceLocalAddresses"];
            if (strWebServiceLocalAddresses != null)
            {
                if (string.IsNullOrEmpty(strWebServiceLocalAddresses))
                    strWebServiceLocalAddresses = "0.0.0.0,[::]";

                string[] strLocalAddresses = strWebServiceLocalAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                List<IPAddress> localAddresses = new List<IPAddress>(strLocalAddresses.Length);

                for (int i = 0; i < strLocalAddresses.Length; i++)
                {
                    if (IPAddress.TryParse(strLocalAddresses[i], out IPAddress localAddress))
                        localAddresses.Add(localAddress);
                }

                if (localAddresses.Count > 0)
                {
                    if (_webServiceLocalAddresses.Count != localAddresses.Count)
                    {
                        restartWebService = true;
                    }
                    else
                    {
                        foreach (IPAddress currentlocalAddress in _webServiceLocalAddresses)
                        {
                            if (!localAddresses.Contains(currentlocalAddress))
                            {
                                restartWebService = true;
                                break;
                            }
                        }
                    }

                    _webServiceLocalAddresses = localAddresses;
                }
            }

            int oldWebServiceHttpPort = _webServiceHttpPort;

            string strWebServiceHttpPort = request.QueryString["webServiceHttpPort"];
            if (!string.IsNullOrEmpty(strWebServiceHttpPort))
            {
                _webServiceHttpPort = int.Parse(strWebServiceHttpPort);

                if (oldWebServiceHttpPort != _webServiceHttpPort)
                    restartWebService = true;
            }

            string strWebServiceEnableTls = request.QueryString["webServiceEnableTls"];
            if (!string.IsNullOrEmpty(strWebServiceEnableTls))
            {
                bool oldWebServiceEnableTls = _webServiceEnableTls;

                _webServiceEnableTls = bool.Parse(strWebServiceEnableTls);

                if (oldWebServiceEnableTls != _webServiceEnableTls)
                    restartWebService = true;
            }

            string strWebServiceHttpToTlsRedirect = request.QueryString["webServiceHttpToTlsRedirect"];
            if (!string.IsNullOrEmpty(strWebServiceHttpToTlsRedirect))
                _webServiceHttpToTlsRedirect = bool.Parse(strWebServiceHttpToTlsRedirect);


            string strWebServiceTlsPort = request.QueryString["webServiceTlsPort"];
            if (!string.IsNullOrEmpty(strWebServiceTlsPort))
            {
                int oldWebServiceTlsPort = _webServiceTlsPort;

                _webServiceTlsPort = int.Parse(strWebServiceTlsPort);

                if (oldWebServiceTlsPort != _webServiceTlsPort)
                    restartWebService = true;
            }

            string strWebServiceTlsCertificatePath = request.QueryString["webServiceTlsCertificatePath"];
            string strWebServiceTlsCertificatePassword = request.QueryString["webServiceTlsCertificatePassword"];
            if (string.IsNullOrEmpty(strWebServiceTlsCertificatePath))
            {
                _webServiceTlsCertificatePath = null;
                _webServiceTlsCertificatePassword = "";
            }
            else
            {
                if (strWebServiceTlsCertificatePassword == "************")
                    strWebServiceTlsCertificatePassword = _webServiceTlsCertificatePassword;

                if ((strWebServiceTlsCertificatePath != _webServiceTlsCertificatePath) || (strWebServiceTlsCertificatePassword != _webServiceTlsCertificatePassword))
                {
                    LoadWebServiceTlsCertificate(strWebServiceTlsCertificatePath, strWebServiceTlsCertificatePassword);

                    _webServiceTlsCertificatePath = strWebServiceTlsCertificatePath;
                    _webServiceTlsCertificatePassword = strWebServiceTlsCertificatePassword;

                    StartTlsCertificateUpdateTimer();
                }
            }

            string enableDnsOverHttp = request.QueryString["enableDnsOverHttp"];
            if (!string.IsNullOrEmpty(enableDnsOverHttp))
            {
                bool oldEnableDnsOverHttp = _dnsServer.EnableDnsOverHttp;

                _dnsServer.EnableDnsOverHttp = bool.Parse(enableDnsOverHttp);

                if (oldEnableDnsOverHttp != _dnsServer.EnableDnsOverHttp)
                    restartDnsService = true;
            }

            string strEnableDnsOverTls = request.QueryString["enableDnsOverTls"];
            if (!string.IsNullOrEmpty(strEnableDnsOverTls))
            {
                bool oldEnableDnsOverTls = _dnsServer.EnableDnsOverTls;

                _dnsServer.EnableDnsOverTls = bool.Parse(strEnableDnsOverTls);

                if (oldEnableDnsOverTls != _dnsServer.EnableDnsOverTls)
                    restartDnsService = true;
            }

            string strEnableDnsOverHttps = request.QueryString["enableDnsOverHttps"];
            if (!string.IsNullOrEmpty(strEnableDnsOverHttps))
            {
                bool oldEnableDnsOverHttps = _dnsServer.EnableDnsOverHttps;

                _dnsServer.EnableDnsOverHttps = bool.Parse(strEnableDnsOverHttps);

                if (oldEnableDnsOverHttps != _dnsServer.EnableDnsOverHttps)
                    restartDnsService = true;
            }

            string strDnsTlsCertificatePath = request.QueryString["dnsTlsCertificatePath"];
            string strDnsTlsCertificatePassword = request.QueryString["dnsTlsCertificatePassword"];
            if (string.IsNullOrEmpty(strDnsTlsCertificatePath))
            {
                _dnsTlsCertificatePath = null;
                _dnsTlsCertificatePassword = "";
            }
            else
            {
                if (strDnsTlsCertificatePassword == "************")
                    strDnsTlsCertificatePassword = _dnsTlsCertificatePassword;

                if ((strDnsTlsCertificatePath != _dnsTlsCertificatePath) || (strDnsTlsCertificatePassword != _dnsTlsCertificatePassword))
                {
                    LoadDnsTlsCertificate(strDnsTlsCertificatePath, strDnsTlsCertificatePassword);

                    _dnsTlsCertificatePath = strDnsTlsCertificatePath;
                    _dnsTlsCertificatePassword = strDnsTlsCertificatePassword;

                    StartTlsCertificateUpdateTimer();
                }
            }

            string strPreferIPv6 = request.QueryString["preferIPv6"];
            if (!string.IsNullOrEmpty(strPreferIPv6))
                _dnsServer.PreferIPv6 = bool.Parse(strPreferIPv6);

            string strEnableLogging = request.QueryString["enableLogging"];
            if (!string.IsNullOrEmpty(strEnableLogging))
                _log.EnableLogging = bool.Parse(strEnableLogging);

            string strLogQueries = request.QueryString["logQueries"];
            if (!string.IsNullOrEmpty(strLogQueries))
            {
                if (bool.Parse(strLogQueries))
                    _dnsServer.QueryLogManager = _log;
                else
                    _dnsServer.QueryLogManager = null;
            }

            string strUseLocalTime = request.QueryString["useLocalTime"];
            if (!string.IsNullOrEmpty(strUseLocalTime))
                _log.UseLocalTime = bool.Parse(strUseLocalTime);

            string strLogFolder = request.QueryString["logFolder"];
            if (!string.IsNullOrEmpty(strLogFolder))
                _log.LogFolder = strLogFolder;

            string strMaxLogFileDays = request.QueryString["maxLogFileDays"];
            if (!string.IsNullOrEmpty(strMaxLogFileDays))
                _log.MaxLogFileDays = int.Parse(strMaxLogFileDays);

            string strMaxStatFileDays = request.QueryString["maxStatFileDays"];
            if (!string.IsNullOrEmpty(strMaxStatFileDays))
                _dnsServer.StatsManager.MaxStatFileDays = int.Parse(strMaxStatFileDays);

            string strAllowRecursion = request.QueryString["allowRecursion"];
            if (!string.IsNullOrEmpty(strAllowRecursion))
                _dnsServer.AllowRecursion = bool.Parse(strAllowRecursion);

            string strAllowRecursionOnlyForPrivateNetworks = request.QueryString["allowRecursionOnlyForPrivateNetworks"];
            if (!string.IsNullOrEmpty(strAllowRecursionOnlyForPrivateNetworks))
                _dnsServer.AllowRecursionOnlyForPrivateNetworks = bool.Parse(strAllowRecursionOnlyForPrivateNetworks);

            string strRandomizeName = request.QueryString["randomizeName"];
            if (!string.IsNullOrEmpty(strRandomizeName))
                _dnsServer.RandomizeName = bool.Parse(strRandomizeName);

            string strServeStale = request.QueryString["serveStale"];
            if (!string.IsNullOrEmpty(strServeStale))
                _dnsServer.ServeStale = bool.Parse(strServeStale);

            string strServeStaleTtl = request.QueryString["serveStaleTtl"];
            if (!string.IsNullOrEmpty(strServeStaleTtl))
                _dnsServer.CacheZoneManager.ServeStaleTtl = uint.Parse(strServeStaleTtl);

            string strCachePrefetchEligibility = request.QueryString["cachePrefetchEligibility"];
            if (!string.IsNullOrEmpty(strCachePrefetchEligibility))
                _dnsServer.CachePrefetchEligibility = int.Parse(strCachePrefetchEligibility);

            string strCachePrefetchTrigger = request.QueryString["cachePrefetchTrigger"];
            if (!string.IsNullOrEmpty(strCachePrefetchTrigger))
                _dnsServer.CachePrefetchTrigger = int.Parse(strCachePrefetchTrigger);

            string strCachePrefetchSampleIntervalInMinutes = request.QueryString["cachePrefetchSampleIntervalInMinutes"];
            if (!string.IsNullOrEmpty(strCachePrefetchSampleIntervalInMinutes))
                _dnsServer.CachePrefetchSampleIntervalInMinutes = int.Parse(strCachePrefetchSampleIntervalInMinutes);

            string strCachePrefetchSampleEligibilityHitsPerHour = request.QueryString["cachePrefetchSampleEligibilityHitsPerHour"];
            if (!string.IsNullOrEmpty(strCachePrefetchSampleEligibilityHitsPerHour))
                _dnsServer.CachePrefetchSampleEligibilityHitsPerHour = int.Parse(strCachePrefetchSampleEligibilityHitsPerHour);

            string strProxyType = request.QueryString["proxyType"];
            if (!string.IsNullOrEmpty(strProxyType))
            {
                NetProxyType proxyType = (NetProxyType)Enum.Parse(typeof(NetProxyType), strProxyType, true);
                if (proxyType == NetProxyType.None)
                {
                    _dnsServer.Proxy = null;
                }
                else
                {
                    NetworkCredential credential = null;

                    string strUsername = request.QueryString["proxyUsername"];
                    if (!string.IsNullOrEmpty(strUsername))
                        credential = new NetworkCredential(strUsername, request.QueryString["proxyPassword"]);

                    _dnsServer.Proxy = NetProxy.CreateProxy(proxyType, request.QueryString["proxyAddress"], int.Parse(request.QueryString["proxyPort"]), credential);

                    string strProxyBypass = request.QueryString["proxyBypass"];
                    if (!string.IsNullOrEmpty(strProxyBypass))
                    {
                        string[] strBypassList = strProxyBypass.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                        _dnsServer.Proxy.BypassList.Clear();

                        for (int i = 0; i < strBypassList.Length; i++)
                            _dnsServer.Proxy.BypassList.Add(new NetProxyBypassItem(strBypassList[i]));
                    }
                }
            }

            DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;
            string strForwarderProtocol = request.QueryString["forwarderProtocol"];
            if (!string.IsNullOrEmpty(strForwarderProtocol))
                forwarderProtocol = (DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), strForwarderProtocol, true);

            string strForwarders = request.QueryString["forwarders"];
            if (!string.IsNullOrEmpty(strForwarders))
            {
                if (strForwarders == "false")
                {
                    _dnsServer.Forwarders = null;
                }
                else
                {
                    string[] strForwardersList = strForwarders.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    NameServerAddress[] forwarders = new NameServerAddress[strForwardersList.Length];

                    for (int i = 0; i < strForwardersList.Length; i++)
                    {
                        if ((forwarderProtocol == DnsTransportProtocol.Tls) && IPAddress.TryParse(strForwardersList[i], out _))
                            strForwardersList[i] += ":853";

                        forwarders[i] = new NameServerAddress(strForwardersList[i], forwarderProtocol);
                    }

                    _dnsServer.Forwarders = forwarders;
                }
            }

            string strBlockListUrls = request.QueryString["blockListUrls"];
            if (!string.IsNullOrEmpty(strBlockListUrls))
            {
                if (strBlockListUrls == "false")
                {
                    StopBlockListUpdateTimer();

                    _dnsServer.BlockListZoneManager.BlockListUrls.Clear();
                    _dnsServer.BlockListZoneManager.Flush();
                }
                else
                {
                    bool updated = false;

                    string[] strBlockListUrlList = strBlockListUrls.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    if (oldWebServiceHttpPort != _webServiceHttpPort)
                    {
                        for (int i = 0; i < strBlockListUrlList.Length; i++)
                        {
                            if (strBlockListUrlList[i].Contains("http://localhost:" + oldWebServiceHttpPort + "/blocklist.txt"))
                            {
                                strBlockListUrlList[i] = "http://localhost:" + _webServiceHttpPort + "/blocklist.txt";
                                updated = true;
                                break;
                            }
                        }
                    }

                    if (!updated)
                    {
                        if (strBlockListUrlList.Length != _dnsServer.BlockListZoneManager.BlockListUrls.Count)
                        {
                            updated = true;
                        }
                        else
                        {
                            foreach (string strBlockListUrl in strBlockListUrlList)
                            {
                                if (!_dnsServer.BlockListZoneManager.BlockListUrls.Contains(new Uri(strBlockListUrl)))
                                {
                                    updated = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (updated)
                    {
                        _dnsServer.BlockListZoneManager.BlockListUrls.Clear();

                        foreach (string strBlockListUrl in strBlockListUrlList)
                        {
                            Uri blockListUrl = new Uri(strBlockListUrl);

                            if (!_dnsServer.BlockListZoneManager.BlockListUrls.Contains(blockListUrl))
                                _dnsServer.BlockListZoneManager.BlockListUrls.Add(blockListUrl);
                        }

                        ForceUpdateBlockLists();
                    }
                }
            }

            string strBlockListUpdateIntervalHours = request.QueryString["blockListUpdateIntervalHours"];
            if (!string.IsNullOrEmpty(strBlockListUpdateIntervalHours))
            {
                int blockListUpdateIntervalHours = int.Parse(strBlockListUpdateIntervalHours);

                if ((blockListUpdateIntervalHours < 1) || (blockListUpdateIntervalHours > 168))
                    throw new ArgumentOutOfRangeException("Parameter `blockListUpdateIntervalHours` must be between 1 hour and 168 hours (7 days).");

                _blockListUpdateIntervalHours = blockListUpdateIntervalHours;
            }

            SaveConfigFile();
            _log.Save();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DNS Settings were updated {dnsServerDomain: " + _dnsServer.ServerDomain + "; dnsServerLocalEndPoints: " + strDnsServerLocalEndPoints + "; webServiceLocalAddresses: " + strWebServiceLocalAddresses + "; webServiceHttpPort: " + _webServiceHttpPort + "; webServiceEnableTls: " + strWebServiceEnableTls + "; webServiceHttpToTlsRedirect: " + strWebServiceHttpToTlsRedirect + "; webServiceTlsPort: " + strWebServiceTlsPort + "; webServiceTlsCertificatePath: " + strWebServiceTlsCertificatePath + "; enableDnsOverHttp: " + _dnsServer.EnableDnsOverHttp + "; enableDnsOverTls: " + _dnsServer.EnableDnsOverTls + "; enableDnsOverHttps: " + _dnsServer.EnableDnsOverHttps + "; dnsTlsCertificatePath: " + _dnsTlsCertificatePath + "; preferIPv6: " + _dnsServer.PreferIPv6 + "; enableLogging: " + strEnableLogging + "; logQueries: " + (_dnsServer.QueryLogManager != null) + "; useLocalTime: " + strUseLocalTime + "; logFolder: " + strLogFolder + "; maxLogFileDays: " + strMaxLogFileDays + "; allowRecursion: " + _dnsServer.AllowRecursion + "; allowRecursionOnlyForPrivateNetworks: " + _dnsServer.AllowRecursionOnlyForPrivateNetworks + "; randomizeName: " + strRandomizeName + "; serveStale: " + strServeStale + "; serveStaleTtl: " + strServeStaleTtl + "; cachePrefetchEligibility: " + strCachePrefetchEligibility + "; cachePrefetchTrigger: " + strCachePrefetchTrigger + "; cachePrefetchSampleIntervalInMinutes: " + strCachePrefetchSampleIntervalInMinutes + "; cachePrefetchSampleEligibilityHitsPerHour: " + strCachePrefetchSampleEligibilityHitsPerHour + "; proxyType: " + strProxyType + "; forwarders: " + strForwarders + "; forwarderProtocol: " + strForwarderProtocol + "; blockListUrl: " + strBlockListUrls + "; blockListUpdateIntervalHours: " + strBlockListUpdateIntervalHours + ";}");

            if ((_webServiceTlsCertificatePath == null) && (_dnsTlsCertificatePath == null))
                StopTlsCertificateUpdateTimer();

            GetDnsSettings(jsonWriter);

            RestartService(restartDnsService, restartWebService);
        }

        private void RestartService(bool restartDnsService, bool restartWebService)
        {
            if (restartDnsService)
            {
                _ = Task.Run(delegate ()
                {
                    _log.Write("Attempting to restart DNS service.");

                    try
                    {
                        _dnsServer.Stop();
                        _dnsServer.Start();

                        _log.Write("DNS service was restarted successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write("Failed to restart DNS service.");
                        _log.Write(ex);
                    }
                });
            }

            if (restartWebService)
            {
                _ = Task.Run(async delegate ()
                {
                    await Task.Delay(2000); //wait for this HTTP response to be delivered before stopping web server

                    _log.Write("Attempting to restart web service.");

                    try
                    {
                        StopWebService();
                        StartWebService();

                        _log.Write("Web service was restarted successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write("Failed to restart web service.");
                        _log.Write(ex);
                    }
                });
            }
        }

        private async Task BackupSettingsAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            bool blockLists = false;
            bool logs = false;
            bool scopes = false;
            bool stats = false;
            bool zones = false;
            bool allowedZones = false;
            bool blockedZones = false;
            bool dnsSettings = false;
            bool logSettings = false;

            string strBlockLists = request.QueryString["blockLists"];
            if (!string.IsNullOrEmpty(strBlockLists))
                blockLists = bool.Parse(strBlockLists);

            string strLogs = request.QueryString["logs"];
            if (!string.IsNullOrEmpty(strLogs))
                logs = bool.Parse(strLogs);

            string strScopes = request.QueryString["scopes"];
            if (!string.IsNullOrEmpty(strScopes))
                scopes = bool.Parse(strScopes);

            string strStats = request.QueryString["stats"];
            if (!string.IsNullOrEmpty(strStats))
                stats = bool.Parse(strStats);

            string strZones = request.QueryString["zones"];
            if (!string.IsNullOrEmpty(strZones))
                zones = bool.Parse(strZones);

            string strAllowedZones = request.QueryString["allowedZones"];
            if (!string.IsNullOrEmpty(strAllowedZones))
                allowedZones = bool.Parse(strAllowedZones);

            string strBlockedZones = request.QueryString["blockedZones"];
            if (!string.IsNullOrEmpty(strBlockedZones))
                blockedZones = bool.Parse(strBlockedZones);

            string strDnsSettings = request.QueryString["dnsSettings"];
            if (!string.IsNullOrEmpty(strDnsSettings))
                dnsSettings = bool.Parse(strDnsSettings);

            string strLogSettings = request.QueryString["logSettings"];
            if (!string.IsNullOrEmpty(strLogSettings))
                logSettings = bool.Parse(strLogSettings);

            string tmpFile = Path.GetTempFileName();
            try
            {
                using (FileStream backupZipStream = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //create backup zip
                    using (ZipArchive backupZip = new ZipArchive(backupZipStream, ZipArchiveMode.Create, true, Encoding.UTF8))
                    {
                        if (blockLists)
                        {
                            string[] blockListFiles = Directory.GetFiles(Path.Combine(_configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);
                            foreach (string blockListFile in blockListFiles)
                            {
                                string entryName = "blocklists/" + Path.GetFileName(blockListFile);
                                backupZip.CreateEntryFromFile(blockListFile, entryName);
                            }
                        }

                        if (logs)
                        {
                            string[] logFiles = Directory.GetFiles(_log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);
                            foreach (string logFile in logFiles)
                            {
                                string entryName = "logs/" + Path.GetFileName(logFile);

                                if (logFile.Equals(_log.CurrentLogFile, StringComparison.OrdinalIgnoreCase))
                                {
                                    using (FileStream fS = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                                    {
                                        ZipArchiveEntry entry = backupZip.CreateEntry(entryName);

                                        using (Stream s = entry.Open())
                                        {
                                            await fS.CopyToAsync(s);
                                        }
                                    }
                                }
                                else
                                {
                                    backupZip.CreateEntryFromFile(logFile, entryName);
                                }
                            }
                        }

                        if (scopes)
                        {
                            string[] scopFiles = Directory.GetFiles(Path.Combine(_configFolder, "scopes"), "*.scope", SearchOption.TopDirectoryOnly);
                            foreach (string scopFile in scopFiles)
                            {
                                string entryName = "scopes/" + Path.GetFileName(scopFile);
                                backupZip.CreateEntryFromFile(scopFile, entryName);
                            }
                        }

                        if (stats)
                        {
                            string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);
                            foreach (string hourlyStatsFile in hourlyStatsFiles)
                            {
                                string entryName = "stats/" + Path.GetFileName(hourlyStatsFile);
                                backupZip.CreateEntryFromFile(hourlyStatsFile, entryName);
                            }

                            string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);
                            foreach (string dailyStatsFile in dailyStatsFiles)
                            {
                                string entryName = "stats/" + Path.GetFileName(dailyStatsFile);
                                backupZip.CreateEntryFromFile(dailyStatsFile, entryName);
                            }
                        }

                        if (zones)
                        {
                            string[] zoneFiles = Directory.GetFiles(Path.Combine(_configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);
                            foreach (string zoneFile in zoneFiles)
                            {
                                string entryName = "zones/" + Path.GetFileName(zoneFile);
                                backupZip.CreateEntryFromFile(zoneFile, entryName);
                            }
                        }

                        if (allowedZones)
                        {
                            string allowedZonesFile = Path.Combine(_configFolder, "allowed.config");

                            if (File.Exists(allowedZonesFile))
                                backupZip.CreateEntryFromFile(allowedZonesFile, "allowed.config");
                        }

                        if (blockedZones)
                        {
                            string blockedZonesFile = Path.Combine(_configFolder, "blocked.config");

                            if (File.Exists(blockedZonesFile))
                                backupZip.CreateEntryFromFile(blockedZonesFile, "blocked.config");
                        }

                        if (dnsSettings)
                        {
                            string dnsSettingsFile = Path.Combine(_configFolder, "dns.config");

                            if (File.Exists(dnsSettingsFile))
                                backupZip.CreateEntryFromFile(dnsSettingsFile, "dns.config");
                        }

                        if (logSettings)
                        {
                            string logSettingsFile = Path.Combine(_configFolder, "log.config");

                            if (File.Exists(logSettingsFile))
                                backupZip.CreateEntryFromFile(logSettingsFile, "log.config");
                        }
                    }

                    //send zip file
                    backupZipStream.Position = 0;

                    response.ContentType = "application/zip";
                    response.ContentLength64 = backupZipStream.Length;
                    response.AddHeader("Content-Disposition", "attachment;filename=DnsServerBackup.zip");

                    using (Stream output = response.OutputStream)
                    {
                        await backupZipStream.CopyToAsync(output);
                    }
                }
            }
            finally
            {
                try
                {
                    File.Delete(tmpFile);
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Settings backup zip file was exported.");
        }

        private async Task RestoreSettingsAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            bool blockLists = false;
            bool logs = false;
            bool scopes = false;
            bool stats = false;
            bool zones = false;
            bool allowedZones = false;
            bool blockedZones = false;
            bool dnsSettings = false;
            bool logSettings = false;

            string strBlockLists = request.QueryString["blockLists"];
            if (!string.IsNullOrEmpty(strBlockLists))
                blockLists = bool.Parse(strBlockLists);

            string strLogs = request.QueryString["logs"];
            if (!string.IsNullOrEmpty(strLogs))
                logs = bool.Parse(strLogs);

            string strScopes = request.QueryString["scopes"];
            if (!string.IsNullOrEmpty(strScopes))
                scopes = bool.Parse(strScopes);

            string strStats = request.QueryString["stats"];
            if (!string.IsNullOrEmpty(strStats))
                stats = bool.Parse(strStats);

            string strZones = request.QueryString["zones"];
            if (!string.IsNullOrEmpty(strZones))
                zones = bool.Parse(strZones);

            string strAllowedZones = request.QueryString["allowedZones"];
            if (!string.IsNullOrEmpty(strAllowedZones))
                allowedZones = bool.Parse(strAllowedZones);

            string strBlockedZones = request.QueryString["blockedZones"];
            if (!string.IsNullOrEmpty(strBlockedZones))
                blockedZones = bool.Parse(strBlockedZones);

            string strDnsSettings = request.QueryString["dnsSettings"];
            if (!string.IsNullOrEmpty(strDnsSettings))
                dnsSettings = bool.Parse(strDnsSettings);

            string strLogSettings = request.QueryString["logSettings"];
            if (!string.IsNullOrEmpty(strLogSettings))
                logSettings = bool.Parse(strLogSettings);

            #region skip to content

            int crlfCount = 0;
            int byteRead;

            while (crlfCount != 4)
            {
                byteRead = request.InputStream.ReadByte();
                switch (byteRead)
                {
                    case -1:
                        throw new EndOfStreamException();

                    case 13: //CR
                    case 10: //LF
                        crlfCount++;
                        break;

                    default:
                        crlfCount = 0;
                        break;
                }
            }

            #endregion

            //write to temp file
            string tmpFile = Path.GetTempFileName();
            try
            {
                using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    await request.InputStream.CopyToAsync(fS);

                    fS.Position = 0;
                    using (ZipArchive backupZip = new ZipArchive(fS, ZipArchiveMode.Read, false, Encoding.UTF8))
                    {
                        if (logSettings || logs)
                        {
                            //stop logging
                            _log.StopLogging();
                        }

                        try
                        {
                            if (logSettings)
                            {
                                ZipArchiveEntry entry = backupZip.GetEntry("log.config");
                                if (entry != null)
                                    entry.ExtractToFile(Path.Combine(_configFolder, entry.Name), true);

                                //reload config
                                _log.LoadConfig();
                            }

                            if (logs)
                            {
                                //delete existing log files
                                string[] logFiles = Directory.GetFiles(_log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);
                                foreach (string logFile in logFiles)
                                {
                                    File.Delete(logFile);
                                }

                                //extract log files from backup
                                foreach (ZipArchiveEntry entry in backupZip.Entries)
                                {
                                    if (entry.FullName.StartsWith("logs/"))
                                        entry.ExtractToFile(Path.Combine(_log.LogFolderAbsolutePath, entry.Name), true);
                                }
                            }
                        }
                        finally
                        {
                            if (logSettings || logs)
                            {
                                //start logging
                                if (_log.EnableLogging)
                                    _log.StartLogging();
                            }
                        }

                        if (blockLists)
                        {
                            //delete existing block list files
                            string[] blockListFiles = Directory.GetFiles(Path.Combine(_configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);
                            foreach (string blockListFile in blockListFiles)
                            {
                                File.Delete(blockListFile);
                            }

                            //extract block list files from backup
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (entry.FullName.StartsWith("blocklists/"))
                                    entry.ExtractToFile(Path.Combine(_configFolder, "blocklists", entry.Name), true);
                            }
                        }

                        if (scopes)
                        {
                            //stop dhcp server
                            _dhcpServer.Stop();

                            try
                            {
                                //delete existing scope files
                                string[] scopeFiles = Directory.GetFiles(Path.Combine(_configFolder, "scopes"), "*.scope", SearchOption.TopDirectoryOnly);
                                foreach (string scopeFile in scopeFiles)
                                {
                                    File.Delete(scopeFile);
                                }

                                //extract scope files from backup
                                foreach (ZipArchiveEntry entry in backupZip.Entries)
                                {
                                    if (entry.FullName.StartsWith("scopes/"))
                                        entry.ExtractToFile(Path.Combine(_configFolder, "scopes", entry.Name), true);
                                }
                            }
                            finally
                            {
                                //start dhcp server
                                _dhcpServer.Start();
                            }
                        }

                        if (stats)
                        {
                            //delete existing stats files
                            string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);
                            foreach (string hourlyStatsFile in hourlyStatsFiles)
                            {
                                File.Delete(hourlyStatsFile);
                            }

                            string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);
                            foreach (string dailyStatsFile in dailyStatsFiles)
                            {
                                File.Delete(dailyStatsFile);
                            }

                            //extract stats files from backup
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (entry.FullName.StartsWith("stats/"))
                                    entry.ExtractToFile(Path.Combine(_configFolder, "stats", entry.Name), true);
                            }

                            //reload stats
                            _dnsServer.StatsManager.ReloadStats();
                        }

                        if (zones)
                        {
                            //delete existing zone files
                            string[] zoneFiles = Directory.GetFiles(Path.Combine(_configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);
                            foreach (string zoneFile in zoneFiles)
                            {
                                File.Delete(zoneFile);
                            }

                            //extract zone files from backup
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (entry.FullName.StartsWith("zones/"))
                                    entry.ExtractToFile(Path.Combine(_configFolder, "zones", entry.Name), true);
                            }

                            //reload zones
                            _dnsServer.AuthZoneManager.LoadAllZoneFiles();
                        }

                        if (allowedZones)
                        {
                            ZipArchiveEntry entry = backupZip.GetEntry("allowed.config");
                            if (entry != null)
                                entry.ExtractToFile(Path.Combine(_configFolder, entry.Name), true);

                            //reload
                            _dnsServer.AllowedZoneManager.LoadAllowedZoneFile();
                        }

                        if (blockedZones)
                        {
                            ZipArchiveEntry entry = backupZip.GetEntry("blocked.config");
                            if (entry != null)
                                entry.ExtractToFile(Path.Combine(_configFolder, entry.Name), true);

                            //reload
                            _dnsServer.BlockedZoneManager.LoadBlockedZoneFile();
                        }

                        if (dnsSettings)
                        {
                            ZipArchiveEntry entry = backupZip.GetEntry("dns.config");
                            if (entry != null)
                                entry.ExtractToFile(Path.Combine(_configFolder, entry.Name), true);

                            //reload settings and block list zone
                            LoadConfigFile();
                            _dnsServer.BlockListZoneManager.LoadBlockLists();
                        }

                        _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Settings backup zip file was restored.");
                    }
                }
            }
            finally
            {
                try
                {
                    File.Delete(tmpFile);
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            if (dnsSettings)
                RestartService(true, true);

            GetDnsSettings(jsonWriter);
        }

        private void ForceUpdateBlockLists(HttpListenerRequest request)
        {
            ForceUpdateBlockLists();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Block list update was triggered.");
        }

        private async Task GetStats(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                strType = "lastHour";

            Dictionary<string, List<KeyValuePair<string, int>>> data;

            switch (strType)
            {
                case "lastHour":
                    data = _dnsServer.StatsManager.GetLastHourStats();
                    break;

                case "lastDay":
                    data = _dnsServer.StatsManager.GetLastDayStats();
                    break;

                case "lastWeek":
                    data = _dnsServer.StatsManager.GetLastWeekStats();
                    break;

                case "lastMonth":
                    data = _dnsServer.StatsManager.GetLastMonthStats();
                    break;

                case "lastYear":
                    data = _dnsServer.StatsManager.GetLastYearStats();
                    break;

                default:
                    throw new WebServiceException("Unknown stats type requested: " + strType);
            }

            //stats
            {
                List<KeyValuePair<string, int>> stats = data["stats"];

                jsonWriter.WritePropertyName("stats");
                jsonWriter.WriteStartObject();

                foreach (KeyValuePair<string, int> item in stats)
                {
                    jsonWriter.WritePropertyName(item.Key);
                    jsonWriter.WriteValue(item.Value);
                }

                jsonWriter.WritePropertyName("zones");
                jsonWriter.WriteValue(_dnsServer.AuthZoneManager.TotalZones);

                jsonWriter.WritePropertyName("allowedZones");
                jsonWriter.WriteValue(_dnsServer.AllowedZoneManager.TotalZonesAllowed);

                jsonWriter.WritePropertyName("blockedZones");
                jsonWriter.WriteValue(_dnsServer.BlockedZoneManager.TotalZonesBlocked);

                jsonWriter.WritePropertyName("blockListZones");
                jsonWriter.WriteValue(_dnsServer.BlockListZoneManager.TotalZonesBlocked);

                jsonWriter.WriteEndObject();
            }

            //main chart
            {
                jsonWriter.WritePropertyName("mainChartData");
                jsonWriter.WriteStartObject();

                //label
                {
                    List<KeyValuePair<string, int>> statsPerInterval = data["totalQueriesPerInterval"];

                    jsonWriter.WritePropertyName("labels");
                    jsonWriter.WriteStartArray();

                    foreach (KeyValuePair<string, int> item in statsPerInterval)
                        jsonWriter.WriteValue(item.Key);

                    jsonWriter.WriteEndArray();
                }

                //datasets
                {
                    jsonWriter.WritePropertyName("datasets");
                    jsonWriter.WriteStartArray();

                    WriteChartDataSet(jsonWriter, "Total", "rgba(102, 153, 255, 0.1)", "rgb(102, 153, 255)", data["totalQueriesPerInterval"]);
                    WriteChartDataSet(jsonWriter, "No Error", "rgba(92, 184, 92, 0.1)", "rgb(92, 184, 92)", data["totalNoErrorPerInterval"]);
                    WriteChartDataSet(jsonWriter, "Server Failure", "rgba(217, 83, 79, 0.1)", "rgb(217, 83, 79)", data["totalServerFailurePerInterval"]);
                    WriteChartDataSet(jsonWriter, "Name Error", "rgba(7, 7, 7, 0.1)", "rgb(7, 7, 7)", data["totalNameErrorPerInterval"]);
                    WriteChartDataSet(jsonWriter, "Refused", "rgba(91, 192, 222, 0.1)", "rgb(91, 192, 222)", data["totalRefusedPerInterval"]);

                    WriteChartDataSet(jsonWriter, "Authoritative", "rgba(150, 150, 0, 0.1)", "rgb(150, 150, 0)", data["totalAuthHitPerInterval"]);
                    WriteChartDataSet(jsonWriter, "Recursive", "rgba(23, 162, 184, 0.1)", "rgb(23, 162, 184)", data["totalRecursionsPerInterval"]);
                    WriteChartDataSet(jsonWriter, "Cached", "rgba(111, 84, 153, 0.1)", "rgb(111, 84, 153)", data["totalCacheHitPerInterval"]);
                    WriteChartDataSet(jsonWriter, "Blocked", "rgba(255, 165, 0, 0.1)", "rgb(255, 165, 0)", data["totalBlockedPerInterval"]);

                    WriteChartDataSet(jsonWriter, "Clients", "rgba(51, 122, 183, 0.1)", "rgb(51, 122, 183)", data["totalClientsPerInterval"]);

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteEndObject();
            }

            //query response chart
            {
                jsonWriter.WritePropertyName("queryResponseChartData");
                jsonWriter.WriteStartObject();

                List<KeyValuePair<string, int>> stats = data["stats"];

                //labels
                {
                    jsonWriter.WritePropertyName("labels");
                    jsonWriter.WriteStartArray();

                    foreach (KeyValuePair<string, int> item in stats)
                    {
                        switch (item.Key)
                        {
                            case "totalAuthoritative":
                                jsonWriter.WriteValue("Authoritative");
                                break;

                            case "totalRecursive":
                                jsonWriter.WriteValue("Recursive");
                                break;

                            case "totalCached":
                                jsonWriter.WriteValue("Cached");
                                break;

                            case "totalBlocked":
                                jsonWriter.WriteValue("Blocked");
                                break;
                        }
                    }

                    jsonWriter.WriteEndArray();
                }

                //datasets
                {
                    jsonWriter.WritePropertyName("datasets");
                    jsonWriter.WriteStartArray();

                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("data");
                    jsonWriter.WriteStartArray();

                    foreach (KeyValuePair<string, int> item in stats)
                    {
                        switch (item.Key)
                        {
                            case "totalAuthoritative":
                            case "totalRecursive":
                            case "totalCached":
                            case "totalBlocked":
                                jsonWriter.WriteValue(item.Value);
                                break;
                        }
                    }

                    jsonWriter.WriteEndArray();

                    jsonWriter.WritePropertyName("backgroundColor");
                    jsonWriter.WriteStartArray();
                    jsonWriter.WriteValue("rgba(150, 150, 0, 0.5)");
                    jsonWriter.WriteValue("rgba(23, 162, 184, 0.5)");
                    jsonWriter.WriteValue("rgba(111, 84, 153, 0.5)");
                    jsonWriter.WriteValue("rgba(255, 165, 0, 0.5)");
                    jsonWriter.WriteEndArray();

                    jsonWriter.WriteEndObject();

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteEndObject();
            }

            //query type chart
            {
                jsonWriter.WritePropertyName("queryTypeChartData");
                jsonWriter.WriteStartObject();

                List<KeyValuePair<string, int>> queryTypes = data["queryTypes"];

                //labels
                {
                    jsonWriter.WritePropertyName("labels");
                    jsonWriter.WriteStartArray();

                    foreach (KeyValuePair<string, int> item in queryTypes)
                        jsonWriter.WriteValue(item.Key);

                    jsonWriter.WriteEndArray();
                }

                //datasets
                {
                    jsonWriter.WritePropertyName("datasets");
                    jsonWriter.WriteStartArray();

                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("data");
                    jsonWriter.WriteStartArray();
                    foreach (KeyValuePair<string, int> item in queryTypes)
                        jsonWriter.WriteValue(item.Value);
                    jsonWriter.WriteEndArray();

                    jsonWriter.WritePropertyName("backgroundColor");
                    jsonWriter.WriteStartArray();
                    jsonWriter.WriteValue("rgba(102, 153, 255, 0.5)");
                    jsonWriter.WriteValue("rgba(92, 184, 92, 0.5)");
                    jsonWriter.WriteValue("rgba(91, 192, 222, 0.5)");
                    jsonWriter.WriteValue("rgba(255, 165, 0, 0.5)");
                    jsonWriter.WriteValue("rgba(51, 122, 183, 0.5)");
                    jsonWriter.WriteEndArray();

                    jsonWriter.WriteEndObject();

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteEndObject();
            }

            //top clients
            {
                List<KeyValuePair<string, int>> topClients = data["topClients"];

                IDictionary<string, string> clientIpMap = await ResolvePtrTopClientsAsync(topClients);

                jsonWriter.WritePropertyName("topClients");
                jsonWriter.WriteStartArray();

                foreach (KeyValuePair<string, int> item in topClients)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("name");
                    jsonWriter.WriteValue(item.Key);

                    if (clientIpMap.TryGetValue(item.Key, out string clientDomain) && !string.IsNullOrEmpty(clientDomain))
                    {
                        jsonWriter.WritePropertyName("domain");
                        jsonWriter.WriteValue(clientDomain);
                    }

                    jsonWriter.WritePropertyName("hits");
                    jsonWriter.WriteValue(item.Value);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            //top domains
            {
                List<KeyValuePair<string, int>> topDomains = data["topDomains"];

                jsonWriter.WritePropertyName("topDomains");
                jsonWriter.WriteStartArray();

                foreach (KeyValuePair<string, int> item in topDomains)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("name");
                    jsonWriter.WriteValue(item.Key);

                    jsonWriter.WritePropertyName("hits");
                    jsonWriter.WriteValue(item.Value);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            //top blocked domains
            {
                List<KeyValuePair<string, int>> topBlockedDomains = data["topBlockedDomains"];

                jsonWriter.WritePropertyName("topBlockedDomains");
                jsonWriter.WriteStartArray();

                foreach (KeyValuePair<string, int> item in topBlockedDomains)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("name");
                    jsonWriter.WriteValue(item.Key);

                    jsonWriter.WritePropertyName("hits");
                    jsonWriter.WriteValue(item.Value);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }
        }

        private static void WriteChartDataSet(JsonTextWriter jsonWriter, string label, string backgroundColor, string borderColor, List<KeyValuePair<string, int>> statsPerInterval)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WritePropertyName("label");
            jsonWriter.WriteValue(label);

            jsonWriter.WritePropertyName("backgroundColor");
            jsonWriter.WriteValue(backgroundColor);

            jsonWriter.WritePropertyName("borderColor");
            jsonWriter.WriteValue(borderColor);

            jsonWriter.WritePropertyName("borderWidth");
            jsonWriter.WriteValue(2);

            jsonWriter.WritePropertyName("fill");
            jsonWriter.WriteValue(true);

            jsonWriter.WritePropertyName("data");
            jsonWriter.WriteStartArray();
            foreach (KeyValuePair<string, int> item in statsPerInterval)
                jsonWriter.WriteValue(item.Value);
            jsonWriter.WriteEndArray();

            jsonWriter.WriteEndObject();
        }

        private async Task GetTopStats(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                strType = "lastHour";

            string strStatsType = request.QueryString["statsType"];
            if (string.IsNullOrEmpty(strStatsType))
                throw new WebServiceException("Parameter 'statsType' missing.");

            string strLimit = request.QueryString["limit"];
            if (string.IsNullOrEmpty(strLimit))
                strLimit = "1000";

            TopStatsType statsType = (TopStatsType)Enum.Parse(typeof(TopStatsType), strStatsType, true);
            int limit = int.Parse(strLimit);

            List<KeyValuePair<string, int>> topStatsData;

            switch (strType)
            {
                case "lastHour":
                    topStatsData = _dnsServer.StatsManager.GetLastHourTopStats(statsType, limit);
                    break;

                case "lastDay":
                    topStatsData = _dnsServer.StatsManager.GetLastDayTopStats(statsType, limit);
                    break;

                case "lastWeek":
                    topStatsData = _dnsServer.StatsManager.GetLastWeekTopStats(statsType, limit);
                    break;

                case "lastMonth":
                    topStatsData = _dnsServer.StatsManager.GetLastMonthTopStats(statsType, limit);
                    break;

                case "lastYear":
                    topStatsData = _dnsServer.StatsManager.GetLastYearTopStats(statsType, limit);
                    break;

                default:
                    throw new WebServiceException("Unknown stats type requested: " + strType);
            }

            switch (statsType)
            {
                case TopStatsType.TopClients:
                    {
                        IDictionary<string, string> clientIpMap = await ResolvePtrTopClientsAsync(topStatsData);

                        jsonWriter.WritePropertyName("topClients");
                        jsonWriter.WriteStartArray();

                        foreach (KeyValuePair<string, int> item in topStatsData)
                        {
                            jsonWriter.WriteStartObject();

                            jsonWriter.WritePropertyName("name");
                            jsonWriter.WriteValue(item.Key);

                            if (clientIpMap.TryGetValue(item.Key, out string clientDomain) && !string.IsNullOrEmpty(clientDomain))
                            {
                                jsonWriter.WritePropertyName("domain");
                                jsonWriter.WriteValue(clientDomain);
                            }

                            jsonWriter.WritePropertyName("hits");
                            jsonWriter.WriteValue(item.Value);

                            jsonWriter.WriteEndObject();
                        }

                        jsonWriter.WriteEndArray();
                    }
                    break;

                case TopStatsType.TopDomains:
                    {
                        jsonWriter.WritePropertyName("topDomains");
                        jsonWriter.WriteStartArray();

                        foreach (KeyValuePair<string, int> item in topStatsData)
                        {
                            jsonWriter.WriteStartObject();

                            jsonWriter.WritePropertyName("name");
                            jsonWriter.WriteValue(item.Key);

                            jsonWriter.WritePropertyName("hits");
                            jsonWriter.WriteValue(item.Value);

                            jsonWriter.WriteEndObject();
                        }

                        jsonWriter.WriteEndArray();
                    }
                    break;

                case TopStatsType.TopBlockedDomains:
                    {
                        jsonWriter.WritePropertyName("topBlockedDomains");
                        jsonWriter.WriteStartArray();

                        foreach (KeyValuePair<string, int> item in topStatsData)
                        {
                            jsonWriter.WriteStartObject();

                            jsonWriter.WritePropertyName("name");
                            jsonWriter.WriteValue(item.Key);

                            jsonWriter.WritePropertyName("hits");
                            jsonWriter.WriteValue(item.Value);

                            jsonWriter.WriteEndObject();
                        }

                        jsonWriter.WriteEndArray();
                    }
                    break;

                default:
                    throw new NotSupportedException();
            }
        }

        private async Task<IDictionary<string, string>> ResolvePtrTopClientsAsync(List<KeyValuePair<string, int>> topClients)
        {
            IDictionary<string, string> dhcpClientIpMap = _dhcpServer.GetAddressClientMap();

            async Task<KeyValuePair<string, string>> ResolvePtrAsync(string ip)
            {
                if (dhcpClientIpMap.TryGetValue(ip, out string dhcpDomain))
                    return new KeyValuePair<string, string>(ip, dhcpDomain);

                IPAddress address = IPAddress.Parse(ip);

                if (IPAddress.IsLoopback(address))
                    return new KeyValuePair<string, string>(ip, "localhost");

                DnsDatagram ptrResponse = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(address, DnsClass.IN), 500);
                if ((ptrResponse != null) && (ptrResponse.Answer.Count > 0))
                {
                    IReadOnlyList<string> ptrDomains = DnsClient.ParseResponsePTR(ptrResponse);
                    if (ptrDomains != null)
                        return new KeyValuePair<string, string>(ip, ptrDomains[0]);
                }

                return new KeyValuePair<string, string>(ip, null);
            }

            List<Task<KeyValuePair<string, string>>> resolverTasks = new List<Task<KeyValuePair<string, string>>>();

            foreach (KeyValuePair<string, int> item in topClients)
            {
                resolverTasks.Add(ResolvePtrAsync(item.Key));
            }

            Dictionary<string, string> result = new Dictionary<string, string>();

            foreach (Task<KeyValuePair<string, string>> resolverTask in resolverTasks)
            {
                try
                {
                    KeyValuePair<string, string> ptrResult = await resolverTask;
                    result[ptrResult.Key] = ptrResult.Value;
                }
                catch
                { }
            }

            return result;
        }

        private void FlushCache(HttpListenerRequest request)
        {
            _dnsServer.CacheZoneManager.Flush();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Cache was flushed.");
        }

        private void ListCachedZones(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (domain == null)
                domain = "";

            string direction = request.QueryString["direction"];

            List<string> subZones;
            List<DnsResourceRecord> records;

            while (true)
            {
                subZones = _dnsServer.CacheZoneManager.ListSubDomains(domain);
                records = _dnsServer.CacheZoneManager.ListAllRecords(domain);

                if (records.Count > 0)
                    break;

                if (subZones.Count != 1)
                    break;

                if (direction == "up")
                {
                    if (domain.Length == 0)
                        break;

                    int i = domain.IndexOf('.');
                    if (i < 0)
                        domain = "";
                    else
                        domain = domain.Substring(i + 1);
                }
                else if (domain.Length == 0)
                {
                    domain = subZones[0];
                }
                else
                {
                    domain = subZones[0] + "." + domain;
                }
            }

            subZones.Sort();

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(domain);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain.Length != 0)
                domain = "." + domain;

            foreach (string subZone in subZones)
                jsonWriter.WriteValue(subZone + domain);

            jsonWriter.WriteEndArray();

            WriteRecordsAsJson(records, jsonWriter, false);
        }

        private void DeleteCachedZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (_dnsServer.CacheZoneManager.DeleteZone(domain))
                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Cached zone was deleted: " + domain);
        }

        private void ListAllowedZones(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (domain == null)
                domain = "";

            string direction = request.QueryString["direction"];

            List<string> subZones;
            IReadOnlyList<DnsResourceRecord> records;

            while (true)
            {
                subZones = _dnsServer.AllowedZoneManager.ListSubDomains(domain);
                records = _dnsServer.AllowedZoneManager.QueryRecords(domain, DnsResourceRecordType.ANY);

                if (records.Count > 0)
                    break;

                if (subZones.Count != 1)
                    break;

                if (direction == "up")
                {
                    if (domain.Length == 0)
                        break;

                    int i = domain.IndexOf('.');
                    if (i < 0)
                        domain = "";
                    else
                        domain = domain.Substring(i + 1);
                }
                else if (domain.Length == 0)
                {
                    domain = subZones[0];
                }
                else
                {
                    domain = subZones[0] + "." + domain;
                }
            }

            subZones.Sort();

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(domain);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain.Length != 0)
                domain = "." + domain;

            foreach (string subZone in subZones)
                jsonWriter.WriteValue(subZone + domain);

            jsonWriter.WriteEndArray();

            WriteRecordsAsJson(new List<DnsResourceRecord>(records), jsonWriter, false);
        }

        private void ImportAllowedZones(HttpListenerRequest request)
        {
            if (!request.ContentType.StartsWith("application/x-www-form-urlencoded"))
                throw new WebServiceException("Invalid content type. Expected application/x-www-form-urlencoded.");

            string formRequest;
            using (StreamReader sR = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                formRequest = sR.ReadToEnd();
            }

            string[] formParts = formRequest.Split('&');

            foreach (string formPart in formParts)
            {
                if (formPart.StartsWith("allowedZones="))
                {
                    string[] allowedZones = formPart.Substring(13).Split(',');
                    bool added = false;

                    foreach (string allowedZone in allowedZones)
                    {
                        if (_dnsServer.AllowedZoneManager.AllowZone(allowedZone))
                            added = true;
                    }

                    if (added)
                    {
                        _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Total " + allowedZones.Length + " zones were imported into allowed zone successfully.");
                        _dnsServer.AllowedZoneManager.SaveZoneFile();
                    }

                    return;
                }
            }

            throw new WebServiceException("Parameter 'allowedZones' missing.");
        }

        private void ExportAllowedZones(HttpListenerResponse response)
        {
            IReadOnlyList<AuthZoneInfo> zoneInfoList = _dnsServer.AllowedZoneManager.ListZones();

            response.ContentType = "text/plain";
            response.AddHeader("Content-Disposition", "attachment;filename=AllowedZones.txt");

            using (StreamWriter sW = new StreamWriter(new BufferedStream(response.OutputStream)))
            {
                foreach (AuthZoneInfo zoneInfo in zoneInfoList)
                    sW.WriteLine(zoneInfo.Name);
            }
        }

        private void DeleteAllowedZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (_dnsServer.AllowedZoneManager.DeleteZone(domain))
            {
                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Allowed zone was deleted: " + domain);
                _dnsServer.AllowedZoneManager.SaveZoneFile();
            }
        }

        private void AllowZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                domain = (new DnsQuestionRecord(ipAddress, DnsClass.IN)).Name;

            if (_dnsServer.AllowedZoneManager.AllowZone(domain))
            {
                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Zone was allowed: " + domain);
                _dnsServer.AllowedZoneManager.SaveZoneFile();
            }
        }

        private void ListBlockedZones(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (domain == null)
                domain = "";

            string direction = request.QueryString["direction"];

            List<string> subZones;
            IReadOnlyList<DnsResourceRecord> records;

            while (true)
            {
                subZones = _dnsServer.BlockedZoneManager.ListSubDomains(domain);
                records = _dnsServer.BlockedZoneManager.QueryRecords(domain, DnsResourceRecordType.ANY);

                if (records.Count > 0)
                    break;

                if (subZones.Count != 1)
                    break;

                if (direction == "up")
                {
                    if (domain.Length == 0)
                        break;

                    int i = domain.IndexOf('.');
                    if (i < 0)
                        domain = "";
                    else
                        domain = domain.Substring(i + 1);
                }
                else if (domain.Length == 0)
                {
                    domain = subZones[0];
                }
                else
                {
                    domain = subZones[0] + "." + domain;
                }
            }

            subZones.Sort();

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(domain);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain.Length != 0)
                domain = "." + domain;

            foreach (string subZone in subZones)
                jsonWriter.WriteValue(subZone + domain);

            jsonWriter.WriteEndArray();

            WriteRecordsAsJson(new List<DnsResourceRecord>(records), jsonWriter, false);
        }

        private void ImportBlockedZones(HttpListenerRequest request)
        {
            if (!request.ContentType.StartsWith("application/x-www-form-urlencoded"))
                throw new WebServiceException("Invalid content type. Expected application/x-www-form-urlencoded.");

            string formRequest;
            using (StreamReader sR = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                formRequest = sR.ReadToEnd();
            }

            string[] formParts = formRequest.Split('&');

            foreach (string formPart in formParts)
            {
                if (formPart.StartsWith("blockedZones="))
                {
                    string[] blockedZones = formPart.Substring(13).Split(',');
                    bool added = false;

                    foreach (string blockedZone in blockedZones)
                    {
                        if (_dnsServer.BlockedZoneManager.BlockZone(blockedZone))
                            added = true;
                    }

                    if (added)
                    {
                        _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Total " + blockedZones.Length + " zones were imported into blocked zone successfully.");
                        _dnsServer.BlockedZoneManager.SaveZoneFile();
                    }

                    return;
                }
            }

            throw new WebServiceException("Parameter 'blockedZones' missing.");
        }

        private void ExportBlockedZones(HttpListenerResponse response)
        {
            IReadOnlyList<AuthZoneInfo> zoneInfoList = _dnsServer.BlockedZoneManager.ListZones();

            response.ContentType = "text/plain";
            response.AddHeader("Content-Disposition", "attachment;filename=BlockedZones.txt");

            using (StreamWriter sW = new StreamWriter(new BufferedStream(response.OutputStream)))
            {
                foreach (AuthZoneInfo zoneInfo in zoneInfoList)
                    sW.WriteLine(zoneInfo.Name);
            }
        }

        private void DeleteBlockedZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (_dnsServer.BlockedZoneManager.DeleteZone(domain))
            {
                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Blocked zone was deleted: " + domain);
                _dnsServer.BlockedZoneManager.SaveZoneFile();
            }
        }

        private void BlockZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                domain = (new DnsQuestionRecord(ipAddress, DnsClass.IN)).Name;

            if (_dnsServer.BlockedZoneManager.BlockZone(domain))
            {
                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Domain was added to blocked zone: " + domain);
                _dnsServer.BlockedZoneManager.SaveZoneFile();
            }
        }

        private void ListZones(JsonTextWriter jsonWriter)
        {
            List<AuthZoneInfo> zones = _dnsServer.AuthZoneManager.ListZones();

            zones.Sort();

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            foreach (AuthZoneInfo zone in zones)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("name");
                jsonWriter.WriteValue(zone.Name);

                jsonWriter.WritePropertyName("type");
                jsonWriter.WriteValue(zone.Type.ToString());

                switch (zone.Type)
                {
                    case AuthZoneType.Primary:
                        jsonWriter.WritePropertyName("internal");
                        jsonWriter.WriteValue(zone.Internal);
                        break;

                    case AuthZoneType.Secondary:
                    case AuthZoneType.Stub:
                        jsonWriter.WritePropertyName("expiry");
                        jsonWriter.WriteValue(zone.Expiry.ToLocalTime().ToString("dd MMM yyyy HH:mm:ss"));

                        jsonWriter.WritePropertyName("isExpired");
                        jsonWriter.WriteValue(zone.IsExpired);
                        break;
                }

                jsonWriter.WritePropertyName("disabled");
                jsonWriter.WriteValue(zone.Disabled);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        private async Task CreateZoneAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.Contains("*"))
                throw new WebServiceException("Domain name for a zone cannot contain wildcard character.");

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
            {
                domain = new DnsQuestionRecord(ipAddress, DnsClass.IN).Name.ToLower();
            }
            else if (domain.Contains("/"))
            {
                string[] parts = domain.Split('/');
                if ((parts.Length == 2) && IPAddress.TryParse(parts[0], out ipAddress) && int.TryParse(parts[1], out int subnetMaskWidth))
                    domain = Zone.GetReverseZone(ipAddress, subnetMaskWidth);
            }
            else if (domain.EndsWith("."))
            {
                domain = domain.Substring(0, domain.Length - 1);
            }

            AuthZoneType type = AuthZoneType.Primary;
            string strType = request.QueryString["type"];
            if (!string.IsNullOrEmpty(strType))
                type = (AuthZoneType)Enum.Parse(typeof(AuthZoneType), strType, true);

            switch (type)
            {
                case AuthZoneType.Primary:
                    if (_dnsServer.AuthZoneManager.CreatePrimaryZone(domain, _dnsServer.ServerDomain, false) == null)
                        throw new WebServiceException("Zone already exists: " + domain);

                    _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Authoritative primary zone was created: " + domain);
                    _dnsServer.AuthZoneManager.SaveZoneFile(domain);
                    break;

                case AuthZoneType.Secondary:
                    {
                        string strPrimaryNameServerAddresses = request.QueryString["primaryNameServerAddresses"];
                        if (string.IsNullOrEmpty(strPrimaryNameServerAddresses))
                            strPrimaryNameServerAddresses = null;

                        if (await _dnsServer.AuthZoneManager.CreateSecondaryZoneAsync(domain, strPrimaryNameServerAddresses) == null)
                            throw new WebServiceException("Zone already exists: " + domain);

                        _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Authoritative secondary zone was created: " + domain);
                        _dnsServer.AuthZoneManager.SaveZoneFile(domain);
                    }
                    break;

                case AuthZoneType.Stub:
                    {
                        string strPrimaryNameServerAddresses = request.QueryString["primaryNameServerAddresses"];
                        if (string.IsNullOrEmpty(strPrimaryNameServerAddresses))
                            strPrimaryNameServerAddresses = null;

                        if (await _dnsServer.AuthZoneManager.CreateStubZoneAsync(domain, strPrimaryNameServerAddresses) == null)
                            throw new WebServiceException("Zone already exists: " + domain);

                        _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Stub zone was created: " + domain);
                        _dnsServer.AuthZoneManager.SaveZoneFile(domain);
                    }
                    break;

                case AuthZoneType.Forwarder:
                    {
                        DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;
                        string strForwarderProtocol = request.QueryString["protocol"];
                        if (!string.IsNullOrEmpty(strForwarderProtocol))
                            forwarderProtocol = (DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), strForwarderProtocol, true);

                        string strForwarder = request.QueryString["forwarder"];
                        if (string.IsNullOrEmpty(strForwarder))
                            throw new WebServiceException("Parameter 'forwarder' missing.");

                        if (_dnsServer.AuthZoneManager.CreateForwarderZone(domain, forwarderProtocol, strForwarder) == null)
                            throw new WebServiceException("Zone already exists: " + domain);

                        _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Forwarder zone was created: " + domain);
                        _dnsServer.AuthZoneManager.SaveZoneFile(domain);
                    }
                    break;

                default:
                    throw new NotSupportedException("Zone type not supported.");
            }

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
            _dnsServer.CacheZoneManager.DeleteZone(domain);

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(string.IsNullOrEmpty(domain) ? "." : domain);
        }

        private void DeleteZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsServer.AuthZoneManager.DeleteZone(domain))
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] " + zoneInfo.Type.ToString() + " zone was deleted: " + domain);

            _dnsServer.AuthZoneManager.DeleteZoneFile(zoneInfo.Name);
        }

        private void EnableZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            zoneInfo.Disabled = false;

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] " + zoneInfo.Type.ToString() + " zone was enabled: " + zoneInfo.Name);

            _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
            _dnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);
        }

        private void DisableZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            zoneInfo.Disabled = true;

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] " + zoneInfo.Type.ToString() + " zone was disabled: " + zoneInfo.Name);

            _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        private void AddRecord(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new WebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

            string value = request.QueryString["value"];
            if (string.IsNullOrEmpty(value))
                throw new WebServiceException("Parameter 'value' missing.");

            uint ttl;
            string strTtl = request.QueryString["ttl"];
            if (string.IsNullOrEmpty(strTtl))
                ttl = 3600;
            else
                ttl = uint.Parse(strTtl);

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    IPAddress ipAddress = IPAddress.Parse(value);

                    bool ptr = false;
                    string strPtr = request.QueryString["ptr"];
                    if (!string.IsNullOrEmpty(strPtr))
                        ptr = bool.Parse(strPtr);

                    if (ptr)
                    {
                        string ptrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);

                        AuthZoneInfo reverseZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(ptrDomain);
                        if (reverseZoneInfo == null)
                        {
                            bool createPtrZone = false;
                            string strCreatePtrZone = request.QueryString["createPtrZone"];
                            if (!string.IsNullOrEmpty(strCreatePtrZone))
                                createPtrZone = bool.Parse(strCreatePtrZone);

                            if (!createPtrZone)
                                throw new DnsServerException("No reverse zone available to add PTR record.");

                            string ptrZone = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 24 : 64);

                            reverseZoneInfo = _dnsServer.AuthZoneManager.CreatePrimaryZone(ptrZone, _dnsServer.ServerDomain, false);
                            if (reverseZoneInfo == null)
                                throw new DnsServerException("Failed to create reverse zone to add PTR record: " + ptrZone);
                        }

                        if (reverseZoneInfo.Internal)
                            throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is an internal zone.");

                        if (reverseZoneInfo.Type != AuthZoneType.Primary)
                            throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is not a primary zone.");

                        _dnsServer.AuthZoneManager.SetRecords(ptrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecord[] { new DnsPTRRecord(domain) });
                        _dnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                    }

                    if (type == DnsResourceRecordType.A)
                        _dnsServer.AuthZoneManager.AddRecord(domain, type, ttl, new DnsARecord(ipAddress));
                    else
                        _dnsServer.AuthZoneManager.AddRecord(domain, type, ttl, new DnsAAAARecord(ipAddress));

                    break;

                case DnsResourceRecordType.MX:
                    {
                        string preference = request.QueryString["preference"];
                        if (string.IsNullOrEmpty(preference))
                            throw new WebServiceException("Parameter 'preference' missing.");

                        _dnsServer.AuthZoneManager.AddRecord(domain, type, ttl, new DnsMXRecord(ushort.Parse(preference), value));
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    _dnsServer.AuthZoneManager.AddRecord(domain, type, ttl, new DnsTXTRecord(value));
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string glueAddresses = request.QueryString["glue"];
                        if (string.IsNullOrEmpty(glueAddresses))
                            glueAddresses = null;

                        DnsResourceRecord nsRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsNSRecord(value));

                        if (glueAddresses != null)
                            nsRecord.SetGlueRecords(glueAddresses);

                        _dnsServer.AuthZoneManager.AddRecord(nsRecord);
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    _dnsServer.AuthZoneManager.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsPTRRecord(value) });
                    break;

                case DnsResourceRecordType.CNAME:
                    _dnsServer.AuthZoneManager.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsCNAMERecord(value) });
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        string priority = request.QueryString["priority"];
                        if (string.IsNullOrEmpty(priority))
                            throw new WebServiceException("Parameter 'priority' missing.");

                        string weight = request.QueryString["weight"];
                        if (string.IsNullOrEmpty(weight))
                            throw new WebServiceException("Parameter 'weight' missing.");

                        string port = request.QueryString["port"];
                        if (string.IsNullOrEmpty(port))
                            throw new WebServiceException("Parameter 'port' missing.");

                        _dnsServer.AuthZoneManager.AddRecord(domain, type, ttl, new DnsSRVRecord(ushort.Parse(priority), ushort.Parse(weight), ushort.Parse(port), value));
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        string flags = request.QueryString["flags"];
                        if (string.IsNullOrEmpty(flags))
                            throw new WebServiceException("Parameter 'flags' missing.");

                        string tag = request.QueryString["tag"];
                        if (string.IsNullOrEmpty(tag))
                            throw new WebServiceException("Parameter 'tag' missing.");

                        _dnsServer.AuthZoneManager.AddRecord(domain, type, ttl, new DnsCAARecord(byte.Parse(flags), tag, value));
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    _dnsServer.AuthZoneManager.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsANAMERecord(value) });
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        string protocol = request.QueryString["protocol"];
                        if (string.IsNullOrEmpty(protocol))
                            protocol = "Udp";

                        _dnsServer.AuthZoneManager.AddRecord(domain, type, 0, new DnsForwarderRecord((DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), protocol, true), value));
                    }
                    break;

                default:
                    throw new WebServiceException("Type not supported for AddRecords().");
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] New record was added to authoritative zone {domain: " + domain + "; type: " + type + "; value: " + value + "; ttl: " + ttl + ";}");

            _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        private void GetRecords(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            jsonWriter.WritePropertyName("zone");
            jsonWriter.WriteStartObject();

            jsonWriter.WritePropertyName("name");
            jsonWriter.WriteValue(zoneInfo.Name);

            jsonWriter.WritePropertyName("type");
            jsonWriter.WriteValue(zoneInfo.Type.ToString());

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    jsonWriter.WritePropertyName("internal");
                    jsonWriter.WriteValue(zoneInfo.Internal);
                    break;

                case AuthZoneType.Secondary:
                case AuthZoneType.Stub:
                    jsonWriter.WritePropertyName("expiry");
                    jsonWriter.WriteValue(zoneInfo.Expiry.ToLocalTime().ToString("dd MMM yyyy HH:mm:ss"));

                    jsonWriter.WritePropertyName("isExpired");
                    jsonWriter.WriteValue(zoneInfo.IsExpired);
                    break;
            }

            jsonWriter.WritePropertyName("disabled");
            jsonWriter.WriteValue(zoneInfo.Disabled);

            jsonWriter.WriteEndObject();

            List<DnsResourceRecord> records = _dnsServer.AuthZoneManager.ListAllRecords(domain);

            WriteRecordsAsJson(records, jsonWriter, true);
        }

        private static void WriteRecordsAsJson(List<DnsResourceRecord> records, JsonTextWriter jsonWriter, bool authoritativeZoneRecords)
        {
            if (records == null)
            {
                jsonWriter.WritePropertyName("records");
                jsonWriter.WriteStartArray();
                jsonWriter.WriteEndArray();

                return;
            }

            records.Sort();

            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = DnsResourceRecord.GroupRecords(records);

            jsonWriter.WritePropertyName("records");
            jsonWriter.WriteStartArray();

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByTypeRecords in groupedByDomainRecords)
            {
                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                {
                    foreach (DnsResourceRecord record in groupedRecords.Value)
                    {
                        jsonWriter.WriteStartObject();

                        if (authoritativeZoneRecords)
                        {
                            jsonWriter.WritePropertyName("disabled");
                            jsonWriter.WriteValue(record.IsDisabled());
                        }

                        jsonWriter.WritePropertyName("name");
                        jsonWriter.WriteValue(record.Name);

                        jsonWriter.WritePropertyName("type");
                        jsonWriter.WriteValue(record.Type.ToString());

                        jsonWriter.WritePropertyName("ttl");
                        if (authoritativeZoneRecords)
                            jsonWriter.WriteValue(record.TtlValue);
                        else
                            jsonWriter.WriteValue(record.TTL);

                        jsonWriter.WritePropertyName("rData");
                        jsonWriter.WriteStartObject();

                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                                {
                                    DnsARecord rdata = (record.RDATA as DnsARecord);
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.IPAddress);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.AAAA:
                                {
                                    DnsAAAARecord rdata = (record.RDATA as DnsAAAARecord);
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.IPAddress);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.SOA:
                                {
                                    DnsSOARecord rdata = record.RDATA as DnsSOARecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("primaryNameServer");
                                        jsonWriter.WriteValue(rdata.PrimaryNameServer);

                                        jsonWriter.WritePropertyName("responsiblePerson");
                                        jsonWriter.WriteValue(rdata.ResponsiblePerson);

                                        jsonWriter.WritePropertyName("serial");
                                        jsonWriter.WriteValue(rdata.Serial);

                                        jsonWriter.WritePropertyName("refresh");
                                        jsonWriter.WriteValue(rdata.Refresh);

                                        jsonWriter.WritePropertyName("retry");
                                        jsonWriter.WriteValue(rdata.Retry);

                                        jsonWriter.WritePropertyName("expire");
                                        jsonWriter.WriteValue(rdata.Expire);

                                        jsonWriter.WritePropertyName("minimum");
                                        jsonWriter.WriteValue(rdata.Minimum);
                                    }

                                    IReadOnlyList<DnsResourceRecord> glueRecords = record.GetGlueRecords();
                                    if (glueRecords.Count > 0)
                                    {
                                        string primaryAddresses = null;

                                        foreach (DnsResourceRecord glueRecord in glueRecords)
                                        {
                                            if (primaryAddresses == null)
                                                primaryAddresses = glueRecord.RDATA.ToString();
                                            else
                                                primaryAddresses = primaryAddresses + ", " + glueRecord.RDATA.ToString();
                                        }

                                        jsonWriter.WritePropertyName("primaryAddresses");
                                        jsonWriter.WriteValue(primaryAddresses);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.PTR:
                                {
                                    DnsPTRRecord rdata = record.RDATA as DnsPTRRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Domain);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.MX:
                                {
                                    DnsMXRecord rdata = record.RDATA as DnsMXRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("preference");
                                        jsonWriter.WriteValue(rdata.Preference);

                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Exchange);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.TXT:
                                {
                                    DnsTXTRecord rdata = record.RDATA as DnsTXTRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Text);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.NS:
                                {
                                    DnsNSRecord rdata = record.RDATA as DnsNSRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.NameServer);
                                    }

                                    IReadOnlyList<DnsResourceRecord> glueRecords = record.GetGlueRecords();
                                    if (glueRecords.Count > 0)
                                    {
                                        string glue = null;

                                        foreach (DnsResourceRecord glueRecord in glueRecords)
                                        {
                                            if (glue == null)
                                                glue = glueRecord.RDATA.ToString();
                                            else
                                                glue = glue + ", " + glueRecord.RDATA.ToString();
                                        }

                                        jsonWriter.WritePropertyName("glue");
                                        jsonWriter.WriteValue(glue);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.CNAME:
                                {
                                    DnsCNAMERecord rdata = record.RDATA as DnsCNAMERecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Domain);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.SRV:
                                {
                                    DnsSRVRecord rdata = record.RDATA as DnsSRVRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("priority");
                                        jsonWriter.WriteValue(rdata.Priority);

                                        jsonWriter.WritePropertyName("weight");
                                        jsonWriter.WriteValue(rdata.Weight);

                                        jsonWriter.WritePropertyName("port");
                                        jsonWriter.WriteValue(rdata.Port);

                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Target);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.CAA:
                                {
                                    DnsCAARecord rdata = record.RDATA as DnsCAARecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("flags");
                                        jsonWriter.WriteValue(rdata.Flags);

                                        jsonWriter.WritePropertyName("tag");
                                        jsonWriter.WriteValue(rdata.Tag);

                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Value);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.ANAME:
                                {
                                    DnsANAMERecord rdata = record.RDATA as DnsANAMERecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Domain);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.FWD:
                                {
                                    DnsForwarderRecord rdata = record.RDATA as DnsForwarderRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("protocol");
                                        jsonWriter.WriteValue(rdata.Protocol.ToString());

                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Forwarder);
                                    }
                                }
                                break;

                            default:
                                {
                                    jsonWriter.WritePropertyName("value");

                                    using (MemoryStream mS = new MemoryStream())
                                    {
                                        record.RDATA.WriteTo(mS, new List<DnsDomainOffset>());

                                        jsonWriter.WriteValue(Convert.ToBase64String(mS.ToArray()));
                                    }
                                }
                                break;
                        }

                        jsonWriter.WriteEndObject();

                        jsonWriter.WriteEndObject();
                    }
                }
            }

            jsonWriter.WriteEndArray();
        }

        private void DeleteRecord(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new WebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

            string value = request.QueryString["value"];
            if (string.IsNullOrEmpty(value))
                throw new WebServiceException("Parameter 'value' missing.");

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        IPAddress address = IPAddress.Parse(value);

                        if (type == DnsResourceRecordType.A)
                            _dnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsARecord(address));
                        else
                            _dnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsAAAARecord(address));

                        string ptrDomain = Zone.GetReverseZone(address, type == DnsResourceRecordType.A ? 32 : 128);
                        AuthZoneInfo reverseZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(ptrDomain);
                        if ((reverseZoneInfo != null) && !reverseZoneInfo.Internal && (reverseZoneInfo.Type == AuthZoneType.Primary))
                        {
                            IReadOnlyList<DnsResourceRecord> ptrRecords = _dnsServer.AuthZoneManager.QueryRecords(ptrDomain, DnsResourceRecordType.PTR);
                            if (ptrRecords.Count > 0)
                            {
                                foreach (DnsResourceRecord ptrRecord in ptrRecords)
                                {
                                    if ((ptrRecord.RDATA as DnsPTRRecord).Domain.Equals(domain, StringComparison.OrdinalIgnoreCase))
                                    {
                                        //delete PTR record and save reverse zone
                                        _dnsServer.AuthZoneManager.DeleteRecord(ptrDomain, DnsResourceRecordType.PTR, ptrRecord.RDATA);
                                        _dnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    break;

                case DnsResourceRecordType.MX:
                    _dnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsMXRecord(0, value));
                    break;

                case DnsResourceRecordType.TXT:
                    _dnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsTXTRecord(value));
                    break;

                case DnsResourceRecordType.NS:
                    _dnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsNSRecord(value));
                    break;

                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.PTR:
                case DnsResourceRecordType.ANAME:
                    _dnsServer.AuthZoneManager.DeleteRecords(domain, type);
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        string port = request.QueryString["port"];
                        if (string.IsNullOrEmpty(port))
                            throw new WebServiceException("Parameter 'port' missing.");

                        _dnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsSRVRecord(0, 0, ushort.Parse(port), value));
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        string flags = request.QueryString["flags"];
                        if (string.IsNullOrEmpty(flags))
                            throw new WebServiceException("Parameter 'flags' missing.");

                        string tag = request.QueryString["tag"];
                        if (string.IsNullOrEmpty(tag))
                            throw new WebServiceException("Parameter 'tag' missing.");

                        _dnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsCAARecord(byte.Parse(flags), tag, value));
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        string strProtocol = request.QueryString["protocol"];
                        if (string.IsNullOrEmpty(strProtocol))
                            strProtocol = "Udp";

                        _dnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsForwarderRecord((DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), strProtocol, true), value));
                    }
                    break;

                default:
                    throw new WebServiceException("Type not supported for DeleteRecord().");
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Record was deleted from authoritative zone {domain: " + domain + "; type: " + type + "; value: " + value + ";}");

            _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        private void UpdateRecord(HttpListenerRequest request)
        {
            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new WebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            string newDomain = request.QueryString["newDomain"];
            if (string.IsNullOrEmpty(newDomain))
                newDomain = domain;

            if (newDomain.EndsWith("."))
                newDomain = newDomain.Substring(0, newDomain.Length - 1);

            uint ttl;
            string strTtl = request.QueryString["ttl"];
            if (string.IsNullOrEmpty(strTtl))
                ttl = 3600;
            else
                ttl = uint.Parse(strTtl);

            string value = request.QueryString["value"];

            string newValue = request.QueryString["newValue"];
            if (string.IsNullOrEmpty(newValue))
                newValue = value;

            bool disable = false;
            string strDisable = request.QueryString["disable"];
            if (!string.IsNullOrEmpty(strDisable))
                disable = bool.Parse(strDisable);

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        IPAddress oldIpAddress = IPAddress.Parse(value);
                        IPAddress newIpAddress = IPAddress.Parse(newValue);

                        bool ptr = false;
                        string strPtr = request.QueryString["ptr"];
                        if (!string.IsNullOrEmpty(strPtr))
                            ptr = bool.Parse(strPtr);

                        if (ptr)
                        {
                            string ptrDomain = Zone.GetReverseZone(newIpAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo reverseZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(ptrDomain);
                            if (reverseZoneInfo == null)
                            {
                                bool createPtrZone = false;
                                string strCreatePtrZone = request.QueryString["createPtrZone"];
                                if (!string.IsNullOrEmpty(strCreatePtrZone))
                                    createPtrZone = bool.Parse(strCreatePtrZone);

                                if (!createPtrZone)
                                    throw new DnsServerException("No reverse zone available to add PTR record.");

                                string ptrZone = Zone.GetReverseZone(newIpAddress, type == DnsResourceRecordType.A ? 24 : 64);

                                reverseZoneInfo = _dnsServer.AuthZoneManager.CreatePrimaryZone(ptrZone, _dnsServer.ServerDomain, false);
                                if (reverseZoneInfo == null)
                                    throw new DnsServerException("Failed to create reverse zone to add PTR record: " + ptrZone);
                            }

                            if (reverseZoneInfo.Internal)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is an internal zone.");

                            if (reverseZoneInfo.Type != AuthZoneType.Primary)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is not a primary zone.");


                            string oldPtrDomain = Zone.GetReverseZone(oldIpAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo oldReverseZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(oldPtrDomain);
                            if ((oldReverseZoneInfo != null) && !oldReverseZoneInfo.Internal && (oldReverseZoneInfo.Type == AuthZoneType.Primary))
                            {
                                //delete old PTR record if any and save old reverse zone
                                _dnsServer.AuthZoneManager.DeleteRecords(oldPtrDomain, DnsResourceRecordType.PTR);
                                _dnsServer.AuthZoneManager.SaveZoneFile(oldReverseZoneInfo.Name);
                            }

                            //add new PTR record and save reverse zone
                            _dnsServer.AuthZoneManager.SetRecords(ptrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecord[] { new DnsPTRRecord(domain) });
                            _dnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                        }

                        DnsResourceRecord oldRecord;
                        DnsResourceRecord newRecord;

                        if (type == DnsResourceRecordType.A)
                        {
                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsARecord(oldIpAddress));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsARecord(newIpAddress));
                        }
                        else
                        {
                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsAAAARecord(oldIpAddress));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsAAAARecord(newIpAddress));
                        }

                        if (disable)
                            newRecord.Disable();

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        string preference = request.QueryString["preference"];
                        if (string.IsNullOrEmpty(preference))
                            preference = "1";

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsMXRecord(0, value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsMXRecord(ushort.Parse(preference), newValue));

                        if (disable)
                            newRecord.Disable();

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsTXTRecord(value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsTXTRecord(newValue));

                        if (disable)
                            newRecord.Disable();

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsNSRecord(value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsNSRecord(newValue));

                        if (disable)
                            newRecord.Disable();

                        string glueAddresses = request.QueryString["glue"];
                        if (!string.IsNullOrEmpty(glueAddresses))
                            newRecord.SetGlueRecords(glueAddresses);

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SOA:
                    {
                        string primaryNameServer = request.QueryString["primaryNameServer"];
                        if (string.IsNullOrEmpty(primaryNameServer))
                            throw new WebServiceException("Parameter 'primaryNameServer' missing.");

                        string responsiblePerson = request.QueryString["responsiblePerson"];
                        if (string.IsNullOrEmpty(responsiblePerson))
                            throw new WebServiceException("Parameter 'responsiblePerson' missing.");

                        string serial = request.QueryString["serial"];
                        if (string.IsNullOrEmpty(serial))
                            throw new WebServiceException("Parameter 'serial' missing.");

                        string refresh = request.QueryString["refresh"];
                        if (string.IsNullOrEmpty(refresh))
                            throw new WebServiceException("Parameter 'refresh' missing.");

                        string retry = request.QueryString["retry"];
                        if (string.IsNullOrEmpty(retry))
                            throw new WebServiceException("Parameter 'retry' missing.");

                        string expire = request.QueryString["expire"];
                        if (string.IsNullOrEmpty(expire))
                            throw new WebServiceException("Parameter 'expire' missing.");

                        string minimum = request.QueryString["minimum"];
                        if (string.IsNullOrEmpty(minimum))
                            throw new WebServiceException("Parameter 'minimum' missing.");

                        DnsResourceRecord soaRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSOARecord(primaryNameServer, responsiblePerson, uint.Parse(serial), uint.Parse(refresh), uint.Parse(retry), uint.Parse(expire), uint.Parse(minimum)));

                        string primaryAddresses = request.QueryString["primaryAddresses"];
                        if (!string.IsNullOrEmpty(primaryAddresses))
                            soaRecord.SetGlueRecords(primaryAddresses);

                        _dnsServer.AuthZoneManager.SetRecord(soaRecord);
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsPTRRecord(value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsPTRRecord(newValue));

                        if (disable)
                            newRecord.Disable();

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCNAMERecord(value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCNAMERecord(newValue));

                        if (disable)
                            newRecord.Disable();

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        string port = request.QueryString["port"];
                        if (string.IsNullOrEmpty(port))
                            throw new WebServiceException("Parameter 'port' missing.");

                        string priority = request.QueryString["priority"];
                        if (string.IsNullOrEmpty(priority))
                            throw new WebServiceException("Parameter 'priority' missing.");

                        string weight = request.QueryString["weight"];
                        if (string.IsNullOrEmpty(weight))
                            throw new WebServiceException("Parameter 'weight' missing.");

                        string newPort = request.QueryString["newPort"];
                        if (string.IsNullOrEmpty(newPort))
                            newPort = port;

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSRVRecord(0, 0, ushort.Parse(port), value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSRVRecord(ushort.Parse(priority), ushort.Parse(weight), ushort.Parse(newPort), newValue));

                        if (disable)
                            newRecord.Disable();

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        string flags = request.QueryString["flags"];
                        if (string.IsNullOrEmpty(flags))
                            throw new WebServiceException("Parameter 'flags' missing.");

                        string tag = request.QueryString["tag"];
                        if (string.IsNullOrEmpty(tag))
                            throw new WebServiceException("Parameter 'tag' missing.");

                        string newFlags = request.QueryString["newFlags"];
                        if (string.IsNullOrEmpty(newFlags))
                            newFlags = flags;

                        string newTag = request.QueryString["newTag"];
                        if (string.IsNullOrEmpty(newTag))
                            newTag = tag;

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCAARecord(byte.Parse(flags), tag, value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCAARecord(byte.Parse(newFlags), newTag, newValue));

                        if (disable)
                            newRecord.Disable();

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsANAMERecord(value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsANAMERecord(newValue));

                        if (disable)
                            newRecord.Disable();

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        string strProtocol = request.QueryString["protocol"];
                        if (string.IsNullOrEmpty(strProtocol))
                            strProtocol = "Udp";

                        DnsTransportProtocol protocol = (DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), strProtocol, true);

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecord(protocol, value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsForwarderRecord(protocol, newValue));

                        if (disable)
                            newRecord.Disable();

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                default:
                    throw new WebServiceException("Type not supported for UpdateRecords().");
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Record was updated for authoritative zone {oldDomain: " + domain + "; domain: " + newDomain + "; type: " + type + "; oldValue: " + value + "; value: " + newValue + "; ttl: " + ttl + "; disabled: " + disable + ";}");

            _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        private async Task ResolveQuery(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string server = request.QueryString["server"];
            if (string.IsNullOrEmpty(server))
                throw new WebServiceException("Parameter 'server' missing.");

            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            domain = domain.Trim();

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new WebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

            string strProtocol = request.QueryString["protocol"];
            if (string.IsNullOrEmpty(strProtocol))
                strProtocol = "Udp";

            bool importRecords = false;
            string strImport = request.QueryString["import"];
            if (!string.IsNullOrEmpty(strImport))
                importRecords = bool.Parse(strImport);

            NetProxy proxy = _dnsServer.Proxy;
            bool preferIPv6 = _dnsServer.PreferIPv6;
            bool randomizeName = false;
            DnsTransportProtocol protocol = (DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), strProtocol, true);
            const int RETRIES = 1;
            const int TIMEOUT = 10000;

            DnsDatagram dnsResponse;

            if (server.Equals("recursive-resolver", StringComparison.OrdinalIgnoreCase))
            {
                if (type == DnsResourceRecordType.AXFR)
                    throw new DnsServerException("Cannot do zone transfer (AXFR) for 'recursive-resolver'.");

                DnsQuestionRecord question;

                if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                    question = new DnsQuestionRecord(address, DnsClass.IN);
                else
                    question = new DnsQuestionRecord(domain, type, DnsClass.IN);

                dnsResponse = await DnsClient.RecursiveResolveAsync(question, null, null, proxy, preferIPv6, randomizeName, RETRIES, TIMEOUT);
            }
            else
            {
                if (type == DnsResourceRecordType.AXFR)
                    protocol = DnsTransportProtocol.Tcp;

                NameServerAddress nameServer;

                if (server.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                {
                    switch (protocol)
                    {
                        case DnsTransportProtocol.Udp:
                            nameServer = _dnsServer.ThisServer;
                            break;

                        case DnsTransportProtocol.Tcp:
                            nameServer = new NameServerAddress(_dnsServer.ThisServer, DnsTransportProtocol.Tcp);
                            break;

                        case DnsTransportProtocol.Tls:
                            throw new DnsServerException("Cannot use DNS-over-TLS protocol for 'this-server'. Please use the TLS certificate domain name as the server.");

                        case DnsTransportProtocol.Https:
                            throw new DnsServerException("Cannot use DNS-over-HTTPS protocol for 'this-server'. Please use the TLS certificate domain name with a url as the server.");

                        case DnsTransportProtocol.HttpsJson:
                            throw new DnsServerException("Cannot use DNS-over-HTTPS (JSON) protocol for 'this-server'. Please use the TLS certificate domain name with a url as the server.");

                        default:
                            throw new InvalidOperationException();
                    }

                    proxy = null; //no proxy required for this server
                }
                else
                {
                    if ((protocol == DnsTransportProtocol.Tls) && !server.Contains(":853"))
                        server += ":853";

                    nameServer = new NameServerAddress(server, protocol);

                    if (nameServer.IPEndPoint == null)
                    {
                        if (proxy == null)
                        {
                            if (_dnsServer.AllowRecursion)
                                await nameServer.ResolveIPAddressAsync(new NameServerAddress[] { _dnsServer.ThisServer }, proxy, preferIPv6, randomizeName, RETRIES, TIMEOUT);
                            else
                                await nameServer.RecursiveResolveIPAddressAsync(_dnsServer.DnsCache, proxy, preferIPv6, randomizeName, RETRIES, TIMEOUT);
                        }
                    }
                    else if (protocol != DnsTransportProtocol.Tls)
                    {
                        try
                        {
                            if (_dnsServer.AllowRecursion)
                                await nameServer.ResolveDomainNameAsync(new NameServerAddress[] { _dnsServer.ThisServer }, proxy, preferIPv6, randomizeName, RETRIES, TIMEOUT);
                            else
                                await nameServer.RecursiveResolveDomainNameAsync(_dnsServer.DnsCache, proxy, preferIPv6, randomizeName, RETRIES, TIMEOUT);
                        }
                        catch
                        { }
                    }
                }

                dnsResponse = await new DnsClient(nameServer) { Proxy = proxy, PreferIPv6 = preferIPv6, RandomizeName = randomizeName, Retries = RETRIES, Timeout = TIMEOUT }.ResolveAsync(domain, type);
            }

            if (importRecords)
            {
                AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);

                if (zoneInfo == null)
                {
                    zoneInfo = _dnsServer.AuthZoneManager.CreatePrimaryZone(domain, _dnsServer.ServerDomain, false);
                    if (zoneInfo == null)
                        throw new DnsServerException("Cannot import records: failed to create primary zone.");
                }
                else
                {
                    switch (zoneInfo.Type)
                    {
                        case AuthZoneType.Primary:
                        case AuthZoneType.Forwarder:
                            break;

                        default:
                            throw new DnsServerException("Cannot import records: import zone must be of primary or forwarder type.");
                    }
                }

                if (type == DnsResourceRecordType.AXFR)
                {
                    bool dontRemoveRecords = zoneInfo.Type == AuthZoneType.Forwarder;

                    _dnsServer.AuthZoneManager.SyncRecords(domain, dnsResponse.Answer, null, dontRemoveRecords);
                }
                else
                {
                    List<DnsResourceRecord> syncRecords = new List<DnsResourceRecord>();

                    foreach (DnsResourceRecord record in dnsResponse.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            record.RemoveExpiry();
                            syncRecords.Add(record);
                        }
                    }

                    _dnsServer.AuthZoneManager.SyncRecords(domain, syncRecords, null, true);
                }

                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DNS Client imported record(s) for authoritative zone {server: " + server + "; domain: " + domain + "; type: " + type + ";}");

                _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
            }

            jsonWriter.WritePropertyName("result");
            jsonWriter.WriteRawValue(JsonConvert.SerializeObject(dnsResponse, new StringEnumConverter()));
        }

        private void ListLogs(JsonTextWriter jsonWriter)
        {
            string[] logFiles = _log.ListLogFiles();

            Array.Sort(logFiles);
            Array.Reverse(logFiles);

            jsonWriter.WritePropertyName("logFiles");
            jsonWriter.WriteStartArray();

            foreach (string logFile in logFiles)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("fileName");
                jsonWriter.WriteValue(Path.GetFileNameWithoutExtension(logFile));

                jsonWriter.WritePropertyName("size");
                jsonWriter.WriteValue(WebUtilities.GetFormattedSize(new FileInfo(logFile).Length));

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        private void DeleteLog(HttpListenerRequest request)
        {
            string log = request.QueryString["log"];
            if (string.IsNullOrEmpty(log))
                throw new WebServiceException("Parameter 'log' missing.");

            _log.DeleteLog(log);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Log file was deleted: " + log);
        }

        private void DeleteAllLogs(HttpListenerRequest request)
        {
            _log.DeleteAllLogs();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] All log files were deleted.");
        }

        private void DeleteAllStats(HttpListenerRequest request)
        {
            _dnsServer.StatsManager.DeleteAllStats();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] All stats files were deleted.");
        }

        private void ListDhcpLeases(JsonTextWriter jsonWriter)
        {
            ICollection<Scope> scopes = _dhcpServer.Scopes;

            //sort by name
            Scope[] scopesArray = new Scope[scopes.Count];
            scopes.CopyTo(scopesArray, 0);
            Array.Sort(scopesArray);

            jsonWriter.WritePropertyName("leases");
            jsonWriter.WriteStartArray();

            foreach (Scope scope in scopesArray)
            {
                ICollection<Lease> leases = scope.Leases;

                //sort by address
                Lease[] leasesArray = new Lease[leases.Count];
                leases.CopyTo(leasesArray, 0);
                Array.Sort(leasesArray);

                foreach (Lease lease in leasesArray)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("scope");
                    jsonWriter.WriteValue(scope.Name);

                    jsonWriter.WritePropertyName("type");
                    jsonWriter.WriteValue(lease.Type.ToString());

                    jsonWriter.WritePropertyName("hardwareAddress");
                    jsonWriter.WriteValue(BitConverter.ToString(lease.HardwareAddress));

                    jsonWriter.WritePropertyName("address");
                    jsonWriter.WriteValue(lease.Address.ToString());

                    jsonWriter.WritePropertyName("hostName");
                    jsonWriter.WriteValue(lease.HostName);

                    jsonWriter.WritePropertyName("leaseObtained");
                    jsonWriter.WriteValue(lease.LeaseObtained.ToLocalTime().ToString());

                    jsonWriter.WritePropertyName("leaseExpires");
                    jsonWriter.WriteValue(lease.LeaseExpires.ToLocalTime().ToString());

                    jsonWriter.WriteEndObject();
                }
            }

            jsonWriter.WriteEndArray();
        }

        private void ListDhcpScopes(JsonTextWriter jsonWriter)
        {
            ICollection<Scope> scopes = _dhcpServer.Scopes;

            //sort by name
            Scope[] scopesArray = new Scope[scopes.Count];
            scopes.CopyTo(scopesArray, 0);
            Array.Sort(scopesArray);

            jsonWriter.WritePropertyName("scopes");
            jsonWriter.WriteStartArray();

            foreach (Scope scope in scopesArray)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("name");
                jsonWriter.WriteValue(scope.Name);

                jsonWriter.WritePropertyName("enabled");
                jsonWriter.WriteValue(scope.Enabled);

                jsonWriter.WritePropertyName("startingAddress");
                jsonWriter.WriteValue(scope.StartingAddress.ToString());

                jsonWriter.WritePropertyName("endingAddress");
                jsonWriter.WriteValue(scope.EndingAddress.ToString());

                jsonWriter.WritePropertyName("subnetMask");
                jsonWriter.WriteValue(scope.SubnetMask.ToString());

                jsonWriter.WritePropertyName("networkAddress");
                jsonWriter.WriteValue(scope.NetworkAddress.ToString());

                jsonWriter.WritePropertyName("broadcastAddress");
                jsonWriter.WriteValue(scope.BroadcastAddress.ToString());

                if (scope.InterfaceAddress != null)
                {
                    jsonWriter.WritePropertyName("interfaceAddress");
                    jsonWriter.WriteValue(scope.InterfaceAddress.ToString());
                }

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        private void GetDhcpScope(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new WebServiceException("Parameter 'name' missing.");

            Scope scope = _dhcpServer.GetScope(scopeName);
            if (scope == null)
                throw new WebServiceException("DHCP scope was not found: " + scopeName);

            jsonWriter.WritePropertyName("name");
            jsonWriter.WriteValue(scope.Name);

            jsonWriter.WritePropertyName("startingAddress");
            jsonWriter.WriteValue(scope.StartingAddress.ToString());

            jsonWriter.WritePropertyName("endingAddress");
            jsonWriter.WriteValue(scope.EndingAddress.ToString());

            jsonWriter.WritePropertyName("subnetMask");
            jsonWriter.WriteValue(scope.SubnetMask.ToString());

            jsonWriter.WritePropertyName("leaseTimeDays");
            jsonWriter.WriteValue(scope.LeaseTimeDays);

            jsonWriter.WritePropertyName("leaseTimeHours");
            jsonWriter.WriteValue(scope.LeaseTimeHours);

            jsonWriter.WritePropertyName("leaseTimeMinutes");
            jsonWriter.WriteValue(scope.LeaseTimeMinutes);

            jsonWriter.WritePropertyName("offerDelayTime");
            jsonWriter.WriteValue(scope.OfferDelayTime);

            if (!string.IsNullOrEmpty(scope.DomainName))
            {
                jsonWriter.WritePropertyName("domainName");
                jsonWriter.WriteValue(scope.DomainName);
            }

            jsonWriter.WritePropertyName("dnsTtl");
            jsonWriter.WriteValue(scope.DnsTtl);

            if (scope.ServerAddress != null)
            {
                jsonWriter.WritePropertyName("serverAddress");
                jsonWriter.WriteValue(scope.ServerAddress.ToString());
            }

            if (scope.ServerHostName != null)
            {
                jsonWriter.WritePropertyName("serverHostName");
                jsonWriter.WriteValue(scope.ServerHostName);
            }

            if (scope.BootFileName != null)
            {
                jsonWriter.WritePropertyName("bootFileName");
                jsonWriter.WriteValue(scope.BootFileName);
            }

            if (scope.RouterAddress != null)
            {
                jsonWriter.WritePropertyName("routerAddress");
                jsonWriter.WriteValue(scope.RouterAddress.ToString());
            }

            jsonWriter.WritePropertyName("useThisDnsServer");
            jsonWriter.WriteValue(scope.UseThisDnsServer);

            if (scope.DnsServers != null)
            {
                jsonWriter.WritePropertyName("dnsServers");
                jsonWriter.WriteStartArray();

                foreach (IPAddress dnsServer in scope.DnsServers)
                    jsonWriter.WriteValue(dnsServer.ToString());

                jsonWriter.WriteEndArray();
            }

            if (scope.WinsServers != null)
            {
                jsonWriter.WritePropertyName("winsServers");
                jsonWriter.WriteStartArray();

                foreach (IPAddress winsServer in scope.WinsServers)
                    jsonWriter.WriteValue(winsServer.ToString());

                jsonWriter.WriteEndArray();
            }

            if (scope.NtpServers != null)
            {
                jsonWriter.WritePropertyName("ntpServers");
                jsonWriter.WriteStartArray();

                foreach (IPAddress ntpServer in scope.NtpServers)
                    jsonWriter.WriteValue(ntpServer.ToString());

                jsonWriter.WriteEndArray();
            }

            if (scope.StaticRoutes != null)
            {
                jsonWriter.WritePropertyName("staticRoutes");
                jsonWriter.WriteStartArray();

                foreach (ClasslessStaticRouteOption.Route route in scope.StaticRoutes)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("destination");
                    jsonWriter.WriteValue(route.Destination.ToString());

                    jsonWriter.WritePropertyName("subnetMask");
                    jsonWriter.WriteValue(route.SubnetMask.ToString());

                    jsonWriter.WritePropertyName("router");
                    jsonWriter.WriteValue(route.Router.ToString());

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            if (scope.VendorInfo != null)
            {
                jsonWriter.WritePropertyName("vendorInfo");
                jsonWriter.WriteStartArray();

                foreach (KeyValuePair<string, VendorSpecificInformationOption> entry in scope.VendorInfo)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("identifier");
                    jsonWriter.WriteValue(entry.Key);

                    jsonWriter.WritePropertyName("information");
                    jsonWriter.WriteValue(entry.Value.ToString());

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            if (scope.Exclusions != null)
            {
                jsonWriter.WritePropertyName("exclusions");
                jsonWriter.WriteStartArray();

                foreach (Exclusion exclusion in scope.Exclusions)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("startingAddress");
                    jsonWriter.WriteValue(exclusion.StartingAddress.ToString());

                    jsonWriter.WritePropertyName("endingAddress");
                    jsonWriter.WriteValue(exclusion.EndingAddress.ToString());

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("reservedLeases");
            jsonWriter.WriteStartArray();

            foreach (Lease reservedLease in scope.ReservedLeases)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("hostName");
                jsonWriter.WriteValue(reservedLease.HostName);

                jsonWriter.WritePropertyName("hardwareAddress");
                jsonWriter.WriteValue(BitConverter.ToString(reservedLease.HardwareAddress));

                jsonWriter.WritePropertyName("address");
                jsonWriter.WriteValue(reservedLease.Address.ToString());

                jsonWriter.WritePropertyName("comments");
                jsonWriter.WriteValue(reservedLease.Comments);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("allowOnlyReservedLeases");
            jsonWriter.WriteValue(scope.AllowOnlyReservedLeases);
        }

        private async Task SetDhcpScopeAsync(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new WebServiceException("Parameter 'name' missing.");

            string newName = request.QueryString["newName"];
            if (!string.IsNullOrEmpty(newName) && !newName.Equals(scopeName))
            {
                _dhcpServer.RenameScope(scopeName, newName);

                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DHCP scope was renamed successfully: '" + scopeName + "' to '" + newName + "'");

                scopeName = newName;
            }

            string strStartingAddress = request.QueryString["startingAddress"];
            if (string.IsNullOrEmpty(strStartingAddress))
                throw new WebServiceException("Parameter 'startingAddress' missing.");

            string strEndingAddress = request.QueryString["endingAddress"];
            if (string.IsNullOrEmpty(strStartingAddress))
                throw new WebServiceException("Parameter 'endingAddress' missing.");

            string strSubnetMask = request.QueryString["subnetMask"];
            if (string.IsNullOrEmpty(strStartingAddress))
                throw new WebServiceException("Parameter 'subnetMask' missing.");

            bool scopeExists;
            Scope scope = _dhcpServer.GetScope(scopeName);
            if (scope == null)
            {
                //scope does not exists; create new scope
                scopeExists = false;
                scope = new Scope(scopeName, true, IPAddress.Parse(strStartingAddress), IPAddress.Parse(strEndingAddress), IPAddress.Parse(strSubnetMask));
            }
            else
            {
                scopeExists = true;
                IPAddress startingAddress = IPAddress.Parse(strStartingAddress);
                IPAddress endingAddress = IPAddress.Parse(strEndingAddress);

                //validate scope address
                foreach (Scope existingScope in _dhcpServer.Scopes)
                {
                    if (existingScope.Equals(scope))
                        continue;

                    if (existingScope.IsAddressInRange(startingAddress) || existingScope.IsAddressInRange(endingAddress))
                        throw new DhcpServerException("Scope with overlapping range already exists: " + existingScope.StartingAddress.ToString() + "-" + existingScope.EndingAddress.ToString());
                }

                scope.ChangeNetwork(startingAddress, endingAddress, IPAddress.Parse(strSubnetMask));
            }

            string strLeaseTimeDays = request.QueryString["leaseTimeDays"];
            if (!string.IsNullOrEmpty(strLeaseTimeDays))
                scope.LeaseTimeDays = ushort.Parse(strLeaseTimeDays);

            string strLeaseTimeHours = request.QueryString["leaseTimeHours"];
            if (!string.IsNullOrEmpty(strLeaseTimeHours))
                scope.LeaseTimeHours = byte.Parse(strLeaseTimeHours);

            string strLeaseTimeMinutes = request.QueryString["leaseTimeMinutes"];
            if (!string.IsNullOrEmpty(strLeaseTimeMinutes))
                scope.LeaseTimeMinutes = byte.Parse(strLeaseTimeMinutes);

            string strOfferDelayTime = request.QueryString["offerDelayTime"];
            if (!string.IsNullOrEmpty(strOfferDelayTime))
                scope.OfferDelayTime = ushort.Parse(strOfferDelayTime);

            string strDomainName = request.QueryString["domainName"];
            if (strDomainName != null)
                scope.DomainName = strDomainName.Length == 0 ? null : strDomainName;

            string strDnsTtl = request.QueryString["dnsTtl"];
            if (!string.IsNullOrEmpty(strDnsTtl))
                scope.DnsTtl = uint.Parse(strDnsTtl);

            string strServerAddress = request.QueryString["serverAddress"];
            if (strServerAddress != null)
                scope.ServerAddress = strServerAddress.Length == 0 ? null : IPAddress.Parse(strServerAddress);

            string strServerHostName = request.QueryString["serverHostName"];
            if (strServerHostName != null)
                scope.ServerHostName = strServerHostName.Length == 0 ? null : strServerHostName;

            string strBootFileName = request.QueryString["bootFileName"];
            if (strBootFileName != null)
                scope.BootFileName = strBootFileName.Length == 0 ? null : strBootFileName;

            string strRouterAddress = request.QueryString["routerAddress"];
            if (strRouterAddress != null)
                scope.RouterAddress = strRouterAddress.Length == 0 ? null : IPAddress.Parse(strRouterAddress);

            string strUseThisDnsServer = request.QueryString["useThisDnsServer"];
            if (!string.IsNullOrEmpty(strUseThisDnsServer))
                scope.UseThisDnsServer = bool.Parse(strUseThisDnsServer);

            if (!scope.UseThisDnsServer)
            {
                string strDnsServers = request.QueryString["dnsServers"];
                if (strDnsServers != null)
                {
                    if (strDnsServers.Length == 0)
                    {
                        scope.DnsServers = null;
                    }
                    else
                    {
                        string[] strDnsServerParts = strDnsServers.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                        IPAddress[] dnsServers = new IPAddress[strDnsServerParts.Length];

                        for (int i = 0; i < strDnsServerParts.Length; i++)
                            dnsServers[i] = IPAddress.Parse(strDnsServerParts[i]);

                        scope.DnsServers = dnsServers;
                    }
                }
            }

            string strWinsServers = request.QueryString["winsServers"];
            if (strWinsServers != null)
            {
                if (strWinsServers.Length == 0)
                {
                    scope.WinsServers = null;
                }
                else
                {
                    string[] strWinsServerParts = strWinsServers.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    IPAddress[] winsServers = new IPAddress[strWinsServerParts.Length];

                    for (int i = 0; i < strWinsServerParts.Length; i++)
                        winsServers[i] = IPAddress.Parse(strWinsServerParts[i]);

                    scope.WinsServers = winsServers;
                }
            }

            string strNtpServers = request.QueryString["ntpServers"];
            if (strNtpServers != null)
            {
                if (strNtpServers.Length == 0)
                {
                    scope.NtpServers = null;
                }
                else
                {
                    string[] strNtpServerParts = strNtpServers.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    IPAddress[] ntpServers = new IPAddress[strNtpServerParts.Length];

                    for (int i = 0; i < strNtpServerParts.Length; i++)
                        ntpServers[i] = IPAddress.Parse(strNtpServerParts[i]);

                    scope.NtpServers = ntpServers;
                }
            }

            string strStaticRoutes = request.QueryString["staticRoutes"];
            if (strStaticRoutes != null)
            {
                if (strStaticRoutes.Length == 0)
                {
                    scope.StaticRoutes = null;
                }
                else
                {
                    string[] strStaticRoutesParts = strStaticRoutes.Split('|');
                    List<ClasslessStaticRouteOption.Route> staticRoutes = new List<ClasslessStaticRouteOption.Route>();

                    for (int i = 0; i < strStaticRoutesParts.Length; i += 3)
                    {
                        staticRoutes.Add(new ClasslessStaticRouteOption.Route(IPAddress.Parse(strStaticRoutesParts[i + 0]), IPAddress.Parse(strStaticRoutesParts[i + 1]), IPAddress.Parse(strStaticRoutesParts[i + 2])));
                    }

                    scope.StaticRoutes = staticRoutes;
                }
            }

            string strVendorInfo = request.QueryString["vendorInfo"];
            if (strVendorInfo != null)
            {
                if (strVendorInfo.Length == 0)
                {
                    scope.VendorInfo = null;
                }
                else
                {
                    string[] strVendorInfoParts = strVendorInfo.Split('|');
                    Dictionary<string, VendorSpecificInformationOption> vendorInfo = new Dictionary<string, VendorSpecificInformationOption>();

                    for (int i = 0; i < strVendorInfoParts.Length; i += 2)
                    {
                        vendorInfo.Add(strVendorInfoParts[i + 0], new VendorSpecificInformationOption(strVendorInfoParts[i + 1]));
                    }

                    scope.VendorInfo = vendorInfo;
                }
            }

            string strExclusions = request.QueryString["exclusions"];
            if (strExclusions != null)
            {
                if (strExclusions.Length == 0)
                {
                    scope.Exclusions = null;
                }
                else
                {
                    string[] strExclusionsParts = strExclusions.Split('|');
                    List<Exclusion> exclusions = new List<Exclusion>();

                    for (int i = 0; i < strExclusionsParts.Length; i += 2)
                    {
                        exclusions.Add(new Exclusion(IPAddress.Parse(strExclusionsParts[i + 0]), IPAddress.Parse(strExclusionsParts[i + 1])));
                    }

                    scope.Exclusions = exclusions;
                }
            }

            string strReservedLeases = request.QueryString["reservedLeases"];
            if (strReservedLeases != null)
            {
                if (strReservedLeases.Length == 0)
                {
                    scope.ReservedLeases = null;
                }
                else
                {
                    string[] strReservedLeaseParts = strReservedLeases.Split('|');
                    List<Lease> reservedLeases = new List<Lease>();

                    for (int i = 0; i < strReservedLeaseParts.Length; i += 3)
                    {
                        Lease reservedLease = new Lease(LeaseType.Reserved, null, DhcpMessageHardwareAddressType.Ethernet, strReservedLeaseParts[i + 0], IPAddress.Parse(strReservedLeaseParts[i + 1]), strReservedLeaseParts[i + 2]);

                        Lease existingReservedLease = scope.GetReservedLease(DhcpMessageHardwareAddressType.Ethernet, reservedLease.HardwareAddress);
                        if (existingReservedLease != null)
                            reservedLease.SetHostName(existingReservedLease.HostName);

                        reservedLeases.Add(reservedLease);
                    }

                    scope.ReservedLeases = reservedLeases;
                }
            }

            string strAllowOnlyReservedLeases = request.QueryString["allowOnlyReservedLeases"];
            if (!string.IsNullOrEmpty(strAllowOnlyReservedLeases))
                scope.AllowOnlyReservedLeases = bool.Parse(strAllowOnlyReservedLeases);

            if (scopeExists)
            {
                _dhcpServer.SaveScope(scopeName);

                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DHCP scope was updated successfully: " + scopeName);
            }
            else
            {
                await _dhcpServer.AddScopeAsync(scope);

                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DHCP scope was added successfully: " + scopeName);
            }
        }

        private async Task EnableDhcpScopeAsync(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new WebServiceException("Parameter 'name' missing.");

            if (!await _dhcpServer.EnableScopeAsync(scopeName))
                throw new WebServiceException("Failed to enable DHCP scope, please check logs for details: " + scopeName);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DHCP scope was enabled successfully: " + scopeName);
        }

        private void DisableDhcpScope(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new WebServiceException("Parameter 'name' missing.");

            if (!_dhcpServer.DisableScope(scopeName))
                throw new WebServiceException("Failed to disable DHCP scope, please check logs for details: " + scopeName);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DHCP scope was disabled successfully: " + scopeName);
        }

        private void DeleteDhcpScope(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new WebServiceException("Parameter 'name' missing.");

            _dhcpServer.DeleteScope(scopeName);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DHCP scope was deleted successfully: " + scopeName);
        }

        private void SetCredentials(string username, string password)
        {
            username = username.ToLower();
            string passwordHash = GetPasswordHash(username, password);

            _credentials[username] = passwordHash;
        }

        private void LoadCredentials(string username, string passwordHash)
        {
            username = username.ToLower();

            _credentials[username] = passwordHash;
        }

        private static string GetPasswordHash(string username, string password)
        {
            using (HMAC hmac = new HMACSHA256(Encoding.UTF8.GetBytes(password)))
            {
                return BitConverter.ToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(username))).Replace("-", "").ToLower();
            }
        }

        private void ForceUpdateBlockLists()
        {
            _blockListLastUpdatedOn = new DateTime();

            StopBlockListUpdateTimer();
            StartBlockListUpdateTimer();
        }

        private void StartBlockListUpdateTimer()
        {
            if (_blockListUpdateTimer == null)
            {
                _blockListUpdateTimer = new Timer(async delegate (object state)
                {
                    try
                    {
                        if (DateTime.UtcNow > _blockListLastUpdatedOn.AddHours(_blockListUpdateIntervalHours))
                        {
                            if (await _dnsServer.BlockListZoneManager.UpdateBlockListsAsync())
                            {
                                //block lists were updated
                                //save last updated on time
                                _blockListLastUpdatedOn = DateTime.UtcNow;
                                SaveConfigFile();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while updating block lists.\r\n" + ex.ToString());
                    }

                }, null, BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, BLOCK_LIST_UPDATE_TIMER_INTERVAL);
            }
        }

        private void StopBlockListUpdateTimer()
        {
            if (_blockListUpdateTimer != null)
            {
                _blockListUpdateTimer.Dispose();
                _blockListUpdateTimer = null;
            }
        }

        private void StartTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer == null)
            {
                _tlsCertificateUpdateTimer = new Timer(delegate (object state)
                {
                    if (!string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                    {
                        try
                        {
                            FileInfo fileInfo = new FileInfo(_webServiceTlsCertificatePath);

                            if (fileInfo.Exists && (fileInfo.LastWriteTimeUtc != _webServiceTlsCertificateLastModifiedOn))
                                LoadWebServiceTlsCertificate(_webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                        }
                        catch (Exception ex)
                        {
                            _log.Write("DNS Server encountered an error while updating Web Service TLS Certificate: " + _webServiceTlsCertificatePath + "\r\n" + ex.ToString());
                        }
                    }

                    if (!string.IsNullOrEmpty(_dnsTlsCertificatePath))
                    {
                        try
                        {
                            FileInfo fileInfo = new FileInfo(_dnsTlsCertificatePath);

                            if (fileInfo.Exists && (fileInfo.LastWriteTimeUtc != _dnsTlsCertificateLastModifiedOn))
                                LoadDnsTlsCertificate(_dnsTlsCertificatePath, _dnsTlsCertificatePassword);
                        }
                        catch (Exception ex)
                        {
                            _log.Write("DNS Server encountered an error while updating DNS Server TLS Certificate: " + _dnsTlsCertificatePath + "\r\n" + ex.ToString());
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

        private void LoadWebServiceTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword)
        {
            FileInfo fileInfo = new FileInfo(tlsCertificatePath);

            if (!fileInfo.Exists)
                throw new ArgumentException("Web Service TLS certificate file does not exists: " + tlsCertificatePath);

            if (Path.GetExtension(tlsCertificatePath) != ".pfx")
                throw new ArgumentException("Web Service TLS certificate file must be PKCS #12 formatted with .pfx extension: " + tlsCertificatePath);

            X509Certificate2 certificate = new X509Certificate2(tlsCertificatePath, tlsCertificatePassword);

            if (!certificate.Verify())
                throw new ArgumentException("Web Service TLS certificate is invalid.");

            _webServiceTlsCertificate = certificate;
            _webServiceTlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

            _log.Write("Web Service TLS certificate was loaded: " + tlsCertificatePath);
        }

        private void LoadDnsTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword)
        {
            FileInfo fileInfo = new FileInfo(tlsCertificatePath);

            if (!fileInfo.Exists)
                throw new ArgumentException("DNS Server TLS certificate file does not exists: " + tlsCertificatePath);

            if (Path.GetExtension(tlsCertificatePath) != ".pfx")
                throw new ArgumentException("DNS Server TLS certificate file must be PKCS #12 formatted with .pfx extension: " + tlsCertificatePath);

            X509Certificate2 certificate = new X509Certificate2(tlsCertificatePath, tlsCertificatePassword);

            if (!certificate.Verify())
                throw new ArgumentException("DNS Server TLS certificate is invalid.");

            _dnsServer.Certificate = certificate;
            _dnsTlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

            _log.Write("DNS Server TLS certificate was loaded: " + tlsCertificatePath);
        }

        private void LoadConfigFile()
        {
            string configFile = Path.Combine(_configFolder, "dns.config");

            try
            {
                bool passwordResetOption = false;

                if (!File.Exists(configFile))
                {
                    string passwordResetConfigFile = Path.Combine(_configFolder, "reset.config");

                    if (File.Exists(passwordResetConfigFile))
                    {
                        passwordResetOption = true;
                        configFile = passwordResetConfigFile;
                    }
                }

                byte version;

                using (FileStream fS = new FileStream(configFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader bR = new BinaryReader(fS);

                    if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DS") //format
                        throw new InvalidDataException("DnsServer config file format is invalid.");

                    version = bR.ReadByte();
                    switch (version)
                    {
                        case 2:
                        case 3:
                        case 4:
                        case 5:
                        case 6:
                        case 7:
                        case 8:
                        case 9:
                        case 10:
                        case 11:
                        case 12:
                        case 13:
                        case 14:
                            _dnsServer.ServerDomain = bR.ReadShortString();
                            _webServiceHttpPort = bR.ReadInt32();

                            if (version >= 13)
                            {
                                {
                                    int count = bR.ReadByte();
                                    if (count > 0)
                                    {
                                        IPAddress[] localAddresses = new IPAddress[count];

                                        for (int i = 0; i < count; i++)
                                            localAddresses[i] = IPAddressExtension.Parse(bR);

                                        _webServiceLocalAddresses = localAddresses;
                                    }
                                }

                                _webServiceTlsPort = bR.ReadInt32();
                                _webServiceEnableTls = bR.ReadBoolean();
                                _webServiceHttpToTlsRedirect = bR.ReadBoolean();
                                _webServiceTlsCertificatePath = bR.ReadShortString();
                                _webServiceTlsCertificatePassword = bR.ReadShortString();

                                if (_webServiceTlsCertificatePath.Length == 0)
                                    _webServiceTlsCertificatePath = null;

                                if (_webServiceTlsCertificatePath != null)
                                {
                                    try
                                    {
                                        LoadWebServiceTlsCertificate(_webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                                    }
                                    catch (Exception ex)
                                    {
                                        _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + _webServiceTlsCertificatePath + "\r\n" + ex.ToString());
                                    }

                                    StartTlsCertificateUpdateTimer();
                                }
                            }

                            _dnsServer.PreferIPv6 = bR.ReadBoolean();

                            if (bR.ReadBoolean()) //logQueries
                                _dnsServer.QueryLogManager = _log;

                            if (version >= 14)
                                _dnsServer.StatsManager.MaxStatFileDays = bR.ReadInt32();

                            _dnsServer.AllowRecursion = bR.ReadBoolean();

                            if (version >= 4)
                                _dnsServer.AllowRecursionOnlyForPrivateNetworks = bR.ReadBoolean();
                            else
                                _dnsServer.AllowRecursionOnlyForPrivateNetworks = true; //default true for security reasons

                            if (version >= 12)
                                _dnsServer.RandomizeName = bR.ReadBoolean();
                            else
                                _dnsServer.RandomizeName = true; //default true to enable security feature

                            if (version >= 13)
                            {
                                _dnsServer.ServeStale = bR.ReadBoolean();
                                _dnsServer.CacheZoneManager.ServeStaleTtl = bR.ReadUInt32();
                            }

                            if (version >= 9)
                            {
                                _dnsServer.CachePrefetchEligibility = bR.ReadInt32();
                                _dnsServer.CachePrefetchTrigger = bR.ReadInt32();
                                _dnsServer.CachePrefetchSampleIntervalInMinutes = bR.ReadInt32();
                                _dnsServer.CachePrefetchSampleEligibilityHitsPerHour = bR.ReadInt32();
                            }

                            NetProxyType proxyType = (NetProxyType)bR.ReadByte();
                            if (proxyType != NetProxyType.None)
                            {
                                string address = bR.ReadShortString();
                                int port = bR.ReadInt32();
                                NetworkCredential credential = null;

                                if (bR.ReadBoolean()) //credential set
                                    credential = new NetworkCredential(bR.ReadShortString(), bR.ReadShortString());

                                _dnsServer.Proxy = NetProxy.CreateProxy(proxyType, address, port, credential);

                                if (version >= 10)
                                {
                                    int count = bR.ReadByte();
                                    _dnsServer.Proxy.BypassList.Clear();

                                    for (int i = 0; i < count; i++)
                                        _dnsServer.Proxy.BypassList.Add(new NetProxyBypassItem(bR.ReadShortString()));
                                }
                            }
                            else
                            {
                                _dnsServer.Proxy = null;
                            }

                            {
                                int count = bR.ReadByte();
                                if (count > 0)
                                {
                                    NameServerAddress[] forwarders = new NameServerAddress[count];

                                    for (int i = 0; i < count; i++)
                                        forwarders[i] = new NameServerAddress(bR);

                                    _dnsServer.Forwarders = forwarders;
                                }
                            }

                            if (version <= 10)
                            {
                                DnsTransportProtocol forwarderProtocol = (DnsTransportProtocol)bR.ReadByte();

                                if (_dnsServer.Forwarders != null)
                                {
                                    List<NameServerAddress> forwarders = new List<NameServerAddress>();

                                    foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                                    {
                                        if (forwarder.Protocol == forwarderProtocol)
                                            forwarders.Add(forwarder);
                                        else
                                            forwarders.Add(new NameServerAddress(forwarder, forwarderProtocol));
                                    }

                                    _dnsServer.Forwarders = forwarders;
                                }
                            }

                            {
                                int count = bR.ReadByte();
                                if (count > 0)
                                {
                                    if (version > 2)
                                    {
                                        for (int i = 0; i < count; i++)
                                            LoadCredentials(bR.ReadShortString(), bR.ReadShortString());
                                    }
                                    else
                                    {
                                        for (int i = 0; i < count; i++)
                                            SetCredentials(bR.ReadShortString(), bR.ReadShortString());
                                    }
                                }
                            }

                            if (version <= 6)
                            {
                                int count = bR.ReadInt32();
                                _configDisabledZones = new List<string>(count);

                                for (int i = 0; i < count; i++)
                                {
                                    string domain = bR.ReadShortString();
                                    _configDisabledZones.Add(domain);
                                }
                            }

                            if (version > 4)
                            {
                                //read block list urls
                                int count = bR.ReadByte();

                                for (int i = 0; i < count; i++)
                                    _dnsServer.BlockListZoneManager.BlockListUrls.Add(new Uri(bR.ReadShortString()));

                                _blockListLastUpdatedOn = bR.ReadDate();

                                if (version >= 13)
                                    _blockListUpdateIntervalHours = bR.ReadInt32();
                            }

                            if (version >= 11)
                            {
                                int count = bR.ReadByte();
                                if (count > 0)
                                {
                                    IPEndPoint[] localEndPoints = new IPEndPoint[count];

                                    for (int i = 0; i < count; i++)
                                        localEndPoints[i] = (IPEndPoint)EndPointExtension.Parse(bR);

                                    _dnsServer.LocalEndPoints = localEndPoints;
                                }
                            }
                            else if (version >= 6)
                            {
                                int count = bR.ReadByte();
                                if (count > 0)
                                {
                                    IPEndPoint[] localEndPoints = new IPEndPoint[count];

                                    for (int i = 0; i < count; i++)
                                        localEndPoints[i] = new IPEndPoint(IPAddressExtension.Parse(bR), 53);

                                    _dnsServer.LocalEndPoints = localEndPoints;
                                }
                            }

                            if (version >= 8)
                            {
                                _dnsServer.EnableDnsOverHttp = bR.ReadBoolean();
                                _dnsServer.EnableDnsOverTls = bR.ReadBoolean();
                                _dnsServer.EnableDnsOverHttps = bR.ReadBoolean();
                                _dnsTlsCertificatePath = bR.ReadShortString();
                                _dnsTlsCertificatePassword = bR.ReadShortString();

                                if (_dnsTlsCertificatePath.Length == 0)
                                    _dnsTlsCertificatePath = null;

                                if (_dnsTlsCertificatePath != null)
                                {
                                    try
                                    {
                                        LoadDnsTlsCertificate(_dnsTlsCertificatePath, _dnsTlsCertificatePassword);
                                    }
                                    catch (Exception ex)
                                    {
                                        _log.Write("DNS Server encountered an error while loading DNS Server TLS certificate: " + _dnsTlsCertificatePath + "\r\n" + ex.ToString());
                                    }

                                    StartTlsCertificateUpdateTimer();
                                }
                            }

                            break;

                        default:
                            throw new InvalidDataException("DNS Server config version not supported.");
                    }
                }

                _log.Write("DNS Server config file was loaded: " + configFile);

                if (passwordResetOption)
                {
                    SetCredentials("admin", "admin");

                    _log.Write("DNS Server reset password for user: admin");
                    SaveConfigFile();

                    try
                    {
                        File.Delete(configFile);
                    }
                    catch
                    { }
                }

                if (version <= 6)
                    SaveConfigFile(); //save as new config version to avoid loading old version next time
            }
            catch (FileNotFoundException)
            {
                _log.Write("DNS Server config file was not found: " + configFile);
                _log.Write("DNS Server is restoring default config file.");

                SetCredentials("admin", "admin");

                _dnsServer.AllowRecursion = true;
                _dnsServer.AllowRecursionOnlyForPrivateNetworks = true; //default true for security reasons
                _dnsServer.RandomizeName = true; //default true to enable security feature

                SaveConfigFile();
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading config file: " + configFile + "\r\n" + ex.ToString());
                _log.Write("Note: You may try deleting the config file to fix this issue. However, you will lose DNS settings but, zone data wont be affected.");
                throw;
            }
        }

        private void SaveConfigFile()
        {
            string configFile = Path.Combine(_configFolder, "dns.config");

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize config
                BinaryWriter bW = new BinaryWriter(mS);

                bW.Write(Encoding.ASCII.GetBytes("DS")); //format
                bW.Write((byte)14); //version

                bW.WriteShortString(_dnsServer.ServerDomain);
                bW.Write(_webServiceHttpPort);

                {
                    bW.Write(Convert.ToByte(_webServiceLocalAddresses.Count));

                    foreach (IPAddress localAddress in _webServiceLocalAddresses)
                        localAddress.WriteTo(bW);
                }

                bW.Write(_webServiceTlsPort);
                bW.Write(_webServiceEnableTls);
                bW.Write(_webServiceHttpToTlsRedirect);

                if (_webServiceTlsCertificatePath == null)
                    bW.WriteShortString(string.Empty);
                else
                    bW.WriteShortString(_webServiceTlsCertificatePath);

                if (_webServiceTlsCertificatePassword == null)
                    bW.WriteShortString(string.Empty);
                else
                    bW.WriteShortString(_webServiceTlsCertificatePassword);

                bW.Write(_dnsServer.PreferIPv6);

                bW.Write(_dnsServer.QueryLogManager != null); //logQueries
                bW.Write(_dnsServer.StatsManager.MaxStatFileDays);

                bW.Write(_dnsServer.AllowRecursion);
                bW.Write(_dnsServer.AllowRecursionOnlyForPrivateNetworks);
                bW.Write(_dnsServer.RandomizeName);

                bW.Write(_dnsServer.ServeStale);
                bW.Write(_dnsServer.CacheZoneManager.ServeStaleTtl);

                bW.Write(_dnsServer.CachePrefetchEligibility);
                bW.Write(_dnsServer.CachePrefetchTrigger);
                bW.Write(_dnsServer.CachePrefetchSampleIntervalInMinutes);
                bW.Write(_dnsServer.CachePrefetchSampleEligibilityHitsPerHour);

                if (_dnsServer.Proxy == null)
                {
                    bW.Write((byte)NetProxyType.None);
                }
                else
                {
                    bW.Write((byte)_dnsServer.Proxy.Type);
                    bW.WriteShortString(_dnsServer.Proxy.Address);
                    bW.Write(_dnsServer.Proxy.Port);

                    NetworkCredential credential = _dnsServer.Proxy.Credential;

                    if (credential == null)
                    {
                        bW.Write(false);
                    }
                    else
                    {
                        bW.Write(true);
                        bW.WriteShortString(credential.UserName);
                        bW.WriteShortString(credential.Password);
                    }

                    //bypass list
                    {
                        bW.Write(Convert.ToByte(_dnsServer.Proxy.BypassList.Count));

                        foreach (NetProxyBypassItem item in _dnsServer.Proxy.BypassList)
                            bW.WriteShortString(item.Value);
                    }
                }

                if (_dnsServer.Forwarders == null)
                {
                    bW.Write((byte)0);
                }
                else
                {
                    bW.Write(Convert.ToByte(_dnsServer.Forwarders.Count));

                    foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                        forwarder.WriteTo(bW);
                }

                {
                    bW.Write(Convert.ToByte(_credentials.Count));

                    foreach (KeyValuePair<string, string> credential in _credentials)
                    {
                        bW.WriteShortString(credential.Key);
                        bW.WriteShortString(credential.Value);
                    }
                }

                //block list
                {
                    bW.Write(Convert.ToByte(_dnsServer.BlockListZoneManager.BlockListUrls.Count));

                    foreach (Uri blockListUrl in _dnsServer.BlockListZoneManager.BlockListUrls)
                        bW.WriteShortString(blockListUrl.AbsoluteUri);

                    bW.Write(_blockListLastUpdatedOn);
                    bW.Write(_blockListUpdateIntervalHours);
                }


                {
                    bW.Write(Convert.ToByte(_dnsServer.LocalEndPoints.Count));

                    foreach (IPEndPoint localEP in _dnsServer.LocalEndPoints)
                        localEP.WriteTo(bW);
                }

                bW.Write(_dnsServer.EnableDnsOverHttp);
                bW.Write(_dnsServer.EnableDnsOverTls);
                bW.Write(_dnsServer.EnableDnsOverHttps);

                if (_dnsTlsCertificatePath == null)
                    bW.WriteShortString(string.Empty);
                else
                    bW.WriteShortString(_dnsTlsCertificatePath);

                if (_dnsTlsCertificatePassword == null)
                    bW.WriteShortString(string.Empty);
                else
                    bW.WriteShortString(_dnsTlsCertificatePassword);

                //write config
                mS.Position = 0;

                using (FileStream fS = new FileStream(configFile, FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _log.Write("DNS Server config file was saved: " + configFile);
        }

        private void StartWebService()
        {
            //HTTP service
            try
            {
                string webServiceHostname = null;

                _webService = new HttpListener();

                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                {
                    string host;

                    if (webServiceLocalAddress.Equals(IPAddress.Any) || webServiceLocalAddress.Equals(IPAddress.IPv6Any))
                    {
                        host = "+";
                    }
                    else
                    {
                        if (webServiceLocalAddress.AddressFamily == AddressFamily.InterNetworkV6)
                            host = "[" + webServiceLocalAddress.ToString() + "]";
                        else
                            host = webServiceLocalAddress.ToString();

                        if (webServiceHostname == null)
                            webServiceHostname = host;
                    }

                    _webService.Prefixes.Add("http://" + host + ":" + _webServiceHttpPort + "/");
                }

                _webService.Start();

                _webServiceHostname = webServiceHostname ?? Environment.MachineName.ToLower();
            }
            catch (Exception ex)
            {
                _log.Write("Web Service failed to bind using default hostname. Attempting to bind again using 'localhost' hostname.\r\n" + ex.ToString());

                _webService = new HttpListener();
                _webService.Prefixes.Add("http://localhost:" + _webServiceHttpPort + "/");
                _webService.Start();

                _webServiceHostname = "localhost";
            }

            _webService.IgnoreWriteExceptions = true;

            _ = Task.Factory.StartNew(delegate ()
            {
                return AcceptWebRequestAsync();
            }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _webServiceTaskScheduler);

            _log.Write(new IPEndPoint(IPAddress.Any, _webServiceHttpPort), "HTTP Web Service was started successfully.");

            //TLS service
            if (_webServiceEnableTls && (_webServiceTlsCertificate != null))
            {
                List<Socket> webServiceTlsListeners = new List<Socket>();

                try
                {
                    foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                    {
                        Socket tlsListener = new Socket(webServiceLocalAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        tlsListener.Bind(new IPEndPoint(webServiceLocalAddress, _webServiceTlsPort));
                        tlsListener.Listen(10);

                        webServiceTlsListeners.Add(tlsListener);
                    }

                    foreach (Socket tlsListener in webServiceTlsListeners)
                    {
                        _ = Task.Factory.StartNew(delegate ()
                        {
                            return AcceptTlsWebRequestAsync(tlsListener);
                        }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _webServiceTaskScheduler);
                    }

                    _webServiceTlsListeners = webServiceTlsListeners;

                    _log.Write(new IPEndPoint(IPAddress.Any, _webServiceHttpPort), "TLS Web Service was started successfully.");
                }
                catch (Exception ex)
                {
                    _log.Write("TLS Web Service failed to start.\r\n" + ex.ToString());

                    foreach (Socket tlsListener in webServiceTlsListeners)
                        tlsListener.Dispose();
                }
            }
        }

        private void StopWebService()
        {
            _webService.Stop();

            if (_webServiceTlsListeners != null)
            {
                foreach (Socket tlsListener in _webServiceTlsListeners)
                    tlsListener.Dispose();

                _webServiceTlsListeners = null;
            }
        }

        #endregion

        #region public

        public void Start()
        {
            if (_disposed)
                throw new ObjectDisposedException("WebService");

            if (_state != ServiceState.Stopped)
                throw new InvalidOperationException("Web Service is already running.");

            _state = ServiceState.Starting;

            try
            {
                //get initial server domain
                string dnsServerDomain = Environment.MachineName.ToLower();
                if (!DnsClient.IsDomainNameValid(dnsServerDomain))
                    dnsServerDomain = "dns-server-1"; //use this name instead since machine name is not a valid domain name

                //init dns server
                _dnsServer = new DnsServer(dnsServerDomain, _configFolder, Path.Combine(_appFolder, "dohwww"), _log);

                //init dhcp server
                _dhcpServer = new DhcpServer(Path.Combine(_configFolder, "scopes"), _log);
                _dhcpServer.AuthZoneManager = _dnsServer.AuthZoneManager;

                //load config
                LoadConfigFile();

                //load all zones files
                _dnsServer.AuthZoneManager.LoadAllZoneFiles();

                //disable zones from old config format
                if (_configDisabledZones != null)
                {
                    foreach (string domain in _configDisabledZones)
                    {
                        AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
                        if (zoneInfo != null)
                        {
                            zoneInfo.Disabled = true;
                            _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                        }
                    }
                }

                //load allowed zone and blocked zone
                _dnsServer.AllowedZoneManager.LoadAllowedZoneFile();
                _dnsServer.BlockedZoneManager.LoadBlockedZoneFile();

                //load block list zone async
                if (_dnsServer.BlockListZoneManager.BlockListUrls.Count > 0)
                {
                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            _dnsServer.BlockListZoneManager.LoadBlockLists();
                            StartBlockListUpdateTimer();
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }
                    });
                }

                //start dns and dhcp
                _dnsServer.Start();
                _dhcpServer.Start();

                //start web service
                StartWebService();

                _state = ServiceState.Running;

                _log.Write("DNS Server (v" + _currentVersion.ToString() + ") was started successfully.");
            }
            catch (Exception ex)
            {
                _log.Write("Failed to start DNS Server (v" + _currentVersion.ToString() + ")\r\n" + ex.ToString());
                throw;
            }
        }

        public void Stop()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            try
            {
                StopWebService();
                _dnsServer.Stop();
                _dhcpServer.Stop();

                StopBlockListUpdateTimer();
                StopTlsCertificateUpdateTimer();

                _state = ServiceState.Stopped;

                _log.Write("DNS Server (v" + _currentVersion.ToString() + ") was stopped successfully.");
            }
            catch (Exception ex)
            {
                _log.Write("Failed to stop DNS Server (v" + _currentVersion.ToString() + ")\r\n" + ex.ToString());
                throw;
            }
        }

        #endregion

        #region properties

        public string ConfigFolder
        { get { return _configFolder; } }

        public int WebServiceHttpPort
        { get { return _webServiceHttpPort; } }

        public string WebServiceHostname
        { get { return _webServiceHostname; } }

        #endregion
    }
}
