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
using DnsServerCore.Dns;
using DnsServerCore.Dns.ZoneManagers;
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
using TechnitiumLibrary.Net.Http;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    public sealed class DnsWebService : IDisposable
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

        readonly static RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        readonly WebServiceDashboardApi _dashboardApi;
        readonly WebServiceZonesApi _zonesApi;
        readonly WebServiceOtherZonesApi _otherZonesApi;
        readonly WebServiceAppsApi _appsApi;
        readonly WebServiceDhcpApi _dhcpApi;
        readonly WebServiceLogsApi _logsApi;

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
        bool _webServiceUseSelfSignedTlsCertificate;
        string _webServiceTlsCertificatePath;
        string _webServiceTlsCertificatePassword;
        DateTime _webServiceTlsCertificateLastModifiedOn;

        HttpListener _webService;
        IReadOnlyList<Socket> _webServiceTlsListeners;
        X509Certificate2 _webServiceTlsCertificate;
        readonly IndependentTaskScheduler _webServiceTaskScheduler = new IndependentTaskScheduler(ThreadPriority.AboveNormal);
        string _webServiceHostname;
        IPEndPoint _webServiceHttpEP;

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
        const int BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL = 900000;

        Timer _temporaryDisableBlockingTimer;
        DateTime _temporaryDisableBlockingTill;

        List<string> _configDisabledZones;

        #endregion

        #region constructor

        public DnsWebService(string configFolder = null, Uri updateCheckUri = null, Uri appStoreUri = null)
        {
            _dashboardApi = new WebServiceDashboardApi(this);
            _zonesApi = new WebServiceZonesApi(this);
            _otherZonesApi = new WebServiceOtherZonesApi(this);
            _appsApi = new WebServiceAppsApi(this, appStoreUri);
            _dhcpApi = new WebServiceDhcpApi(this);
            _logsApi = new WebServiceLogsApi(this);

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

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            Stop();

            if (_webService != null)
                _webService.Close();

            if (_dnsServer != null)
                _dnsServer.Dispose();

            if (_dhcpServer != null)
                _dhcpServer.Dispose();

            if (_log != null)
                _log.Dispose();

            _disposed = true;
        }

        #endregion

        #region private

        #region web service

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
            Socket tunnel = null;

            try
            {
                if (_webServiceLocalAddresses.Count < 1)
                    return;

                string remoteIP = (socket.RemoteEndPoint as IPEndPoint).Address.ToString();

                SslStream sslStream = new SslStream(new NetworkStream(socket, true));

                await sslStream.AuthenticateAsServerAsync(_webServiceTlsCertificate);

                tunnel = new Socket(_webServiceHttpEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                tunnel.Connect(_webServiceHttpEP);

                NetworkStream tunnelStream = new NetworkStream(tunnel, true);

                //copy tunnel to ssl
                _ = tunnelStream.CopyToAsync(sslStream).ContinueWith(delegate (Task prevTask) { sslStream.Dispose(); tunnelStream.Dispose(); });

                //copy ssl to tunnel
                try
                {
                    while (true)
                    {
                        HttpRequest httpRequest = await HttpRequest.ReadRequestAsync(sslStream);
                        if (httpRequest == null)
                            return; //connection closed gracefully by client

                        //inject X-Real-IP & host header
                        httpRequest.Headers.Add("X-Real-IP", remoteIP);
                        httpRequest.Headers[HttpRequestHeader.Host] = "localhost:" + _webServiceHttpPort.ToString();

                        //relay request
                        await tunnelStream.WriteAsync(Encoding.ASCII.GetBytes(httpRequest.HttpMethod + " " + httpRequest.RequestPathAndQuery + " " + httpRequest.Protocol + "\r\n"));
                        await tunnelStream.WriteAsync(httpRequest.Headers.ToByteArray());

                        if (httpRequest.InputStream != null)
                            await httpRequest.InputStream.CopyToAsync(tunnelStream);

                        await tunnelStream.FlushAsync();
                    }
                }
                finally
                {
                    sslStream.Dispose();
                    tunnelStream.Dispose();
                }
            }
            catch (IOException)
            {
                //ignore
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
            finally
            {
                socket.Dispose();

                if (tunnel != null)
                    tunnel.Dispose();
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

                                            case "/api/temporaryDisableBlocking":
                                                TemporaryDisableBlocking(request, jsonWriter);
                                                break;

                                            case "/api/backupSettings":
                                                await BackupSettingsAsync(request, response);
                                                return;

                                            case "/api/restoreSettings":
                                                await RestoreSettingsAsync(request, jsonWriter);
                                                break;

                                            case "/api/getStats":
                                                await _dashboardApi.GetStats(request, jsonWriter);
                                                break;

                                            case "/api/getTopStats":
                                                await _dashboardApi.GetTopStats(request, jsonWriter);
                                                break;

                                            case "/api/flushDnsCache":
                                                _otherZonesApi.FlushCache(request);
                                                break;

                                            case "/api/listCachedZones":
                                                _otherZonesApi.ListCachedZones(request, jsonWriter);
                                                break;

                                            case "/api/deleteCachedZone":
                                                _otherZonesApi.DeleteCachedZone(request);
                                                break;

                                            case "/api/listAllowedZones":
                                                _otherZonesApi.ListAllowedZones(request, jsonWriter);
                                                break;

                                            case "/api/importAllowedZones":
                                                _otherZonesApi.ImportAllowedZones(request);
                                                break;

                                            case "/api/exportAllowedZones":
                                                _otherZonesApi.ExportAllowedZones(response);
                                                return;

                                            case "/api/deleteAllowedZone":
                                                _otherZonesApi.DeleteAllowedZone(request);
                                                break;

                                            case "/api/allowZone":
                                                _otherZonesApi.AllowZone(request);
                                                break;

                                            case "/api/listBlockedZones":
                                                _otherZonesApi.ListBlockedZones(request, jsonWriter);
                                                break;

                                            case "/api/importBlockedZones":
                                                _otherZonesApi.ImportBlockedZones(request);
                                                break;

                                            case "/api/exportBlockedZones":
                                                _otherZonesApi.ExportBlockedZones(response);
                                                return;

                                            case "/api/deleteBlockedZone":
                                                _otherZonesApi.DeleteBlockedZone(request);
                                                break;

                                            case "/api/blockZone":
                                                _otherZonesApi.BlockZone(request);
                                                break;

                                            case "/api/listZones":
                                                _zonesApi.ListZones(jsonWriter);
                                                break;

                                            case "/api/createZone":
                                                await _zonesApi.CreateZoneAsync(request, jsonWriter);
                                                break;

                                            case "/api/deleteZone":
                                                _zonesApi.DeleteZone(request);
                                                break;

                                            case "/api/enableZone":
                                                _zonesApi.EnableZone(request);
                                                break;

                                            case "/api/disableZone":
                                                _zonesApi.DisableZone(request);
                                                break;

                                            case "/api/zone/options/get":
                                                _zonesApi.GetZoneOptions(request, jsonWriter);
                                                break;

                                            case "/api/zone/options/set":
                                                _zonesApi.SetZoneOptions(request);
                                                break;

                                            case "/api/zone/resync":
                                                _zonesApi.ResyncZone(request);
                                                break;

                                            case "/api/addRecord":
                                                _zonesApi.AddRecord(request);
                                                break;

                                            case "/api/getRecords":
                                                _zonesApi.GetRecords(request, jsonWriter);
                                                break;

                                            case "/api/deleteRecord":
                                                _zonesApi.DeleteRecord(request);
                                                break;

                                            case "/api/updateRecord":
                                                _zonesApi.UpdateRecord(request);
                                                break;

                                            case "/api/apps/list":
                                                await _appsApi.ListInstalledAppsAsync(jsonWriter);
                                                break;

                                            case "/api/apps/listStoreApps":
                                                await _appsApi.ListStoreApps(jsonWriter);
                                                break;

                                            case "/api/apps/downloadAndInstall":
                                                await _appsApi.DownloadAndInstallAppAsync(request);
                                                break;

                                            case "/api/apps/downloadAndUpdate":
                                                await _appsApi.DownloadAndUpdateAppAsync(request);
                                                break;

                                            case "/api/apps/install":
                                                await _appsApi.InstallAppAsync(request);
                                                break;

                                            case "/api/apps/update":
                                                await _appsApi.UpdateAppAsync(request);
                                                break;

                                            case "/api/apps/uninstall":
                                                _appsApi.UninstallApp(request);
                                                break;

                                            case "/api/apps/getConfig":
                                                await _appsApi.GetAppConfigAsync(request, jsonWriter);
                                                break;

                                            case "/api/apps/setConfig":
                                                await _appsApi.SetAppConfigAsync(request);
                                                break;

                                            case "/api/resolveQuery":
                                                await ResolveQuery(request, jsonWriter);
                                                break;

                                            case "/api/listLogs":
                                                _logsApi.ListLogs(jsonWriter);
                                                break;

                                            case "/api/deleteLog":
                                                _logsApi.DeleteLog(request);
                                                break;

                                            case "/api/deleteAllLogs":
                                                _logsApi.DeleteAllLogs(request);
                                                break;

                                            case "/api/deleteAllStats":
                                                _logsApi.DeleteAllStats(request);
                                                break;

                                            case "/api/queryLogs":
                                                await _logsApi.QueryLogsAsync(request, jsonWriter);
                                                break;

                                            case "/api/listDhcpScopes":
                                                _dhcpApi.ListDhcpScopes(jsonWriter);
                                                break;

                                            case "/api/listDhcpLeases":
                                                _dhcpApi.ListDhcpLeases(jsonWriter);
                                                break;

                                            case "/api/getDhcpScope":
                                                _dhcpApi.GetDhcpScope(request, jsonWriter);
                                                break;

                                            case "/api/setDhcpScope":
                                                await _dhcpApi.SetDhcpScopeAsync(request);
                                                break;

                                            case "/api/enableDhcpScope":
                                                await _dhcpApi.EnableDhcpScopeAsync(request);
                                                break;

                                            case "/api/disableDhcpScope":
                                                _dhcpApi.DisableDhcpScope(request);
                                                break;

                                            case "/api/deleteDhcpScope":
                                                _dhcpApi.DeleteDhcpScope(request);
                                                break;

                                            case "/api/removeDhcpLease":
                                                _dhcpApi.RemoveDhcpLease(request);
                                                break;

                                            case "/api/convertToReservedLease":
                                                _dhcpApi.ConvertToReservedLease(request);
                                                break;

                                            case "/api/convertToDynamicLease":
                                                _dhcpApi.ConvertToDynamicLease(request);
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

                        mS.Position = 0;
                        using (Stream stream = response.OutputStream)
                        {
                            await mS.CopyToAsync(stream);
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

        internal static IPEndPoint GetRequestRemoteEndPoint(HttpListenerRequest request)
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
                    await stream.WriteAsync(buffer);
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

        #endregion

        #region user session

        private string CreateSession(string username)
        {
            string token = BinaryNumber.GenerateRandomNumber256().ToString();

            if (!_sessions.TryAdd(token, new UserSession(username)))
                throw new DnsWebServiceException("Error while creating session. Please try again.");

            return token;
        }

        private UserSession GetSession(string token)
        {
            if (_sessions.TryGetValue(token, out UserSession session))
                return session;

            return null;
        }

        internal UserSession GetSession(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new DnsWebServiceException("Parameter 'token' missing.");

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
                throw new DnsWebServiceException("Parameter 'token' missing.");

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

        #endregion

        #region auth api

        private async Task LoginAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strUsername = request.QueryString["user"];
            if (string.IsNullOrEmpty(strUsername))
                throw new DnsWebServiceException("Parameter 'user' missing.");

            string strPassword = request.QueryString["pass"];
            if (string.IsNullOrEmpty(strPassword))
                throw new DnsWebServiceException("Parameter 'pass' missing.");

            IPEndPoint remoteEP = GetRequestRemoteEndPoint(request);

            if (IsAddressBlocked(remoteEP.Address))
                throw new DnsWebServiceException("Max limit of " + MAX_LOGIN_ATTEMPTS + " attempts exceeded. Access blocked for " + (BLOCK_ADDRESS_INTERVAL / 1000) + " seconds.");

            strUsername = strUsername.Trim().ToLower();
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

                throw new DnsWebServiceException("Invalid username or password for user: " + strUsername);
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
                throw new DnsWebServiceException("Parameter 'token' missing.");

            string strPassword = request.QueryString["pass"];
            if (string.IsNullOrEmpty(strPassword))
                throw new DnsWebServiceException("Parameter 'pass' missing.");

            UserSession session = GetSession(strToken);
            if (session == null)
                throw new DnsWebServiceException("User session does not exists.");

            SetCredentials(session.Username, strPassword);
            SaveConfigFile();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + session.Username + "] Password was changed for user.");
        }

        private void Logout(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new DnsWebServiceException("Parameter 'token' missing.");

            UserSession session = DeleteSession(strToken);

            if (session != null)
                _log.Write(GetRequestRemoteEndPoint(request), "[" + session.Username + "] User logged out.");
        }

        #endregion

        #region update api

        private async Task CheckForUpdateAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            if (_updateCheckUri is null)
            {
                jsonWriter.WritePropertyName("updateAvailable");
                jsonWriter.WriteValue(false);
                return;
            }

            try
            {
                SocketsHttpHandler handler = new SocketsHttpHandler();
                handler.Proxy = _dnsServer.Proxy;

                using (HttpClient http = new HttpClient(handler))
                {
                    string response = await http.GetStringAsync(_updateCheckUri);
                    dynamic jsonResponse = JsonConvert.DeserializeObject(response);

                    string updateVersion = jsonResponse.updateVersion.Value;
                    string updateTitle = jsonResponse.updateTitle?.Value;
                    string updateMessage = jsonResponse.updateMessage?.Value;
                    string downloadLink = jsonResponse.downloadLink?.Value;
                    string instructionsLink = jsonResponse.instructionsLink?.Value;
                    string changeLogLink = jsonResponse.changeLogLink?.Value;

                    bool updateAvailable = new Version(updateVersion) > _currentVersion;

                    jsonWriter.WritePropertyName("updateAvailable");
                    jsonWriter.WriteValue(updateAvailable);

                    jsonWriter.WritePropertyName("updateVersion");
                    jsonWriter.WriteValue(updateVersion);

                    jsonWriter.WritePropertyName("currentVersion");
                    jsonWriter.WriteValue(GetCleanVersion(_currentVersion));

                    if (updateAvailable)
                    {
                        jsonWriter.WritePropertyName("updateTitle");
                        jsonWriter.WriteValue(updateTitle);

                        jsonWriter.WritePropertyName("updateMessage");
                        jsonWriter.WriteValue(updateMessage);

                        jsonWriter.WritePropertyName("downloadLink");
                        jsonWriter.WriteValue(downloadLink);

                        jsonWriter.WritePropertyName("instructionsLink");
                        jsonWriter.WriteValue(instructionsLink);

                        jsonWriter.WritePropertyName("changeLogLink");
                        jsonWriter.WriteValue(changeLogLink);
                    }

                    string strLog = "Check for update was done {updateAvailable: " + updateAvailable + "; updateVersion: " + updateVersion + ";";

                    if (!string.IsNullOrEmpty(updateTitle))
                        strLog += " updateTitle: " + updateTitle + ";";

                    if (!string.IsNullOrEmpty(updateMessage))
                        strLog += " updateMessage: " + updateMessage + ";";

                    if (!string.IsNullOrEmpty(downloadLink))
                        strLog += " downloadLink: " + downloadLink + ";";

                    if (!string.IsNullOrEmpty(instructionsLink))
                        strLog += " instructionsLink: " + instructionsLink + ";";

                    if (!string.IsNullOrEmpty(changeLogLink))
                        strLog += " changeLogLink: " + changeLogLink + ";";

                    strLog += "}";

                    _log.Write(GetRequestRemoteEndPoint(request), strLog);
                }
            }
            catch (Exception ex)
            {
                _log.Write(GetRequestRemoteEndPoint(request), "Check for update was done {updateAvailable: False;}\r\n" + ex.ToString());

                jsonWriter.WritePropertyName("updateAvailable");
                jsonWriter.WriteValue(false);
            }
        }

        internal static string GetCleanVersion(Version version)
        {
            string strVersion = version.Major + "." + version.Minor;

            if (version.Build > 0)
                strVersion += "." + version.Build;

            if (version.Revision > 0)
                strVersion += "." + version.Revision;

            return strVersion;
        }

        #endregion

        #region settings api

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
            {
                if (localAddress.AddressFamily == AddressFamily.InterNetworkV6)
                    jsonWriter.WriteValue("[" + localAddress.ToString() + "]");
                else
                    jsonWriter.WriteValue(localAddress.ToString());
            }

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("webServiceHttpPort");
            jsonWriter.WriteValue(_webServiceHttpPort);

            jsonWriter.WritePropertyName("webServiceEnableTls");
            jsonWriter.WriteValue(_webServiceEnableTls);

            jsonWriter.WritePropertyName("webServiceHttpToTlsRedirect");
            jsonWriter.WriteValue(_webServiceHttpToTlsRedirect);

            jsonWriter.WritePropertyName("webServiceTlsPort");
            jsonWriter.WriteValue(_webServiceTlsPort);

            jsonWriter.WritePropertyName("webServiceUseSelfSignedTlsCertificate");
            jsonWriter.WriteValue(_webServiceUseSelfSignedTlsCertificate);

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

            jsonWriter.WritePropertyName("tsigKeys");
            {
                jsonWriter.WriteStartArray();

                if (_dnsServer.TsigKeys is not null)
                {
                    foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsServer.TsigKeys)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WritePropertyName("keyName");
                        jsonWriter.WriteValue(tsigKey.Key);

                        jsonWriter.WritePropertyName("sharedSecret");
                        jsonWriter.WriteValue(tsigKey.Value.SharedSecret);

                        jsonWriter.WritePropertyName("algorithmName");
                        jsonWriter.WriteValue(tsigKey.Value.AlgorithmName);

                        jsonWriter.WriteEndObject();
                    }
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("defaultRecordTtl");
            jsonWriter.WriteValue(_zonesApi.DefaultRecordTtl);

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

            jsonWriter.WritePropertyName("recursion");
            jsonWriter.WriteValue(_dnsServer.Recursion.ToString());

            jsonWriter.WritePropertyName("recursionDeniedNetworks");
            {
                jsonWriter.WriteStartArray();

                if (_dnsServer.RecursionDeniedNetworks is not null)
                {
                    foreach (NetworkAddress networkAddress in _dnsServer.RecursionDeniedNetworks)
                        jsonWriter.WriteValue(networkAddress.ToString());
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("recursionAllowedNetworks");
            {
                jsonWriter.WriteStartArray();

                if (_dnsServer.RecursionAllowedNetworks is not null)
                {
                    foreach (NetworkAddress networkAddress in _dnsServer.RecursionAllowedNetworks)
                        jsonWriter.WriteValue(networkAddress.ToString());
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("randomizeName");
            jsonWriter.WriteValue(_dnsServer.RandomizeName);

            jsonWriter.WritePropertyName("qnameMinimization");
            jsonWriter.WriteValue(_dnsServer.QnameMinimization);

            jsonWriter.WritePropertyName("nsRevalidation");
            jsonWriter.WriteValue(_dnsServer.NsRevalidation);

            jsonWriter.WritePropertyName("qpmLimitRequests");
            jsonWriter.WriteValue(_dnsServer.QpmLimitRequests);

            jsonWriter.WritePropertyName("qpmLimitErrors");
            jsonWriter.WriteValue(_dnsServer.QpmLimitErrors);

            jsonWriter.WritePropertyName("qpmLimitSampleMinutes");
            jsonWriter.WriteValue(_dnsServer.QpmLimitSampleMinutes);

            jsonWriter.WritePropertyName("qpmLimitIPv4PrefixLength");
            jsonWriter.WriteValue(_dnsServer.QpmLimitIPv4PrefixLength);

            jsonWriter.WritePropertyName("qpmLimitIPv6PrefixLength");
            jsonWriter.WriteValue(_dnsServer.QpmLimitIPv6PrefixLength);

            jsonWriter.WritePropertyName("serveStale");
            jsonWriter.WriteValue(_dnsServer.ServeStale);

            jsonWriter.WritePropertyName("serveStaleTtl");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.ServeStaleTtl);

            jsonWriter.WritePropertyName("cacheMinimumRecordTtl");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.MinimumRecordTtl);

            jsonWriter.WritePropertyName("cacheMaximumRecordTtl");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.MaximumRecordTtl);

            jsonWriter.WritePropertyName("cacheNegativeRecordTtl");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.NegativeRecordTtl);

            jsonWriter.WritePropertyName("cacheFailureRecordTtl");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.FailureRecordTtl);

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

            jsonWriter.WritePropertyName("enableBlocking");
            jsonWriter.WriteValue(_dnsServer.EnableBlocking);

            jsonWriter.WritePropertyName("allowTxtBlockingReport");
            jsonWriter.WriteValue(_dnsServer.AllowTxtBlockingReport);

            if (!_dnsServer.EnableBlocking && (DateTime.UtcNow < _temporaryDisableBlockingTill))
            {
                jsonWriter.WritePropertyName("temporaryDisableBlockingTill");
                jsonWriter.WriteValue(_temporaryDisableBlockingTill);
            }

            jsonWriter.WritePropertyName("blockingType");
            jsonWriter.WriteValue(_dnsServer.BlockingType.ToString());

            jsonWriter.WritePropertyName("customBlockingAddresses");
            jsonWriter.WriteStartArray();

            foreach (DnsARecord record in _dnsServer.CustomBlockingARecords)
                jsonWriter.WriteValue(record.Address.ToString());

            foreach (DnsAAAARecord record in _dnsServer.CustomBlockingAAAARecords)
                jsonWriter.WriteValue(record.Address.ToString());

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("blockListUrls");

            if ((_dnsServer.BlockListZoneManager.AllowListUrls.Count == 0) && (_dnsServer.BlockListZoneManager.BlockListUrls.Count == 0))
            {
                jsonWriter.WriteNull();
            }
            else
            {
                jsonWriter.WriteStartArray();

                foreach (Uri allowListUrl in _dnsServer.BlockListZoneManager.AllowListUrls)
                    jsonWriter.WriteValue("!" + allowListUrl.AbsoluteUri);

                foreach (Uri blockListUrl in _dnsServer.BlockListZoneManager.BlockListUrls)
                    jsonWriter.WriteValue(blockListUrl.AbsoluteUri);

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("blockListUpdateIntervalHours");
            jsonWriter.WriteValue(_blockListUpdateIntervalHours);

            if (_blockListUpdateTimer is not null)
            {
                DateTime blockListNextUpdatedOn = _blockListLastUpdatedOn.AddHours(_blockListUpdateIntervalHours);

                jsonWriter.WritePropertyName("blockListNextUpdatedOn");
                jsonWriter.WriteValue(blockListNextUpdatedOn);
            }
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

            string strWebServiceUseSelfSignedTlsCertificate = request.QueryString["webServiceUseSelfSignedTlsCertificate"];
            if (!string.IsNullOrEmpty(strWebServiceUseSelfSignedTlsCertificate))
                _webServiceUseSelfSignedTlsCertificate = bool.Parse(strWebServiceUseSelfSignedTlsCertificate);

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

            string strTsigKeys = request.QueryString["tsigKeys"];
            if (!string.IsNullOrEmpty(strTsigKeys))
            {
                if (strTsigKeys == "false")
                {
                    _dnsServer.TsigKeys = null;
                }
                else
                {
                    string[] strTsigKeyParts = strTsigKeys.Split('|');
                    Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(strTsigKeyParts.Length);

                    for (int i = 0; i < strTsigKeyParts.Length; i += 3)
                    {
                        string keyName = strTsigKeyParts[i + 0].ToLower();
                        string sharedSecret = strTsigKeyParts[i + 1];
                        string algorithmName = strTsigKeyParts[i + 2];

                        if (sharedSecret.Length == 0)
                        {
                            byte[] key = new byte[32];
                            _rng.GetBytes(key);

                            tsigKeys.Add(keyName, new TsigKey(keyName, Convert.ToBase64String(key), algorithmName));
                        }
                        else
                        {
                            tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, algorithmName));
                        }
                    }

                    _dnsServer.TsigKeys = tsigKeys;
                }
            }

            string strPreferIPv6 = request.QueryString["preferIPv6"];
            if (!string.IsNullOrEmpty(strPreferIPv6))
                _dnsServer.PreferIPv6 = bool.Parse(strPreferIPv6);

            string strDefaultRecordTtl = request.QueryString["defaultRecordTtl"];
            if (!string.IsNullOrEmpty(strDefaultRecordTtl))
                _zonesApi.DefaultRecordTtl = uint.Parse(strDefaultRecordTtl);

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

            string strRecursion = request.QueryString["recursion"];
            if (!string.IsNullOrEmpty(strRecursion))
                _dnsServer.Recursion = Enum.Parse<DnsServerRecursion>(strRecursion, true);

            string strRecursionDeniedNetworks = request.QueryString["recursionDeniedNetworks"];
            if (!string.IsNullOrEmpty(strRecursionDeniedNetworks))
            {
                if (strRecursionDeniedNetworks == "false")
                {
                    _dnsServer.RecursionDeniedNetworks = null;
                }
                else
                {
                    string[] strNetworks = strRecursionDeniedNetworks.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    NetworkAddress[] networks = new NetworkAddress[strNetworks.Length];

                    for (int i = 0; i < networks.Length; i++)
                        networks[i] = NetworkAddress.Parse(strNetworks[i]);

                    _dnsServer.RecursionDeniedNetworks = networks;
                }
            }

            string strRecursionAllowedNetworks = request.QueryString["recursionAllowedNetworks"];
            if (!string.IsNullOrEmpty(strRecursionAllowedNetworks))
            {
                if (strRecursionAllowedNetworks == "false")
                {
                    _dnsServer.RecursionAllowedNetworks = null;
                }
                else
                {
                    string[] strNetworks = strRecursionAllowedNetworks.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    NetworkAddress[] networks = new NetworkAddress[strNetworks.Length];

                    for (int i = 0; i < networks.Length; i++)
                        networks[i] = NetworkAddress.Parse(strNetworks[i]);

                    _dnsServer.RecursionAllowedNetworks = networks;
                }
            }

            string strRandomizeName = request.QueryString["randomizeName"];
            if (!string.IsNullOrEmpty(strRandomizeName))
                _dnsServer.RandomizeName = bool.Parse(strRandomizeName);

            string strQnameMinimization = request.QueryString["qnameMinimization"];
            if (!string.IsNullOrEmpty(strQnameMinimization))
                _dnsServer.QnameMinimization = bool.Parse(strQnameMinimization);

            string strNsRevalidation = request.QueryString["nsRevalidation"];
            if (!string.IsNullOrEmpty(strNsRevalidation))
                _dnsServer.NsRevalidation = bool.Parse(strNsRevalidation);

            string strQpmLimitRequests = request.QueryString["qpmLimitRequests"];
            if (!string.IsNullOrEmpty(strQpmLimitRequests))
                _dnsServer.QpmLimitRequests = int.Parse(strQpmLimitRequests);

            string strQpmLimitErrors = request.QueryString["qpmLimitErrors"];
            if (!string.IsNullOrEmpty(strQpmLimitErrors))
                _dnsServer.QpmLimitErrors = int.Parse(strQpmLimitErrors);

            string strQpmLimitSampleMinutes = request.QueryString["qpmLimitSampleMinutes"];
            if (!string.IsNullOrEmpty(strQpmLimitSampleMinutes))
                _dnsServer.QpmLimitSampleMinutes = int.Parse(strQpmLimitSampleMinutes);

            string strQpmLimitIPv4PrefixLength = request.QueryString["qpmLimitIPv4PrefixLength"];
            if (!string.IsNullOrEmpty(strQpmLimitIPv4PrefixLength))
                _dnsServer.QpmLimitIPv4PrefixLength = int.Parse(strQpmLimitIPv4PrefixLength);

            string strQpmLimitIPv6PrefixLength = request.QueryString["qpmLimitIPv6PrefixLength"];
            if (!string.IsNullOrEmpty(strQpmLimitIPv6PrefixLength))
                _dnsServer.QpmLimitIPv6PrefixLength = int.Parse(strQpmLimitIPv6PrefixLength);

            string strServeStale = request.QueryString["serveStale"];
            if (!string.IsNullOrEmpty(strServeStale))
                _dnsServer.ServeStale = bool.Parse(strServeStale);

            string strServeStaleTtl = request.QueryString["serveStaleTtl"];
            if (!string.IsNullOrEmpty(strServeStaleTtl))
                _dnsServer.CacheZoneManager.ServeStaleTtl = uint.Parse(strServeStaleTtl);

            string strCacheMinimumRecordTtl = request.QueryString["cacheMinimumRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheMinimumRecordTtl))
                _dnsServer.CacheZoneManager.MinimumRecordTtl = uint.Parse(strCacheMinimumRecordTtl);

            string strCacheMaximumRecordTtl = request.QueryString["cacheMaximumRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheMaximumRecordTtl))
                _dnsServer.CacheZoneManager.MaximumRecordTtl = uint.Parse(strCacheMaximumRecordTtl);

            string strCacheNegativeRecordTtl = request.QueryString["cacheNegativeRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheNegativeRecordTtl))
                _dnsServer.CacheZoneManager.NegativeRecordTtl = uint.Parse(strCacheNegativeRecordTtl);

            string strCacheFailureRecordTtl = request.QueryString["cacheFailureRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheFailureRecordTtl))
                _dnsServer.CacheZoneManager.FailureRecordTtl = uint.Parse(strCacheFailureRecordTtl);

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
                        List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(strBypassList.Length);

                        for (int i = 0; i < strBypassList.Length; i++)
                            bypassList.Add(new NetProxyBypassItem(strBypassList[i]));

                        _dnsServer.Proxy.BypassList = bypassList;
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
                        NameServerAddress forwarder = new NameServerAddress(strForwardersList[i]);

                        if (forwarder.Protocol != forwarderProtocol)
                            forwarder = forwarder.ChangeProtocol(forwarderProtocol);

                        forwarders[i] = forwarder;
                    }

                    _dnsServer.Forwarders = forwarders;
                }
            }

            string strEnableBlocking = request.QueryString["enableBlocking"];
            if (!string.IsNullOrEmpty(strEnableBlocking))
            {
                _dnsServer.EnableBlocking = bool.Parse(strEnableBlocking);
                if (_dnsServer.EnableBlocking)
                {
                    if (_temporaryDisableBlockingTimer is not null)
                        _temporaryDisableBlockingTimer.Dispose();
                }
            }

            string strAllowTxtBlockingReport = request.QueryString["allowTxtBlockingReport"];
            if (!string.IsNullOrEmpty(strAllowTxtBlockingReport))
                _dnsServer.AllowTxtBlockingReport = bool.Parse(strAllowTxtBlockingReport);

            string strBlockingType = request.QueryString["blockingType"];
            if (!string.IsNullOrEmpty(strBlockingType))
                _dnsServer.BlockingType = Enum.Parse<DnsServerBlockingType>(strBlockingType, true);

            string strCustomBlockingAddresses = request.QueryString["customBlockingAddresses"];
            if (!string.IsNullOrEmpty(strCustomBlockingAddresses))
            {
                if (strCustomBlockingAddresses == "false")
                {
                    _dnsServer.CustomBlockingARecords = null;
                    _dnsServer.CustomBlockingAAAARecords = null;
                }
                else
                {
                    string[] strAddresses = strCustomBlockingAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    List<DnsARecord> dnsARecords = new List<DnsARecord>();
                    List<DnsAAAARecord> dnsAAAARecords = new List<DnsAAAARecord>();

                    foreach (string strAddress in strAddresses)
                    {
                        if (IPAddress.TryParse(strAddress, out IPAddress customAddress))
                        {
                            switch (customAddress.AddressFamily)
                            {
                                case AddressFamily.InterNetwork:
                                    dnsARecords.Add(new DnsARecord(customAddress));
                                    break;

                                case AddressFamily.InterNetworkV6:
                                    dnsAAAARecords.Add(new DnsAAAARecord(customAddress));
                                    break;
                            }
                        }
                    }

                    _dnsServer.CustomBlockingARecords = dnsARecords;
                    _dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                }
            }

            string strBlockListUrls = request.QueryString["blockListUrls"];
            if (!string.IsNullOrEmpty(strBlockListUrls))
            {
                if (strBlockListUrls == "false")
                {
                    StopBlockListUpdateTimer();

                    _dnsServer.BlockListZoneManager.AllowListUrls.Clear();
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
                        if (strBlockListUrlList.Length != (_dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsServer.BlockListZoneManager.BlockListUrls.Count))
                        {
                            updated = true;
                        }
                        else
                        {
                            foreach (string strBlockListUrl in strBlockListUrlList)
                            {
                                if (strBlockListUrl.StartsWith("!"))
                                {
                                    string strAllowListUrl = strBlockListUrl.Substring(1);

                                    if (!_dnsServer.BlockListZoneManager.AllowListUrls.Contains(new Uri(strAllowListUrl)))
                                    {
                                        updated = true;
                                        break;
                                    }
                                }
                                else
                                {
                                    if (!_dnsServer.BlockListZoneManager.BlockListUrls.Contains(new Uri(strBlockListUrl)))
                                    {
                                        updated = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (updated)
                    {
                        _dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                        _dnsServer.BlockListZoneManager.BlockListUrls.Clear();

                        foreach (string strBlockListUrl in strBlockListUrlList)
                        {
                            if (strBlockListUrl.StartsWith("!"))
                            {
                                Uri allowListUrl = new Uri(strBlockListUrl.Substring(1));

                                if (!_dnsServer.BlockListZoneManager.AllowListUrls.Contains(allowListUrl))
                                    _dnsServer.BlockListZoneManager.AllowListUrls.Add(allowListUrl);
                            }
                            else
                            {
                                Uri blockListUrl = new Uri(strBlockListUrl);

                                if (!_dnsServer.BlockListZoneManager.BlockListUrls.Contains(blockListUrl))
                                    _dnsServer.BlockListZoneManager.BlockListUrls.Add(blockListUrl);
                            }
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
                    throw new DnsWebServiceException("Parameter `blockListUpdateIntervalHours` must be between 1 hour and 168 hours (7 days).");

                _blockListUpdateIntervalHours = blockListUpdateIntervalHours;
            }

            if ((_webServiceTlsCertificatePath == null) && (_dnsTlsCertificatePath == null))
                StopTlsCertificateUpdateTimer();

            SelfSignedCertCheck(true);

            if (_webServiceEnableTls && string.IsNullOrEmpty(_webServiceTlsCertificatePath) && !_webServiceUseSelfSignedTlsCertificate)
            {
                //disable TLS
                _webServiceEnableTls = false;
                restartWebService = true;
            }

            SaveConfigFile();
            _log.Save();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DNS Settings were updated {dnsServerDomain: " + _dnsServer.ServerDomain + "; dnsServerLocalEndPoints: " + strDnsServerLocalEndPoints + "; webServiceLocalAddresses: " + strWebServiceLocalAddresses + "; webServiceHttpPort: " + _webServiceHttpPort + "; webServiceEnableTls: " + strWebServiceEnableTls + "; webServiceHttpToTlsRedirect: " + strWebServiceHttpToTlsRedirect + "; webServiceTlsPort: " + strWebServiceTlsPort + "; webServiceUseSelfSignedTlsCertificate: " + _webServiceUseSelfSignedTlsCertificate + "; webServiceTlsCertificatePath: " + strWebServiceTlsCertificatePath + "; enableDnsOverHttp: " + _dnsServer.EnableDnsOverHttp + "; enableDnsOverTls: " + _dnsServer.EnableDnsOverTls + "; enableDnsOverHttps: " + _dnsServer.EnableDnsOverHttps + "; dnsTlsCertificatePath: " + _dnsTlsCertificatePath + "; defaultRecordTtl: " + _zonesApi.DefaultRecordTtl + "; preferIPv6: " + _dnsServer.PreferIPv6 + "; enableLogging: " + strEnableLogging + "; logQueries: " + (_dnsServer.QueryLogManager != null) + "; useLocalTime: " + strUseLocalTime + "; logFolder: " + strLogFolder + "; maxLogFileDays: " + strMaxLogFileDays + "; recursion: " + _dnsServer.Recursion.ToString() + "; randomizeName: " + strRandomizeName + "; qnameMinimization: " + strQnameMinimization + "; serveStale: " + strServeStale + "; serveStaleTtl: " + strServeStaleTtl + "; cachePrefetchEligibility: " + strCachePrefetchEligibility + "; cachePrefetchTrigger: " + strCachePrefetchTrigger + "; cachePrefetchSampleIntervalInMinutes: " + strCachePrefetchSampleIntervalInMinutes + "; cachePrefetchSampleEligibilityHitsPerHour: " + strCachePrefetchSampleEligibilityHitsPerHour + "; proxyType: " + strProxyType + "; forwarders: " + strForwarders + "; forwarderProtocol: " + strForwarderProtocol + "; enableBlocking: " + _dnsServer.EnableBlocking + "; allowTxtBlockingReport: " + _dnsServer.AllowTxtBlockingReport + "; blockingType: " + _dnsServer.BlockingType.ToString() + "; blockListUrl: " + strBlockListUrls + "; blockListUpdateIntervalHours: " + strBlockListUpdateIntervalHours + ";}");

            GetDnsSettings(jsonWriter);

            RestartService(restartDnsService, restartWebService);
        }

        private void SelfSignedCertCheck(bool throwException)
        {
            string selfSignedCertificateFilePath = Path.Combine(_configFolder, "cert.pfx");

            if (_webServiceUseSelfSignedTlsCertificate)
            {
                if (!File.Exists(selfSignedCertificateFilePath))
                {
                    RSA rsa = RSA.Create(2048);
                    CertificateRequest req = new CertificateRequest("cn=" + _dnsServer.ServerDomain, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(5));

                    File.WriteAllBytes(selfSignedCertificateFilePath, cert.Export(X509ContentType.Pkcs12, null as string));
                }

                if (_webServiceEnableTls && string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                {
                    try
                    {
                        LoadWebServiceTlsCertificate(selfSignedCertificateFilePath, null);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading self signed Web Service TLS certificate: " + selfSignedCertificateFilePath + "\r\n" + ex.ToString());

                        if (throwException)
                            throw;
                    }
                }
            }
            else
            {
                File.Delete(selfSignedCertificateFilePath);
            }
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
                        StopDnsWebService();
                        StartDnsWebService();

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
            bool apps = false;
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

            string strApps = request.QueryString["apps"];
            if (!string.IsNullOrEmpty(strApps))
                apps = bool.Parse(strApps);

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
                            string[] scopeFiles = Directory.GetFiles(Path.Combine(_configFolder, "scopes"), "*.scope", SearchOption.TopDirectoryOnly);
                            foreach (string scopeFile in scopeFiles)
                            {
                                string entryName = "scopes/" + Path.GetFileName(scopeFile);
                                backupZip.CreateEntryFromFile(scopeFile, entryName);
                            }
                        }

                        if (apps)
                        {
                            string[] appFiles = Directory.GetFiles(Path.Combine(_configFolder, "apps"), "*", SearchOption.AllDirectories);
                            foreach (string appFile in appFiles)
                            {
                                string entryName = appFile.Substring(_configFolder.Length);

                                if (Path.DirectorySeparatorChar != '/')
                                    entryName = entryName.Replace(Path.DirectorySeparatorChar, '/');

                                entryName = entryName.TrimStart('/');

                                backupZip.CreateEntryFromFile(appFile, entryName);
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
            bool apps = false;
            bool stats = false;
            bool zones = false;
            bool allowedZones = false;
            bool blockedZones = false;
            bool dnsSettings = false;
            bool logSettings = false;

            bool deleteExistingFiles = false;

            string strBlockLists = request.QueryString["blockLists"];
            if (!string.IsNullOrEmpty(strBlockLists))
                blockLists = bool.Parse(strBlockLists);

            string strLogs = request.QueryString["logs"];
            if (!string.IsNullOrEmpty(strLogs))
                logs = bool.Parse(strLogs);

            string strScopes = request.QueryString["scopes"];
            if (!string.IsNullOrEmpty(strScopes))
                scopes = bool.Parse(strScopes);

            string strApps = request.QueryString["apps"];
            if (!string.IsNullOrEmpty(strApps))
                apps = bool.Parse(strApps);

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

            string strDeleteExistingFiles = request.QueryString["deleteExistingFiles"];
            if (!string.IsNullOrEmpty(strDeleteExistingFiles))
                deleteExistingFiles = bool.Parse(strDeleteExistingFiles);

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
                                if (deleteExistingFiles)
                                {
                                    //delete existing log files
                                    string[] logFiles = Directory.GetFiles(_log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);
                                    foreach (string logFile in logFiles)
                                    {
                                        File.Delete(logFile);
                                    }
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
                            if (deleteExistingFiles)
                            {
                                //delete existing block list files
                                string[] blockListFiles = Directory.GetFiles(Path.Combine(_configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);
                                foreach (string blockListFile in blockListFiles)
                                {
                                    File.Delete(blockListFile);
                                }
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
                                if (deleteExistingFiles)
                                {
                                    //delete existing scope files
                                    string[] scopeFiles = Directory.GetFiles(Path.Combine(_configFolder, "scopes"), "*.scope", SearchOption.TopDirectoryOnly);
                                    foreach (string scopeFile in scopeFiles)
                                    {
                                        File.Delete(scopeFile);
                                    }
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

                        if (apps)
                        {
                            //unload apps
                            _dnsServer.DnsApplicationManager.UnloadAllApplications();

                            if (deleteExistingFiles)
                            {
                                //delete existing apps
                                string appFolder = Path.Combine(_configFolder, "apps");
                                if (Directory.Exists(appFolder))
                                    Directory.Delete(appFolder, true);

                                //create apps folder
                                Directory.CreateDirectory(appFolder);
                            }

                            //extract apps files from backup
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (entry.FullName.StartsWith("apps/"))
                                {
                                    string entryPath = entry.FullName;

                                    if (Path.DirectorySeparatorChar != '/')
                                        entryPath = entryPath.Replace('/', '\\');

                                    string filePath = Path.Combine(_configFolder, entryPath);

                                    Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                                    entry.ExtractToFile(filePath, true);
                                }
                            }

                            //reload apps
                            _dnsServer.DnsApplicationManager.LoadAllApplications();
                        }

                        if (stats)
                        {
                            if (deleteExistingFiles)
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
                            if (deleteExistingFiles)
                            {
                                //delete existing zone files
                                string[] zoneFiles = Directory.GetFiles(Path.Combine(_configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);
                                foreach (string zoneFile in zoneFiles)
                                {
                                    File.Delete(zoneFile);
                                }
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
                            if (entry == null)
                            {
                                string fileName = Path.Combine(_configFolder, "allowed.config");
                                if (File.Exists(fileName))
                                    File.Delete(fileName);
                            }
                            else
                            {
                                entry.ExtractToFile(Path.Combine(_configFolder, entry.Name), true);
                            }

                            //reload
                            _dnsServer.AllowedZoneManager.LoadAllowedZoneFile();
                        }

                        if (blockedZones)
                        {
                            ZipArchiveEntry entry = backupZip.GetEntry("blocked.config");
                            if (entry == null)
                            {
                                string fileName = Path.Combine(_configFolder, "allowed.config");
                                if (File.Exists(fileName))
                                    File.Delete(fileName);
                            }
                            else
                            {
                                entry.ExtractToFile(Path.Combine(_configFolder, entry.Name), true);
                            }

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
            if (ForceUpdateBlockLists())
                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Block list update was triggered.");
        }

        private void TemporaryDisableBlocking(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strMinutes = request.QueryString["minutes"];
            if (string.IsNullOrEmpty(strMinutes))
                throw new DnsWebServiceException("Parameter 'minutes' missing.");

            int minutes = int.Parse(strMinutes);

            Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
            if (temporaryDisableBlockingTimer is not null)
                temporaryDisableBlockingTimer.Dispose();

            Timer newTemporaryDisableBlockingTimer = new Timer(delegate (object state)
            {
                try
                {
                    _dnsServer.EnableBlocking = true;
                    _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Blocking was enabled after " + minutes + " minute(s) being temporarily disabled.");
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            });

            Timer originalTimer = Interlocked.CompareExchange(ref _temporaryDisableBlockingTimer, newTemporaryDisableBlockingTimer, temporaryDisableBlockingTimer);
            if (ReferenceEquals(originalTimer, temporaryDisableBlockingTimer))
            {
                newTemporaryDisableBlockingTimer.Change(minutes * 60 * 1000, Timeout.Infinite);
                _dnsServer.EnableBlocking = false;
                _temporaryDisableBlockingTill = DateTime.UtcNow.AddMinutes(minutes);

                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Blocking was temporarily disabled for " + minutes + " minute(s).");
            }
            else
            {
                newTemporaryDisableBlockingTimer.Dispose();
            }

            jsonWriter.WritePropertyName("temporaryDisableBlockingTill");
            jsonWriter.WriteValue(_temporaryDisableBlockingTill);
        }

        #endregion

        #region dns client api

        private async Task ResolveQuery(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string server = request.QueryString["server"];
            if (string.IsNullOrEmpty(server))
                throw new DnsWebServiceException("Parameter 'server' missing.");

            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.Trim(new char[] { '\t', ' ', '.' });

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

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
            bool qnameMinimization = _dnsServer.QnameMinimization;
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

                DnsCache dnsCache = new DnsCache();
                dnsCache.MinimumRecordTtl = 0;
                dnsCache.MaximumRecordTtl = 7 * 24 * 60 * 60;

                dnsResponse = await DnsClient.RecursiveResolveAsync(question, dnsCache, proxy, preferIPv6, randomizeName, qnameMinimization, false, RETRIES, TIMEOUT);
            }
            else
            {
                if ((type == DnsResourceRecordType.AXFR) && (protocol == DnsTransportProtocol.Udp))
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
                            nameServer = _dnsServer.ThisServer.ChangeProtocol(DnsTransportProtocol.Tcp);
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
                    nameServer = new NameServerAddress(server);

                    if (nameServer.Protocol != protocol)
                        nameServer = nameServer.ChangeProtocol(protocol);

                    if (nameServer.IPEndPoint is null)
                    {
                        if (proxy is null)
                            await nameServer.ResolveIPAddressAsync(_dnsServer);
                    }
                    else if (protocol != DnsTransportProtocol.Tls)
                    {
                        try
                        {
                            await nameServer.ResolveDomainNameAsync(_dnsServer);
                        }
                        catch
                        { }
                    }
                }

                dnsResponse = await new DnsClient(nameServer) { Proxy = proxy, PreferIPv6 = preferIPv6, RandomizeName = randomizeName, Retries = RETRIES, Timeout = TIMEOUT }.ResolveAsync(domain, type);

                if (type == DnsResourceRecordType.AXFR)
                    dnsResponse = dnsResponse.Join();
            }

            if (importRecords)
            {
                AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
                if ((zoneInfo == null) || zoneInfo.Name.Equals("", StringComparison.OrdinalIgnoreCase))
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
                            break;

                        case AuthZoneType.Forwarder:
                            if (type == DnsResourceRecordType.AXFR)
                                throw new DnsServerException("Cannot import records via zone transfer: import zone must be of primary type.");

                            break;

                        default:
                            throw new DnsServerException("Cannot import records: import zone must be of primary or forwarder type.");
                    }
                }

                if (type == DnsResourceRecordType.AXFR)
                {
                    _dnsServer.AuthZoneManager.SyncZoneTransferRecords(zoneInfo.Name, dnsResponse.Answer);
                }
                else
                {
                    List<DnsResourceRecord> syncRecords = new List<DnsResourceRecord>(dnsResponse.Answer.Count);

                    foreach (DnsResourceRecord record in dnsResponse.Answer)
                    {
                        if (record.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneInfo.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            record.RemoveExpiry();
                            syncRecords.Add(record);
                        }
                    }

                    _dnsServer.AuthZoneManager.LoadRecords(syncRecords);
                }

                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DNS Client imported record(s) for authoritative zone {server: " + server + "; zone: " + zoneInfo.Name + "; type: " + type + ";}");

                _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
            }

            jsonWriter.WritePropertyName("result");
            jsonWriter.WriteRawValue(JsonConvert.SerializeObject(dnsResponse, new StringEnumConverter()));
        }

        #endregion

        #region auth

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

        #endregion

        #region block list

        private bool ForceUpdateBlockLists()
        {
            if ((_dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsServer.BlockListZoneManager.BlockListUrls.Count) > 0)
            {
                _blockListLastUpdatedOn = new DateTime();

                StopBlockListUpdateTimer();
                StartBlockListUpdateTimer();

                return true;
            }

            return false;
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

                }, null, BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL);
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

        #endregion

        #region tls

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

            _dnsServer.Certificate = certificate;
            _dnsTlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

            _log.Write("DNS Server TLS certificate was loaded: " + tlsCertificatePath);
        }

        #endregion

        #region config

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
                        case 15:
                        case 16:
                        case 17:
                        case 18:
                        case 19:
                        case 20:
                        case 21:
                        case 22:
                        case 23:
                        case 24:
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
                            else
                            {
                                _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };

                                _webServiceTlsPort = 53443;
                                _webServiceEnableTls = false;
                                _webServiceHttpToTlsRedirect = false;
                                _webServiceTlsCertificatePath = string.Empty;
                                _webServiceTlsCertificatePassword = string.Empty;
                            }

                            _dnsServer.PreferIPv6 = bR.ReadBoolean();

                            if (bR.ReadBoolean()) //logQueries
                                _dnsServer.QueryLogManager = _log;

                            if (version >= 14)
                                _dnsServer.StatsManager.MaxStatFileDays = bR.ReadInt32();
                            else
                                _dnsServer.StatsManager.MaxStatFileDays = 0;

                            if (version >= 17)
                            {
                                _dnsServer.Recursion = (DnsServerRecursion)bR.ReadByte();

                                {
                                    int count = bR.ReadByte();
                                    if (count > 0)
                                    {
                                        NetworkAddress[] networks = new NetworkAddress[count];

                                        for (int i = 0; i < count; i++)
                                            networks[i] = NetworkAddress.Parse(bR);

                                        _dnsServer.RecursionDeniedNetworks = networks;
                                    }
                                }


                                {
                                    int count = bR.ReadByte();
                                    if (count > 0)
                                    {
                                        NetworkAddress[] networks = new NetworkAddress[count];

                                        for (int i = 0; i < count; i++)
                                            networks[i] = NetworkAddress.Parse(bR);

                                        _dnsServer.RecursionAllowedNetworks = networks;
                                    }
                                }
                            }
                            else
                            {
                                bool allowRecursion = bR.ReadBoolean();
                                bool allowRecursionOnlyForPrivateNetworks;

                                if (version >= 4)
                                    allowRecursionOnlyForPrivateNetworks = bR.ReadBoolean();
                                else
                                    allowRecursionOnlyForPrivateNetworks = true; //default true for security reasons

                                if (allowRecursion)
                                {
                                    if (allowRecursionOnlyForPrivateNetworks)
                                        _dnsServer.Recursion = DnsServerRecursion.AllowOnlyForPrivateNetworks;
                                    else
                                        _dnsServer.Recursion = DnsServerRecursion.Allow;
                                }
                                else
                                {
                                    _dnsServer.Recursion = DnsServerRecursion.Deny;
                                }
                            }

                            if (version >= 12)
                                _dnsServer.RandomizeName = bR.ReadBoolean();
                            else
                                _dnsServer.RandomizeName = true; //default true to enable security feature

                            if (version >= 15)
                                _dnsServer.QnameMinimization = bR.ReadBoolean();
                            else
                                _dnsServer.QnameMinimization = true; //default true to enable privacy feature

                            if (version >= 20)
                            {
                                _dnsServer.QpmLimitRequests = bR.ReadInt32();
                                _dnsServer.QpmLimitErrors = bR.ReadInt32();
                                _dnsServer.QpmLimitSampleMinutes = bR.ReadInt32();
                                _dnsServer.QpmLimitIPv4PrefixLength = bR.ReadInt32();
                                _dnsServer.QpmLimitIPv6PrefixLength = bR.ReadInt32();
                            }
                            else if (version >= 17)
                            {
                                _dnsServer.QpmLimitRequests = bR.ReadInt32();
                                _dnsServer.QpmLimitSampleMinutes = bR.ReadInt32();
                                _ = bR.ReadInt32(); //read obsolete value _dnsServer.QpmLimitSamplingIntervalInMinutes
                            }
                            else
                            {
                                _dnsServer.QpmLimitRequests = 0;
                                _dnsServer.QpmLimitErrors = 0;
                                _dnsServer.QpmLimitSampleMinutes = 1;
                                _dnsServer.QpmLimitIPv4PrefixLength = 24;
                                _dnsServer.QpmLimitIPv6PrefixLength = 56;
                            }

                            if (version >= 13)
                            {
                                _dnsServer.ServeStale = bR.ReadBoolean();
                                _dnsServer.CacheZoneManager.ServeStaleTtl = bR.ReadUInt32();
                            }
                            else
                            {
                                _dnsServer.ServeStale = true;
                                _dnsServer.CacheZoneManager.ServeStaleTtl = CacheZoneManager.SERVE_STALE_TTL;
                            }

                            if (version >= 9)
                            {
                                _dnsServer.CachePrefetchEligibility = bR.ReadInt32();
                                _dnsServer.CachePrefetchTrigger = bR.ReadInt32();
                                _dnsServer.CachePrefetchSampleIntervalInMinutes = bR.ReadInt32();
                                _dnsServer.CachePrefetchSampleEligibilityHitsPerHour = bR.ReadInt32();
                            }
                            else
                            {
                                _dnsServer.CachePrefetchEligibility = 2;
                                _dnsServer.CachePrefetchTrigger = 9;
                                _dnsServer.CachePrefetchSampleIntervalInMinutes = 5;
                                _dnsServer.CachePrefetchSampleEligibilityHitsPerHour = 30;
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
                                    List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(count);

                                    for (int i = 0; i < count; i++)
                                        bypassList.Add(new NetProxyBypassItem(bR.ReadShortString()));

                                    _dnsServer.Proxy.BypassList = bypassList;
                                }
                                else
                                {
                                    _dnsServer.Proxy.BypassList = null;
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
                                            forwarders.Add(forwarder.ChangeProtocol(forwarderProtocol));
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

                            if (version >= 18)
                                _dnsServer.EnableBlocking = bR.ReadBoolean();
                            else
                                _dnsServer.EnableBlocking = true;

                            if (version >= 18)
                                _dnsServer.BlockingType = (DnsServerBlockingType)bR.ReadByte();
                            else if (version >= 16)
                                _dnsServer.BlockingType = bR.ReadBoolean() ? DnsServerBlockingType.NxDomain : DnsServerBlockingType.AnyAddress;
                            else
                                _dnsServer.BlockingType = DnsServerBlockingType.AnyAddress;

                            if (version >= 18)
                            {
                                //read custom blocking addresses
                                int count = bR.ReadByte();
                                if (count > 0)
                                {
                                    List<DnsARecord> dnsARecords = new List<DnsARecord>();
                                    List<DnsAAAARecord> dnsAAAARecords = new List<DnsAAAARecord>();

                                    for (int i = 0; i < count; i++)
                                    {
                                        IPAddress customAddress = IPAddressExtension.Parse(bR);

                                        switch (customAddress.AddressFamily)
                                        {
                                            case AddressFamily.InterNetwork:
                                                dnsARecords.Add(new DnsARecord(customAddress));
                                                break;

                                            case AddressFamily.InterNetworkV6:
                                                dnsAAAARecords.Add(new DnsAAAARecord(customAddress));
                                                break;
                                        }
                                    }

                                    _dnsServer.CustomBlockingARecords = dnsARecords;
                                    _dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                                }
                            }
                            else
                            {
                                _dnsServer.CustomBlockingARecords = null;
                                _dnsServer.CustomBlockingAAAARecords = null;
                            }

                            if (version > 4)
                            {
                                //read block list urls
                                int count = bR.ReadByte();

                                for (int i = 0; i < count; i++)
                                {
                                    string listUrl = bR.ReadShortString();

                                    if (listUrl.StartsWith("!"))
                                        _dnsServer.BlockListZoneManager.AllowListUrls.Add(new Uri(listUrl.Substring(1)));
                                    else
                                        _dnsServer.BlockListZoneManager.BlockListUrls.Add(new Uri(listUrl));
                                }

                                _blockListLastUpdatedOn = bR.ReadDateTime();

                                if (version >= 13)
                                    _blockListUpdateIntervalHours = bR.ReadInt32();
                            }
                            else
                            {
                                _dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                                _dnsServer.BlockListZoneManager.BlockListUrls.Clear();
                                _blockListLastUpdatedOn = DateTime.MinValue;
                                _blockListUpdateIntervalHours = 24;
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
                            else
                            {
                                _dnsServer.LocalEndPoints = new IPEndPoint[] { new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53) };
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
                            else
                            {
                                _dnsServer.EnableDnsOverHttp = false;
                                _dnsServer.EnableDnsOverTls = false;
                                _dnsServer.EnableDnsOverHttps = false;
                                _dnsTlsCertificatePath = string.Empty;
                                _dnsTlsCertificatePassword = string.Empty;
                            }

                            if (version >= 19)
                            {
                                _dnsServer.CacheZoneManager.MinimumRecordTtl = bR.ReadUInt32();
                                _dnsServer.CacheZoneManager.MaximumRecordTtl = bR.ReadUInt32();
                                _dnsServer.CacheZoneManager.NegativeRecordTtl = bR.ReadUInt32();
                                _dnsServer.CacheZoneManager.FailureRecordTtl = bR.ReadUInt32();
                            }
                            else
                            {
                                _dnsServer.CacheZoneManager.MinimumRecordTtl = CacheZoneManager.MINIMUM_RECORD_TTL;
                                _dnsServer.CacheZoneManager.MaximumRecordTtl = CacheZoneManager.MAXIMUM_RECORD_TTL;
                                _dnsServer.CacheZoneManager.NegativeRecordTtl = CacheZoneManager.NEGATIVE_RECORD_TTL;
                                _dnsServer.CacheZoneManager.FailureRecordTtl = CacheZoneManager.FAILURE_RECORD_TTL;
                            }

                            if (version >= 21)
                            {
                                int count = bR.ReadByte();
                                Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(count);

                                for (int i = 0; i < count; i++)
                                {
                                    string keyName = bR.ReadShortString();
                                    string sharedSecret = bR.ReadShortString();
                                    TsigAlgorithm algorithm = (TsigAlgorithm)bR.ReadByte();

                                    tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, algorithm));
                                }

                                _dnsServer.TsigKeys = tsigKeys;
                            }
                            else if (version >= 20)
                            {
                                int count = bR.ReadByte();
                                Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(count);

                                for (int i = 0; i < count; i++)
                                {
                                    string keyName = bR.ReadShortString();
                                    string sharedSecret = bR.ReadShortString();

                                    tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, TsigAlgorithm.HMAC_SHA256));
                                }

                                _dnsServer.TsigKeys = tsigKeys;
                            }
                            else
                            {
                                _dnsServer.TsigKeys = null;
                            }

                            if (version >= 22)
                                _dnsServer.NsRevalidation = bR.ReadBoolean();
                            else
                                _dnsServer.NsRevalidation = false; //default false since some badly configured websites fail to load

                            if (version >= 23)
                            {
                                _dnsServer.AllowTxtBlockingReport = bR.ReadBoolean();
                                _zonesApi.DefaultRecordTtl = bR.ReadUInt32();
                            }
                            else
                            {
                                _dnsServer.AllowTxtBlockingReport = true;
                                _zonesApi.DefaultRecordTtl = 3600;
                            }

                            if (version >= 24)
                            {
                                _webServiceUseSelfSignedTlsCertificate = bR.ReadBoolean();

                                SelfSignedCertCheck(false);
                            }
                            else
                            {
                                _webServiceUseSelfSignedTlsCertificate = false;
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

                string serverDomain = Environment.GetEnvironmentVariable("DNS_SERVER_DOMAIN");
                if (!string.IsNullOrEmpty(serverDomain))
                    _dnsServer.ServerDomain = serverDomain;

                string adminPassword = Environment.GetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD");
                string adminPasswordFile = Environment.GetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD_FILE");

                if (!string.IsNullOrEmpty(adminPassword))
                {
                    SetCredentials("admin", adminPassword);
                }
                else if (!string.IsNullOrEmpty(adminPasswordFile))
                {
                    try
                    {
                        using (StreamReader sR = new StreamReader(adminPasswordFile, true))
                        {
                            string password = sR.ReadLine();
                            SetCredentials("admin", password);
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);

                        SetCredentials("admin", "admin");
                    }
                }
                else
                {
                    SetCredentials("admin", "admin");
                }

                string strPreferIPv6 = Environment.GetEnvironmentVariable("DNS_SERVER_PREFER_IPV6");
                if (!string.IsNullOrEmpty(strPreferIPv6))
                    _dnsServer.PreferIPv6 = bool.Parse(strPreferIPv6);

                string strDnsOverHttp = Environment.GetEnvironmentVariable("DNS_SERVER_OPTIONAL_PROTOCOL_DNS_OVER_HTTP");
                if (!string.IsNullOrEmpty(strDnsOverHttp))
                    _dnsServer.EnableDnsOverHttp = bool.Parse(strDnsOverHttp);

                string strRecursion = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION");
                if (!string.IsNullOrEmpty(strRecursion))
                    _dnsServer.Recursion = Enum.Parse<DnsServerRecursion>(strRecursion, true);
                else
                    _dnsServer.Recursion = DnsServerRecursion.AllowOnlyForPrivateNetworks; //default for security reasons

                string strRecursionDeniedNetworks = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION_DENIED_NETWORKS");
                if (!string.IsNullOrEmpty(strRecursionDeniedNetworks))
                {
                    string[] strRecursionDeniedNetworkAddresses = strRecursionDeniedNetworks.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    NetworkAddress[] networks = new NetworkAddress[strRecursionDeniedNetworkAddresses.Length];

                    for (int i = 0; i < networks.Length; i++)
                        networks[i] = NetworkAddress.Parse(strRecursionDeniedNetworkAddresses[i].Trim());

                    _dnsServer.RecursionDeniedNetworks = networks;
                }

                string strRecursionAllowedNetworks = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION_ALLOWED_NETWORKS");
                if (!string.IsNullOrEmpty(strRecursionAllowedNetworks))
                {
                    string[] strRecursionAllowedNetworkAddresses = strRecursionAllowedNetworks.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    NetworkAddress[] networks = new NetworkAddress[strRecursionAllowedNetworkAddresses.Length];

                    for (int i = 0; i < networks.Length; i++)
                        networks[i] = NetworkAddress.Parse(strRecursionAllowedNetworkAddresses[i].Trim());

                    _dnsServer.RecursionAllowedNetworks = networks;
                }

                string strEnableBlocking = Environment.GetEnvironmentVariable("DNS_SERVER_ENABLE_BLOCKING");
                if (!string.IsNullOrEmpty(strEnableBlocking))
                    _dnsServer.EnableBlocking = bool.Parse(strEnableBlocking);

                string strAllowTxtBlockingReport = Environment.GetEnvironmentVariable("DNS_SERVER_ALLOW_TXT_BLOCKING_REPORT");
                if (!string.IsNullOrEmpty(strAllowTxtBlockingReport))
                    _dnsServer.AllowTxtBlockingReport = bool.Parse(strAllowTxtBlockingReport);

                string strForwarders = Environment.GetEnvironmentVariable("DNS_SERVER_FORWARDERS");
                if (!string.IsNullOrEmpty(strForwarders))
                {
                    DnsTransportProtocol forwarderProtocol;

                    string strForwarderProtocol = Environment.GetEnvironmentVariable("DNS_SERVER_FORWARDER_PROTOCOL");
                    if (string.IsNullOrEmpty(strForwarderProtocol))
                        forwarderProtocol = DnsTransportProtocol.Udp;
                    else
                        forwarderProtocol = Enum.Parse<DnsTransportProtocol>(strForwarderProtocol, true);

                    List<NameServerAddress> forwarders = new List<NameServerAddress>();
                    string[] strForwardersAddresses = strForwarders.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    foreach (string strForwarderAddress in strForwardersAddresses)
                        forwarders.Add(new NameServerAddress(strForwarderAddress.Trim(), forwarderProtocol));

                    _dnsServer.Forwarders = forwarders;
                }

                _dnsServer.RandomizeName = true; //default true to enable security feature
                _dnsServer.QnameMinimization = true; //default true to enable privacy feature
                _dnsServer.NsRevalidation = false; //default false since some badly configured websites fail to load

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
                bW.Write((byte)24); //version

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

                bW.Write((byte)_dnsServer.Recursion);

                if (_dnsServer.RecursionDeniedNetworks is null)
                {
                    bW.Write((byte)0);
                }
                else
                {
                    bW.Write(Convert.ToByte(_dnsServer.RecursionDeniedNetworks.Count));
                    foreach (NetworkAddress networkAddress in _dnsServer.RecursionDeniedNetworks)
                        networkAddress.WriteTo(bW);
                }

                if (_dnsServer.RecursionAllowedNetworks is null)
                {
                    bW.Write((byte)0);
                }
                else
                {
                    bW.Write(Convert.ToByte(_dnsServer.RecursionAllowedNetworks.Count));
                    foreach (NetworkAddress networkAddress in _dnsServer.RecursionAllowedNetworks)
                        networkAddress.WriteTo(bW);
                }

                bW.Write(_dnsServer.RandomizeName);
                bW.Write(_dnsServer.QnameMinimization);

                bW.Write(_dnsServer.QpmLimitRequests);
                bW.Write(_dnsServer.QpmLimitErrors);
                bW.Write(_dnsServer.QpmLimitSampleMinutes);
                bW.Write(_dnsServer.QpmLimitIPv4PrefixLength);
                bW.Write(_dnsServer.QpmLimitIPv6PrefixLength);

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
                bW.Write(_dnsServer.EnableBlocking);
                bW.Write((byte)_dnsServer.BlockingType);

                {
                    bW.Write(Convert.ToByte(_dnsServer.CustomBlockingARecords.Count + _dnsServer.CustomBlockingAAAARecords.Count));

                    foreach (DnsARecord record in _dnsServer.CustomBlockingARecords)
                        record.Address.WriteTo(bW);

                    foreach (DnsAAAARecord record in _dnsServer.CustomBlockingAAAARecords)
                        record.Address.WriteTo(bW);
                }

                {
                    bW.Write(Convert.ToByte(_dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsServer.BlockListZoneManager.BlockListUrls.Count));

                    foreach (Uri allowListUrl in _dnsServer.BlockListZoneManager.AllowListUrls)
                        bW.WriteShortString("!" + allowListUrl.AbsoluteUri);

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

                bW.Write(_dnsServer.CacheZoneManager.MinimumRecordTtl);
                bW.Write(_dnsServer.CacheZoneManager.MaximumRecordTtl);
                bW.Write(_dnsServer.CacheZoneManager.NegativeRecordTtl);
                bW.Write(_dnsServer.CacheZoneManager.FailureRecordTtl);

                if (_dnsServer.TsigKeys is null)
                {
                    bW.Write((byte)0);
                }
                else
                {
                    bW.Write(Convert.ToByte(_dnsServer.TsigKeys.Count));

                    foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsServer.TsigKeys)
                    {
                        bW.WriteShortString(tsigKey.Key);
                        bW.WriteShortString(tsigKey.Value.SharedSecret);
                        bW.Write((byte)tsigKey.Value.Algorithm);
                    }
                }

                bW.Write(_dnsServer.NsRevalidation);
                bW.Write(_dnsServer.AllowTxtBlockingReport);
                bW.Write(_zonesApi.DefaultRecordTtl);
                bW.Write(_webServiceUseSelfSignedTlsCertificate);

                //write config
                mS.Position = 0;

                using (FileStream fS = new FileStream(configFile, FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _log.Write("DNS Server config file was saved: " + configFile);
        }

        #endregion

        #region web service start stop

        private void StartDnsWebService()
        {
            int acceptTasks = Math.Max(1, Environment.ProcessorCount);

            //HTTP service
            try
            {
                string webServiceHostname = null;

                _webService = new HttpListener();
                IPAddress httpAddress = null;

                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                {
                    string host;

                    if (webServiceLocalAddress.Equals(IPAddress.Any))
                    {
                        host = "+";

                        httpAddress = IPAddress.Loopback;
                    }
                    else if (webServiceLocalAddress.Equals(IPAddress.IPv6Any))
                    {
                        host = "+";

                        if ((httpAddress == null) || !IPAddress.IsLoopback(httpAddress))
                            httpAddress = IPAddress.IPv6Loopback;
                    }
                    else
                    {
                        if (webServiceLocalAddress.AddressFamily == AddressFamily.InterNetworkV6)
                            host = "[" + webServiceLocalAddress.ToString() + "]";
                        else
                            host = webServiceLocalAddress.ToString();

                        if (httpAddress == null)
                            httpAddress = webServiceLocalAddress;

                        if (webServiceHostname == null)
                            webServiceHostname = host;
                    }

                    _webService.Prefixes.Add("http://" + host + ":" + _webServiceHttpPort + "/");
                }

                _webService.Start();

                if (httpAddress == null)
                    httpAddress = IPAddress.Loopback;

                _webServiceHttpEP = new IPEndPoint(httpAddress, _webServiceHttpPort);

                _webServiceHostname = webServiceHostname ?? Environment.MachineName.ToLower();
            }
            catch (Exception ex)
            {
                _log.Write("Web Service failed to bind using default hostname. Attempting to bind again using 'localhost' hostname.\r\n" + ex.ToString());

                try
                {
                    _webService = new HttpListener();
                    _webService.Prefixes.Add("http://localhost:" + _webServiceHttpPort + "/");
                    _webService.Prefixes.Add("http://127.0.0.1:" + _webServiceHttpPort + "/");
                    _webService.Start();
                }
                catch
                {
                    _webService = new HttpListener();
                    _webService.Prefixes.Add("http://localhost:" + _webServiceHttpPort + "/");
                    _webService.Start();
                }

                _webServiceHttpEP = new IPEndPoint(IPAddress.Loopback, _webServiceHttpPort);

                _webServiceHostname = "localhost";
            }

            _webService.IgnoreWriteExceptions = true;

            for (int i = 0; i < acceptTasks; i++)
            {
                _ = Task.Factory.StartNew(delegate ()
                {
                    return AcceptWebRequestAsync();
                }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _webServiceTaskScheduler);
            }

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
                        for (int i = 0; i < acceptTasks; i++)
                        {
                            _ = Task.Factory.StartNew(delegate ()
                            {
                                return AcceptTlsWebRequestAsync(tlsListener);
                            }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _webServiceTaskScheduler);
                        }
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

        private void StopDnsWebService()
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

                //load all dns applications
                _dnsServer.DnsApplicationManager.LoadAllApplications();

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
                StartDnsWebService();

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
                StopDnsWebService();
                _dnsServer.Dispose();
                _dhcpServer.Dispose();

                StopBlockListUpdateTimer();
                StopTlsCertificateUpdateTimer();

                if (_temporaryDisableBlockingTimer is not null)
                    _temporaryDisableBlockingTimer.Dispose();

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

        internal LogManager Log
        { get { return _log; } }

        internal DnsServer DnsServer
        { get { return _dnsServer; } }

        internal DhcpServer DhcpServer
        { get { return _dhcpServer; } }

        public string ConfigFolder
        { get { return _configFolder; } }

        public int WebServiceHttpPort
        { get { return _webServiceHttpPort; } }

        public string WebServiceHostname
        { get { return _webServiceHostname; } }

        #endregion
    }
}
