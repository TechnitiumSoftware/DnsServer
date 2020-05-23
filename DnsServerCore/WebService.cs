/*
Technitium DNS Server
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using DnsServerCore.Dns.Zones;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
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

        readonly string _currentVersion;
        readonly string _appFolder;
        readonly string _configFolder;
        readonly Uri _updateCheckUri;

        readonly LogManager _log;
        StatsManager _stats;

        DnsServer _dnsServer;
        DhcpServer _dhcpServer;

        string _serverDomain;
        DnsSOARecord _defaultSoaRecord;
        DnsNSRecord _defaultNsRecord;

        int _webServicePort;
        HttpListener _webService;
        Thread _webServiceThread;
        string _webServiceHostname;

        string _tlsCertificatePath;
        string _tlsCertificatePassword;
        Timer _tlsCertificateUpdateTimer;
        DateTime _tlsCertificateLastModifiedOn;
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
        const int BLOCK_LIST_UPDATE_AFTER_HOURS = 24;
        const int BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL = 5000;
        const int BLOCK_LIST_UPDATE_TIMER_INTERVAL = 900000;
        const int BLOCK_LIST_UPDATE_RETRIES = 3;

        int _totalZonesAllowed;
        int _totalZonesBlocked;

        List<string> _configDisabledZones;

        #endregion

        #region constructor

        public WebService(string configFolder = null, Uri updateCheckUri = null)
        {
            Assembly assembly = Assembly.GetEntryAssembly();
            AssemblyName assemblyName = assembly.GetName();

            _currentVersion = assemblyName.Version.ToString();
            _appFolder = Path.GetDirectoryName(assembly.Location);

            if (configFolder == null)
                _configFolder = Path.Combine(_appFolder, "config");
            else
                _configFolder = configFolder;

            if (!Directory.Exists(_configFolder))
                Directory.CreateDirectory(_configFolder);

            _updateCheckUri = updateCheckUri;

            string logFolder = Path.Combine(_configFolder, "logs");

            if (!Directory.Exists(logFolder))
                Directory.CreateDirectory(logFolder);

            _log = new LogManager(logFolder);

            string blockListsFolder = Path.Combine(_configFolder, "blocklists");

            if (!Directory.Exists(blockListsFolder))
                Directory.CreateDirectory(blockListsFolder);
        }

        #endregion

        #region IDisposable

        private bool _disposed = false;

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

                if (_stats != null)
                    _stats.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private void AcceptWebRequestAsync(object state)
        {
            try
            {
                while (true)
                {
                    HttpListenerContext context = _webService.GetContext();
                    ThreadPool.QueueUserWorkItem(ProcessRequestAsync, new object[] { context.Request, context.Response });
                }
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //web service stopping

                _log.Write(ex);

                throw;
            }
        }

        private void ProcessRequestAsync(object state)
        {
            object[] parameters = state as object[];
            HttpListenerRequest request = parameters[0] as HttpListenerRequest;
            HttpListenerResponse response = parameters[1] as HttpListenerResponse;

            response.AddHeader("Server", "");
            response.AddHeader("X-Robots-Tag", "noindex, nofollow");

            try
            {
                Uri url = request.Url;
                string path = url.AbsolutePath;

                if (!path.StartsWith("/"))
                {
                    SendError(response, 404);
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
                                    Login(request, jsonWriter);
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
                                                CheckForUpdate(request, jsonWriter);
                                                break;

                                            case "/api/getDnsSettings":
                                                GetDnsSettings(jsonWriter);
                                                break;

                                            case "/api/setDnsSettings":
                                                SetDnsSettings(request, jsonWriter);
                                                break;

                                            case "/api/getStats":
                                                GetStats(request, jsonWriter);
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
                                                CreateZone(request, jsonWriter);
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
                                                ResolveQuery(request, jsonWriter);
                                                break;

                                            case "/api/listLogs":
                                                ListLogs(jsonWriter);
                                                break;

                                            case "/api/deleteLog":
                                                DeleteLog(request);
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
                                                SetDhcpScope(request);
                                                break;

                                            case "/api/enableDhcpScope":
                                                EnableDhcpScope(request);
                                                break;

                                            case "/api/disableDhcpScope":
                                                DisableDhcpScope(request);
                                                break;

                                            case "/api/deleteDhcpScope":
                                                DeleteDhcpScope(request);
                                                break;

                                            default:
                                                throw new WebServiceException("Invalid command: " + path);
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
                            mS.SetLength(0);
                            JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                            jsonWriter.WriteStartObject();

                            _log.Write(GetRequestRemoteEndPoint(request), ex);

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
                        SendError(response, 403, "Invalid token or session expired.");
                        return;
                    }

                    string[] pathParts = path.Split('/');

                    string logFileName = pathParts[2];
                    string logFile = Path.Combine(_log.LogFolder, logFileName + ".log");

                    int limit = 0;
                    string strLimit = request.QueryString["limit"];
                    if (!string.IsNullOrEmpty(strLimit))
                        limit = int.Parse(strLimit);

                    LogManager.DownloadLog(response, logFile, limit * 1024 * 1024);
                }
                else
                {
                    if (path.Contains("/../"))
                    {
                        SendError(response, 404);
                        return;
                    }

                    if (path == "/blocklist.txt")
                    {
                        if (!IPAddress.IsLoopback(GetRequestRemoteEndPoint(request).Address))
                            SendError(response, 403);
                    }

                    if (path == "/")
                        path = "/index.html";

                    path = Path.Combine(_appFolder, "www" + path.Replace('/', Path.DirectorySeparatorChar));

                    if (!File.Exists(path))
                    {
                        SendError(response, 404);
                        return;
                    }

                    SendFile(response, path);
                }
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //web service stopping

                _log.Write(GetRequestRemoteEndPoint(request), ex);

                SendError(response, ex);
            }
        }

        private static IPEndPoint GetRequestRemoteEndPoint(HttpListenerRequest request)
        {
            try
            {
                string xRealIp = request.Headers["X-Real-IP"];
                if (IPAddress.TryParse(xRealIp, out IPAddress address))
                {
                    //get the real IP address of the requesting client from X-Real-IP header set in nginx proxy_pass block
                    return new IPEndPoint(address, 0);
                }

                if (request.RemoteEndPoint == null)
                    return new IPEndPoint(IPAddress.Any, 0);

                return request.RemoteEndPoint;
            }
            catch
            {
                return new IPEndPoint(IPAddress.Any, 0);
            }
        }

        private static void SendError(HttpListenerResponse response, Exception ex)
        {
            SendError(response, 500, ex.ToString());
        }

        private static void SendError(HttpListenerResponse response, int statusCode, string message = null)
        {
            try
            {
                string statusString = statusCode + " " + DnsServer.GetStatusString((HttpStatusCode)statusCode);
                byte[] buffer = Encoding.UTF8.GetBytes("<html><head><title>" + statusString + "</title></head><body><h1>" + statusString + "</h1>" + (message == null ? "" : "<p>" + message + "</p>") + "</body></html>");

                response.StatusCode = statusCode;
                response.ContentType = "text/html";
                response.ContentLength64 = buffer.Length;

                using (Stream stream = response.OutputStream)
                {
                    stream.Write(buffer, 0, buffer.Length);
                }
            }
            catch
            { }
        }

        private static void SendFile(HttpListenerResponse response, string path)
        {
            using (FileStream fS = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                response.ContentType = WebUtilities.GetContentType(path).MediaType;
                response.ContentLength64 = fS.Length;
                response.AddHeader("Cache-Control", "private, max-age=300");

                using (Stream stream = response.OutputStream)
                {
                    try
                    {
                        fS.CopyTo(stream);
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

        private void Login(HttpListenerRequest request, JsonTextWriter jsonWriter)
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

                    Thread.Sleep(1000);
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

        private void CheckForUpdate(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string updateVersion = null;
            string displayText = null;
            string downloadLink = null;

            bool updateAvailable = false;

            if (_updateCheckUri != null)
            {
                try
                {
                    using (WebClientEx wc = new WebClientEx())
                    {
                        wc.Proxy = _dnsServer.Proxy;

                        byte[] response = wc.DownloadData(_updateCheckUri);

                        using (MemoryStream mS = new MemoryStream(response, false))
                        {
                            BinaryReader bR = new BinaryReader(mS);

                            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DU") //format
                                throw new InvalidDataException("DNS Server update info format is invalid.");

                            switch (bR.ReadByte()) //version
                            {
                                case 2:
                                    updateVersion = bR.ReadShortString();
                                    displayText = bR.ReadShortString();
                                    downloadLink = bR.ReadShortString();
                                    break;

                                default:
                                    throw new InvalidDataException("DNS Server update info version not supported.");
                            }

                            updateAvailable = IsUpdateAvailable(_currentVersion, updateVersion);
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

        private static bool IsUpdateAvailable(string currentVersion, string updateVersion)
        {
            if (updateVersion == null)
                return false;

            string[] uVer = updateVersion.Split(new char[] { '.' });
            string[] cVer = currentVersion.Split(new char[] { '.' });

            int x = uVer.Length;
            if (x > cVer.Length)
                x = cVer.Length;

            for (int i = 0; i < x; i++)
            {
                if (Convert.ToInt32(uVer[i]) > Convert.ToInt32(cVer[i]))
                    return true;
                else if (Convert.ToInt32(uVer[i]) < Convert.ToInt32(cVer[i]))
                    return false;
            }

            if (uVer.Length > cVer.Length)
            {
                for (int i = x; i < uVer.Length; i++)
                {
                    if (Convert.ToInt32(uVer[i]) > 0)
                        return true;
                }
            }

            return false;
        }

        private static string GetCleanVersion(string version)
        {
            while (version.EndsWith(".0"))
            {
                version = version.Substring(0, version.Length - 2);
            }

            return version;
        }

        private void GetDnsSettings(JsonTextWriter jsonWriter)
        {
            jsonWriter.WritePropertyName("version");
            jsonWriter.WriteValue(GetCleanVersion(_currentVersion));

            jsonWriter.WritePropertyName("serverDomain");
            jsonWriter.WriteValue(_serverDomain);

            jsonWriter.WritePropertyName("webServicePort");
            jsonWriter.WriteValue(_webServicePort);

            jsonWriter.WritePropertyName("dnsServerLocalAddresses");
            jsonWriter.WriteStartArray();

            foreach (IPAddress localAddress in _dnsServer.LocalAddresses)
                jsonWriter.WriteValue(localAddress.ToString());

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("enableDnsOverHttp");
            jsonWriter.WriteValue(_dnsServer.EnableDnsOverHttp);

            jsonWriter.WritePropertyName("enableDnsOverTls");
            jsonWriter.WriteValue(_dnsServer.EnableDnsOverTls);

            jsonWriter.WritePropertyName("enableDnsOverHttps");
            jsonWriter.WriteValue(_dnsServer.EnableDnsOverHttps);

            jsonWriter.WritePropertyName("tlsCertificatePath");
            jsonWriter.WriteValue(_tlsCertificatePath);

            jsonWriter.WritePropertyName("tlsCertificatePassword");
            jsonWriter.WriteValue("************");

            jsonWriter.WritePropertyName("preferIPv6");
            jsonWriter.WriteValue(_dnsServer.PreferIPv6);

            jsonWriter.WritePropertyName("logQueries");
            jsonWriter.WriteValue(_dnsServer.QueryLogManager != null);

            jsonWriter.WritePropertyName("allowRecursion");
            jsonWriter.WriteValue(_dnsServer.AllowRecursion);

            jsonWriter.WritePropertyName("allowRecursionOnlyForPrivateNetworks");
            jsonWriter.WriteValue(_dnsServer.AllowRecursionOnlyForPrivateNetworks);

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

            if (_dnsServer.Forwarders == null)
            {
                jsonWriter.WriteNull();
            }
            else
            {
                jsonWriter.WriteStartArray();

                foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                    jsonWriter.WriteValue(forwarder.OriginalString);

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("forwarderProtocol");
            jsonWriter.WriteValue(_dnsServer.ForwarderProtocol.ToString());


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
        }

        private void SetDnsSettings(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strServerDomain = request.QueryString["serverDomain"];
            if (!string.IsNullOrEmpty(strServerDomain))
            {
                strServerDomain = strServerDomain.ToLower();

                if (_serverDomain != strServerDomain)
                {
                    string oldServerDomain = _serverDomain;

                    UpdateServerDomain(strServerDomain);

                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            //update authoritative zone SOA and NS records
                            List<AuthZoneInfo> zones = _dnsServer.AuthZoneManager.ListZones();

                            foreach (AuthZoneInfo zone in zones)
                            {
                                IReadOnlyList<DnsResourceRecord> soaResourceRecords = zone.QueryRecords(DnsResourceRecordType.SOA);
                                if (soaResourceRecords.Count > 0)
                                {
                                    DnsResourceRecord soaRecord = soaResourceRecords[0];
                                    DnsSOARecord soaRecordData = soaRecord.RDATA as DnsSOARecord;

                                    if (soaRecordData.MasterNameServer.Equals(oldServerDomain, StringComparison.OrdinalIgnoreCase))
                                    {
                                        string responsiblePerson = soaRecordData.ResponsiblePerson;
                                        if (responsiblePerson.EndsWith(oldServerDomain))
                                            responsiblePerson = responsiblePerson.Replace(oldServerDomain, strServerDomain);

                                        _dnsServer.AuthZoneManager.SetRecords(soaRecord.Name, soaRecord.Type, soaRecord.TtlValue, new DnsResourceRecordData[] { new DnsSOARecord(strServerDomain, responsiblePerson, soaRecordData.Serial, soaRecordData.Refresh, soaRecordData.Retry, soaRecordData.Expire, soaRecordData.Minimum) });

                                        //update NS records
                                        IReadOnlyList<DnsResourceRecord> nsResourceRecords = zone.QueryRecords(DnsResourceRecordType.NS);

                                        foreach (DnsResourceRecord nsResourceRecord in nsResourceRecords)
                                        {
                                            if ((nsResourceRecord.RDATA as DnsNSRecord).NSDomainName.Equals(oldServerDomain, StringComparison.OrdinalIgnoreCase))
                                            {
                                                _dnsServer.AuthZoneManager.UpdateRecord(nsResourceRecord, new DnsResourceRecord(nsResourceRecord.Name, nsResourceRecord.Type, nsResourceRecord.Class, nsResourceRecord.TtlValue, new DnsNSRecord(strServerDomain)));
                                                break;
                                            }
                                        }

                                        try
                                        {
                                            SaveZoneFile(zone.Name);
                                        }
                                        catch (Exception ex)
                                        {
                                            _log.Write(ex);
                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }
                    });
                }
            }

            string strDnsServerLocalAddresses = request.QueryString["dnsServerLocalAddresses"];
            if (strDnsServerLocalAddresses != null)
            {
                if (string.IsNullOrEmpty(strDnsServerLocalAddresses))
                    strDnsServerLocalAddresses = "0.0.0.0,::";

                string[] strLocalAddresses = strDnsServerLocalAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                IPAddress[] localAddresses = new IPAddress[strLocalAddresses.Length];

                for (int i = 0; i < strLocalAddresses.Length; i++)
                    localAddresses[i] = IPAddress.Parse(strLocalAddresses[i]);

                _dnsServer.LocalAddresses = localAddresses;
            }

            int oldWebServicePort = _webServicePort;

            string strWebServicePort = request.QueryString["webServicePort"];
            if (!string.IsNullOrEmpty(strWebServicePort))
                _webServicePort = int.Parse(strWebServicePort);

            string enableDnsOverHttp = request.QueryString["enableDnsOverHttp"];
            if (!string.IsNullOrEmpty(enableDnsOverHttp))
                _dnsServer.EnableDnsOverHttp = bool.Parse(enableDnsOverHttp);

            string strEnableDnsOverTls = request.QueryString["enableDnsOverTls"];
            if (!string.IsNullOrEmpty(strEnableDnsOverTls))
                _dnsServer.EnableDnsOverTls = bool.Parse(strEnableDnsOverTls);

            string strEnableDnsOverHttps = request.QueryString["enableDnsOverHttps"];
            if (!string.IsNullOrEmpty(strEnableDnsOverHttps))
                _dnsServer.EnableDnsOverHttps = bool.Parse(strEnableDnsOverHttps);

            string strTlsCertificatePath = request.QueryString["tlsCertificatePath"];
            string strTlsCertificatePassword = request.QueryString["tlsCertificatePassword"];
            if (string.IsNullOrEmpty(strTlsCertificatePath))
            {
                StopTlsCertificateUpdateTimer();
                _tlsCertificatePath = null;
                _tlsCertificatePassword = "";
            }
            else
            {
                if (strTlsCertificatePassword == "************")
                    strTlsCertificatePassword = _tlsCertificatePassword;

                if ((strTlsCertificatePath != _tlsCertificatePath) || (strTlsCertificatePassword != _tlsCertificatePassword))
                {
                    LoadTlsCertificate(strTlsCertificatePath, strTlsCertificatePassword);

                    _tlsCertificatePath = strTlsCertificatePath;
                    _tlsCertificatePassword = strTlsCertificatePassword;

                    StartTlsCertificateUpdateTimer();
                }
            }

            string strPreferIPv6 = request.QueryString["preferIPv6"];
            if (!string.IsNullOrEmpty(strPreferIPv6))
                _dnsServer.PreferIPv6 = bool.Parse(strPreferIPv6);

            string strLogQueries = request.QueryString["logQueries"];
            if (!string.IsNullOrEmpty(strLogQueries))
            {
                if (bool.Parse(strLogQueries))
                    _dnsServer.QueryLogManager = _log;
                else
                    _dnsServer.QueryLogManager = null;
            }

            string strAllowRecursion = request.QueryString["allowRecursion"];
            if (!string.IsNullOrEmpty(strAllowRecursion))
                _dnsServer.AllowRecursion = bool.Parse(strAllowRecursion);

            string strAllowRecursionOnlyForPrivateNetworks = request.QueryString["allowRecursionOnlyForPrivateNetworks"];
            if (!string.IsNullOrEmpty(strAllowRecursionOnlyForPrivateNetworks))
                _dnsServer.AllowRecursionOnlyForPrivateNetworks = bool.Parse(strAllowRecursionOnlyForPrivateNetworks);

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

            string strForwarderProtocol = request.QueryString["forwarderProtocol"];
            if (!string.IsNullOrEmpty(strForwarderProtocol))
                _dnsServer.ForwarderProtocol = (DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), strForwarderProtocol, true);

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
                        if ((_dnsServer.ForwarderProtocol == DnsTransportProtocol.Tls) && IPAddress.TryParse(strForwardersList[i], out _))
                            strForwardersList[i] += ":853";

                        forwarders[i] = new NameServerAddress(strForwardersList[i]);
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

                    _dnsServer.BlockListZoneManager.Flush();
                }
                else
                {
                    bool updated = false;

                    string[] strBlockListUrlList = strBlockListUrls.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    if (oldWebServicePort != _webServicePort)
                    {
                        for (int i = 0; i < strBlockListUrlList.Length; i++)
                        {
                            if (strBlockListUrlList[i].Contains("http://localhost:" + oldWebServicePort + "/blocklist.txt"))
                            {
                                strBlockListUrlList[i] = "http://localhost:" + _webServicePort + "/blocklist.txt";
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
                            _dnsServer.BlockListZoneManager.BlockListUrls.Add(new Uri(strBlockListUrl));

                        _blockListLastUpdatedOn = new DateTime();

                        StopBlockListUpdateTimer();
                        StartBlockListUpdateTimer();
                    }
                }
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DNS Settings were updated {serverDomain: " + _serverDomain + "; dnsServerLocalAddresses: " + strDnsServerLocalAddresses + "; webServicePort: " + _webServicePort + "; enableDnsOverHttp: " + _dnsServer.EnableDnsOverHttp + "; enableDnsOverTls: " + _dnsServer.EnableDnsOverTls + "; enableDnsOverHttps: " + _dnsServer.EnableDnsOverHttps + "; tlsCertificatePath: " + _tlsCertificatePath + "; preferIPv6: " + _dnsServer.PreferIPv6 + "; logQueries: " + (_dnsServer.QueryLogManager != null) + "; allowRecursion: " + _dnsServer.AllowRecursion + "; allowRecursionOnlyForPrivateNetworks: " + _dnsServer.AllowRecursionOnlyForPrivateNetworks + "; proxyType: " + strProxyType + "; forwarders: " + strForwarders + "; forwarderProtocol: " + strForwarderProtocol + "; blockListUrl: " + strBlockListUrls + ";}");

            SaveConfigFile();

            GetDnsSettings(jsonWriter);
        }

        private void GetStats(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                strType = "lastHour";

            Dictionary<string, List<KeyValuePair<string, int>>> data;

            switch (strType)
            {
                case "lastHour":
                    data = _stats.GetLastHourStats();
                    break;

                case "lastDay":
                    data = _stats.GetLastDayStats();
                    break;

                case "lastWeek":
                    data = _stats.GetLastWeekStats();
                    break;

                case "lastMonth":
                    data = _stats.GetLastMonthStats();
                    break;

                case "lastYear":
                    data = _stats.GetLastYearStats();
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

                jsonWriter.WritePropertyName("allowedZones");
                jsonWriter.WriteValue(_totalZonesAllowed);

                jsonWriter.WritePropertyName("blockedZones");
                jsonWriter.WriteValue(_totalZonesBlocked + _dnsServer.BlockListZoneManager.TotalZonesBlocked);

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
                            case "totalAuthHit":
                                jsonWriter.WriteValue("Authoritative");
                                break;

                            case "totalRecursions":
                                jsonWriter.WriteValue("Recursive");
                                break;

                            case "totalCacheHit":
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
                            case "totalAuthHit":
                            case "totalRecursions":
                            case "totalCacheHit":
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

                IDictionary<string, string> clientIpMap = _dhcpServer.GetAddressClientMap();

                jsonWriter.WritePropertyName("topClients");
                jsonWriter.WriteStartArray();

                foreach (KeyValuePair<string, int> item in topClients)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("name");
                    jsonWriter.WriteValue(item.Key);

                    if (clientIpMap.TryGetValue(item.Key, out string clientDomain))
                    {
                        jsonWriter.WritePropertyName("domain");
                        jsonWriter.WriteValue(clientDomain);
                    }
                    else
                    {
                        IPAddress address = IPAddress.Parse(item.Key);

                        if (IPAddress.IsLoopback(address))
                        {
                            jsonWriter.WritePropertyName("domain");
                            jsonWriter.WriteValue("localhost");
                        }
                        else
                        {
                            try
                            {
                                DnsDatagram ptrResponse = _dnsServer.DirectQuery(new DnsQuestionRecord(address, DnsClass.IN), 200);
                                if (ptrResponse != null)
                                {
                                    string ptrDomain = DnsClient.ParseResponsePTR(ptrResponse);

                                    jsonWriter.WritePropertyName("domain");
                                    jsonWriter.WriteValue(ptrDomain);
                                }
                            }
                            catch
                            { }
                        }
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

                    foreach (string allowedZone in allowedZones)
                        _dnsServer.AllowedZoneManager.CreatePrimaryZone(allowedZone, _defaultSoaRecord, _defaultNsRecord, false);

                    _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Total " + allowedZones.Length + " zones were imported into allowed zone successfully.");
                    SaveAllowedZoneFile();
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

            _dnsServer.AllowedZoneManager.DeleteZone(domain);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Allowed zone was deleted: " + domain);

            SaveAllowedZoneFile();
        }

        private void AllowZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                domain = (new DnsQuestionRecord(ipAddress, DnsClass.IN)).Name;

            _dnsServer.AllowedZoneManager.CreatePrimaryZone(domain, _defaultSoaRecord, _defaultNsRecord, false);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Zone was allowed: " + domain);
            SaveAllowedZoneFile();
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

                    foreach (string blockedZone in blockedZones)
                        _dnsServer.BlockedZoneManager.CreatePrimaryZone(blockedZone, _defaultSoaRecord, _defaultNsRecord, false);

                    _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Total " + blockedZones.Length + " zones were imported into blocked zone successfully.");
                    SaveBlockedZoneFile();
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

            _dnsServer.BlockedZoneManager.DeleteZone(domain);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Blocked zone was deleted: " + domain);

            SaveBlockedZoneFile();
            _totalZonesBlocked--;
        }

        private void BlockZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                domain = (new DnsQuestionRecord(ipAddress, DnsClass.IN)).Name;

            _dnsServer.BlockedZoneManager.CreatePrimaryZone(domain, _defaultSoaRecord, _defaultNsRecord, false);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Domain was added to blocked zone: " + domain);

            SaveBlockedZoneFile();
            _totalZonesBlocked++;
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

                jsonWriter.WritePropertyName("zoneName");
                jsonWriter.WriteValue(zone.Name);

                jsonWriter.WritePropertyName("disabled");
                jsonWriter.WriteValue(zone.Disabled);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        private void CreateZone(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.Contains("*"))
                throw new WebServiceException("Domain name for a zone cannot contain wildcard character.");

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                domain = (new DnsQuestionRecord(ipAddress, DnsClass.IN)).Name.ToLower();
            else if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            if (_dnsServer.AuthZoneManager.CreatePrimaryZone(domain, _serverDomain, false))
            {
                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Authoritative zone was created: " + domain);

                SaveZoneFile(domain);
            }

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(domain);
        }

        private void DeleteZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetZoneInfo(domain);
            if (zoneInfo == null)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsServer.AuthZoneManager.DeleteZone(domain))
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Authoritative zone was deleted: " + domain);

            DeleteZoneFile(domain);
        }

        private void EnableZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetZoneInfo(domain);
            if (zoneInfo == null)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            zoneInfo.Disabled = false;

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Authoritative zone was enabled: " + domain);

            SaveZoneFile(zoneInfo.Name);
        }

        private void DisableZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetZoneInfo(domain);
            if (zoneInfo == null)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            zoneInfo.Disabled = true;

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Authoritative zone was disabled: " + domain);

            SaveZoneFile(zoneInfo.Name);
        }

        private void AddRecord(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetZoneInfo(domain);
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
                    _dnsServer.AuthZoneManager.AddRecord(domain, type, ttl, new DnsARecord(IPAddress.Parse(value)));
                    break;

                case DnsResourceRecordType.AAAA:
                    _dnsServer.AuthZoneManager.AddRecord(domain, type, ttl, new DnsAAAARecord(IPAddress.Parse(value)));
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
                    _dnsServer.AuthZoneManager.AddRecord(domain, type, ttl, new DnsNSRecord(value));
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

                default:
                    throw new WebServiceException("Type not supported for AddRecords().");
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] New record was added to authoritative zone {domain: " + domain + "; type: " + type + "; value: " + value + "; ttl: " + ttl + ";}");

            SaveZoneFile(zoneInfo.Name);
        }

        private void GetRecords(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            List<DnsResourceRecord> records = _dnsServer.AuthZoneManager.ListAllRecords(domain);
            if (records.Count == 0)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

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
                    foreach (DnsResourceRecord resourceRecord in groupedRecords.Value)
                    {
                        jsonWriter.WriteStartObject();

                        if (authoritativeZoneRecords)
                        {
                            jsonWriter.WritePropertyName("disabled");
                            jsonWriter.WriteValue(resourceRecord.IsDisabled());
                        }

                        jsonWriter.WritePropertyName("name");
                        jsonWriter.WriteValue(resourceRecord.Name);

                        jsonWriter.WritePropertyName("type");
                        jsonWriter.WriteValue(resourceRecord.Type.ToString());

                        jsonWriter.WritePropertyName("ttl");
                        if (authoritativeZoneRecords)
                            jsonWriter.WriteValue(resourceRecord.TtlValue);
                        else
                            jsonWriter.WriteValue(resourceRecord.TTL);

                        jsonWriter.WritePropertyName("rData");
                        jsonWriter.WriteStartObject();

                        switch (resourceRecord.Type)
                        {
                            case DnsResourceRecordType.A:
                                {
                                    DnsARecord rdata = (resourceRecord.RDATA as DnsARecord);
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.IPAddress);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.AAAA:
                                {
                                    DnsAAAARecord rdata = (resourceRecord.RDATA as DnsAAAARecord);
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.IPAddress);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.SOA:
                                {
                                    DnsSOARecord rdata = resourceRecord.RDATA as DnsSOARecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("masterNameServer");
                                        jsonWriter.WriteValue(rdata.MasterNameServer);

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
                                }
                                break;

                            case DnsResourceRecordType.PTR:
                                {
                                    DnsPTRRecord rdata = resourceRecord.RDATA as DnsPTRRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.PTRDomainName);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.MX:
                                {
                                    DnsMXRecord rdata = resourceRecord.RDATA as DnsMXRecord;
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
                                    DnsTXTRecord rdata = resourceRecord.RDATA as DnsTXTRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.TXTData);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.NS:
                                {
                                    DnsNSRecord rdata = resourceRecord.RDATA as DnsNSRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.NSDomainName);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.CNAME:
                                {
                                    DnsCNAMERecord rdata = resourceRecord.RDATA as DnsCNAMERecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.CNAMEDomainName);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.SRV:
                                {
                                    DnsSRVRecord rdata = resourceRecord.RDATA as DnsSRVRecord;
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
                                    DnsCAARecord rdata = resourceRecord.RDATA as DnsCAARecord;
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

                            default:
                                {
                                    jsonWriter.WritePropertyName("value");

                                    using (MemoryStream mS = new MemoryStream())
                                    {
                                        resourceRecord.RDATA.WriteTo(mS, new List<DnsDomainOffset>());

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

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetZoneInfo(domain);
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
                    _dnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsARecord(IPAddress.Parse(value)));
                    break;

                case DnsResourceRecordType.AAAA:
                    _dnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsAAAARecord(IPAddress.Parse(value)));
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

                default:
                    throw new WebServiceException("Type not supported for DeleteRecord().");
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Record was deleted from authoritative zone {domain: " + domain + "; type: " + type + "; value: " + value + ";}");

            SaveZoneFile(zoneInfo.Name);
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

            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetZoneInfo(domain);
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
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsARecord(IPAddress.Parse(value)));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsARecord(IPAddress.Parse(newValue)));

                        if (disable)
                            newRecord.Disable();

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.AAAA:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsAAAARecord(IPAddress.Parse(value)));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsAAAARecord(IPAddress.Parse(newValue)));

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

                        string glueAddresses = request.QueryString["glueAddresses"];
                        if (!string.IsNullOrEmpty(glueAddresses))
                            newRecord.SetGlueRecords(glueAddresses);

                        _dnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SOA:
                    {
                        string masterNameServer = request.QueryString["masterNameServer"];
                        if (string.IsNullOrEmpty(masterNameServer))
                            throw new WebServiceException("Parameter 'masterNameServer' missing.");

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

                        _dnsServer.AuthZoneManager.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsSOARecord(masterNameServer, responsiblePerson, uint.Parse(serial), uint.Parse(refresh), uint.Parse(retry), uint.Parse(expire), uint.Parse(minimum)) });
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

                default:
                    throw new WebServiceException("Type not supported for UpdateRecords().");
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Record was updated for authoritative zone {oldDomain: " + domain + "; domain: " + newDomain + "; type: " + type + "; oldValue: " + value + "; value: " + newValue + "; ttl: " + ttl + "; disabled: " + disable + ";}");

            SaveZoneFile(zoneInfo.Name);
        }

        private IPAddress GetThisDnsServerAddress()
        {
            if (_dnsServer.LocalAddresses.Length == 0)
                return IPAddress.Loopback;

            if (_dnsServer.LocalAddresses[0].Equals(IPAddress.Any))
                return IPAddress.Loopback;
            else if (_dnsServer.LocalAddresses[0].Equals(IPAddress.IPv6Any))
                return IPAddress.IPv6Loopback;
            else
                return _dnsServer.LocalAddresses[0];
        }

        private void ResolveQuery(HttpListenerRequest request, JsonTextWriter jsonWriter)
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
            DnsTransportProtocol protocol = (DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), strProtocol, true);
            const int RETRIES = 1;
            const int TIMEOUT = 10000;

            DnsDatagram dnsResponse;

            if (server == "recursive-resolver")
            {
                DnsQuestionRecord question;

                if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                    question = new DnsQuestionRecord(address, DnsClass.IN);
                else
                    question = new DnsQuestionRecord(domain, type, DnsClass.IN);

                dnsResponse = DnsClient.RecursiveResolve(question, null, null, proxy, preferIPv6, RETRIES, TIMEOUT);
            }
            else
            {
                NameServerAddress nameServer;

                if (server == "this-server")
                {
                    nameServer = new NameServerAddress(_serverDomain, GetThisDnsServerAddress());
                    proxy = null; //no proxy required for this server

                    switch (protocol)
                    {
                        case DnsTransportProtocol.Tls:
                            throw new DnsServerException("Cannot use DNS-over-TLS protocol for \"This Server\". Please use the TLS certificate domain name as the server.");

                        case DnsTransportProtocol.Https:
                            throw new DnsServerException("Cannot use DNS-over-HTTPS protocol for \"This Server\". Please use the TLS certificate domain name with a url as the server.");

                        case DnsTransportProtocol.HttpsJson:
                            throw new DnsServerException("Cannot use DNS-over-HTTPS (JSON) protocol for \"This Server\". Please use the TLS certificate domain name with a url as the server.");
                    }
                }
                else
                {
                    nameServer = new NameServerAddress(server);

                    if (nameServer.IPEndPoint == null)
                    {
                        if (proxy == null)
                        {
                            if (_dnsServer.AllowRecursion)
                                nameServer.ResolveIPAddress(new NameServerAddress[] { new NameServerAddress(GetThisDnsServerAddress()) }, proxy, preferIPv6, RETRIES, TIMEOUT);
                            else
                                nameServer.RecursiveResolveIPAddress(_dnsServer.CacheZoneManager, proxy, preferIPv6, RETRIES, TIMEOUT);
                        }
                    }
                    else if (protocol != DnsTransportProtocol.Tls)
                    {
                        try
                        {
                            if (_dnsServer.AllowRecursion)
                                nameServer.ResolveDomainName(new NameServerAddress[] { new NameServerAddress(GetThisDnsServerAddress()) }, proxy, preferIPv6, RETRIES, TIMEOUT);
                            else
                                nameServer.RecursiveResolveDomainName(_dnsServer.CacheZoneManager, proxy, preferIPv6, RETRIES, TIMEOUT);
                        }
                        catch
                        { }
                    }
                }

                dnsResponse = (new DnsClient(nameServer) { Proxy = proxy, PreferIPv6 = preferIPv6, Protocol = protocol, Retries = RETRIES, Timeout = TIMEOUT }).Resolve(domain, type);
            }

            if (importRecords)
            {
                AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetZoneInfo(domain);

                if (zoneInfo == null)
                {
                    _dnsServer.AuthZoneManager.CreatePrimaryZone(domain, _serverDomain, false);
                }
                else if (zoneInfo.Type != AuthZoneType.Primary)
                {
                    throw new DnsServerException("Cannot import records: import zone type must be primary.");
                }

                List<DnsResourceRecord> recordsToImport = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord record in dnsResponse.Answer)
                {
                    if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        record.RemoveExpiry();
                        recordsToImport.Add(record);
                    }
                }

                _dnsServer.AuthZoneManager.SetRecords(recordsToImport);

                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DNS Client imported record(s) for authoritative zone {server: " + server + "; domain: " + domain + "; type: " + type + ";}");

                SaveZoneFile(zoneInfo.Name);
            }

            jsonWriter.WritePropertyName("result");
            jsonWriter.WriteRawValue(JsonConvert.SerializeObject(dnsResponse, new StringEnumConverter()));
        }

        private void ListLogs(JsonTextWriter jsonWriter)
        {
            string[] logFiles = Directory.GetFiles(_log.LogFolder, "*.log");

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

            string logFile = Path.Combine(_log.LogFolder, log + ".log");

            if (_log.CurrentLogFile.Equals(logFile, StringComparison.OrdinalIgnoreCase))
                _log.DeleteCurrentLogFile();
            else
                File.Delete(logFile);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Log file was deleted: " + log);
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

            if (scope.ReservedLeases != null)
            {
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
            }

            jsonWriter.WritePropertyName("allowOnlyReservedLeases");
            jsonWriter.WriteValue(scope.AllowOnlyReservedLeases);
        }

        private void SetDhcpScope(HttpListenerRequest request)
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
                scope.ChangeNetwork(IPAddress.Parse(strStartingAddress), IPAddress.Parse(strEndingAddress), IPAddress.Parse(strSubnetMask));
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
                    string[] strStaticRoutesParts = strStaticRoutes.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    ClasslessStaticRouteOption.Route[] staticRoutes = new ClasslessStaticRouteOption.Route[strStaticRoutesParts.Length];

                    for (int i = 0; i < strStaticRoutesParts.Length; i++)
                    {
                        string[] routeParts = strStaticRoutesParts[i].Split(';');

                        staticRoutes[i] = new ClasslessStaticRouteOption.Route(IPAddress.Parse(routeParts[0]), IPAddress.Parse(routeParts[1]), IPAddress.Parse(routeParts[2]));
                    }

                    scope.StaticRoutes = staticRoutes;
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
                    string[] strExclusionsParts = strExclusions.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    Exclusion[] exclusions = new Exclusion[strExclusionsParts.Length];

                    for (int i = 0; i < strExclusionsParts.Length; i++)
                    {
                        string[] rangeParts = strExclusionsParts[i].Split(';');

                        exclusions[i] = new Exclusion(IPAddress.Parse(rangeParts[0]), IPAddress.Parse(rangeParts[1]));
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
                    string[] strReservedLeaseParts = strReservedLeases.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    Lease[] reservedLeases = new Lease[strReservedLeaseParts.Length];

                    for (int i = 0; i < strReservedLeaseParts.Length; i++)
                    {
                        string[] leaseParts = strReservedLeaseParts[i].Split(';');
                        string hostname = null;

                        if (scope.ReservedLeases != null)
                        {
                            //search for current hostname
                            foreach (Lease lease in scope.ReservedLeases)
                            {
                                if (BitConverter.ToString(lease.HardwareAddress) == leaseParts[0])
                                {
                                    hostname = lease.HostName;
                                    break;
                                }
                            }
                        }

                        reservedLeases[i] = new Lease(LeaseType.Reserved, hostname, leaseParts[0], IPAddress.Parse(leaseParts[1]), leaseParts[2]);
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
                _dhcpServer.AddScope(scope);

                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DHCP scope was added successfully: " + scopeName);
            }
        }

        private void EnableDhcpScope(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new WebServiceException("Parameter 'name' missing.");

            if (!_dhcpServer.EnableScope(scopeName))
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

            _credentials.AddOrUpdate(username, passwordHash, delegate (string key, string oldValue)
            {
                return passwordHash;
            });
        }

        private void LoadCredentials(string username, string passwordHash)
        {
            username = username.ToLower();

            _credentials.AddOrUpdate(username, passwordHash, delegate (string key, string oldValue)
            {
                return passwordHash;
            });
        }

        private static string GetPasswordHash(string username, string password)
        {
            using (HMAC hmac = new HMACSHA256(Encoding.UTF8.GetBytes(password)))
            {
                return BitConverter.ToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(username))).Replace("-", "").ToLower();
            }
        }

        private void LoadZoneFiles()
        {
            string zonePath = Path.Combine(_configFolder, "zones");
            if (!Directory.Exists(zonePath))
                Directory.CreateDirectory(zonePath);

            //move zone files to new folder
            {
                string[] oldZoneFiles = Directory.GetFiles(_configFolder, "*.zone");

                foreach (string oldZoneFile in oldZoneFiles)
                    File.Move(oldZoneFile, Path.Combine(zonePath, Path.GetFileName(oldZoneFile)));
            }

            //remove old internal zones
            {
                string[] oldZoneFiles = new string[] { "localhost.zone", "1.0.0.127.in-addr.arpa.zone", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.zone" };

                foreach (string oldZoneFile in oldZoneFiles)
                {
                    string filePath = Path.Combine(zonePath, oldZoneFile);

                    if (File.Exists(filePath))
                    {
                        try
                        {
                            File.Delete(filePath);
                        }
                        catch
                        { }
                    }
                }
            }

            //load system zones
            {
                {
                    _dnsServer.AuthZoneManager.CreatePrimaryZone("localhost", _serverDomain, true);
                    _dnsServer.AuthZoneManager.SetRecords("localhost", DnsResourceRecordType.A, 3600, new DnsResourceRecordData[] { new DnsARecord(IPAddress.Loopback) });
                    _dnsServer.AuthZoneManager.SetRecords("localhost", DnsResourceRecordType.AAAA, 3600, new DnsResourceRecordData[] { new DnsAAAARecord(IPAddress.IPv6Loopback) });
                }

                {
                    string prtDomain = "0.in-addr.arpa";

                    _dnsServer.AuthZoneManager.CreatePrimaryZone(prtDomain, _serverDomain, true);
                }

                {
                    string prtDomain = "255.in-addr.arpa";

                    _dnsServer.AuthZoneManager.CreatePrimaryZone(prtDomain, _serverDomain, true);
                }

                {
                    string prtDomain = "127.in-addr.arpa";

                    _dnsServer.AuthZoneManager.CreatePrimaryZone(prtDomain, _serverDomain, true);
                    _dnsServer.AuthZoneManager.SetRecords("1.0.0.127.in-addr.arpa", DnsResourceRecordType.PTR, 3600, new DnsResourceRecordData[] { new DnsPTRRecord("localhost") });
                }

                {
                    string prtDomain = new DnsQuestionRecord(IPAddress.IPv6Loopback, DnsClass.IN).Name;

                    _dnsServer.AuthZoneManager.CreatePrimaryZone(prtDomain, _serverDomain, true);
                    _dnsServer.AuthZoneManager.SetRecords(prtDomain, DnsResourceRecordType.PTR, 3600, new DnsResourceRecordData[] { new DnsPTRRecord("localhost") });
                }
            }

            //load zone files
            string[] zoneFiles = Directory.GetFiles(zonePath, "*.zone");

            foreach (string zoneFile in zoneFiles)
            {
                try
                {
                    using (FileStream fS = new FileStream(zoneFile, FileMode.Open, FileAccess.Read))
                    {
                        _dnsServer.AuthZoneManager.LoadZoneFrom(fS);
                    }

                    _log.Write("DNS Server successfully loaded zone file: " + zoneFile);
                }
                catch (Exception ex)
                {
                    _log.Write("DNS Server failed to load zone file: " + zoneFile + "\r\n" + ex.ToString());
                }
            }
        }

        private void SaveZoneFile(string domain)
        {
            domain = domain.ToLower();

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize zone
                _dnsServer.AuthZoneManager.WriteZoneTo(domain, mS);

                //write to zone file
                mS.Position = 0;

                using (FileStream fS = new FileStream(Path.Combine(_configFolder, "zones", domain + ".zone"), FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _log.Write("Saved zone file for domain: " + domain);
        }

        private void DeleteZoneFile(string domain)
        {
            domain = domain.ToLower();

            File.Delete(Path.Combine(_configFolder, "zones", domain + ".zone"));

            _log.Write("Deleted zone file for domain: " + domain);
        }

        private void LoadAllowedZoneFile()
        {
            string allowedZoneFile = Path.Combine(_configFolder, "allowed.config");

            try
            {
                _log.Write("DNS Server is loading allowed zone file: " + allowedZoneFile);

                using (FileStream fS = new FileStream(allowedZoneFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader bR = new BinaryReader(fS);

                    if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "AZ") //format
                        throw new InvalidDataException("DnsServer allowed zone file format is invalid.");

                    byte version = bR.ReadByte();
                    switch (version)
                    {
                        case 1:
                            int length = bR.ReadInt32();

                            for (int i = 0; i < length; i++)
                                _dnsServer.AllowedZoneManager.CreatePrimaryZone(bR.ReadShortString(), _defaultSoaRecord, _defaultNsRecord, false);

                            _totalZonesAllowed = length;
                            break;

                        default:
                            throw new InvalidDataException("DnsServer allowed zone file version not supported.");
                    }
                }

                _log.Write("DNS Server allowed zone file was loaded: " + allowedZoneFile);
            }
            catch (FileNotFoundException)
            { }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading allowed zone file: " + allowedZoneFile + "\r\n" + ex.ToString());
            }
        }

        private void SaveAllowedZoneFile()
        {
            List<AuthZoneInfo> allowedZones = _dnsServer.AllowedZoneManager.ListZones();

            _totalZonesAllowed = allowedZones.Count;

            string allowedZoneFile = Path.Combine(_configFolder, "allowed.config");

            using (FileStream fS = new FileStream(allowedZoneFile, FileMode.Create, FileAccess.Write))
            {
                BinaryWriter bW = new BinaryWriter(fS);

                bW.Write(Encoding.ASCII.GetBytes("AZ")); //format
                bW.Write((byte)1); //version

                bW.Write(allowedZones.Count);

                foreach (AuthZoneInfo zone in allowedZones)
                    bW.WriteShortString(zone.Name);
            }

            _log.Write("DNS Server allowed zone file was saved: " + allowedZoneFile);
        }

        private void LoadBlockedZoneFile()
        {
            string blockedZoneFile;

            string oldCustomBlockedZoneFile = Path.Combine(_configFolder, "custom-blocked.config");
            string newBlockedZoneFile = Path.Combine(_configFolder, "blocked.config");

            if (File.Exists(newBlockedZoneFile))
                blockedZoneFile = newBlockedZoneFile;
            else if (File.Exists(oldCustomBlockedZoneFile))
                blockedZoneFile = oldCustomBlockedZoneFile;
            else
                blockedZoneFile = newBlockedZoneFile;

            try
            {
                _log.Write("DNS Server is loading blocked zone file: " + blockedZoneFile);

                using (FileStream fS = new FileStream(blockedZoneFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader bR = new BinaryReader(fS);

                    if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "BZ") //format
                        throw new InvalidDataException("DnsServer blocked zone file format is invalid.");

                    byte version = bR.ReadByte();
                    switch (version)
                    {
                        case 1:
                            int length = bR.ReadInt32();

                            for (int i = 0; i < length; i++)
                                _dnsServer.BlockedZoneManager.CreatePrimaryZone(bR.ReadShortString(), _defaultSoaRecord, _defaultNsRecord, false);

                            _totalZonesBlocked = length;
                            break;

                        default:
                            throw new InvalidDataException("DnsServer blocked zone file version not supported.");
                    }
                }

                _log.Write("DNS Server blocked zone file was loaded: " + blockedZoneFile);
            }
            catch (FileNotFoundException)
            { }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading blocked zone file: " + blockedZoneFile + "\r\n" + ex.ToString());
            }
        }

        private void SaveBlockedZoneFile()
        {
            List<AuthZoneInfo> blockedZones = _dnsServer.BlockedZoneManager.ListZones();

            string blockedZoneFile = Path.Combine(_configFolder, "blocked.config");

            using (FileStream fS = new FileStream(blockedZoneFile, FileMode.Create, FileAccess.Write))
            {
                BinaryWriter bW = new BinaryWriter(fS);

                bW.Write(Encoding.ASCII.GetBytes("BZ")); //format
                bW.Write((byte)1); //version

                bW.Write(blockedZones.Count);

                foreach (AuthZoneInfo zone in blockedZones)
                    bW.WriteShortString(zone.Name);
            }

            _log.Write("DNS Server blocked zone file was saved: " + blockedZoneFile);
        }

        private void StartBlockListUpdateTimer()
        {
            if (_blockListUpdateTimer == null)
            {
                _blockListUpdateTimer = new Timer(delegate (object state)
                {
                    try
                    {
                        if (DateTime.UtcNow > _blockListLastUpdatedOn.AddHours(BLOCK_LIST_UPDATE_AFTER_HOURS))
                        {
                            string localCacheFolder = Path.Combine(_configFolder, "blocklists");

                            if (_dnsServer.BlockListZoneManager.UpdateBlockLists(localCacheFolder, BLOCK_LIST_UPDATE_RETRIES, _dnsServer.Proxy))
                            {
                                //block lists were updated
                                //save last updated on time
                                _blockListLastUpdatedOn = DateTime.UtcNow;
                                SaveConfigFile();

                                _dnsServer.BlockListZoneManager.LoadBlockLists(localCacheFolder);

                                //force GC collection to remove old zone data from memory quickly
                                GC.Collect();
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
                    try
                    {
                        FileInfo fileInfo = new FileInfo(_tlsCertificatePath);

                        if (fileInfo.Exists && (fileInfo.LastWriteTimeUtc != _tlsCertificateLastModifiedOn))
                            LoadTlsCertificate(_tlsCertificatePath, _tlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while updating TLS Certificate: " + _tlsCertificatePath + "\r\n" + ex.ToString());
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

        private void LoadTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword)
        {
            FileInfo fileInfo = new FileInfo(tlsCertificatePath);

            if (!fileInfo.Exists)
                throw new ArgumentException("Tls certificate file does not exists: " + tlsCertificatePath);

            if (Path.GetExtension(tlsCertificatePath) != ".pfx")
                throw new ArgumentException("Tls certificate file must be PKCS #12 formatted with .pfx extension: " + tlsCertificatePath);

            X509Certificate2 certificate = new X509Certificate2(tlsCertificatePath, tlsCertificatePassword);

            if (!certificate.Verify())
                throw new ArgumentException("Tls certificate is invalid.");

            _dnsServer.Certificate = certificate;
            _tlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

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
                            UpdateServerDomain(bR.ReadShortString());
                            _webServicePort = bR.ReadInt32();

                            _dnsServer.PreferIPv6 = bR.ReadBoolean();

                            if (bR.ReadBoolean()) //logQueries
                                _dnsServer.QueryLogManager = _log;

                            _dnsServer.AllowRecursion = bR.ReadBoolean();

                            if (version >= 4)
                                _dnsServer.AllowRecursionOnlyForPrivateNetworks = bR.ReadBoolean();
                            else
                                _dnsServer.AllowRecursionOnlyForPrivateNetworks = true; //default true for security reasons

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

                            _dnsServer.ForwarderProtocol = (DnsTransportProtocol)bR.ReadByte();

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

                                if (count > 0)
                                    StartBlockListUpdateTimer();
                            }

                            if (version >= 6)
                            {
                                int count = bR.ReadByte();
                                _dnsServer.LocalAddresses = new IPAddress[count];

                                for (int i = 0; i < count; i++)
                                    _dnsServer.LocalAddresses[i] = IPAddressExtension.Parse(bR);
                            }
                            else
                            {
                                _dnsServer.LocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };
                            }

                            if (version >= 8)
                            {
                                _dnsServer.EnableDnsOverHttp = bR.ReadBoolean();
                                _dnsServer.EnableDnsOverTls = bR.ReadBoolean();
                                _dnsServer.EnableDnsOverHttps = bR.ReadBoolean();
                                _tlsCertificatePath = bR.ReadShortString();
                                _tlsCertificatePassword = bR.ReadShortString();

                                if (_tlsCertificatePath.Length == 0)
                                    _tlsCertificatePath = null;

                                if (_tlsCertificatePath != null)
                                {
                                    try
                                    {
                                        LoadTlsCertificate(_tlsCertificatePath, _tlsCertificatePassword);
                                    }
                                    catch (Exception ex)
                                    {
                                        _log.Write("DNS Server encountered an error while loading TLS certificate: " + _tlsCertificatePath + "\r\n" + ex.ToString());
                                    }

                                    StartTlsCertificateUpdateTimer();
                                }
                            }

                            break;

                        default:
                            throw new InvalidDataException("DnsServer config version not supported.");
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

                UpdateServerDomain(Environment.MachineName.ToLower());

                _webServicePort = 5380;
                _dnsServer.LocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };

                SetCredentials("admin", "admin");

                _dnsServer.AllowRecursion = true;
                _dnsServer.AllowRecursionOnlyForPrivateNetworks = true; //default true for security reasons

                SaveConfigFile();
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading config file: " + configFile + "\r\n" + ex.ToString());
                _log.Write("Note: You may try deleting the config file to fix this issue. However, you will lose DNS settings but, zone data wont be affected.");
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
                bW.Write((byte)10); //version

                bW.WriteShortString(_serverDomain);
                bW.Write(_webServicePort);

                bW.Write(_dnsServer.PreferIPv6);
                bW.Write((_dnsServer.QueryLogManager != null)); //logQueries
                bW.Write(_dnsServer.AllowRecursion);
                bW.Write(_dnsServer.AllowRecursionOnlyForPrivateNetworks);

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
                    bW.Write(Convert.ToByte(_dnsServer.Forwarders.Length));

                    foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                        forwarder.WriteTo(bW);
                }

                bW.Write((byte)_dnsServer.ForwarderProtocol);

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
                }

                if (_dnsServer.LocalAddresses == null)
                {
                    bW.Write((byte)0);
                }
                else
                {
                    bW.Write(Convert.ToByte(_dnsServer.LocalAddresses.Length));

                    foreach (IPAddress localAddress in _dnsServer.LocalAddresses)
                        localAddress.WriteTo(bW);
                }

                bW.Write(_dnsServer.EnableDnsOverHttp);
                bW.Write(_dnsServer.EnableDnsOverTls);
                bW.Write(_dnsServer.EnableDnsOverHttps);

                if (_tlsCertificatePath == null)
                    bW.WriteShortString(string.Empty);
                else
                    bW.WriteShortString(_tlsCertificatePath);

                if (_tlsCertificatePassword == null)
                    bW.WriteShortString(string.Empty);
                else
                    bW.WriteShortString(_tlsCertificatePassword);

                //write config
                mS.Position = 0;

                using (FileStream fS = new FileStream(configFile, FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _log.Write("DNS Server config file was saved: " + configFile);
        }

        private void UpdateServerDomain(string serverDomain)
        {
            _serverDomain = serverDomain;
            _defaultSoaRecord = new DnsSOARecord(_serverDomain, "hostmaster." + _serverDomain, 1, 14400, 3600, 604800, 900);
            _defaultNsRecord = new DnsNSRecord(_serverDomain);
            _dnsServer.BlockListZoneManager.ServerDomain = _serverDomain;
            _dhcpServer.ServerDomain = _serverDomain;
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
                //start dns server
                if (_stats == null)
                {
                    string statsFolder = Path.Combine(_configFolder, "stats");

                    if (!Directory.Exists(statsFolder))
                        Directory.CreateDirectory(statsFolder);

                    _stats = new StatsManager(statsFolder, _log);
                }

                _dnsServer = new DnsServer();
                _dnsServer.LogManager = _log;
                _dnsServer.StatsManager = _stats;

                LoadConfigFile();
                LoadZoneFiles();

                if (_configDisabledZones != null)
                {
                    foreach (string domain in _configDisabledZones)
                    {
                        _dnsServer.AuthZoneManager.DisableZone(domain);
                        SaveZoneFile(domain);
                    }
                }

                LoadAllowedZoneFile();
                LoadBlockedZoneFile();
                _dnsServer.BlockListZoneManager.LoadBlockLists(Path.Combine(_configFolder, "blocklists"));

                _dnsServer.Start();

                //start dhcp server
                _dhcpServer = new DhcpServer(Path.Combine(_configFolder, "scopes"));
                _dhcpServer.AuthZoneManager = _dnsServer.AuthZoneManager;
                _dhcpServer.ServerDomain = _serverDomain;
                _dhcpServer.LogManager = _log;

                _dhcpServer.Start();

                //start web service
                try
                {
                    _webService = new HttpListener();
                    _webService.Prefixes.Add("http://+:" + _webServicePort + "/");
                    _webService.Start();

                    _webServiceHostname = Environment.MachineName.ToLower();
                }
                catch (Exception ex)
                {
                    _log.Write("Web Service failed to bind using default hostname. Attempting to bind again using 'localhost' hostname.\r\n" + ex.ToString());

                    _webService = new HttpListener();
                    _webService.Prefixes.Add("http://localhost:" + _webServicePort + "/");
                    _webService.Start();

                    _webServiceHostname = "localhost";
                }

                _webService.IgnoreWriteExceptions = true;

                _webServiceThread = new Thread(AcceptWebRequestAsync);
                _webServiceThread.IsBackground = true;
                _webServiceThread.Start();

                _state = ServiceState.Running;

                _log.Write(new IPEndPoint(IPAddress.Any, _webServicePort), "Web Service (v" + _currentVersion + ") was started successfully.");
            }
            catch (Exception ex)
            {
                _log.Write("Failed to start Web Service (v" + _currentVersion + ")\r\n" + ex.ToString());
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
                _webService.Stop();
                _dnsServer.Stop();
                _dhcpServer.Stop();

                StopBlockListUpdateTimer();
                StopTlsCertificateUpdateTimer();

                _state = ServiceState.Stopped;

                _log.Write(new IPEndPoint(IPAddress.Loopback, _webServicePort), "Web Service (v" + _currentVersion + ") was stopped successfully.");
            }
            catch (Exception ex)
            {
                _log.Write("Failed to stop Web Service (v" + _currentVersion + ")\r\n" + ex.ToString());
                throw;
            }
        }

        #endregion

        #region properties

        public string ConfigFolder
        { get { return _configFolder; } }

        public string ServerDomain
        { get { return _serverDomain; } }

        public int WebServicePort
        { get { return _webServicePort; } }

        public string WebServiceHostname
        { get { return _webServiceHostname; } }

        #endregion
    }
}
