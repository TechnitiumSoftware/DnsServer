﻿/*
Technitium DNS Server
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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

        readonly Zone _customBlockedZoneRoot = new Zone(true);

        Timer _blockListUpdateTimer;
        readonly List<Uri> _blockListUrls = new List<Uri>();
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

                                            case "/api/flushAllowedZone":
                                                FlushAllowedZone(request);
                                                break;

                                            case "/api/deleteAllowedZone":
                                                DeleteAllowedZone(request);
                                                break;

                                            case "/api/allowZone":
                                                AllowZone(request);
                                                break;

                                            case "/api/listBlockedZones":
                                                ListBlockedZones(request, jsonWriter);
                                                break;

                                            case "/api/importCustomBlockedZones":
                                                ImportCustomBlockedZones(request);
                                                break;

                                            case "/api/exportCustomBlockedZones":
                                                ExportCustomBlockedZones(response);
                                                return;

                                            case "/api/flushCustomBlockedZone":
                                                FlushCustomBlockedZone(request);
                                                break;

                                            case "/api/deleteCustomBlockedZone":
                                                DeleteCustomBlockedZone(request);
                                                break;

                                            case "/api/customBlockZone":
                                                CustomBlockZone(request);
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

        private IPEndPoint GetRequestRemoteEndPoint(HttpListenerRequest request)
        {
            //this is due to mono NullReferenceException issue
            try
            {
                if (NetUtilities.IsPrivateIP(request.RemoteEndPoint.Address))
                {
                    //reverse proxy X-Real-IP header supported only when remote IP address is private

                    string xRealIp = request.Headers["X-Real-IP"];
                    if (!string.IsNullOrEmpty(xRealIp))
                    {
                        //get the real IP address of the requesting client from X-Real-IP header set in nginx proxy_pass block
                        return new IPEndPoint(IPAddress.Parse(xRealIp), 0);
                    }
                }

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

        public static void CreateUpdateInfov1(Stream s, string version, string displayText, string downloadLink)
        {
            BincodingEncoder encoder = new BincodingEncoder(s, "DU", 1);

            encoder.EncodeKeyValue("version", version);
            encoder.EncodeKeyValue("displayText", displayText);
            encoder.EncodeKeyValue("downloadLink", downloadLink);
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
                                case 1:
                                    #region old version

                                    mS.Position = 0;
                                    BincodingDecoder decoder = new BincodingDecoder(mS, "DU");

                                    switch (decoder.Version)
                                    {
                                        case 1:
                                            while (true)
                                            {
                                                Bincoding entry = decoder.DecodeNext();
                                                if (entry == null)
                                                    break;

                                                KeyValuePair<string, Bincoding> value = entry.GetKeyValuePair();

                                                switch (value.Key)
                                                {
                                                    case "version":
                                                        updateVersion = value.Value.GetStringValue();
                                                        break;

                                                    case "displayText":
                                                        displayText = value.Value.GetStringValue();
                                                        break;

                                                    case "downloadLink":
                                                        downloadLink = value.Value.GetStringValue();
                                                        break;
                                                }
                                            }
                                            break;

                                        default:
                                            throw new IOException("File version not supported: " + decoder.Version);
                                    }

                                    #endregion
                                    break;

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
            jsonWriter.WriteValue(_dnsServer.ServerDomain);

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

            if (_blockListUrls.Count == 0)
            {
                jsonWriter.WriteNull();
            }
            else
            {
                jsonWriter.WriteStartArray();

                foreach (Uri blockListUrl in _blockListUrls)
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

                if (_dnsServer.ServerDomain != strServerDomain)
                {
                    string oldServerDomain = _dnsServer.ServerDomain;
                    _dnsServer.ServerDomain = strServerDomain;

                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            //authoritative zone
                            {
                                ICollection<ZoneInfo> zones = _dnsServer.AuthoritativeZoneRoot.ListAuthoritativeZones();

                                foreach (ZoneInfo zone in zones)
                                {
                                    DnsResourceRecord[] soaResourceRecords = _dnsServer.AuthoritativeZoneRoot.GetAllRecords(zone.ZoneName, DnsResourceRecordType.SOA, false, true);
                                    if (soaResourceRecords.Length > 0)
                                    {
                                        DnsResourceRecord soaRecord = soaResourceRecords[0];
                                        DnsSOARecord soaRecordData = soaRecord.RDATA as DnsSOARecord;

                                        if (soaRecordData.MasterNameServer.Equals(oldServerDomain, StringComparison.OrdinalIgnoreCase))
                                        {
                                            string responsiblePerson = soaRecordData.ResponsiblePerson;
                                            if (responsiblePerson.EndsWith(oldServerDomain))
                                                responsiblePerson = responsiblePerson.Replace(oldServerDomain, strServerDomain);

                                            _dnsServer.AuthoritativeZoneRoot.SetRecords(soaRecord.Name, soaRecord.Type, soaRecord.TtlValue, new DnsResourceRecordData[] { new DnsSOARecord(strServerDomain, responsiblePerson, soaRecordData.Serial, soaRecordData.Refresh, soaRecordData.Retry, soaRecordData.Expire, soaRecordData.Minimum) });

                                            //update NS records
                                            DnsResourceRecord[] nsResourceRecords = _dnsServer.AuthoritativeZoneRoot.GetAllRecords(zone.ZoneName, DnsResourceRecordType.NS, false, true);

                                            foreach (DnsResourceRecord nsResourceRecord in nsResourceRecords)
                                            {
                                                if ((nsResourceRecord.RDATA as DnsNSRecord).NSDomainName.Equals(oldServerDomain, StringComparison.OrdinalIgnoreCase))
                                                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(nsResourceRecord, new DnsResourceRecord(nsResourceRecord.Name, nsResourceRecord.Type, nsResourceRecord.Class, nsResourceRecord.TtlValue, new DnsNSRecord(strServerDomain)));
                                            }

                                            try
                                            {
                                                SaveZoneFile(zone.ZoneName);
                                            }
                                            catch (Exception ex)
                                            {
                                                _log.Write(ex);
                                            }
                                        }
                                    }
                                }
                            }

                            //allowed zone
                            {
                                ICollection<ZoneInfo> zones = _dnsServer.AllowedZoneRoot.ListAuthoritativeZones();

                                foreach (ZoneInfo zone in zones)
                                {
                                    DnsResourceRecord[] soaResourceRecords = _dnsServer.AllowedZoneRoot.GetAllRecords(zone.ZoneName, DnsResourceRecordType.SOA, false, true);
                                    if (soaResourceRecords.Length > 0)
                                    {
                                        DnsResourceRecord soaRecord = soaResourceRecords[0];
                                        DnsSOARecord soaRecordData = soaRecord.RDATA as DnsSOARecord;

                                        _dnsServer.AllowedZoneRoot.SetRecords(soaRecord.Name, soaRecord.Type, soaRecord.TtlValue, new DnsResourceRecordData[] { new DnsSOARecord(strServerDomain, "hostmaster." + strServerDomain, soaRecordData.Serial, soaRecordData.Refresh, soaRecordData.Retry, soaRecordData.Expire, soaRecordData.Minimum) });
                                    }
                                }
                            }

                            //custom blocked zone
                            {
                                ICollection<ZoneInfo> zones = _customBlockedZoneRoot.ListAuthoritativeZones();

                                foreach (ZoneInfo zone in zones)
                                {
                                    DnsResourceRecord[] soaResourceRecords = _customBlockedZoneRoot.GetAllRecords(zone.ZoneName, DnsResourceRecordType.SOA, false, true);
                                    if (soaResourceRecords.Length > 0)
                                    {
                                        DnsResourceRecord soaRecord = soaResourceRecords[0];
                                        DnsSOARecord soaRecordData = soaRecord.RDATA as DnsSOARecord;

                                        _customBlockedZoneRoot.SetRecords(soaRecord.Name, soaRecord.Type, soaRecord.TtlValue, new DnsResourceRecordData[] { new DnsSOARecord(strServerDomain, "hostmaster." + strServerDomain, soaRecordData.Serial, soaRecordData.Refresh, soaRecordData.Retry, soaRecordData.Expire, soaRecordData.Minimum) });
                                    }
                                }
                            }

                            //blocked zone
                            {
                                ICollection<ZoneInfo> zones = _dnsServer.BlockedZoneRoot.ListAuthoritativeZones();

                                foreach (ZoneInfo zone in zones)
                                {
                                    DnsResourceRecord[] soaResourceRecords = _dnsServer.BlockedZoneRoot.GetAllRecords(zone.ZoneName, DnsResourceRecordType.SOA, false, true);
                                    if (soaResourceRecords.Length > 0)
                                    {
                                        DnsResourceRecord soaRecord = soaResourceRecords[0];
                                        DnsSOARecord soaRecordData = soaRecord.RDATA as DnsSOARecord;

                                        _dnsServer.BlockedZoneRoot.SetRecords(soaRecord.Name, soaRecord.Type, soaRecord.TtlValue, new DnsResourceRecordData[] { new DnsSOARecord(strServerDomain, "hostmaster." + strServerDomain, soaRecordData.Serial, soaRecordData.Refresh, soaRecordData.Retry, soaRecordData.Expire, soaRecordData.Minimum) });
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
                    strDnsServerLocalAddresses = "0.0.0.0,127.0.0.1,::";

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

                    _dnsServer.Proxy = new NetProxy(proxyType, request.QueryString["proxyAddress"], int.Parse(request.QueryString["proxyPort"]), credential);
                }
            }

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
                        forwarders[i] = new NameServerAddress(strForwardersList[i]);

                    _dnsServer.Forwarders = forwarders;
                }
            }

            string strForwarderProtocol = request.QueryString["forwarderProtocol"];
            if (!string.IsNullOrEmpty(strForwarderProtocol))
                _dnsServer.ForwarderProtocol = (DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), strForwarderProtocol, true);

            string strBlockListUrls = request.QueryString["blockListUrls"];
            if (!string.IsNullOrEmpty(strBlockListUrls))
            {
                if (strBlockListUrls == "false")
                {
                    StopBlockListUpdateTimer();
                    FlushBlockedZone(request);

                    _blockListUrls.Clear();
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
                        if (strBlockListUrlList.Length != _blockListUrls.Count)
                        {
                            updated = true;
                        }
                        else
                        {
                            foreach (string strBlockListUrl in strBlockListUrlList)
                            {
                                if (!_blockListUrls.Contains(new Uri(strBlockListUrl)))
                                {
                                    updated = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (updated)
                    {
                        _blockListUrls.Clear();

                        foreach (string strBlockListUrl in strBlockListUrlList)
                            _blockListUrls.Add(new Uri(strBlockListUrl));

                        _blockListLastUpdatedOn = new DateTime();

                        StopBlockListUpdateTimer();
                        StartBlockListUpdateTimer();
                    }
                }
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DNS Settings were updated {serverDomain: " + _dnsServer.ServerDomain + "; dnsServerLocalAddresses: " + strDnsServerLocalAddresses + "; webServicePort: " + _webServicePort + "; enableDnsOverHttp: " + _dnsServer.EnableDnsOverHttp + "; enableDnsOverTls: " + _dnsServer.EnableDnsOverTls + "; enableDnsOverHttps: " + _dnsServer.EnableDnsOverHttps + "; tlsCertificatePath: " + _tlsCertificatePath + "; preferIPv6: " + _dnsServer.PreferIPv6 + "; logQueries: " + (_dnsServer.QueryLogManager != null) + "; allowRecursion: " + _dnsServer.AllowRecursion + "; allowRecursionOnlyForPrivateNetworks: " + _dnsServer.AllowRecursionOnlyForPrivateNetworks + "; proxyType: " + strProxyType + "; forwarders: " + strForwarders + "; forwarderProtocol: " + strForwarderProtocol + "; blockListUrl: " + strBlockListUrls + ";}");

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
                jsonWriter.WriteValue(_totalZonesBlocked);

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

                DnsClient dnsClient = new DnsClient(IPAddress.Parse("127.0.0.1"));
                dnsClient.Timeout = 200;

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
                                string ptrDomain = dnsClient.ResolvePTR(address);

                                jsonWriter.WritePropertyName("domain");
                                jsonWriter.WriteValue(ptrDomain);
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

        private void WriteChartDataSet(JsonTextWriter jsonWriter, string label, string backgroundColor, string borderColor, List<KeyValuePair<string, int>> statsPerInterval)
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
            _dnsServer.CacheZoneRoot.Flush();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Cache was flushed.");
        }

        private void ListCachedZones(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (domain == null)
                domain = "";

            string direction = request.QueryString["direction"];

            string[] subZones;
            DnsResourceRecord[] records;

            while (true)
            {
                subZones = _dnsServer.CacheZoneRoot.ListSubZones(domain);
                records = _dnsServer.CacheZoneRoot.GetAllRecords(domain, DnsResourceRecordType.ANY, false);

                if (records.Length > 0)
                    break;

                if (subZones.Length != 1)
                    break;

                if (direction == "up")
                {
                    if (domain == "")
                        break;

                    int i = domain.IndexOf('.');
                    if (i < 0)
                        domain = "";
                    else
                        domain = domain.Substring(i + 1);
                }
                else if (domain == "")
                {
                    domain = subZones[0];
                }
                else
                {
                    domain = subZones[0] + "." + domain;
                }
            }

            Array.Sort(subZones);

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(domain);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain != "")
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

            _dnsServer.CacheZoneRoot.DeleteZone(domain, true);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Cached zone was deleted: " + domain);
        }

        private void ListAllowedZones(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (domain == null)
                domain = "";

            string direction = request.QueryString["direction"];

            string[] subZones;
            DnsResourceRecord[] records;

            while (true)
            {
                subZones = _dnsServer.AllowedZoneRoot.ListSubZones(domain);
                records = _dnsServer.AllowedZoneRoot.GetAllRecords(domain, DnsResourceRecordType.ANY, false);

                if (records.Length > 0)
                    break;

                if (subZones.Length != 1)
                    break;

                if (direction == "up")
                {
                    if (domain == "")
                        break;

                    int i = domain.IndexOf('.');
                    if (i < 0)
                        domain = "";
                    else
                        domain = domain.Substring(i + 1);
                }
                else if (domain == "")
                {
                    domain = subZones[0];
                }
                else
                {
                    domain = subZones[0] + "." + domain;
                }
            }

            Array.Sort(subZones);

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(domain);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain != "")
                domain = "." + domain;

            foreach (string subZone in subZones)
                jsonWriter.WriteValue(subZone + domain);

            jsonWriter.WriteEndArray();

            WriteRecordsAsJson(records, jsonWriter, false);
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
                        AllowZone(allowedZone);

                    _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Total " + allowedZones.Length + " zones were imported into allowed zone successfully.");
                    SaveAllowedZoneFile();
                    return;
                }
            }

            throw new WebServiceException("Parameter 'allowedZones' missing.");
        }

        private void ExportAllowedZones(HttpListenerResponse response)
        {
            ICollection<ZoneInfo> zoneInfoList = _dnsServer.AllowedZoneRoot.ListAuthoritativeZones();

            response.ContentType = "text/plain";
            response.AddHeader("Content-Disposition", "attachment;filename=AllowedZones.txt");

            using (StreamWriter sW = new StreamWriter(new BufferedStream(response.OutputStream)))
            {
                foreach (ZoneInfo zoneInfo in zoneInfoList)
                    sW.WriteLine(zoneInfo.ZoneName);
            }
        }

        private void FlushAllowedZone(HttpListenerRequest request)
        {
            _dnsServer.AllowedZoneRoot.Flush();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Allowed zone was flushed.");

            SaveAllowedZoneFile();
        }

        private void DeleteAllowedZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            _dnsServer.AllowedZoneRoot.DeleteZone(domain, false);

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

            AllowZone(domain);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Zone was allowed: " + domain);
            SaveAllowedZoneFile();
        }

        private void AllowZone(string domain)
        {
            _dnsServer.AllowedZoneRoot.SetRecords(domain, DnsResourceRecordType.SOA, 60, new DnsResourceRecordData[] { new DnsSOARecord(_dnsServer.ServerDomain, "hostmaster." + _dnsServer.ServerDomain, 1, 28800, 7200, 604800, 600) });
        }

        private void ListBlockedZones(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (domain == null)
                domain = "";

            string direction = request.QueryString["direction"];

            string[] subZones;
            DnsResourceRecord[] records;

            while (true)
            {
                subZones = _dnsServer.BlockedZoneRoot.ListSubZones(domain);
                records = _dnsServer.BlockedZoneRoot.GetAllRecords(domain, DnsResourceRecordType.ANY, false);

                if (records.Length > 0)
                    break;

                if (subZones.Length != 1)
                    break;

                if (direction == "up")
                {
                    if (domain == "")
                        break;

                    int i = domain.IndexOf('.');
                    if (i < 0)
                        domain = "";
                    else
                        domain = domain.Substring(i + 1);
                }
                else if (domain == "")
                {
                    domain = subZones[0];
                }
                else
                {
                    domain = subZones[0] + "." + domain;
                }
            }

            Array.Sort(subZones);

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(domain);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain != "")
                domain = "." + domain;

            foreach (string subZone in subZones)
                jsonWriter.WriteValue(subZone + domain);

            jsonWriter.WriteEndArray();

            WriteRecordsAsJson(records, jsonWriter, false);
        }

        private void ImportCustomBlockedZones(HttpListenerRequest request)
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
                    {
                        BlockZone(blockedZone, _customBlockedZoneRoot, "custom");
                        BlockZone(blockedZone, _dnsServer.BlockedZoneRoot, "custom");
                    }

                    _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Total " + blockedZones.Length + " zones were imported into custom blocked zone successfully.");
                    SaveCustomBlockedZoneFile();
                    return;
                }
            }

            throw new WebServiceException("Parameter 'blockedZones' missing.");
        }

        private void ExportCustomBlockedZones(HttpListenerResponse response)
        {
            ICollection<ZoneInfo> zoneInfoList = _customBlockedZoneRoot.ListAuthoritativeZones();

            response.ContentType = "text/plain";
            response.AddHeader("Content-Disposition", "attachment;filename=CustomBlockedZones.txt");

            using (StreamWriter sW = new StreamWriter(new BufferedStream(response.OutputStream)))
            {
                foreach (ZoneInfo zoneInfo in zoneInfoList)
                    sW.WriteLine(zoneInfo.ZoneName);
            }
        }

        private void FlushCustomBlockedZone(HttpListenerRequest request)
        {
            //delete custom blocked zones from dns blocked zone
            foreach (ZoneInfo zone in _customBlockedZoneRoot.ListAuthoritativeZones())
                _dnsServer.BlockedZoneRoot.DeleteZone(zone.ZoneName, false);

            _customBlockedZoneRoot.Flush();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Custom blocked zone was flushed.");

            SaveCustomBlockedZoneFile();
            _totalZonesBlocked = _dnsServer.BlockedZoneRoot.ListAuthoritativeZones().Count;
        }

        private void FlushBlockedZone(HttpListenerRequest request)
        {
            _dnsServer.BlockedZoneRoot.Flush();

            //load custom blocked zone into dns block zone
            foreach (ZoneInfo zone in _customBlockedZoneRoot.ListAuthoritativeZones())
                BlockZone(zone.ZoneName, _dnsServer.BlockedZoneRoot, "custom");

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Blocked zone was flushed.");
            _totalZonesBlocked = _dnsServer.BlockedZoneRoot.ListAuthoritativeZones().Count;
        }

        private void DeleteCustomBlockedZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            bool customZoneDeleted = _customBlockedZoneRoot.DeleteZone(domain, false);
            if (!customZoneDeleted)
                throw new WebServiceException("Domain '" + domain + "' was not found in custom blocked zone. Try adding the domain into allowed zone instead to unblock it.");

            _dnsServer.BlockedZoneRoot.DeleteZone(domain, false);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Custom blocked zone was deleted: " + domain);

            SaveCustomBlockedZoneFile();
            _totalZonesBlocked--;
        }

        private void CustomBlockZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                domain = (new DnsQuestionRecord(ipAddress, DnsClass.IN)).Name;

            BlockZone(domain, _customBlockedZoneRoot, "custom");
            BlockZone(domain, _dnsServer.BlockedZoneRoot, "custom");

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Domain was added to custom block zone: " + domain);

            SaveCustomBlockedZoneFile();
            _totalZonesBlocked++;
        }

        private void BlockZone(string domain, Zone blockedZoneRoot, string blockListUrl)
        {
            blockedZoneRoot.SetRecords(new DnsResourceRecord[]
            {
                new DnsResourceRecord(domain, DnsResourceRecordType.SOA, DnsClass.IN, 60, new DnsSOARecord(_dnsServer.ServerDomain, "hostmaster." + _dnsServer.ServerDomain, 1, 28800, 7200, 604800, 600)),
                new DnsResourceRecord(domain, DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecord(IPAddress.Any)),
                new DnsResourceRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN, 60, new DnsAAAARecord(IPAddress.IPv6Any))
            });

            blockedZoneRoot.AddRecord(domain, DnsResourceRecordType.TXT, 60, new DnsTXTRecord("blockList=" + blockListUrl));
        }

        private void ListZones(JsonTextWriter jsonWriter)
        {
            ICollection<ZoneInfo> zoneList = _dnsServer.AuthoritativeZoneRoot.ListAuthoritativeZones();

            ZoneInfo[] zones = new ZoneInfo[zoneList.Count];
            zoneList.CopyTo(zones, 0);

            Array.Sort(zones);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            foreach (ZoneInfo zone in zones)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("zoneName");
                jsonWriter.WriteValue(zone.ZoneName);

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

            if (Zone.DomainEquals(domain, "resolver-associated-doh.arpa") || Zone.DomainEquals(domain, "resolver-addresses.arpa"))
                throw new WebServiceException("Access was denied to manage special DNS Server zone.");

            CreateZone(domain);
            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Authoritative zone was created: " + domain);

            SaveZoneFile(domain);

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(domain);
        }

        private void CreateZone(string domain)
        {
            _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord(_dnsServer.ServerDomain, "hostmaster." + _dnsServer.ServerDomain, uint.Parse(DateTime.UtcNow.ToString("yyyyMMddHH")), 28800, 7200, 604800, 600) });
            _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, DnsResourceRecordType.NS, 14400, new DnsResourceRecordData[] { new DnsNSRecord(_dnsServer.ServerDomain) });
        }

        private void DeleteZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            ZoneInfo zoneInfo = _dnsServer.AuthoritativeZoneRoot.GetZoneInfo(domain);
            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsServer.AuthoritativeZoneRoot.DeleteZone(domain, false))
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

            ZoneInfo zoneInfo = _dnsServer.AuthoritativeZoneRoot.GetZoneInfo(domain);
            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            _dnsServer.AuthoritativeZoneRoot.EnableZone(domain);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Authoritative zone was enabled: " + domain);

            SaveZoneFile(domain);
        }

        private void DisableZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            ZoneInfo zoneInfo = _dnsServer.AuthoritativeZoneRoot.GetZoneInfo(domain);
            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            _dnsServer.AuthoritativeZoneRoot.DisableZone(domain);

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Authoritative zone was disabled: " + domain);

            SaveZoneFile(domain);
        }

        private void AddRecord(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            ZoneInfo zoneInfo = _dnsServer.AuthoritativeZoneRoot.GetZoneInfo(domain);
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
                    _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsARecord(IPAddress.Parse(value)));
                    break;

                case DnsResourceRecordType.AAAA:
                    _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsAAAARecord(IPAddress.Parse(value)));
                    break;

                case DnsResourceRecordType.MX:
                    {
                        string preference = request.QueryString["preference"];
                        if (string.IsNullOrEmpty(preference))
                            throw new WebServiceException("Parameter 'preference' missing.");

                        _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsMXRecord(ushort.Parse(preference), value));
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsTXTRecord(value));
                    break;

                case DnsResourceRecordType.NS:
                    _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsNSRecord(value));
                    break;

                case DnsResourceRecordType.PTR:
                    _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsPTRRecord(value) });
                    break;

                case DnsResourceRecordType.CNAME:
                    _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsCNAMERecord(value) });
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

                        _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsSRVRecord(ushort.Parse(priority), ushort.Parse(weight), ushort.Parse(port), value));
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

                        _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsCAARecord(byte.Parse(flags), tag, value));
                    }
                    break;

                default:
                    throw new WebServiceException("Type not supported for AddRecords().");
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] New record was added to authoritative zone {domain: " + domain + "; type: " + type + "; value: " + value + "; ttl: " + ttl + ";}");

            SaveZoneFile(domain);
        }

        private void GetRecords(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            DnsResourceRecord[] records = _dnsServer.AuthoritativeZoneRoot.GetAllRecords(domain);
            if (records.Length == 0)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            WriteRecordsAsJson(records, jsonWriter, true);
        }

        private void WriteRecordsAsJson(DnsResourceRecord[] records, JsonTextWriter jsonWriter, bool authoritativeZoneRecords)
        {
            if (records == null)
            {
                jsonWriter.WritePropertyName("records");
                jsonWriter.WriteStartArray();
                jsonWriter.WriteEndArray();

                return;
            }

            Array.Sort(records);

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
                            DnsResourceRecordInfo rrInfo = resourceRecord.Tag as DnsResourceRecordInfo;
                            jsonWriter.WritePropertyName("disabled");
                            jsonWriter.WriteValue((rrInfo != null) && rrInfo.Disabled);
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

            ZoneInfo zoneInfo = _dnsServer.AuthoritativeZoneRoot.GetZoneInfo(domain);
            if (zoneInfo.Internal)
                throw new WebServiceException("Access was denied to manage internal DNS Server zone.");

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new WebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

            string value = request.QueryString["value"];
            if (string.IsNullOrEmpty(value))
                throw new WebServiceException("Parameter 'value' missing.");

            if (!_dnsServer.AuthoritativeZoneRoot.ZoneExists(domain))
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            switch (type)
            {
                case DnsResourceRecordType.A:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsARecord(IPAddress.Parse(value)));
                    break;

                case DnsResourceRecordType.AAAA:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsAAAARecord(IPAddress.Parse(value)));
                    break;

                case DnsResourceRecordType.MX:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsMXRecord(0, value));
                    break;

                case DnsResourceRecordType.TXT:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsTXTRecord(value));
                    break;

                case DnsResourceRecordType.NS:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsNSRecord(value));
                    break;

                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.PTR:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecords(domain, type);
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        string port = request.QueryString["port"];
                        if (string.IsNullOrEmpty(port))
                            throw new WebServiceException("Parameter 'port' missing.");

                        _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsSRVRecord(0, 0, ushort.Parse(port), value));
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

                        _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsCAARecord(byte.Parse(flags), tag, value));
                    }
                    break;

                default:
                    throw new WebServiceException("Type not supported for DeleteRecord().");
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Record was deleted from authoritative zone {domain: " + domain + "; type: " + type + "; value: " + value + ";}");

            SaveZoneFile(domain);
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

            ZoneInfo zoneInfo = _dnsServer.AuthoritativeZoneRoot.GetZoneInfo(domain);
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
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsARecord(IPAddress.Parse(value))), new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsARecord(IPAddress.Parse(newValue))) { Tag = new DnsResourceRecordInfo(disable) });
                    break;

                case DnsResourceRecordType.AAAA:
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsAAAARecord(IPAddress.Parse(value))), new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsAAAARecord(IPAddress.Parse(newValue))) { Tag = new DnsResourceRecordInfo(disable) });
                    break;

                case DnsResourceRecordType.MX:
                    string preference = request.QueryString["preference"];
                    if (string.IsNullOrEmpty(preference))
                        preference = "1";

                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsMXRecord(0, value)), new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsMXRecord(ushort.Parse(preference), newValue)) { Tag = new DnsResourceRecordInfo(disable) });
                    break;

                case DnsResourceRecordType.TXT:
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsTXTRecord(value)), new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsTXTRecord(newValue)) { Tag = new DnsResourceRecordInfo(disable) });
                    break;

                case DnsResourceRecordType.NS:
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsNSRecord(value)), new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsNSRecord(newValue)) { Tag = new DnsResourceRecordInfo(disable) });
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

                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsSOARecord(masterNameServer, responsiblePerson, uint.Parse(serial), uint.Parse(refresh), uint.Parse(retry), uint.Parse(expire), uint.Parse(minimum)) });
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsPTRRecord(value)), new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsPTRRecord(newValue)) { Tag = new DnsResourceRecordInfo(disable) });
                    break;

                case DnsResourceRecordType.CNAME:
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCNAMERecord(value)), new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCNAMERecord(newValue)) { Tag = new DnsResourceRecordInfo(disable) });
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
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSRVRecord(ushort.Parse(priority), ushort.Parse(weight), ushort.Parse(newPort), newValue)) { Tag = new DnsResourceRecordInfo(disable) };

                        _dnsServer.AuthoritativeZoneRoot.UpdateRecord(oldRecord, newRecord);
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
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCAARecord(byte.Parse(newFlags), newTag, newValue)) { Tag = new DnsResourceRecordInfo(disable) };

                        _dnsServer.AuthoritativeZoneRoot.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                default:
                    throw new WebServiceException("Type not supported for UpdateRecords().");
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] Record was updated for authoritative zone {oldDomain: " + domain + "; domain: " + newDomain + "; type: " + type + "; oldValue: " + value + "; value: " + newValue + "; ttl: " + ttl + "; disabled: " + disable + ";}");

            SaveZoneFile(newDomain);
        }

        private void ResolveQuery(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string server = request.QueryString["server"];
            if (string.IsNullOrEmpty(server))
                throw new WebServiceException("Parameter 'server' missing.");

            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new WebServiceException("Parameter 'domain' missing.");

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

                if (type == DnsResourceRecordType.PTR)
                    question = new DnsQuestionRecord(IPAddress.Parse(domain), DnsClass.IN);
                else
                    question = new DnsQuestionRecord(domain, type, DnsClass.IN);

                dnsResponse = DnsClient.RecursiveResolve(question, null, null, proxy, preferIPv6, RETRIES, TIMEOUT);
            }
            else
            {
                NameServerAddress nameServer;

                if (server == "this-server")
                {
                    nameServer = new NameServerAddress(_dnsServer.ServerDomain, IPAddress.Parse("127.0.0.1"));
                    proxy = null; //no proxy required for this server
                }
                else
                {
                    nameServer = new NameServerAddress(server);

                    if (nameServer.IPEndPoint == null)
                    {
                        if (proxy == null)
                        {
                            if (_dnsServer.AllowRecursion)
                                nameServer.ResolveIPAddress(new NameServerAddress[] { new NameServerAddress(IPAddress.Loopback) }, proxy, preferIPv6, RETRIES, TIMEOUT);
                            else
                                nameServer.RecursiveResolveIPAddress(_dnsServer.Cache, proxy, preferIPv6, RETRIES, TIMEOUT);
                        }
                    }
                    else if (protocol != DnsTransportProtocol.Tls)
                    {
                        try
                        {
                            if (_dnsServer.AllowRecursion)
                                nameServer.ResolveDomainName(new NameServerAddress[] { new NameServerAddress(IPAddress.Loopback) }, proxy, preferIPv6, RETRIES, TIMEOUT);
                            else
                                nameServer.RecursiveResolveDomainName(_dnsServer.Cache, proxy, preferIPv6, RETRIES, TIMEOUT);
                        }
                        catch
                        { }
                    }
                }

                dnsResponse = (new DnsClient(nameServer) { Proxy = proxy, PreferIPv6 = preferIPv6, Protocol = protocol, Retries = RETRIES, Timeout = TIMEOUT }).Resolve(domain, type);
            }

            if (importRecords)
            {
                List<DnsResourceRecord> recordsToSet = new List<DnsResourceRecord>();
                bool containsSOARecord = false;

                foreach (DnsResourceRecord record in dnsResponse.Answer)
                {
                    if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        record.RemoveExpiry();
                        recordsToSet.Add(record);

                        if (record.Type == DnsResourceRecordType.SOA)
                            containsSOARecord = true;
                    }
                }

                if (!containsSOARecord)
                {
                    bool SOARecordExists = false;

                    foreach (ZoneInfo zone in _dnsServer.AuthoritativeZoneRoot.ListAuthoritativeZones())
                    {
                        if (domain.EndsWith(zone.ZoneName, StringComparison.OrdinalIgnoreCase))
                        {
                            SOARecordExists = true;
                            break;
                        }
                    }

                    if (!SOARecordExists)
                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord(_dnsServer.ServerDomain, "hostmaster." + _dnsServer.ServerDomain, uint.Parse(DateTime.UtcNow.ToString("yyyyMMddHH")), 28800, 7200, 604800, 600) });
                }

                _dnsServer.AuthoritativeZoneRoot.SetRecords(recordsToSet);

                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).Username + "] DNS Client imported record(s) for authoritative zone {server: " + server + "; domain: " + domain + "; type: " + type + ";}");

                SaveZoneFile(domain);
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

                    if (!string.IsNullOrEmpty(reservedLease.HostName))
                    {
                        jsonWriter.WritePropertyName("hostName");
                        jsonWriter.WriteValue(reservedLease.HostName);
                    }

                    jsonWriter.WritePropertyName("hardwareAddress");
                    jsonWriter.WriteValue(BitConverter.ToString(reservedLease.HardwareAddress));

                    jsonWriter.WritePropertyName("address");
                    jsonWriter.WriteValue(reservedLease.Address.ToString());

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
                scope.DomainName = strDomainName == "" ? null : strDomainName;

            string strDnsTtl = request.QueryString["dnsTtl"];
            if (!string.IsNullOrEmpty(strDnsTtl))
                scope.DnsTtl = uint.Parse(strDnsTtl);

            string strRouterAddress = request.QueryString["routerAddress"];
            if (strRouterAddress != null)
                scope.RouterAddress = strRouterAddress == "" ? null : IPAddress.Parse(strRouterAddress);

            string strUseThisDnsServer = request.QueryString["useThisDnsServer"];
            if (!string.IsNullOrEmpty(strUseThisDnsServer))
                scope.UseThisDnsServer = bool.Parse(strUseThisDnsServer);

            if (!scope.UseThisDnsServer)
            {
                string strDnsServers = request.QueryString["dnsServers"];
                if (strDnsServers != null)
                {
                    if (strDnsServers == "")
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
                if (strWinsServers == "")
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
                if (strNtpServers == "")
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
                if (strStaticRoutes == "")
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
                if (strExclusions == "")
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
                if (strReservedLeases == "")
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

                        reservedLeases[i] = new Lease(LeaseType.Reserved, leaseParts[0], leaseParts[1], IPAddress.Parse(leaseParts[2]));
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

            string[] zoneFiles = Directory.GetFiles(zonePath, "*.zone");

            if (zoneFiles.Length == 0)
            {
                {
                    CreateZone("localhost");
                    _dnsServer.AuthoritativeZoneRoot.SetRecords("localhost", DnsResourceRecordType.A, 3600, new DnsResourceRecordData[] { new DnsARecord(IPAddress.Loopback) });
                    _dnsServer.AuthoritativeZoneRoot.SetRecords("localhost", DnsResourceRecordType.AAAA, 3600, new DnsResourceRecordData[] { new DnsAAAARecord(IPAddress.IPv6Loopback) });

                    SaveZoneFile("localhost");
                }

                {
                    string prtDomain = new DnsQuestionRecord(IPAddress.Loopback, DnsClass.IN).Name;

                    CreateZone(prtDomain);
                    _dnsServer.AuthoritativeZoneRoot.SetRecords(prtDomain, DnsResourceRecordType.PTR, 3600, new DnsResourceRecordData[] { new DnsPTRRecord("localhost") });

                    SaveZoneFile(prtDomain);
                }

                {
                    string prtDomain = new DnsQuestionRecord(IPAddress.IPv6Loopback, DnsClass.IN).Name;

                    CreateZone(prtDomain);
                    _dnsServer.AuthoritativeZoneRoot.SetRecords(prtDomain, DnsResourceRecordType.PTR, 3600, new DnsResourceRecordData[] { new DnsPTRRecord("localhost") });

                    SaveZoneFile(prtDomain);
                }
            }
            else
            {
                foreach (string zoneFile in zoneFiles)
                {
                    try
                    {
                        LoadZoneFile(zoneFile);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server failed to load zone file: " + zoneFile + "\r\n" + ex.ToString());
                    }
                }
            }
        }

        private void LoadZoneFile(string zoneFile)
        {
            using (FileStream fS = new FileStream(zoneFile, FileMode.Open, FileAccess.Read))
            {
                BinaryReader bR = new BinaryReader(fS);

                if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DZ")
                    throw new InvalidDataException("DnsServer zone file format is invalid.");

                switch (bR.ReadByte())
                {
                    case 1:
                        fS.Position = 0;
                        LoadZoneFileV1(fS);
                        break;

                    case 2:
                        {
                            int count = bR.ReadInt32();
                            DnsResourceRecord[] records = new DnsResourceRecord[count];

                            for (int i = 0; i < count; i++)
                                records[i] = new DnsResourceRecord(fS);

                            _dnsServer.AuthoritativeZoneRoot.SetRecords(records);
                        }
                        break;

                    case 3:
                        {
                            bool zoneDisabled = bR.ReadBoolean();
                            int count = bR.ReadInt32();

                            if (count > 0)
                            {
                                DnsResourceRecord[] records = new DnsResourceRecord[count];

                                for (int i = 0; i < count; i++)
                                {
                                    records[i] = new DnsResourceRecord(fS);
                                    records[i].Tag = new DnsResourceRecordInfo(new BinaryReader(fS));
                                }

                                _dnsServer.AuthoritativeZoneRoot.SetRecords(records);

                                if (zoneDisabled)
                                    _dnsServer.AuthoritativeZoneRoot.DisableZone(records[0].Name);
                            }
                        }
                        break;

                    default:
                        throw new InvalidDataException("DNS Zone file version not supported.");
                }
            }

            _log.Write("DNS Server successfully loaded zone file: " + zoneFile);
        }

        private void LoadZoneFileV1(Stream s)
        {
            BincodingDecoder decoder = new BincodingDecoder(s, "DZ");

            switch (decoder.Version)
            {
                case 1:
                    ICollection<Bincoding> entries = decoder.DecodeNext().GetList();
                    DnsResourceRecord[] records = new DnsResourceRecord[entries.Count];

                    int i = 0;
                    foreach (Bincoding entry in entries)
                        records[i++] = new DnsResourceRecord(entry.GetValueStream());

                    _dnsServer.AuthoritativeZoneRoot.SetRecords(records);
                    break;

                default:
                    throw new IOException("DNS Zone file version not supported: " + decoder.Version);
            }
        }

        private void SaveZoneFile(string domain)
        {
            domain = domain.ToLower();
            DnsResourceRecord[] records = _dnsServer.AuthoritativeZoneRoot.GetAllRecords(domain, DnsResourceRecordType.ANY, true, true);
            if (records.Length == 0)
                throw new WebServiceException("Zone '" + domain + "' was not found.");

            string authZone = records[0].Name.ToLower();

            ZoneInfo zoneInfo = _dnsServer.AuthoritativeZoneRoot.GetZoneInfo(domain);
            if (zoneInfo.Internal)
                return;

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize zone
                BinaryWriter bW = new BinaryWriter(mS);

                bW.Write(Encoding.ASCII.GetBytes("DZ")); //format
                bW.Write((byte)3); //version

                bW.Write(_dnsServer.AuthoritativeZoneRoot.IsZoneDisabled(domain));
                bW.Write(records.Length);

                foreach (DnsResourceRecord record in records)
                {
                    record.WriteTo(mS);

                    DnsResourceRecordInfo rrInfo = record.Tag as DnsResourceRecordInfo;
                    if (rrInfo == null)
                        rrInfo = new DnsResourceRecordInfo(); //default info

                    rrInfo.WriteTo(bW);
                }

                //write to zone file
                mS.Position = 0;

                using (FileStream fS = new FileStream(Path.Combine(Path.Combine(_configFolder, "zones"), authZone + ".zone"), FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _log.Write("Saved zone file for domain: " + domain);
        }

        private void DeleteZoneFile(string domain)
        {
            domain = domain.ToLower();

            File.Delete(Path.Combine(Path.Combine(_configFolder, "zones"), domain + ".zone"));

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
                                AllowZone(bR.ReadShortString());

                            _totalZonesAllowed = length;
                            break;

                        default:
                            throw new InvalidDataException("DnsServer allowed zone version not supported.");
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
            ICollection<ZoneInfo> allowedZones = _dnsServer.AllowedZoneRoot.ListAuthoritativeZones();

            _totalZonesAllowed = allowedZones.Count;

            string allowedZoneFile = Path.Combine(_configFolder, "allowed.config");

            using (FileStream fS = new FileStream(allowedZoneFile, FileMode.Create, FileAccess.Write))
            {
                BinaryWriter bW = new BinaryWriter(fS);

                bW.Write(Encoding.ASCII.GetBytes("AZ")); //format
                bW.Write((byte)1); //version

                bW.Write(allowedZones.Count);

                foreach (ZoneInfo zone in allowedZones)
                    bW.WriteShortString(zone.ZoneName);
            }

            _log.Write("DNS Server allowed zone file was saved: " + allowedZoneFile);
        }

        private void LoadCustomBlockedZoneFile()
        {
            string customBlockedZoneFile = Path.Combine(_configFolder, "custom-blocked.config");

            try
            {
                _log.Write("DNS Server is loading custom blocked zone file: " + customBlockedZoneFile);

                using (FileStream fS = new FileStream(customBlockedZoneFile, FileMode.Open, FileAccess.Read))
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
                            {
                                string zoneName = bR.ReadShortString();

                                BlockZone(zoneName, _customBlockedZoneRoot, "custom");
                                BlockZone(zoneName, _dnsServer.BlockedZoneRoot, "custom");
                            }

                            _totalZonesBlocked = length;
                            break;

                        default:
                            throw new InvalidDataException("DnsServer blocked zone file version not supported.");
                    }
                }

                _log.Write("DNS Server custom blocked zone file was loaded: " + customBlockedZoneFile);
            }
            catch (FileNotFoundException)
            { }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading custom blocked zone file: " + customBlockedZoneFile + "\r\n" + ex.ToString());
            }
        }

        private void SaveCustomBlockedZoneFile()
        {
            ICollection<ZoneInfo> customBlockedZones = _customBlockedZoneRoot.ListAuthoritativeZones();

            string customBlockedZoneFile = Path.Combine(_configFolder, "custom-blocked.config");

            using (FileStream fS = new FileStream(customBlockedZoneFile, FileMode.Create, FileAccess.Write))
            {
                BinaryWriter bW = new BinaryWriter(fS);

                bW.Write(Encoding.ASCII.GetBytes("BZ")); //format
                bW.Write((byte)1); //version

                bW.Write(customBlockedZones.Count);

                foreach (ZoneInfo zone in customBlockedZones)
                    bW.WriteShortString(zone.ZoneName);
            }

            _log.Write("DNS Server custom blocked zone file was saved: " + customBlockedZoneFile);
        }

        private void LoadBlockLists()
        {
            Zone blockedZoneRoot = new Zone(true);

            using (CountdownEvent countdown = new CountdownEvent(_blockListUrls.Count))
            {
                foreach (Uri blockListUrl in _blockListUrls)
                {
                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            LoadBlockListFile(blockedZoneRoot, state as Uri);
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }

                        countdown.Signal();

                    }, blockListUrl);
                }

                //load custom blocked zone into new block zone
                foreach (ZoneInfo zone in _customBlockedZoneRoot.ListAuthoritativeZones())
                    BlockZone(zone.ZoneName, blockedZoneRoot, "custom");

                countdown.Wait();
            }

            //set new blocked zone
            _dnsServer.BlockedZoneRoot = blockedZoneRoot;
            _totalZonesBlocked = blockedZoneRoot.ListAuthoritativeZones().Count;

            _log.Write("DNS Server blocked zone loading finished successfully.");
        }

        private string GetBlockListFilePath(Uri blockListUrl)
        {
            using (HashAlgorithm hash = SHA256.Create())
            {
                return Path.Combine(_configFolder, "blocklists", BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(blockListUrl.AbsoluteUri))).Replace("-", "").ToLower());
            }
        }

        private void LoadBlockListFile(Zone blockedZoneRoot, Uri blockListUrl)
        {
            string blockListAbsoluteUrl = blockListUrl.AbsoluteUri;

            try
            {
                string blockListFilePath = GetBlockListFilePath(blockListUrl);
                int count = 0;

                _log.Write("DNS Server is loading blocked zone from: " + blockListAbsoluteUrl);

                using (FileStream fS = new FileStream(blockListFilePath, FileMode.Open, FileAccess.Read))
                {
                    //parse hosts file and populate block zone
                    StreamReader sR = new StreamReader(fS, true);

                    while (true)
                    {
                        string line = sR.ReadLine();
                        if (line == null)
                            break; //eof

                        line = line.TrimStart(' ', '\t');

                        if (line == "")
                            continue; //skip empty line

                        if (line.StartsWith("#"))
                            continue; //skip comment line

                        string firstWord = PopWord(ref line);
                        string secondWord = PopWord(ref line);

                        string strIpAddress = null;
                        string hostname;

                        if (secondWord == "")
                        {
                            hostname = firstWord;
                        }
                        else
                        {
                            strIpAddress = firstWord;
                            hostname = secondWord;
                        }

                        if (!DnsClient.IsDomainNameValid(hostname, false))
                            continue;

                        switch (hostname.ToLower())
                        {
                            case "":
                            case "localhost":
                            case "localhost.localdomain":
                            case "local":
                            case "broadcasthost":
                            case "ip6-localhost":
                            case "ip6-loopback":
                            case "ip6-localnet":
                            case "ip6-mcastprefix":
                            case "ip6-allnodes":
                            case "ip6-allrouters":
                            case "ip6-allhosts":
                                continue; //skip these hostnames
                        }

                        if (IPAddress.TryParse(hostname, out IPAddress host))
                            continue; //skip line when hostname is IP address

                        IPAddress ipAddress;

                        if (string.IsNullOrEmpty(strIpAddress) || !IPAddress.TryParse(strIpAddress, out ipAddress))
                            ipAddress = IPAddress.Any;

                        if (ipAddress.Equals(IPAddress.Any) || ipAddress.Equals(IPAddress.Loopback) || ipAddress.Equals(IPAddress.IPv6Any) || ipAddress.Equals(IPAddress.IPv6Loopback))
                        {
                            BlockZone(hostname, blockedZoneRoot, blockListAbsoluteUrl);
                            count++;
                        }
                    }
                }

                _log.Write("DNS Server blocked zone was loaded (" + count + " domains) from: " + blockListAbsoluteUrl);
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server failed to load block list from: " + blockListAbsoluteUrl + "\r\n" + ex.ToString());
            }
        }

        private void UpdateBlockLists()
        {
            bool success = false;

            foreach (Uri blockListUrl in _blockListUrls)
            {
                string blockListFilePath = GetBlockListFilePath(blockListUrl);
                string blockListDownloadFilePath = blockListFilePath + ".downloading";

                try
                {
                    int retries = 1;

                    while (true)
                    {
                        if (File.Exists(blockListDownloadFilePath))
                            File.Delete(blockListDownloadFilePath);

                        using (WebClientEx wC = new WebClientEx())
                        {
                            wC.Proxy = _dnsServer.Proxy;
                            wC.Timeout = 60000;

                            try
                            {
                                wC.DownloadFile(blockListUrl, blockListDownloadFilePath);
                            }
                            catch (WebException)
                            {
                                if (retries < BLOCK_LIST_UPDATE_RETRIES)
                                {
                                    retries++;
                                    continue;
                                }

                                throw;
                            }
                        }

                        if (File.Exists(blockListFilePath))
                            File.Delete(blockListFilePath);

                        File.Move(blockListDownloadFilePath, blockListFilePath);

                        success = true;
                        _log.Write("DNS Server successfully downloaded block list (" + WebUtilities.GetFormattedSize(new FileInfo(blockListFilePath).Length) + "): " + blockListUrl.AbsoluteUri);
                        break;
                    }
                }
                catch (Exception ex)
                {
                    _log.Write("DNS Server failed to download block list and will use previously downloaded file (if available): " + blockListUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            if (success)
            {
                //save last updated on time
                _blockListLastUpdatedOn = DateTime.UtcNow;
                SaveConfigFile();

                LoadBlockLists();
            }
        }

        private static string PopWord(ref string line)
        {
            if (line == "")
                return line;

            line = line.TrimStart(' ', '\t');

            int i = line.IndexOf(' ');

            if (i < 0)
                i = line.IndexOf('\t');

            string word;

            if (i < 0)
            {
                word = line;
                line = "";
            }
            else
            {
                word = line.Substring(0, i);
                line = line.Substring(i + 1);
            }

            return word;
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
                            UpdateBlockLists();
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while updating block list.\r\n" + ex.ToString());
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
                        case 1:
                            fS.Position = 0;
                            LoadConfigFileV1(fS);
                            break;

                        case 2:
                        case 3:
                        case 4:
                        case 5:
                        case 6:
                        case 7:
                        case 8:
                        case 9:
                            _dnsServer.ServerDomain = bR.ReadShortString();
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

                                _dnsServer.Proxy = new NetProxy(proxyType, address, port, credential);
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
                                //block list
                                int count = bR.ReadByte();

                                for (int i = 0; i < count; i++)
                                    _blockListUrls.Add(new Uri(bR.ReadShortString()));

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

                                if (_tlsCertificatePath == "")
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

                _dnsServer.ServerDomain = Environment.MachineName.ToLower();
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

        private void LoadConfigFileV1(Stream s)
        {
            BincodingDecoder decoder = new BincodingDecoder(s, "DS");

            switch (decoder.Version)
            {
                case 1:
                    while (true)
                    {
                        Bincoding item = decoder.DecodeNext();
                        if (item.Type == BincodingType.NULL)
                            break;

                        if (item.Type == BincodingType.KEY_VALUE_PAIR)
                        {
                            KeyValuePair<string, Bincoding> pair = item.GetKeyValuePair();

                            switch (pair.Key)
                            {
                                case "serverDomain":
                                    _dnsServer.ServerDomain = pair.Value.GetStringValue();
                                    break;

                                case "webServicePort":
                                    _webServicePort = pair.Value.GetIntegerValue();
                                    break;

                                case "dnsPreferIPv6":
                                    _dnsServer.PreferIPv6 = pair.Value.GetBooleanValue();
                                    break;

                                case "logQueries":
                                    if (pair.Value.GetBooleanValue())
                                        _dnsServer.QueryLogManager = _log;

                                    break;

                                case "dnsAllowRecursion":
                                    _dnsServer.AllowRecursion = pair.Value.GetBooleanValue();
                                    break;

                                case "dnsForwarders":
                                    ICollection<Bincoding> entries = pair.Value.GetList();
                                    NameServerAddress[] forwarders = new NameServerAddress[entries.Count];

                                    int i = 0;
                                    foreach (Bincoding entry in entries)
                                        forwarders[i++] = new NameServerAddress(IPAddress.Parse(entry.GetStringValue()));

                                    _dnsServer.Forwarders = forwarders;
                                    break;

                                case "credentials":
                                    foreach (KeyValuePair<string, Bincoding> credential in pair.Value.GetDictionary())
                                        SetCredentials(credential.Key, credential.Value.GetStringValue());

                                    break;

                                case "disabledZones":
                                    foreach (Bincoding disabledZone in pair.Value.GetList())
                                        _dnsServer.AuthoritativeZoneRoot.DisableZone(disabledZone.GetStringValue());

                                    break;
                            }
                        }
                    }
                    break;

                default:
                    throw new IOException("DNS Config file version not supported: " + decoder.Version);
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
                bW.Write((byte)9); //version

                bW.WriteShortString(_dnsServer.ServerDomain);
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
                    bW.Write((byte)_blockListUrls.Count);

                    foreach (Uri blockListUrl in _blockListUrls)
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
                        _dnsServer.AuthoritativeZoneRoot.DisableZone(domain);
                        SaveZoneFile(domain);
                    }
                }

                ThreadPool.QueueUserWorkItem(delegate (object state)
                {
                    try
                    {
                        LoadAllowedZoneFile();
                        LoadCustomBlockedZoneFile();
                        LoadBlockLists();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                });

                _dnsServer.Start();

                //start dhcp server
                _dhcpServer = new DhcpServer(Path.Combine(_configFolder, "scopes"));
                _dhcpServer.AuthoritativeZoneRoot = _dnsServer.AuthoritativeZoneRoot;
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

            //Scope scope = new Scope("test", IPAddress.Parse("192.168.120.1"), IPAddress.Parse("192.168.120.100"), IPAddress.Parse("255.255.255.0"), true);

            //scope.RouterAddress = IPAddress.Parse("192.168.120.1");
            //scope.DnsServers = new IPAddress[] { IPAddress.Parse("192.168.10.4") };
            //scope.WinsServers = new IPAddress[] { IPAddress.Parse("192.168.10.4") };
            //scope.NtpServers = new IPAddress[] { IPAddress.Parse("192.168.10.4") };
            //scope.StaticRoutes = new Dhcp.Options.ClasslessStaticRouteOption.Route[] { new Dhcp.Options.ClasslessStaticRouteOption.Route(IPAddress.Parse("192.168.10.0"), IPAddress.Parse("255.255.255.0"), IPAddress.Parse("192.168.10.4")) };
            //scope.OfferDelayTime = 2;
            //scope.DomainName = "local";
            //scope.Enabled = true;
            //scope.AddExclusion(IPAddress.Parse("192.168.120.1"), IPAddress.Parse("192.168.120.10"));
            //scope.AddReservedLease(new byte[] { 0x00, 0x0C, 0x29, 0x36, 0xC9, 0x84 }, IPAddress.Parse("192.168.120.50"));

            //_dhcpServer.AddScope(scope);
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
        { get { return _dnsServer.ServerDomain; } }

        public int WebServicePort
        { get { return _webServicePort; } }

        public string WebServiceHostname
        { get { return _webServiceHostname; } }

        #endregion
    }
}
