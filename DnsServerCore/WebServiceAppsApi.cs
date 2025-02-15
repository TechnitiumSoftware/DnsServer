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
using DnsServerCore.Auth;
using DnsServerCore.Dns.Applications;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Http.Client;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        sealed class WebServiceAppsApi : IDisposable
        {
            #region variables

            readonly DnsWebService _dnsWebService;
            readonly Uri _appStoreUri;

            string _storeAppsJsonData;
            DateTime _storeAppsJsonDataUpdatedOn;
            const int STORE_APPS_JSON_DATA_CACHE_TIME_SECONDS = 900;

            Timer _appUpdateTimer;
            const int APP_UPDATE_TIMER_INITIAL_INTERVAL = 10000;
            const int APP_UPDATE_TIMER_PERIODIC_INTERVAL = 86400000;

            #endregion

            #region constructor

            public WebServiceAppsApi(DnsWebService dnsWebService, Uri appStoreUri)
            {
                _dnsWebService = dnsWebService;
                _appStoreUri = appStoreUri;
            }

            #endregion

            #region IDisposable

            bool _disposed;

            public void Dispose()
            {
                if (_disposed)
                    return;

                if (_appUpdateTimer is not null)
                    _appUpdateTimer.Dispose();

                _disposed = true;
            }

            #endregion

            #region private

            private void StartAutomaticUpdate()
            {
                if (_appUpdateTimer is null)
                {
                    _appUpdateTimer = new Timer(async delegate (object state)
                    {
                        try
                        {
                            if (_dnsWebService._dnsServer.DnsApplicationManager.Applications.Count < 1)
                                return;

                            _dnsWebService._log.Write("DNS Server has started automatic update check for DNS Apps.");

                            string storeAppsJsonData = await GetStoreAppsJsonData(true);
                            using JsonDocument jsonDocument = JsonDocument.Parse(storeAppsJsonData);
                            JsonElement jsonStoreAppsArray = jsonDocument.RootElement;

                            foreach (DnsApplication application in _dnsWebService._dnsServer.DnsApplicationManager.Applications.Values)
                            {
                                foreach (JsonElement jsonStoreApp in jsonStoreAppsArray.EnumerateArray())
                                {
                                    string name = jsonStoreApp.GetProperty("name").GetString();
                                    if (name.Equals(application.Name))
                                    {
                                        string url = null;
                                        Version storeAppVersion = null;
                                        Version lastServerVersion = null;

                                        foreach (JsonElement jsonVersion in jsonStoreApp.GetProperty("versions").EnumerateArray())
                                        {
                                            string strServerVersion = jsonVersion.GetProperty("serverVersion").GetString();
                                            Version requiredServerVersion = new Version(strServerVersion);

                                            if (_dnsWebService._currentVersion < requiredServerVersion)
                                                continue;

                                            if ((lastServerVersion is not null) && (lastServerVersion > requiredServerVersion))
                                                continue;

                                            string version = jsonVersion.GetProperty("version").GetString();
                                            url = jsonVersion.GetProperty("url").GetString();

                                            storeAppVersion = new Version(version);
                                            lastServerVersion = requiredServerVersion;
                                        }

                                        if ((storeAppVersion is not null) && (storeAppVersion > application.Version))
                                        {
                                            try
                                            {
                                                await DownloadAndUpdateAppAsync(application.Name, url, true);

                                                _dnsWebService._log.Write("DNS application '" + application.Name + "' was automatically updated successfully from: " + url);
                                            }
                                            catch (Exception ex)
                                            {
                                                _dnsWebService._log.Write("Failed to automatically download and update DNS application '" + application.Name + "': " + ex.ToString());
                                            }
                                        }

                                        break;
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    });

                    _appUpdateTimer.Change(APP_UPDATE_TIMER_INITIAL_INTERVAL, APP_UPDATE_TIMER_PERIODIC_INTERVAL);
                }
            }

            private void StopAutomaticUpdate()
            {
                if (_appUpdateTimer is not null)
                {
                    _appUpdateTimer.Dispose();
                    _appUpdateTimer = null;
                }
            }

            private async Task<string> GetStoreAppsJsonData(bool doRetry)
            {
                if ((_storeAppsJsonData is null) || (DateTime.UtcNow > _storeAppsJsonDataUpdatedOn.AddSeconds(STORE_APPS_JSON_DATA_CACHE_TIME_SECONDS)))
                {
                    SocketsHttpHandler handler = new SocketsHttpHandler();
                    handler.Proxy = _dnsWebService._dnsServer.Proxy;
                    handler.UseProxy = _dnsWebService._dnsServer.Proxy is not null;
                    handler.AutomaticDecompression = DecompressionMethods.All;

                    HttpClientNetworkHandler networkHandler = new HttpClientNetworkHandler(handler, _dnsWebService._dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default, _dnsWebService._dnsServer);

                    if (!doRetry)
                        networkHandler.Retries = 1;

                    using (HttpClient http = new HttpClient(networkHandler))
                    {
                        _storeAppsJsonData = await http.GetStringAsync(_appStoreUri);
                        _storeAppsJsonDataUpdatedOn = DateTime.UtcNow;
                    }
                }

                return _storeAppsJsonData;
            }

            private async Task<DnsApplication> DownloadAndUpdateAppAsync(string applicationName, string url, bool doRetry)
            {
                string tmpFile = Path.GetTempFileName();
                try
                {
                    using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        //download to temp file
                        SocketsHttpHandler handler = new SocketsHttpHandler();
                        handler.Proxy = _dnsWebService._dnsServer.Proxy;
                        handler.UseProxy = _dnsWebService._dnsServer.Proxy is not null;
                        handler.AutomaticDecompression = DecompressionMethods.All;

                        HttpClientNetworkHandler networkHandler = new HttpClientNetworkHandler(handler, _dnsWebService._dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default, _dnsWebService._dnsServer);

                        if (!doRetry)
                            networkHandler.Retries = 1;

                        using (HttpClient http = new HttpClient(networkHandler))
                        {
                            using (Stream httpStream = await http.GetStreamAsync(url))
                            {
                                await httpStream.CopyToAsync(fS);
                            }
                        }

                        //update app
                        fS.Position = 0;
                        return await _dnsWebService._dnsServer.DnsApplicationManager.UpdateApplicationAsync(applicationName, fS);
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
                        _dnsWebService._log.Write(ex);
                    }
                }
            }

            private void WriteAppAsJson(Utf8JsonWriter jsonWriter, DnsApplication application, JsonElement jsonStoreAppsArray = default)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WriteString("name", application.Name);
                jsonWriter.WriteString("description", application.Description);
                jsonWriter.WriteString("version", DnsWebService.GetCleanVersion(application.Version));

                if (jsonStoreAppsArray.ValueKind != JsonValueKind.Undefined)
                {
                    foreach (JsonElement jsonStoreApp in jsonStoreAppsArray.EnumerateArray())
                    {
                        string name = jsonStoreApp.GetProperty("name").GetString();
                        if (name.Equals(application.Name))
                        {
                            string version = null;
                            string url = null;
                            Version storeAppVersion = null;
                            Version lastServerVersion = null;

                            foreach (JsonElement jsonVersion in jsonStoreApp.GetProperty("versions").EnumerateArray())
                            {
                                string strServerVersion = jsonVersion.GetProperty("serverVersion").GetString();
                                Version requiredServerVersion = new Version(strServerVersion);

                                if (_dnsWebService._currentVersion < requiredServerVersion)
                                    continue;

                                if ((lastServerVersion is not null) && (lastServerVersion > requiredServerVersion))
                                    continue;

                                version = jsonVersion.GetProperty("version").GetString();
                                url = jsonVersion.GetProperty("url").GetString();

                                storeAppVersion = new Version(version);
                                lastServerVersion = requiredServerVersion;
                            }

                            if (storeAppVersion is null)
                                break; //no compatible update available

                            jsonWriter.WriteString("updateVersion", version);
                            jsonWriter.WriteString("updateUrl", url);
                            jsonWriter.WriteBoolean("updateAvailable", storeAppVersion > application.Version);
                            break;
                        }
                    }
                }

                jsonWriter.WritePropertyName("dnsApps");
                {
                    jsonWriter.WriteStartArray();

                    foreach (KeyValuePair<string, IDnsApplication> dnsApp in application.DnsApplications)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("classPath", dnsApp.Key);
                        jsonWriter.WriteString("description", dnsApp.Value.Description);

                        if (dnsApp.Value is IDnsAppRecordRequestHandler appRecordHandler)
                        {
                            jsonWriter.WriteBoolean("isAppRecordRequestHandler", true);
                            jsonWriter.WriteString("recordDataTemplate", appRecordHandler.ApplicationRecordDataTemplate);
                        }
                        else
                        {
                            jsonWriter.WriteBoolean("isAppRecordRequestHandler", false);
                        }

                        jsonWriter.WriteBoolean("isRequestController", dnsApp.Value is IDnsRequestController);
                        jsonWriter.WriteBoolean("isAuthoritativeRequestHandler", dnsApp.Value is IDnsAuthoritativeRequestHandler);
                        jsonWriter.WriteBoolean("isRequestBlockingHandler", dnsApp.Value is IDnsRequestBlockingHandler);
                        jsonWriter.WriteBoolean("isQueryLogger", dnsApp.Value is IDnsQueryLogger);
                        jsonWriter.WriteBoolean("isQueryLogs", dnsApp.Value is IDnsQueryLogs);
                        jsonWriter.WriteBoolean("isPostProcessor", dnsApp.Value is IDnsPostProcessor);

                        jsonWriter.WriteEndObject();
                    }

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteEndObject();
            }

            #endregion

            #region public

            public async Task ListInstalledAppsAsync(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.View) &&
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.View) &&
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.View)
                   )
                {
                    throw new DnsWebServiceException("Access was denied.");
                }

                List<string> apps = new List<string>(_dnsWebService._dnsServer.DnsApplicationManager.Applications.Keys);
                apps.Sort();

                JsonDocument jsonDocument = null;
                try
                {
                    JsonElement jsonStoreAppsArray = default;

                    if (apps.Count > 0)
                    {
                        try
                        {
                            string storeAppsJsonData = await TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                            {
                                return GetStoreAppsJsonData(false);
                            }, 5000);

                            jsonDocument = JsonDocument.Parse(storeAppsJsonData);
                            jsonStoreAppsArray = jsonDocument.RootElement;
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    }

                    Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                    jsonWriter.WritePropertyName("apps");
                    jsonWriter.WriteStartArray();

                    foreach (string app in apps)
                    {
                        if (_dnsWebService._dnsServer.DnsApplicationManager.Applications.TryGetValue(app, out DnsApplication application))
                            WriteAppAsJson(jsonWriter, application, jsonStoreAppsArray);
                    }

                    jsonWriter.WriteEndArray();
                }
                finally
                {
                    if (jsonDocument is not null)
                        jsonDocument.Dispose();
                }
            }

            public async Task ListStoreApps(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                string storeAppsJsonData = await TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                {
                    return GetStoreAppsJsonData(false);
                }, 30000);

                using JsonDocument jsonDocument = JsonDocument.Parse(storeAppsJsonData);
                JsonElement jsonStoreAppsArray = jsonDocument.RootElement;

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("storeApps");
                jsonWriter.WriteStartArray();

                foreach (JsonElement jsonStoreApp in jsonStoreAppsArray.EnumerateArray())
                {
                    string name = jsonStoreApp.GetProperty("name").GetString();
                    string description = jsonStoreApp.GetProperty("description").GetString();
                    string version = null;
                    string url = null;
                    string size = null;
                    Version storeAppVersion = null;
                    Version lastServerVersion = null;

                    foreach (JsonElement jsonVersion in jsonStoreApp.GetProperty("versions").EnumerateArray())
                    {
                        string strServerVersion = jsonVersion.GetProperty("serverVersion").GetString();
                        Version requiredServerVersion = new Version(strServerVersion);

                        if (_dnsWebService._currentVersion < requiredServerVersion)
                            continue;

                        if ((lastServerVersion is not null) && (lastServerVersion > requiredServerVersion))
                            continue;

                        version = jsonVersion.GetProperty("version").GetString();
                        url = jsonVersion.GetProperty("url").GetString();
                        size = jsonVersion.GetProperty("size").GetString();

                        storeAppVersion = new Version(version);
                        lastServerVersion = requiredServerVersion;
                    }

                    if (storeAppVersion is null)
                        continue; //app is not compatible

                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteString("name", name);
                    jsonWriter.WriteString("description", description);
                    jsonWriter.WriteString("version", version);
                    jsonWriter.WriteString("url", url);
                    jsonWriter.WriteString("size", size);

                    bool installed = _dnsWebService._dnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication installedApp);

                    jsonWriter.WriteBoolean("installed", installed);

                    if (installed)
                    {
                        jsonWriter.WriteString("installedVersion", DnsWebService.GetCleanVersion(installedApp.Version));
                        jsonWriter.WriteBoolean("updateAvailable", storeAppVersion > installedApp.Version);
                    }

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            public async Task DownloadAndInstallAppAsync(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();
                string url = request.GetQueryOrForm("url");

                if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    throw new DnsWebServiceException("Parameter 'url' value must start with 'https://'.");

                string tmpFile = Path.GetTempFileName();
                try
                {
                    using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        //download to temp file
                        SocketsHttpHandler handler = new SocketsHttpHandler();
                        handler.Proxy = _dnsWebService._dnsServer.Proxy;
                        handler.UseProxy = _dnsWebService._dnsServer.Proxy is not null;
                        handler.AutomaticDecompression = DecompressionMethods.All;

                        using (HttpClient http = new HttpClient(new HttpClientNetworkHandler(handler, _dnsWebService._dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default, _dnsWebService._dnsServer)))
                        {
                            using (Stream httpStream = await http.GetStreamAsync(url))
                            {
                                await httpStream.CopyToAsync(fS);
                            }
                        }

                        //install app
                        fS.Position = 0;
                        DnsApplication application = await _dnsWebService._dnsServer.DnsApplicationManager.InstallApplicationAsync(name, fS);

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] DNS application '" + name + "' was installed successfully from: " + url);

                        Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                        jsonWriter.WritePropertyName("installedApp");
                        WriteAppAsJson(jsonWriter, application);
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
                        _dnsWebService._log.Write(ex);
                    }
                }
            }

            public async Task DownloadAndUpdateAppAsync(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();
                string url = request.GetQueryOrForm("url");

                if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    throw new DnsWebServiceException("Parameter 'url' value must start with 'https://'.");

                DnsApplication application = await DownloadAndUpdateAppAsync(name, url, false);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] DNS application '" + name + "' was updated successfully from: " + url);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("updatedApp");
                WriteAppAsJson(jsonWriter, application);
            }

            public async Task InstallAppAsync(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();

                if (!request.HasFormContentType || (request.Form.Files.Count == 0))
                    throw new DnsWebServiceException("DNS application zip file is missing.");

                string tmpFile = Path.GetTempFileName();
                try
                {
                    using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        //write to temp file
                        await request.Form.Files[0].CopyToAsync(fS);

                        //install app
                        fS.Position = 0;
                        DnsApplication application = await _dnsWebService._dnsServer.DnsApplicationManager.InstallApplicationAsync(name, fS);

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] DNS application '" + name + "' was installed successfully.");

                        Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                        jsonWriter.WritePropertyName("installedApp");
                        WriteAppAsJson(jsonWriter, application);
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
                        _dnsWebService._log.Write(ex);
                    }
                }
            }

            public async Task UpdateAppAsync(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();

                if (!request.HasFormContentType || (request.Form.Files.Count == 0))
                    throw new DnsWebServiceException("DNS application zip file is missing.");

                string tmpFile = Path.GetTempFileName();
                try
                {
                    using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        //write to temp file
                        await request.Form.Files[0].CopyToAsync(fS);

                        //update app
                        fS.Position = 0;
                        DnsApplication application = await _dnsWebService._dnsServer.DnsApplicationManager.UpdateApplicationAsync(name, fS);

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] DNS application '" + name + "' was updated successfully.");

                        Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                        jsonWriter.WritePropertyName("updatedApp");
                        WriteAppAsJson(jsonWriter, application);
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
                        _dnsWebService._log.Write(ex);
                    }
                }
            }

            public void UninstallApp(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();

                _dnsWebService._dnsServer.DnsApplicationManager.UninstallApplication(name);
                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] DNS application '" + name + "' was uninstalled successfully.");
            }

            public async Task GetAppConfigAsync(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();

                if (!_dnsWebService._dnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication application))
                    throw new DnsWebServiceException("DNS application was not found: " + name);

                string config = await application.GetConfigAsync();

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteString("config", config);
            }

            public async Task SetAppConfigAsync(HttpContext context)
            {
                UserSession session = context.GetCurrentSession();

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();

                if (!_dnsWebService._dnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication application))
                    throw new DnsWebServiceException("DNS application was not found: " + name);

                string config = request.QueryOrForm("config");
                if (config is null)
                    throw new DnsWebServiceException("Parameter 'config' missing.");

                if (config.Length == 0)
                    config = null;

                await application.SetConfigAsync(config);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + session.User.Username + "] DNS application '" + name + "' app config was saved successfully.");
            }

            #endregion

            #region properties

            public bool EnableAutomaticUpdate
            {
                get { return _appUpdateTimer is not null; }
                set
                {
                    if (value)
                        StartAutomaticUpdate();
                    else
                        StopAutomaticUpdate();
                }
            }

            #endregion
        }
    }
}
