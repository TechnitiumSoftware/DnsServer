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
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        sealed class WebServiceAppsApi 
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceAppsApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.View) &&
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.View) &&
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, sessionUser, PermissionFlag.View)
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
                                return _dnsWebService._dnsServer.DnsApplicationManager.GetStoreAppsJsonData();
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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                string storeAppsJsonData = await TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                {
                    return _dnsWebService._dnsServer.DnsApplicationManager.GetStoreAppsJsonData();
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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();
                string url = request.GetQueryOrForm("url");

                if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    throw new DnsWebServiceException("Parameter 'url' value must start with 'https://'.");

                DnsApplication application = await _dnsWebService._dnsServer.DnsApplicationManager.DownloadAndInstallAppAsync(name, new Uri(url));

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DNS application '" + name + "' was installed successfully from: " + url);
                
                //trigger cluster update
                if (_dnsWebService._clusterManager.ClusterInitialized)
                    _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("installedApp");
                WriteAppAsJson(jsonWriter, application);
            }

            public async Task DownloadAndUpdateAppAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();
                string url = request.GetQueryOrForm("url");

                if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    throw new DnsWebServiceException("Parameter 'url' value must start with 'https://'.");

                DnsApplication application = await _dnsWebService._dnsServer.DnsApplicationManager.DownloadAndUpdateAppAsync(name, new Uri(url));

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DNS application '" + name + "' was updated successfully from: " + url);

                //trigger cluster update
                if (_dnsWebService._clusterManager.ClusterInitialized)
                    _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("updatedApp");
                WriteAppAsJson(jsonWriter, application);
            }

            public async Task InstallAppAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();

                if (!request.HasFormContentType || (request.Form.Files.Count == 0))
                    throw new DnsWebServiceException("DNS application zip file is missing.");

                string tmpFile = Path.GetTempFileName();
                try
                {
                    await using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        //write to temp file
                        await request.Form.Files[0].CopyToAsync(fS);

                        //install app
                        fS.Position = 0;
                        DnsApplication application = await _dnsWebService._dnsServer.DnsApplicationManager.InstallApplicationAsync(name, fS);

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DNS application '" + name + "' was installed successfully.");
                        
                        //trigger cluster update
                        if (_dnsWebService._clusterManager.ClusterInitialized)
                            _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();

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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();

                if (!request.HasFormContentType || (request.Form.Files.Count == 0))
                    throw new DnsWebServiceException("DNS application zip file is missing.");

                string tmpFile = Path.GetTempFileName();
                try
                {
                    await using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        //write to temp file
                        await request.Form.Files[0].CopyToAsync(fS);

                        //update app
                        fS.Position = 0;
                        DnsApplication application = await _dnsWebService._dnsServer.DnsApplicationManager.UpdateApplicationAsync(name, fS);

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DNS application '" + name + "' was updated successfully.");

                        //trigger cluster update
                        if (_dnsWebService._clusterManager.ClusterInitialized)
                            _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
                        
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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name").Trim();

                _dnsWebService._dnsServer.DnsApplicationManager.UninstallApplication(name);
                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DNS application '" + name + "' was uninstalled successfully.");

                //trigger cluster update
                if (_dnsWebService._clusterManager.ClusterInitialized)
                    _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
            }

            public async Task GetAppConfigAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.View))
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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Apps, sessionUser, PermissionFlag.Modify))
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

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DNS application '" + name + "' app config was saved successfully.");

                //trigger cluster update
                if (_dnsWebService._clusterManager.ClusterInitialized)
                    _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
            }

            #endregion
        }
    }
}
