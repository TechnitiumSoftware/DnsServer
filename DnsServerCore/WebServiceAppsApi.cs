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
using DnsServerCore.Dns.Applications;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace DnsServerCore
{
    class WebServiceAppsApi
    {
        #region variables

        readonly DnsWebService _dnsWebService;
        readonly Uri _appStoreUri;

        string _storeAppsJsonData;
        DateTime _storeAppsJsonDataUpdatedOn;
        const int STORE_APPS_JSON_DATA_CACHE_TIME_SECONDS = 300;

        #endregion

        #region constructor

        public WebServiceAppsApi(DnsWebService dnsWebService, Uri appStoreUri)
        {
            _dnsWebService = dnsWebService;
            _appStoreUri = appStoreUri;
        }

        #endregion

        #region private

        private async Task<string> GetStoreAppsJsonData()
        {
            if ((_storeAppsJsonData == null) || (DateTime.UtcNow > _storeAppsJsonDataUpdatedOn.AddSeconds(STORE_APPS_JSON_DATA_CACHE_TIME_SECONDS)))
            {
                SocketsHttpHandler handler = new SocketsHttpHandler();
                handler.Proxy = _dnsWebService.DnsServer.Proxy;
                handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;

                using (HttpClient http = new HttpClient(handler))
                {
                    _storeAppsJsonData = await http.GetStringAsync(_appStoreUri);
                    _storeAppsJsonDataUpdatedOn = DateTime.UtcNow;
                }
            }

            return _storeAppsJsonData;
        }

        #endregion

        #region public

        public async Task ListInstalledAppsAsync(JsonTextWriter jsonWriter)
        {
            List<string> apps = new List<string>(_dnsWebService.DnsServer.DnsApplicationManager.Applications.Keys);

            apps.Sort();

            dynamic jsonStoreAppsArray = null;

            if (apps.Count > 0)
            {
                try
                {
                    string storeAppsJsonData = await GetStoreAppsJsonData().WithTimeout(5000);
                    jsonStoreAppsArray = JsonConvert.DeserializeObject(storeAppsJsonData);
                }
                catch
                { }
            }

            jsonWriter.WritePropertyName("apps");
            jsonWriter.WriteStartArray();

            foreach (string app in apps)
            {
                if (_dnsWebService.DnsServer.DnsApplicationManager.Applications.TryGetValue(app, out DnsApplication application))
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("name");
                    jsonWriter.WriteValue(application.Name);

                    jsonWriter.WritePropertyName("version");
                    jsonWriter.WriteValue(DnsWebService.GetCleanVersion(application.Version));

                    if (jsonStoreAppsArray != null)
                    {
                        foreach (dynamic jsonStoreApp in jsonStoreAppsArray)
                        {
                            string name = jsonStoreApp.name.Value;
                            if (name.Equals(application.Name))
                            {
                                string version = jsonStoreApp.version.Value;
                                string url = jsonStoreApp.url.Value;

                                jsonWriter.WritePropertyName("updateVersion");
                                jsonWriter.WriteValue(version);

                                jsonWriter.WritePropertyName("updateUrl");
                                jsonWriter.WriteValue(url);

                                jsonWriter.WritePropertyName("updateAvailable");
                                jsonWriter.WriteValue(new Version(version) > application.Version);
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

                            jsonWriter.WritePropertyName("classPath");
                            jsonWriter.WriteValue(dnsApp.Key);

                            jsonWriter.WritePropertyName("description");
                            jsonWriter.WriteValue(dnsApp.Value.Description);

                            if (dnsApp.Value is IDnsAppRecordRequestHandler appRecordHandler)
                            {
                                jsonWriter.WritePropertyName("isAppRecordRequestHandler");
                                jsonWriter.WriteValue(true);

                                jsonWriter.WritePropertyName("recordDataTemplate");
                                jsonWriter.WriteValue(appRecordHandler.ApplicationRecordDataTemplate);
                            }
                            else
                            {
                                jsonWriter.WritePropertyName("isAppRecordRequestHandler");
                                jsonWriter.WriteValue(false);
                            }

                            jsonWriter.WritePropertyName("isRequestController");
                            jsonWriter.WriteValue(dnsApp.Value is IDnsRequestController);

                            jsonWriter.WritePropertyName("isAuthoritativeRequestHandler");
                            jsonWriter.WriteValue(dnsApp.Value is IDnsAuthoritativeRequestHandler);

                            jsonWriter.WritePropertyName("isQueryLogger");
                            jsonWriter.WriteValue(dnsApp.Value is IDnsQueryLogger);

                            jsonWriter.WriteEndObject();
                        }

                        jsonWriter.WriteEndArray();
                    }

                    jsonWriter.WriteEndObject();
                }
            }

            jsonWriter.WriteEndArray();
        }

        public async Task ListStoreApps(JsonTextWriter jsonWriter)
        {
            string storeAppsJsonData = await GetStoreAppsJsonData();
            dynamic jsonStoreAppsArray = JsonConvert.DeserializeObject(storeAppsJsonData);

            jsonWriter.WritePropertyName("storeApps");
            jsonWriter.WriteStartArray();

            foreach (dynamic jsonStoreApp in jsonStoreAppsArray)
            {
                string name = jsonStoreApp.name.Value;
                string version = jsonStoreApp.version.Value;
                string description = jsonStoreApp.description.Value;
                string url = jsonStoreApp.url.Value;
                string size = jsonStoreApp.size.Value;

                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("name");
                jsonWriter.WriteValue(name);

                jsonWriter.WritePropertyName("version");
                jsonWriter.WriteValue(version);

                jsonWriter.WritePropertyName("description");
                jsonWriter.WriteValue(description);

                jsonWriter.WritePropertyName("url");
                jsonWriter.WriteValue(url);

                jsonWriter.WritePropertyName("size");
                jsonWriter.WriteValue(size);

                bool installed = _dnsWebService.DnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication installedApp);

                jsonWriter.WritePropertyName("installed");
                jsonWriter.WriteValue(installed);

                if (installed)
                {
                    jsonWriter.WritePropertyName("installedVersion");
                    jsonWriter.WriteValue(DnsWebService.GetCleanVersion(installedApp.Version));

                    jsonWriter.WritePropertyName("updateAvailable");
                    jsonWriter.WriteValue(new Version(version) > installedApp.Version);
                }

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        public async Task DownloadAndInstallAppAsync(HttpListenerRequest request)
        {
            string name = request.QueryString["name"];
            if (string.IsNullOrEmpty(name))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            name = name.Trim();

            string url = request.QueryString["url"];
            if (string.IsNullOrEmpty(url))
                throw new DnsWebServiceException("Parameter 'url' missing.");

            if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                throw new DnsWebServiceException("Parameter 'url' value must start with 'https://'.");

            string tmpFile = Path.GetTempFileName();
            try
            {
                using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //download to temp file
                    SocketsHttpHandler handler = new SocketsHttpHandler();
                    handler.Proxy = _dnsWebService.DnsServer.Proxy;
                    handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        using (Stream httpStream = await http.GetStreamAsync(url))
                        {
                            await httpStream.CopyToAsync(fS);
                        }
                    }

                    //install app
                    fS.Position = 0;
                    await _dnsWebService.DnsServer.DnsApplicationManager.InstallApplicationAsync(name, fS);

                    _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DNS application '" + name + "' was installed successfully from: " + url);
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
                    _dnsWebService.Log.Write(ex);
                }
            }
        }

        public async Task DownloadAndUpdateAppAsync(HttpListenerRequest request)
        {
            string name = request.QueryString["name"];
            if (string.IsNullOrEmpty(name))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            name = name.Trim();

            string url = request.QueryString["url"];
            if (string.IsNullOrEmpty(url))
                throw new DnsWebServiceException("Parameter 'url' missing.");

            if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                throw new DnsWebServiceException("Parameter 'url' value must start with 'https://'.");

            string tmpFile = Path.GetTempFileName();
            try
            {
                using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //download to temp file
                    SocketsHttpHandler handler = new SocketsHttpHandler();
                    handler.Proxy = _dnsWebService.DnsServer.Proxy;
                    handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        using (Stream httpStream = await http.GetStreamAsync(url))
                        {
                            await httpStream.CopyToAsync(fS);
                        }
                    }

                    //update app
                    fS.Position = 0;
                    await _dnsWebService.DnsServer.DnsApplicationManager.UpdateApplicationAsync(name, fS);

                    _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DNS application '" + name + "' was updated successfully from: " + url);
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
                    _dnsWebService.Log.Write(ex);
                }
            }
        }

        public async Task InstallAppAsync(HttpListenerRequest request)
        {
            string name = request.QueryString["name"];
            if (string.IsNullOrEmpty(name))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            name = name.Trim();

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

            string tmpFile = Path.GetTempFileName();
            try
            {
                using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //write to temp file
                    await request.InputStream.CopyToAsync(fS);

                    //install app
                    fS.Position = 0;
                    await _dnsWebService.DnsServer.DnsApplicationManager.InstallApplicationAsync(name, fS);

                    _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DNS application '" + name + "' was installed successfully.");
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
                    _dnsWebService.Log.Write(ex);
                }
            }
        }

        public async Task UpdateAppAsync(HttpListenerRequest request)
        {
            string name = request.QueryString["name"];
            if (string.IsNullOrEmpty(name))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            name = name.Trim();

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

            string tmpFile = Path.GetTempFileName();
            try
            {
                using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //write to temp file
                    await request.InputStream.CopyToAsync(fS);

                    //update app
                    fS.Position = 0;
                    await _dnsWebService.DnsServer.DnsApplicationManager.UpdateApplicationAsync(name, fS);

                    _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DNS application '" + name + "' was updated successfully.");
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
                    _dnsWebService.Log.Write(ex);
                }
            }
        }

        public void UninstallApp(HttpListenerRequest request)
        {
            string name = request.QueryString["name"];
            if (string.IsNullOrEmpty(name))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            name = name.Trim();

            _dnsWebService.DnsServer.DnsApplicationManager.UninstallApplication(name);
            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DNS application '" + name + "' was uninstalled successfully.");
        }

        public async Task GetAppConfigAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string name = request.QueryString["name"];
            if (string.IsNullOrEmpty(name))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            name = name.Trim();

            if (!_dnsWebService.DnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication application))
                throw new DnsWebServiceException("DNS application was not found: " + name);

            string config = await application.GetConfigAsync();

            jsonWriter.WritePropertyName("config");
            jsonWriter.WriteValue(config);
        }

        public async Task SetAppConfigAsync(HttpListenerRequest request)
        {
            string name = request.QueryString["name"];
            if (string.IsNullOrEmpty(name))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            name = name.Trim();

            if (!_dnsWebService.DnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication application))
                throw new DnsWebServiceException("DNS application was not found: " + name);

            string formRequest;
            using (StreamReader sR = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                formRequest = sR.ReadToEnd();
            }

            string[] formParts = formRequest.Split('&');

            foreach (string formPart in formParts)
            {
                if (formPart.StartsWith("config="))
                {
                    string config = formPart.Substring(7);

                    if (config.Length == 0)
                        config = null;

                    await application.SetConfigAsync(config);

                    _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DNS application '" + name + "' app config was saved successfully.");
                    return;
                }
            }

            throw new DnsWebServiceException("Missing POST parameter: config");
        }

        #endregion
    }
}
