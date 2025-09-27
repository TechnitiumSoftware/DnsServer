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
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Http.Client;

namespace DnsServerCore.Dns.Applications
{
    public sealed class DnsApplicationManager : IDisposable
    {
        #region variables

        readonly static Uri APP_STORE_URI = new Uri("https://go.technitium.com/?id=44");

        readonly DnsServer _dnsServer;

        readonly string _appsPath;

        readonly ConcurrentDictionary<string, DnsApplication> _applications = new ConcurrentDictionary<string, DnsApplication>();

        IReadOnlyList<IDnsRequestController> _dnsRequestControllers = [];
        IReadOnlyList<IDnsAuthoritativeRequestHandler> _dnsAuthoritativeRequestHandlers = [];
        IReadOnlyList<IDnsRequestBlockingHandler> _dnsRequestBlockingHandlers = [];
        IReadOnlyList<IDnsQueryLogger> _dnsQueryLoggers = [];
        IReadOnlyList<IDnsPostProcessor> _dnsPostProcessors = [];

        string _storeAppsJsonData;
        DateTime _storeAppsJsonDataUpdatedOn;
        const int STORE_APPS_JSON_DATA_CACHE_TIME_SECONDS = 900;

        Timer _appUpdateTimer;
        const int APP_UPDATE_TIMER_INITIAL_INTERVAL = 10000;
        const int APP_UPDATE_TIMER_PERIODIC_INTERVAL = 86400000;

        #endregion

        #region constructor

        public DnsApplicationManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _appsPath = Path.Combine(_dnsServer.ConfigFolder, "apps");

            if (!Directory.Exists(_appsPath))
                Directory.CreateDirectory(_appsPath);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                _appUpdateTimer?.Dispose();

                if (_applications != null)
                    UnloadAllApplications();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private async Task<DnsApplication> LoadApplicationAsync(string applicationFolder, bool refreshAppObjectList)
        {
            string applicationName = Path.GetFileName(applicationFolder);

            DnsApplication application = new DnsApplication(new InternalDnsServer(_dnsServer, applicationName, applicationFolder), applicationName);

            await application.InitializeAsync();

            if (!_applications.TryAdd(application.Name, application))
            {
                application.Dispose();
                throw new DnsServerException("DNS application already exists: " + application.Name);
            }

            application.ConfigUpdated += Application_ConfigUpdated;

            if (refreshAppObjectList)
                RefreshAppObjectLists();

            return application;
        }

        private void UnloadApplication(string applicationName)
        {
            if (!_applications.TryRemove(applicationName, out DnsApplication removedApp))
                throw new DnsServerException("DNS application does not exists: " + applicationName);

            RefreshAppObjectLists();

            removedApp.ConfigUpdated -= Application_ConfigUpdated;
            removedApp.Dispose();
        }

        private void Application_ConfigUpdated(object sender, EventArgs e)
        {
            //refresh app objects to allow sorting them as per app preference
            RefreshAppObjectLists();
        }

        private void RefreshAppObjectLists()
        {
            List<IDnsRequestController> dnsRequestControllers = new List<IDnsRequestController>(1);
            List<IDnsAuthoritativeRequestHandler> dnsAuthoritativeRequestHandlers = new List<IDnsAuthoritativeRequestHandler>(1);
            List<IDnsRequestBlockingHandler> dnsRequestBlockingHandlers = new List<IDnsRequestBlockingHandler>(1);
            List<IDnsQueryLogger> dnsQueryLoggers = new List<IDnsQueryLogger>(1);
            List<IDnsPostProcessor> dnsPostProcessors = new List<IDnsPostProcessor>(1);

            foreach (KeyValuePair<string, DnsApplication> application in _applications)
            {
                foreach (KeyValuePair<string, IDnsRequestController> controller in application.Value.DnsRequestControllers)
                    dnsRequestControllers.Add(controller.Value);

                foreach (KeyValuePair<string, IDnsAuthoritativeRequestHandler> handler in application.Value.DnsAuthoritativeRequestHandlers)
                    dnsAuthoritativeRequestHandlers.Add(handler.Value);

                foreach (KeyValuePair<string, IDnsRequestBlockingHandler> blocker in application.Value.DnsRequestBlockingHandler)
                    dnsRequestBlockingHandlers.Add(blocker.Value);

                foreach (KeyValuePair<string, IDnsQueryLogger> logger in application.Value.DnsQueryLoggers)
                    dnsQueryLoggers.Add(logger.Value);

                foreach (KeyValuePair<string, IDnsPostProcessor> processor in application.Value.DnsPostProcessors)
                    dnsPostProcessors.Add(processor.Value);
            }

            //sort app objects by preference
            dnsRequestControllers.Sort(CompareApps);
            dnsAuthoritativeRequestHandlers.Sort(CompareApps);
            dnsRequestBlockingHandlers.Sort(CompareApps);
            dnsQueryLoggers.Sort(CompareApps);
            dnsPostProcessors.Sort(CompareApps);

            _dnsRequestControllers = dnsRequestControllers;
            _dnsAuthoritativeRequestHandlers = dnsAuthoritativeRequestHandlers;
            _dnsRequestBlockingHandlers = dnsRequestBlockingHandlers;
            _dnsQueryLoggers = dnsQueryLoggers;
            _dnsPostProcessors = dnsPostProcessors;
        }

        private static int CompareApps<T>(T x, T y)
        {
            int xp;
            int yp;

            if (x is IDnsApplicationPreference xpref)
                xp = xpref.Preference;
            else
                xp = 100;

            if (y is IDnsApplicationPreference ypref)
                yp = ypref.Preference;
            else
                yp = 100;

            return xp.CompareTo(yp);
        }

        private void StartAutomaticUpdate()
        {
            if (_appUpdateTimer is null)
            {
                _appUpdateTimer = new Timer(async delegate (object state)
                {
                    try
                    {
                        if (_applications.IsEmpty)
                            return;

                        _dnsServer.LogManager.Write("DNS Server has started automatic update check for DNS Apps.");

                        string storeAppsJsonData = await GetStoreAppsJsonData();
                        using JsonDocument jsonDocument = JsonDocument.Parse(storeAppsJsonData);
                        JsonElement jsonStoreAppsArray = jsonDocument.RootElement;

                        Version currentVersion = Assembly.GetExecutingAssembly().GetName().Version;

                        foreach (DnsApplication application in _applications.Values)
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

                                        if (currentVersion < requiredServerVersion)
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
                                            await DownloadAndUpdateAppAsync(application.Name, new Uri(url));

                                            _dnsServer.LogManager.Write("DNS application '" + application.Name + "' was automatically updated successfully from: " + url);
                                        }
                                        catch (Exception ex)
                                        {
                                            _dnsServer.LogManager.Write("Failed to automatically download and update DNS application '" + application.Name + "': " + ex.ToString());
                                        }
                                    }

                                    break;
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
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

        internal async Task<string> GetStoreAppsJsonData()
        {
            if ((_storeAppsJsonData is null) || (DateTime.UtcNow > _storeAppsJsonDataUpdatedOn.AddSeconds(STORE_APPS_JSON_DATA_CACHE_TIME_SECONDS)))
            {
                HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                handler.Proxy = _dnsServer.Proxy;
                handler.NetworkType = _dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
                handler.DnsClient = _dnsServer;

                using (HttpClient http = new HttpClient(handler))
                {
                    _storeAppsJsonData = await http.GetStringAsync(APP_STORE_URI);
                    _storeAppsJsonDataUpdatedOn = DateTime.UtcNow;
                }
            }

            return _storeAppsJsonData;
        }

        #endregion

        #region public

        public void UnloadAllApplications()
        {
            foreach (KeyValuePair<string, DnsApplication> application in _applications)
            {
                try
                {
                    application.Value.Dispose();
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            }

            _applications.Clear();
            _dnsRequestControllers = Array.Empty<IDnsRequestController>();
            _dnsAuthoritativeRequestHandlers = Array.Empty<IDnsAuthoritativeRequestHandler>();
            _dnsRequestBlockingHandlers = Array.Empty<IDnsRequestBlockingHandler>();
            _dnsQueryLoggers = Array.Empty<IDnsQueryLogger>();
            _dnsPostProcessors = Array.Empty<IDnsPostProcessor>();
        }

        public async Task LoadAllApplicationsAsync()
        {
            UnloadAllApplications();

            List<Task> tasks = new List<Task>();

            foreach (string applicationFolder in Directory.GetDirectories(_appsPath))
            {
                tasks.Add(Task.Run(async delegate ()
                {
                    try
                    {
                        _dnsServer.LogManager.Write("DNS Server is loading DNS application: " + Path.GetFileName(applicationFolder));

                        _ = await LoadApplicationAsync(applicationFolder, false);

                        _dnsServer.LogManager.Write("DNS Server successfully loaded DNS application: " + Path.GetFileName(applicationFolder));
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write("DNS Server failed to load DNS application: " + Path.GetFileName(applicationFolder) + "\r\n" + ex.ToString());
                    }
                }));
            }

            await Task.WhenAll(tasks);

            RefreshAppObjectLists();
        }

        public async Task<DnsApplication> InstallApplicationAsync(string applicationName, Stream appZipStream)
        {
            foreach (char invalidChar in Path.GetInvalidFileNameChars())
            {
                if (applicationName.Contains(invalidChar))
                    throw new DnsServerException("The application name contains an invalid character: " + invalidChar);
            }

            if (_applications.ContainsKey(applicationName))
                throw new DnsServerException("DNS application already exists: " + applicationName);

            string applicationFolder = Path.Combine(_appsPath, applicationName);

            if (Directory.Exists(applicationFolder))
                Directory.Delete(applicationFolder, true);

            Directory.CreateDirectory(applicationFolder);

            //keep a copy of the zip file in the application folder for transferring to other nodes
            await using (FileStream zipCopyStream = new FileStream(Path.Combine(applicationFolder, applicationName + ".zip"), FileMode.Create, FileAccess.ReadWrite))
            {
                await appZipStream.CopyToAsync(zipCopyStream);

                zipCopyStream.Position = 0;

                using (ZipArchive appZip = new ZipArchive(zipCopyStream, ZipArchiveMode.Read, false, Encoding.UTF8))
                {
                    try
                    {
                        appZip.ExtractToDirectory(applicationFolder, true);

                        return await LoadApplicationAsync(applicationFolder, true);
                    }
                    catch
                    {
                        if (Directory.Exists(applicationFolder))
                            Directory.Delete(applicationFolder, true);

                        throw;
                    }
                }
            }
        }

        public async Task<DnsApplication> UpdateApplicationAsync(string applicationName, Stream appZipStream)
        {
            if (!_applications.ContainsKey(applicationName))
                throw new DnsServerException("DNS application does not exists: " + applicationName);

            string applicationFolder = Path.Combine(_appsPath, applicationName);

            //keep a copy of the zip file in the application folder for transferring to other nodes
            await using (FileStream zipCopyStream = new FileStream(Path.Combine(applicationFolder, applicationName + ".zip"), FileMode.Create, FileAccess.ReadWrite))
            {
                await appZipStream.CopyToAsync(zipCopyStream);

                zipCopyStream.Position = 0;

                using (ZipArchive appZip = new ZipArchive(zipCopyStream, ZipArchiveMode.Read, false, Encoding.UTF8))
                {
                    UnloadApplication(applicationName);

                    foreach (ZipArchiveEntry entry in appZip.Entries)
                    {
                        string entryPath = entry.FullName;

                        if (Path.DirectorySeparatorChar != '/')
                            entryPath = entryPath.Replace('/', '\\');

                        string filePath = Path.Combine(applicationFolder, entryPath);

                        if ((entry.Name == "dnsApp.config") && File.Exists(filePath))
                            continue; //avoid overwriting existing config file

                        Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                        entry.ExtractToFile(filePath, true);
                    }

                    return await LoadApplicationAsync(applicationFolder, true);
                }
            }
        }

        public void UninstallApplication(string applicationName)
        {
            if (_applications.TryRemove(applicationName, out DnsApplication removedApp))
            {
                RefreshAppObjectLists();

                removedApp.ConfigUpdated -= Application_ConfigUpdated;
                removedApp.Dispose();

                if (Directory.Exists(removedApp.DnsServer.ApplicationFolder))
                {
                    try
                    {
                        Directory.Delete(removedApp.DnsServer.ApplicationFolder, true);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                }
            }
        }

        public async Task<DnsApplication> DownloadAndInstallAppAsync(string applicationName, Uri uri)
        {
            string tmpFile = Path.GetTempFileName();
            try
            {
                await using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //download to temp file
                    HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                    handler.Proxy = _dnsServer.Proxy;
                    handler.NetworkType = _dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
                    handler.DnsClient = _dnsServer;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        await using (Stream httpStream = await http.GetStreamAsync(uri))
                        {
                            await httpStream.CopyToAsync(fS);
                        }
                    }

                    //install app
                    fS.Position = 0;
                    return await InstallApplicationAsync(applicationName, fS);
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
                    _dnsServer.LogManager.Write(ex);
                }
            }
        }

        public async Task<DnsApplication> DownloadAndUpdateAppAsync(string applicationName, Uri uri)
        {
            string tmpFile = Path.GetTempFileName();
            try
            {
                await using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //download to temp file
                    HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                    handler.Proxy = _dnsServer.Proxy;
                    handler.NetworkType = _dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
                    handler.DnsClient = _dnsServer;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        await using (Stream httpStream = await http.GetStreamAsync(uri))
                        {
                            await httpStream.CopyToAsync(fS);
                        }
                    }

                    //update app
                    fS.Position = 0;
                    return await UpdateApplicationAsync(applicationName, fS);
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
                    _dnsServer.LogManager.Write(ex);
                }
            }
        }

        #endregion

        #region properties

        public IReadOnlyDictionary<string, DnsApplication> Applications
        { get { return _applications; } }

        public IReadOnlyList<IDnsRequestController> DnsRequestControllers
        { get { return _dnsRequestControllers; } }

        public IReadOnlyList<IDnsAuthoritativeRequestHandler> DnsAuthoritativeRequestHandlers
        { get { return _dnsAuthoritativeRequestHandlers; } }

        public IReadOnlyList<IDnsRequestBlockingHandler> DnsRequestBlockingHandlers
        { get { return _dnsRequestBlockingHandlers; } }

        public IReadOnlyList<IDnsQueryLogger> DnsQueryLoggers
        { get { return _dnsQueryLoggers; } }

        public IReadOnlyList<IDnsPostProcessor> DnsPostProcessors
        { get { return _dnsPostProcessors; } }

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
