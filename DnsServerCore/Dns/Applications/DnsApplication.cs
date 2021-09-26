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
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;

namespace DnsServerCore.Dns.Applications
{
    public sealed class DnsApplication : IDisposable
    {
        #region variables

        readonly IDnsServer _dnsServer;
        readonly string _name;

        readonly DnsApplicationAssemblyLoadContext _appContext;

        readonly Version _version;
        readonly IReadOnlyDictionary<string, IDnsApplication> _dnsApplications;
        readonly IReadOnlyDictionary<string, IDnsAppRecordRequestHandler> _dnsAppRecordRequestHandlers;
        readonly IReadOnlyDictionary<string, IDnsRequestController> _dnsRequestControllers;
        readonly IReadOnlyDictionary<string, IDnsAuthoritativeRequestHandler> _dnsAuthoritativeRequestHandlers;
        readonly IReadOnlyDictionary<string, IDnsQueryLogger> _dnsQueryLoggers;

        #endregion

        #region constructor

        public DnsApplication(IDnsServer dnsServer, string name)
        {
            _dnsServer = dnsServer;
            _name = name;

            _appContext = new DnsApplicationAssemblyLoadContext(_dnsServer.ApplicationFolder);

            //load app assemblies
            Assembly[] loadedAssemblies = AppDomain.CurrentDomain.GetAssemblies();
            List<Assembly> appAssemblies = new List<Assembly>();

            foreach (string dllFile in Directory.GetFiles(_dnsServer.ApplicationFolder, "*.dll", SearchOption.TopDirectoryOnly))
            {
                string dllFileName = Path.GetFileNameWithoutExtension(dllFile);

                bool isLoaded = false;

                foreach (Assembly loadedAssembly in loadedAssemblies)
                {
                    AssemblyName assemblyName = loadedAssembly.GetName();

                    if (assemblyName.CodeBase != null)
                    {
                        if (Path.GetFileNameWithoutExtension(assemblyName.CodeBase).Equals(dllFileName, StringComparison.OrdinalIgnoreCase))
                        {
                            isLoaded = true;
                            break;
                        }
                    }
                    else if ((assemblyName.Name != null) && assemblyName.Name.Equals(dllFileName, StringComparison.OrdinalIgnoreCase))
                    {
                        isLoaded = true;
                        break;
                    }
                }

                if (isLoaded)
                    continue;

                try
                {
                    string pdbFile = Path.Combine(_dnsServer.ApplicationFolder, Path.GetFileNameWithoutExtension(dllFile) + ".pdb");

                    if (File.Exists(pdbFile))
                    {
                        using (FileStream dllStream = new FileStream(dllFile, FileMode.Open, FileAccess.Read))
                        {
                            using (FileStream pdbStream = new FileStream(pdbFile, FileMode.Open, FileAccess.Read))
                            {
                                appAssemblies.Add(_appContext.LoadFromStream(dllStream, pdbStream));
                            }
                        }
                    }
                    else
                    {
                        using (FileStream dllStream = new FileStream(dllFile, FileMode.Open, FileAccess.Read))
                        {
                            appAssemblies.Add(_appContext.LoadFromStream(dllStream));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);
                }
            }

            //load apps
            Dictionary<string, IDnsApplication> dnsApplications = new Dictionary<string, IDnsApplication>();
            Dictionary<string, IDnsAppRecordRequestHandler> dnsAppRecordRequestHandlers = new Dictionary<string, IDnsAppRecordRequestHandler>(2);
            Dictionary<string, IDnsRequestController> dnsRequestControllers = new Dictionary<string, IDnsRequestController>(1);
            Dictionary<string, IDnsAuthoritativeRequestHandler> dnsAuthoritativeRequestHandlers = new Dictionary<string, IDnsAuthoritativeRequestHandler>(1);
            Dictionary<string, IDnsQueryLogger> dnsQueryLoggers = new Dictionary<string, IDnsQueryLogger>(1);

            Type dnsApplicationInterface = typeof(IDnsApplication);

            foreach (Assembly appAssembly in appAssemblies)
            {
                try
                {
                    foreach (Type classType in appAssembly.ExportedTypes)
                    {
                        bool isDnsApp = false;

                        foreach (Type interfaceType in classType.GetInterfaces())
                        {
                            if (interfaceType == dnsApplicationInterface)
                            {
                                isDnsApp = true;
                                break;
                            }
                        }

                        if (isDnsApp)
                        {
                            try
                            {
                                IDnsApplication app = Activator.CreateInstance(classType) as IDnsApplication;

                                dnsApplications.Add(classType.FullName, app);

                                if (app is IDnsAppRecordRequestHandler appRecordHandler)
                                    dnsAppRecordRequestHandlers.Add(classType.FullName, appRecordHandler);

                                if (app is IDnsRequestController requestController)
                                    dnsRequestControllers.Add(classType.FullName, requestController);

                                if (app is IDnsAuthoritativeRequestHandler requestHandler)
                                    dnsAuthoritativeRequestHandlers.Add(classType.FullName, requestHandler);

                                if (app is IDnsQueryLogger logger)
                                    dnsQueryLoggers.Add(classType.FullName, logger);

                                if (_version is null)
                                    _version = appAssembly.GetName().Version;
                            }
                            catch (Exception ex)
                            {
                                _dnsServer.WriteLog(ex);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);
                }
            }

            if (_version is null)
            {
                if (dnsApplications.Count > 0)
                    _version = new Version(1, 0);
                else
                    _version = new Version(0, 0);
            }

            _dnsApplications = dnsApplications;
            _dnsAppRecordRequestHandlers = dnsAppRecordRequestHandlers;
            _dnsRequestControllers = dnsRequestControllers;
            _dnsAuthoritativeRequestHandlers = dnsAuthoritativeRequestHandlers;
            _dnsQueryLoggers = dnsQueryLoggers;
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
                if (_dnsApplications is not null)
                {
                    foreach (KeyValuePair<string, IDnsApplication> app in _dnsApplications)
                        app.Value.Dispose();
                }

                if (_appContext != null)
                    _appContext.Unload();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region internal

        internal async Task InitializeAsync()
        {
            string config = await GetConfigAsync();

            foreach (KeyValuePair<string, IDnsApplication> app in _dnsApplications)
                await app.Value.InitializeAsync(_dnsServer, config);
        }

        #endregion

        #region public

        public Task<string> GetConfigAsync()
        {
            string configFile = Path.Combine(_dnsServer.ApplicationFolder, "dnsApp.config");

            if (File.Exists(configFile))
                return File.ReadAllTextAsync(configFile);

            return Task.FromResult<string>(null);
        }

        public async Task SetConfigAsync(string config)
        {
            string configFile = Path.Combine(_dnsServer.ApplicationFolder, "dnsApp.config");

            foreach (KeyValuePair<string, IDnsApplication> app in _dnsApplications)
                await app.Value.InitializeAsync(_dnsServer, config);

            if (string.IsNullOrEmpty(config))
                File.Delete(configFile);
            else
                await File.WriteAllTextAsync(configFile, config);
        }

        #endregion

        #region properties

        public IDnsServer DnsServer
        { get { return _dnsServer; } }

        public string Name
        { get { return _name; } }

        public Version Version
        { get { return _version; } }

        public IReadOnlyDictionary<string, IDnsApplication> DnsApplications
        { get { return _dnsApplications; } }

        public IReadOnlyDictionary<string, IDnsAppRecordRequestHandler> DnsAppRecordRequestHandlers
        { get { return _dnsAppRecordRequestHandlers; } }

        public IReadOnlyDictionary<string, IDnsRequestController> DnsRequestControllers
        { get { return _dnsRequestControllers; } }

        public IReadOnlyDictionary<string, IDnsAuthoritativeRequestHandler> DnsAuthoritativeRequestHandlers
        { get { return _dnsAuthoritativeRequestHandlers; } }

        public IReadOnlyDictionary<string, IDnsQueryLogger> DnsQueryLoggers
        { get { return _dnsQueryLoggers; } }

        #endregion
    }
}
