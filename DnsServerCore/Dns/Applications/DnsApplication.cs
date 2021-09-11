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

using DnsApplicationCommon;
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
        readonly string _appName;

        readonly DnsApplicationAssemblyLoadContext _appContext;

        readonly Version _version;
        readonly IReadOnlyDictionary<string, IDnsAppRecordRequestHandler> _dnsAppRecordRequestHandlers;
        readonly IReadOnlyDictionary<string, IDnsRequestController> _dnsRequestControllers;
        readonly IReadOnlyDictionary<string, IDnsAuthoritativeRequestHandler> _dnsAuthoritativeRequestHandlers;
        readonly IReadOnlyDictionary<string, IDnsLogger> _dnsLoggers;

        #endregion

        #region constructor

        public DnsApplication(IDnsServer dnsServer, string appName)
        {
            _dnsServer = dnsServer;
            _appName = appName;

            _appContext = new DnsApplicationAssemblyLoadContext(_dnsServer.ApplicationFolder);

            //load DLLs and handlers
            Dictionary<string, IDnsAppRecordRequestHandler> dnsAppRecordRequestHandlers = new Dictionary<string, IDnsAppRecordRequestHandler>(2);
            Type dnsAppRecordRequestHandlerInterface = typeof(IDnsAppRecordRequestHandler);

            Dictionary<string, IDnsRequestController> dnsRequestControllers = new Dictionary<string, IDnsRequestController>(1);
            Type dnsRequestControllerInterface = typeof(IDnsRequestController);

            Dictionary<string, IDnsAuthoritativeRequestHandler> dnsAuthoritativeRequestHandlers = new Dictionary<string, IDnsAuthoritativeRequestHandler>(1);
            Type dnsRequestHandlersInterface = typeof(IDnsAuthoritativeRequestHandler);

            Dictionary<string, IDnsLogger> dnsLoggers = new Dictionary<string, IDnsLogger>(1);
            Type dnsLoggerInterface = typeof(IDnsLogger);

            Assembly[] loadedAssemblies = AppDomain.CurrentDomain.GetAssemblies();

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

                Assembly assembly;

                try
                {
                    string pdbFile = Path.Combine(_dnsServer.ApplicationFolder, Path.GetFileNameWithoutExtension(dllFile) + ".pdb");

                    if (File.Exists(pdbFile))
                    {
                        using (FileStream dllStream = new FileStream(dllFile, FileMode.Open, FileAccess.Read))
                        {
                            using (FileStream pdbStream = new FileStream(pdbFile, FileMode.Open, FileAccess.Read))
                            {
                                assembly = _appContext.LoadFromStream(dllStream, pdbStream);
                            }
                        }
                    }
                    else
                    {
                        using (FileStream dllStream = new FileStream(dllFile, FileMode.Open, FileAccess.Read))
                        {
                            assembly = _appContext.LoadFromStream(dllStream);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);
                    continue;
                }

                foreach (Type classType in assembly.ExportedTypes)
                {
                    foreach (Type interfaceType in classType.GetInterfaces())
                    {
                        if (interfaceType == dnsAppRecordRequestHandlerInterface)
                        {
                            IDnsAppRecordRequestHandler handler = Activator.CreateInstance(classType) as IDnsAppRecordRequestHandler;
                            dnsAppRecordRequestHandlers.TryAdd(classType.FullName, handler);

                            if (_version is null)
                                _version = assembly.GetName().Version;
                        }
                        else if (interfaceType == dnsRequestControllerInterface)
                        {
                            IDnsRequestController controller = Activator.CreateInstance(classType) as IDnsRequestController;
                            dnsRequestControllers.TryAdd(classType.FullName, controller);

                            if (_version is null)
                                _version = assembly.GetName().Version;
                        }
                        else if (interfaceType == dnsRequestHandlersInterface)
                        {
                            IDnsAuthoritativeRequestHandler handler = Activator.CreateInstance(classType) as IDnsAuthoritativeRequestHandler;
                            dnsAuthoritativeRequestHandlers.TryAdd(classType.FullName, handler);

                            if (_version is null)
                                _version = assembly.GetName().Version;
                        }
                        else if (interfaceType == dnsLoggerInterface)
                        {
                            IDnsLogger logger = Activator.CreateInstance(classType) as IDnsLogger;
                            dnsLoggers.TryAdd(classType.FullName, logger);

                            if (_version is null)
                                _version = assembly.GetName().Version;
                        }
                    }
                }
            }

            if (_version is null)
                _version = new Version(1, 0);

            _dnsAppRecordRequestHandlers = dnsAppRecordRequestHandlers;
            _dnsRequestControllers = dnsRequestControllers;
            _dnsAuthoritativeRequestHandlers = dnsAuthoritativeRequestHandlers;
            _dnsLoggers = dnsLoggers;
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
                if (_dnsAppRecordRequestHandlers is not null)
                {
                    foreach (KeyValuePair<string, IDnsAppRecordRequestHandler> handler in _dnsAppRecordRequestHandlers)
                        handler.Value.Dispose();
                }

                if (_dnsRequestControllers is not null)
                {
                    foreach (KeyValuePair<string, IDnsRequestController> controller in _dnsRequestControllers)
                        controller.Value.Dispose();
                }

                if (_dnsAuthoritativeRequestHandlers is not null)
                {
                    foreach (KeyValuePair<string, IDnsAuthoritativeRequestHandler> handler in _dnsAuthoritativeRequestHandlers)
                        handler.Value.Dispose();
                }

                if (_dnsLoggers is not null)
                {
                    foreach (KeyValuePair<string, IDnsLogger> logger in _dnsLoggers)
                        logger.Value.Dispose();
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

            foreach (KeyValuePair<string, IDnsAppRecordRequestHandler> handler in _dnsAppRecordRequestHandlers)
                await handler.Value.InitializeAsync(_dnsServer, config);

            foreach (KeyValuePair<string, IDnsRequestController> controller in _dnsRequestControllers)
                await controller.Value.InitializeAsync(_dnsServer, config);

            foreach (KeyValuePair<string, IDnsAuthoritativeRequestHandler> handler in _dnsAuthoritativeRequestHandlers)
                await handler.Value.InitializeAsync(_dnsServer, config);

            foreach (KeyValuePair<string, IDnsLogger> logger in _dnsLoggers)
                await logger.Value.InitializeAsync(_dnsServer, config);
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

            foreach (KeyValuePair<string, IDnsAppRecordRequestHandler> handler in _dnsAppRecordRequestHandlers)
                await handler.Value.InitializeAsync(_dnsServer, config);

            foreach (KeyValuePair<string, IDnsRequestController> controller in _dnsRequestControllers)
                await controller.Value.InitializeAsync(_dnsServer, config);

            foreach (KeyValuePair<string, IDnsAuthoritativeRequestHandler> handler in _dnsAuthoritativeRequestHandlers)
                await handler.Value.InitializeAsync(_dnsServer, config);

            foreach (KeyValuePair<string, IDnsLogger> logger in _dnsLoggers)
                await logger.Value.InitializeAsync(_dnsServer, config);

            if (string.IsNullOrEmpty(config))
                File.Delete(configFile);
            else
                await File.WriteAllTextAsync(configFile, config);
        }

        #endregion

        #region properties

        public IDnsServer DnsServer
        { get { return _dnsServer; } }

        public string AppName
        { get { return _appName; } }

        public Version Version
        { get { return _version; } }

        public IReadOnlyDictionary<string, IDnsAppRecordRequestHandler> DnsAppRecordRequestHandlers
        { get { return _dnsAppRecordRequestHandlers; } }

        public IReadOnlyDictionary<string, IDnsRequestController> DnsRequestControllers
        { get { return _dnsRequestControllers; } }

        public IReadOnlyDictionary<string, IDnsAuthoritativeRequestHandler> DnsAuthoritativeRequestHandlers
        { get { return _dnsAuthoritativeRequestHandlers; } }

        public IReadOnlyDictionary<string, IDnsLogger> DnsLoggers
        { get { return _dnsLoggers; } }

        #endregion
    }
}
