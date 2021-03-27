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

        readonly DnsApplicationAssemblyLoadContext _appContext = new DnsApplicationAssemblyLoadContext();

        readonly Version _version;
        readonly Dictionary<string, IDnsApplicationRequestHandler> _dnsRequestHandlers;

        #endregion

        #region constructor

        public DnsApplication(IDnsServer dnsServer, string appName)
        {
            _dnsServer = dnsServer;
            _appName = appName;

            //load DLLs and handlers
            Dictionary<string, IDnsApplicationRequestHandler> dnsRequestHandlers = new Dictionary<string, IDnsApplicationRequestHandler>();
            Type dnsRequestHandlerInterface = typeof(IDnsApplicationRequestHandler);

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
                        if (interfaceType == dnsRequestHandlerInterface)
                        {
                            IDnsApplicationRequestHandler handler = Activator.CreateInstance(classType) as IDnsApplicationRequestHandler;
                            dnsRequestHandlers.TryAdd(classType.FullName, handler);

                            if (_version == null)
                                _version = assembly.GetName().Version;
                        }
                    }
                }
            }

            if (_version == null)
                _version = new Version(1, 0);

            _dnsRequestHandlers = dnsRequestHandlers;
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
                if (_dnsRequestHandlers != null)
                {
                    foreach (IDnsApplicationRequestHandler handler in _dnsRequestHandlers.Values)
                        handler.Dispose();

                    _dnsRequestHandlers.Clear();
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

            foreach (IDnsApplicationRequestHandler handler in _dnsRequestHandlers.Values)
                await handler.InitializeAsync(_dnsServer, config);
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

            foreach (IDnsApplicationRequestHandler handler in _dnsRequestHandlers.Values)
                await handler.InitializeAsync(_dnsServer, config);

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

        public IReadOnlyDictionary<string, IDnsApplicationRequestHandler> DnsRequestHandlers
        { get { return _dnsRequestHandlers; } }

        #endregion
    }
}
