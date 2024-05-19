/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace DnsServerCore.Dns
{
    class DnsApplicationAssemblyLoadContext : AssemblyLoadContext
    {
        #region variables

        readonly static Type _dnsApplicationInterface = typeof(IDnsApplication);

        readonly IDnsServer _dnsServer;

        readonly List<Assembly> _appAssemblies;
        readonly AssemblyDependencyResolver _dependencyResolver;

        readonly Dictionary<string, IntPtr> _loadedUnmanagedDlls = new Dictionary<string, IntPtr>();
        readonly List<string> _unmanagedDllTempPaths = new List<string>();

        #endregion

        #region constructor

        public DnsApplicationAssemblyLoadContext(IDnsServer dnsServer)
            : base(true)
        {
            _dnsServer = dnsServer;

            Unloading += delegate (AssemblyLoadContext obj)
            {
                foreach (string unmanagedDllTempPath in _unmanagedDllTempPaths)
                {
                    try
                    {
                        File.Delete(unmanagedDllTempPath);
                    }
                    catch
                    { }
                }
            };

            _appAssemblies = new List<Assembly>();

            IEnumerable<Assembly> loadedAssemblies = Default.Assemblies;

            foreach (string dllFile in Directory.GetFiles(_dnsServer.ApplicationFolder, "*.dll", SearchOption.TopDirectoryOnly))
            {
                string dllFileName = Path.GetFileNameWithoutExtension(dllFile);

                bool isLoaded = false;

                foreach (Assembly loadedAssembly in loadedAssemblies)
                {
                    if (!string.IsNullOrEmpty(loadedAssembly.Location))
                    {
                        if (Path.GetFileNameWithoutExtension(loadedAssembly.Location).Equals(dllFileName, StringComparison.OrdinalIgnoreCase))
                        {
                            isLoaded = true;
                            break;
                        }
                    }
                    else
                    {
                        AssemblyName assemblyName = loadedAssembly.GetName();

                        if ((assemblyName.Name != null) && assemblyName.Name.Equals(dllFileName, StringComparison.OrdinalIgnoreCase))
                        {
                            isLoaded = true;
                            break;
                        }
                    }
                }

                if (isLoaded)
                    continue;

                try
                {
                    Assembly appAssembly;
                    string pdbFile = Path.Combine(_dnsServer.ApplicationFolder, Path.GetFileNameWithoutExtension(dllFile) + ".pdb");

                    if (File.Exists(pdbFile))
                    {
                        using (FileStream dllStream = new FileStream(dllFile, FileMode.Open, FileAccess.Read))
                        {
                            using (FileStream pdbStream = new FileStream(pdbFile, FileMode.Open, FileAccess.Read))
                            {
                                appAssembly = LoadFromStream(dllStream, pdbStream);
                            }
                        }
                    }
                    else
                    {
                        using (FileStream dllStream = new FileStream(dllFile, FileMode.Open, FileAccess.Read))
                        {
                            appAssembly = LoadFromStream(dllStream);
                        }
                    }

                    if (_dependencyResolver is null)
                    {
                        bool isMainAssembly = false;

                        foreach (Type classType in appAssembly.ExportedTypes)
                        {
                            foreach (Type interfaceType in classType.GetInterfaces())
                            {
                                if (interfaceType == _dnsApplicationInterface)
                                {
                                    isMainAssembly = true;
                                    break;
                                }
                            }

                            if (isMainAssembly)
                                break;
                        }

                        if (isMainAssembly)
                            _dependencyResolver = new AssemblyDependencyResolver(dllFile);
                    }

                    _appAssemblies.Add(appAssembly);
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);
                }
            }
        }

        #endregion

        #region overrides

        protected override Assembly Load(AssemblyName assemblyName)
        {
            return null;
        }

        protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
        {
            string unmanagedDllPath = null;

            if (_dependencyResolver is not null)
            {
                string resolvedPath = _dependencyResolver.ResolveUnmanagedDllToPath(unmanagedDllName);
                if (!string.IsNullOrEmpty(resolvedPath) && File.Exists(resolvedPath))
                    unmanagedDllPath = resolvedPath;
            }

            if (unmanagedDllPath is null)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    string runtime = "win-" + RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
                    string[] prefixes = new string[] { "" };
                    string[] extensions = new string[] { ".dll" };

                    unmanagedDllPath = FindUnmanagedDllPath(unmanagedDllName, runtime, prefixes, extensions);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    bool isAlpine = false;

                    try
                    {
                        string osReleaseFile = "/etc/os-release";

                        if (File.Exists(osReleaseFile))
                            isAlpine = File.ReadAllText(osReleaseFile).Contains("alpine", StringComparison.OrdinalIgnoreCase);
                    }
                    catch
                    { }

                    string runtimeAlpine = "linux-musl-" + RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
                    string runtimeLinux = "linux-" + RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
                    string[] prefixes = new string[] { "", "lib" };
                    string[] extensions = new string[] { ".so", ".so.1" };

                    if (isAlpine)
                    {
                        unmanagedDllPath = FindUnmanagedDllPath(unmanagedDllName, runtimeAlpine, prefixes, extensions);
                        if (unmanagedDllPath is null)
                            unmanagedDllPath = FindUnmanagedDllPath(unmanagedDllName, runtimeLinux, prefixes, extensions);
                    }
                    else
                    {
                        unmanagedDllPath = FindUnmanagedDllPath(unmanagedDllName, runtimeLinux, prefixes, extensions);
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    string runtime = "osx-" + RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
                    string[] prefixes = new string[] { "", "lib" };
                    string[] extensions = new string[] { ".dylib" };

                    unmanagedDllPath = FindUnmanagedDllPath(unmanagedDllName, runtime, prefixes, extensions);
                }

                if (unmanagedDllPath is null)
                    return IntPtr.Zero;
            }

            lock (_loadedUnmanagedDlls)
            {
                if (!_loadedUnmanagedDlls.TryGetValue(unmanagedDllPath.ToLowerInvariant(), out IntPtr value))
                {
                    //load the unmanaged DLL
                    //copy unmanaged dll into temp file for loading to allow uninstalling/updating app at runtime.
                    string tempPath = Path.GetTempFileName();

                    using (FileStream srcFile = new FileStream(unmanagedDllPath, FileMode.Open, FileAccess.Read))
                    {
                        using (FileStream dstFile = new FileStream(tempPath, FileMode.Create, FileAccess.Write))
                        {
                            srcFile.CopyTo(dstFile);
                        }
                    }

                    _unmanagedDllTempPaths.Add(tempPath);

                    value = LoadUnmanagedDllFromPath(tempPath);
                    _loadedUnmanagedDlls.Add(unmanagedDllPath.ToLowerInvariant(), value);
                }

                return value;
            }
        }

        #endregion

        #region private

        private string FindUnmanagedDllPath(string unmanagedDllName, string runtime, string[] prefixes, string[] extensions)
        {
            foreach (string prefix in prefixes)
            {
                foreach (string extension in extensions)
                {
                    string path = Path.Combine(_dnsServer.ApplicationFolder, "runtimes", runtime, "native", prefix + unmanagedDllName + extension);
                    if (File.Exists(path))
                        return path;
                }
            }

            return null;
        }

        #endregion

        #region properties

        public IReadOnlyList<Assembly> AppAssemblies
        { get { return _appAssemblies; } }

        #endregion
    }
}
