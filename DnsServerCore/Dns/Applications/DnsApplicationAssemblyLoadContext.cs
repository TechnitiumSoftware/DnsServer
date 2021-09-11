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

        readonly string _applicationFolder;

        readonly List<string> _unmanagedDllTempPaths = new List<string>(1);

        #endregion

        #region constructor

        public DnsApplicationAssemblyLoadContext(string applicationFolder)
            : base(true)
        {
            _applicationFolder = applicationFolder;

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

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string runtime = "win-" + RuntimeInformation.ProcessArchitecture.ToString().ToLower();
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

                string runtimeAlpine = "alpine-" + RuntimeInformation.ProcessArchitecture.ToString().ToLower();
                string runtimeLinux = "linux-" + RuntimeInformation.ProcessArchitecture.ToString().ToLower();
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
                string runtime = "osx-" + RuntimeInformation.ProcessArchitecture.ToString().ToLower();
                string[] prefixes = new string[] { "", "lib" };
                string[] extensions = new string[] { ".dylib" };

                unmanagedDllPath = FindUnmanagedDllPath(unmanagedDllName, runtime, prefixes, extensions);
            }

            if (unmanagedDllPath is null)
                return IntPtr.Zero;

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

            return LoadUnmanagedDllFromPath(tempPath);
        }

        #endregion

        #region private

        private string FindUnmanagedDllPath(string unmanagedDllName, string runtime, string[] prefixes, string[] extensions)
        {
            foreach (string prefix in prefixes)
            {
                foreach (string extension in extensions)
                {
                    string path = Path.Combine(_applicationFolder, "runtimes", runtime, "native", prefix + unmanagedDllName + extension);
                    if (File.Exists(path))
                        return path;
                }
            }

            return null;
        }

        #endregion
    }
}
