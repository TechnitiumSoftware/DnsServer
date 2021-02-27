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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace DnsServerCore.Dns.Applications
{
    public sealed class DnsApplicationManager : IDisposable
    {
        #region variables

        readonly string _packagesPath;

        readonly ConcurrentDictionary<string, DnsApplicationPackage> _packages = new ConcurrentDictionary<string, DnsApplicationPackage>();

        #endregion

        #region constructor

        public DnsApplicationManager(string configFolder)
        {
            _packagesPath = Path.Combine(configFolder, "apps");

            if (!Directory.Exists(_packagesPath))
                Directory.CreateDirectory(_packagesPath);
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
                if (_packages != null)
                {
                    foreach (DnsApplicationPackage package in _packages.Values)
                        package.Dispose();

                    _packages.Clear();
                }
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private void LoadPackage(string packagePath)
        {
            DnsApplicationPackage package = new DnsApplicationPackage(packagePath);

            if (!_packages.TryAdd(package.Name, package))
                package.Dispose();
        }

        #endregion

        #region public

        public void LoadAllPackages()
        {
            foreach (string packagePath in Directory.GetDirectories(_packagesPath))
            {
                LoadPackage(packagePath);
            }
        }

        public void InstallPackage(string packageName, Stream package)
        {
            if (_packages.ContainsKey(packageName))
                throw new DnsServerException("Package already exists: " + packageName);

            using (ZipArchive packageZip = new ZipArchive(package, ZipArchiveMode.Read, false, Encoding.UTF8))
            {
                string packagePath = Path.Combine(_packagesPath, packageName);

                packageZip.ExtractToDirectory(packagePath, true);

                LoadPackage(packagePath);
            }
        }

        public void UninstallPackage(string packageName)
        {
            if (_packages.TryRemove(packageName, out DnsApplicationPackage package))
                package.Dispose();

            if (Directory.Exists(package.PackagePath))
                Directory.Delete(package.PackagePath, true);
        }

        #endregion

        #region properties

        public IReadOnlyDictionary<string, DnsApplicationPackage> Packages
        { get { return _packages; } }

        #endregion
    }
}
