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

namespace DnsServerCore.Dns.Applications
{
    public sealed class DnsApplicationPackage : IDisposable
    {
        #region variables

        readonly string _packagePath;

        readonly string _name;
        readonly DnsApplicationAssemblyLoadContext _appContext = new DnsApplicationAssemblyLoadContext();
        readonly IReadOnlyDictionary<string, IDnsApplication> _dnsApplications;

        #endregion

        #region constructor

        public DnsApplicationPackage(string packagePath)
        {
            _packagePath = packagePath;

            _name = Path.GetDirectoryName(_packagePath);

            //load package
            Dictionary<string, IDnsApplication> applications = new Dictionary<string, IDnsApplication>();

            foreach (string dllFile in Directory.GetFiles(_packagePath, "*.dll", SearchOption.TopDirectoryOnly))
            {
                Assembly assembly;

                try
                {
                    assembly = _appContext.LoadFromAssemblyPath(dllFile);
                }
                catch (BadImageFormatException)
                {
                    continue;
                }

                Type dnsApp = typeof(IDnsApplication);

                foreach (Type classType in assembly.ExportedTypes)
                {
                    foreach (Type interfaceType in classType.GetInterfaces())
                    {
                        if (interfaceType == dnsApp)
                        {
                            IDnsApplication dnsApplication = Activator.CreateInstance(classType) as IDnsApplication;
                            applications.TryAdd(classType.FullName, dnsApplication);
                        }
                    }
                }
            }

            _dnsApplications = applications;
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

        #region properties

        public string PackagePath
        { get { return _packagePath; } }

        public string Name
        { get { return _name; } }

        public IReadOnlyDictionary<string, IDnsApplication> DnsApplications
        { get { return _dnsApplications; } }

        #endregion
    }
}
