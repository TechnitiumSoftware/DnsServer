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
using System.Threading.Tasks;

namespace DnsServerCore.Dns.Applications
{
    public sealed class DnsApplicationManager : IDisposable
    {
        #region variables

        readonly DnsServer _dnsServer;

        readonly string _appsPath;

        readonly ConcurrentDictionary<string, DnsApplication> _applications = new ConcurrentDictionary<string, DnsApplication>();

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

        private async Task LoadApplicationAsync(string applicationFolder)
        {
            string appName = Path.GetFileName(applicationFolder);

            DnsApplication application = new DnsApplication(new DnsServerInternal(_dnsServer, appName, applicationFolder), appName);

            try
            {
                await application.InitializeAsync();

                if (!_applications.TryAdd(application.AppName, application))
                    throw new DnsServerException("DNS application already exists: " + application.AppName);
            }
            catch
            {
                application.Dispose();
                throw;
            }
        }

        public void UnloadApplication(string appName)
        {
            if (!_applications.TryRemove(appName, out DnsApplication existingApp))
                throw new DnsServerException("DNS application does not exists: " + appName);

            existingApp.Dispose();
        }


        #endregion

        #region public

        public void UnloadAllApplications()
        {
            foreach (DnsApplication _application in _applications.Values)
            {
                try
                {
                    _application.Dispose();
                }
                catch (Exception ex)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write(ex);
                }
            }

            _applications.Clear();
        }

        public void LoadAllApplications()
        {
            UnloadAllApplications();

            foreach (string applicationFolder in Directory.GetDirectories(_appsPath))
            {
                Task.Run(async delegate ()
                {
                    try
                    {
                        await LoadApplicationAsync(applicationFolder);

                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write("DNS Server successfully loaded DNS application: " + Path.GetFileName(applicationFolder));
                    }
                    catch (Exception ex)
                    {
                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write("DNS Server failed to load DNS application: " + Path.GetFileName(applicationFolder) + "\r\n" + ex.ToString());
                    }
                });
            }
        }

        public async Task InstallApplicationAsync(string appName, Stream appStream)
        {
            if (_applications.ContainsKey(appName))
                throw new DnsServerException("DNS application already exists: " + appName);

            using (ZipArchive appZip = new ZipArchive(appStream, ZipArchiveMode.Read, false, Encoding.UTF8))
            {
                string applicationFolder = Path.Combine(_appsPath, appName);

                if (Directory.Exists(applicationFolder))
                    Directory.Delete(applicationFolder, true);

                try
                {
                    appZip.ExtractToDirectory(applicationFolder, true);

                    await LoadApplicationAsync(applicationFolder);
                }
                catch
                {
                    if (Directory.Exists(applicationFolder))
                        Directory.Delete(applicationFolder, true);

                    throw;
                }
            }
        }

        public async Task UpdateApplicationAsync(string appName, Stream appStream)
        {
            if (!_applications.ContainsKey(appName))
                throw new DnsServerException("DNS application does not exists: " + appName);

            using (ZipArchive appZip = new ZipArchive(appStream, ZipArchiveMode.Read, false, Encoding.UTF8))
            {
                UnloadApplication(appName);

                string applicationFolder = Path.Combine(_appsPath, appName);

                appZip.ExtractToDirectory(applicationFolder, true);

                await LoadApplicationAsync(applicationFolder);
            }
        }

        public void UninstallApplication(string appName)
        {
            if (_applications.TryRemove(appName, out DnsApplication app))
                app.Dispose();

            if (Directory.Exists(app.DnsServer.ApplicationFolder))
                Directory.Delete(app.DnsServer.ApplicationFolder, true);
        }

        #endregion

        #region properties

        public IReadOnlyDictionary<string, DnsApplication> Applications
        { get { return _applications; } }

        #endregion
    }
}
