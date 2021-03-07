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
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

namespace DnsServerSystemTrayApp
{
    static class Program
    {
        #region variables

        const string MUTEX_NAME = "TechnitiumDnsServerSystemTrayApp";

        static string _appPath = Assembly.GetEntryAssembly().Location;
        static readonly bool _isAdmin = (new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator);
        static Mutex _app;

        #endregion

        #region public

        [STAThread]
        public static void Main(string[] args)
        {
            if (_appPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                _appPath = _appPath.Substring(0, _appPath.Length - 4) + ".exe";

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            #region check for multiple instances

            _app = new Mutex(true, MUTEX_NAME, out bool createdNewMutex);

            if (!createdNewMutex)
            {
                MessageBox.Show("Technitium DNS Server system tray app is already running.", "Already Running!", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            #endregion

            string configFile = Path.Combine(Path.GetDirectoryName(_appPath), "SystemTrayApp.config");

            Application.Run(new MainApplicationContext(configFile, args));
        }

        public static void RunAsAdmin(string args)
        {
            if (_isAdmin)
                throw new Exception("App is already running as admin.");

            ProcessStartInfo processInfo = new ProcessStartInfo(_appPath, args);

            processInfo.UseShellExecute = true;
            processInfo.Verb = "runas";

            try
            {
                _app.Dispose();
                Process.Start(processInfo);
                Application.Exit();
                return;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error! " + ex.Message, "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            //user cancels UAC or exception occurred
            _app = new Mutex(true, MUTEX_NAME, out _);
        }

        #endregion

        #region properties

        public static bool IsAdmin
        { get { return _isAdmin; } }

        #endregion
    }
}
