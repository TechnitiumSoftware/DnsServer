/*
Technitium DNS Server
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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

        public static readonly string APP_PATH = Assembly.GetEntryAssembly().Location;

        static readonly bool _isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        static Mutex _app;

        #endregion

        #region constructor

        static Program()
        {
            if (APP_PATH.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                APP_PATH = APP_PATH.Substring(0, APP_PATH.Length - 4) + ".exe";
        }

        #endregion

        #region public

        [STAThread]
        public static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            #region check for multiple instances

            _app = new Mutex(true, MUTEX_NAME, out bool createdNewMutex);

            bool exitApp = false;

            if (!createdNewMutex)
            {
                if (args.Length == 0)
                {
                    MessageBox.Show("Technitium DNS Server system tray app is already running.", "Already Running!", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                else
                {
                    exitApp = true;
                }
            }

            #endregion

            string configFile = Path.Combine(Path.GetDirectoryName(APP_PATH), "SystemTrayApp.config");

            MainApplicationContext mainApp = new MainApplicationContext(configFile, args, ref exitApp);

            if (exitApp)
                mainApp.Dispose();
            else
                Application.Run(mainApp);
        }

        public static void RunAsAdmin(string args)
        {
            if (_isAdmin)
                throw new Exception("App is already running as admin.");

            ProcessStartInfo processInfo = new ProcessStartInfo(APP_PATH, args);

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
