/*
Technitium DNS Server
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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
using System.ComponentModel;
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

        public const string MUTEX_NAME = "TechnitiumDnsServerSystemTrayApp";

        static Mutex _app;

        #endregion

        #region public

        [STAThread]
        public static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            string appPath = Assembly.GetEntryAssembly().Location;

            #region admin elevation

            bool isAdmin = (new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator);
            if (!isAdmin)
            {
                ProcessStartInfo processInfo = new ProcessStartInfo(appPath, string.Join(" ", args));

                processInfo.UseShellExecute = true;
                processInfo.Verb = "runas";

                try
                {
                    Process.Start(processInfo);
                }
                catch (Win32Exception)
                { }
                catch (Exception ex)
                {
                    MessageBox.Show("Error! " + ex.Message, "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }

                return;
            }

            #endregion

            #region check for multiple instances

            bool createdNewMutex;

            _app = new Mutex(true, MUTEX_NAME, out createdNewMutex);

            if (!createdNewMutex)
            {
                MessageBox.Show("Technitium DNS Server system tray app is already running.", "Already Running!", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            #endregion

            string configFile = Path.Combine(Path.GetDirectoryName(appPath), "SystemTrayApp.config");

            Application.Run(new MainApplicationContext(configFile));
        }

        #endregion
    }
}
