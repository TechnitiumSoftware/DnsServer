/*
Technitium Library
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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

using System.Collections;
using System.ComponentModel;
using System.Configuration.Install;
using System.ServiceProcess;

namespace DnsService
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : Installer
    {
        public ProjectInstaller()
        {
            InitializeComponent();
        }

        protected override void OnBeforeInstall(IDictionary savedState)
        {
            try
            {
                foreach (ServiceController sc in ServiceController.GetServices())
                {
                    if (sc.ServiceName == serviceInstaller1.ServiceName)
                    {
                        //found previously installed service
                        //stop service
                        if (sc.Status == ServiceControllerStatus.Running)
                            sc.Stop();

                        //uninstall service
                        using (ServiceInstaller si = new ServiceInstaller())
                        {
                            si.Context = new InstallContext();
                            si.ServiceName = serviceInstaller1.ServiceName;
                            si.Uninstall(null);
                        }

                        break;
                    }
                }
            }
            catch
            { }
        }

        protected override void OnAfterInstall(IDictionary savedState)
        {
            try
            {
                using (ServiceController sc = new ServiceController(serviceInstaller1.ServiceName))
                {
                    sc.Start();
                }
            }
            catch
            { }
        }

        protected override void OnBeforeUninstall(IDictionary savedState)
        {
            try
            {
                using (ServiceController sc = new ServiceController(serviceInstaller1.ServiceName))
                {
                    sc.Stop();
                }
            }
            catch
            { }
        }
    }
}
