/*
Technitium DNS Server
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using System.Reflection;
using System.ServiceProcess;
using TechnitiumLibrary.Net.Firewall;

namespace DnsService
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main()
        {
            #region check windows firewall entry

            string appPath = Assembly.GetEntryAssembly().Location;

            if (!WindowsFirewallEntryExists(appPath))
                AddWindowsFirewallEntry(appPath);

            #endregion

            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new DnsService()
            };
            ServiceBase.Run(ServicesToRun);
        }
        #region private

        private static bool WindowsFirewallEntryExists(string appPath)
        {
            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                    if (Environment.OSVersion.Version.Major > 5)
                    {
                        //vista and above
                        try
                        {
                            return WindowsFirewall.RuleExistsVista("", appPath) == RuleStatus.Allowed;
                        }
                        catch
                        {
                            return false;
                        }
                    }
                    else
                    {
                        try
                        {
                            return WindowsFirewall.ApplicationExists(appPath) == RuleStatus.Allowed;
                        }
                        catch
                        {
                            return false;
                        }
                    }

                default:
                    return false;
            }
        }

        private static bool AddWindowsFirewallEntry(string appPath)
        {
            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                    if (Environment.OSVersion.Version.Major > 5)
                    {
                        //vista and above
                        try
                        {
                            RuleStatus status = WindowsFirewall.RuleExistsVista("", appPath);

                            switch (status)
                            {
                                case RuleStatus.Blocked:
                                case RuleStatus.Disabled:
                                    WindowsFirewall.RemoveRuleVista("", appPath);
                                    break;

                                case RuleStatus.Allowed:
                                    return true;
                            }

                            WindowsFirewall.AddRuleVista("Technitium DNS Server", "Allow incoming connection request to the DNS server.", FirewallAction.Allow, appPath, Protocol.ANY, null, null, null, null, InterfaceTypeFlags.All, true, Direction.Inbound, true);
                            return true;
                        }
                        catch
                        { }
                    }
                    else
                    {
                        try
                        {
                            RuleStatus status = WindowsFirewall.ApplicationExists(appPath);

                            switch (status)
                            {
                                case RuleStatus.Disabled:
                                    WindowsFirewall.RemoveApplication(appPath);
                                    break;

                                case RuleStatus.Allowed:
                                    return true;
                            }

                            WindowsFirewall.AddApplication("Technitium DNS Server", appPath);
                            return true;
                        }
                        catch
                        { }
                    }

                    break;
            }

            return false;
        }

        #endregion
    }
}
