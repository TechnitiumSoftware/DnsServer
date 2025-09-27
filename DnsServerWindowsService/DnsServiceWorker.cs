/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Win32;
using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Firewall;

namespace DnsServerWindowsService
{
    public sealed class DnsServiceWorker : BackgroundService
    {
        readonly DnsWebService _service;

        public DnsServiceWorker()
        {
            string configFolder = null;

            string[] args = Environment.GetCommandLineArgs();
            if (args.Length == 2)
                configFolder = args[1];

            _service = new DnsWebService(configFolder, new Uri("https://go.technitium.com/?id=43"));
        }

        public override async Task StartAsync(CancellationToken cancellationToken)
        {
            CheckFirewallEntries();

            await _service.StartAsync();
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            await _service.StopAsync();
        }

        public override void Dispose()
        {
            if (_service != null)
                _service.Dispose();
        }

        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            return Task.CompletedTask;
        }

        private static void CheckFirewallEntries()
        {
            bool autoFirewallEntry = true;

            try
            {
#pragma warning disable CA1416 // Validate platform compatibility

                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Technitium\DNS Server", false))
                {
                    if (key is not null)
                        autoFirewallEntry = Convert.ToInt32(key.GetValue("AutoFirewallEntry", 1)) == 1;
                }

#pragma warning restore CA1416 // Validate platform compatibility
            }
            catch
            { }

            if (autoFirewallEntry)
            {
                string appPath = Assembly.GetEntryAssembly().Location;

                if (appPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    appPath = appPath.Substring(0, appPath.Length - 4) + ".exe";

                if (!WindowsFirewallEntryExists(appPath))
                    AddWindowsFirewallEntry(appPath);
            }
        }

        private static bool WindowsFirewallEntryExists(string appPath)
        {
            try
            {
                return WindowsFirewall.RuleExistsVista("", appPath) == RuleStatus.Allowed;
            }
            catch
            {
                return false;
            }
        }

        private static bool AddWindowsFirewallEntry(string appPath)
        {
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

                WindowsFirewall.AddRuleVista("Technitium DNS Server", "Allows incoming connection request to the DNS server.", FirewallAction.Allow, appPath, Protocol.ANY, null, null, null, null, InterfaceTypeFlags.All, true, Direction.Inbound, true);

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
