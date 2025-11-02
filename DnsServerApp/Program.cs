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
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerApp
{
    class Program
    {
        static async Task Main(string[] args)
        {
            bool throwIfBindFails = false;
            string? configFolder = null;

            foreach (string arg in args)
            {
                switch (arg)
                {
                    case "--icu-test":
                        _ = System.Globalization.CultureInfo.CurrentCulture;
                        return;

                    case "--stop-if-bind-fails":
                        throwIfBindFails = true;
                        break;

                    default:
                        configFolder = arg;
                        break;
                }
            }

            ManualResetEvent waitHandle = new ManualResetEvent(false);
            ManualResetEvent exitHandle = new ManualResetEvent(false);
            DnsWebService? service = null;

            try
            {
                Uri updateCheckUri;

                switch (Environment.OSVersion.Platform)
                {
                    case PlatformID.Win32NT:
                        updateCheckUri = new Uri("https://go.technitium.com/?id=41");
                        break;

                    default:
                        updateCheckUri = new Uri("https://go.technitium.com/?id=42");
                        break;
                }

                service = new DnsWebService(configFolder, updateCheckUri);
                await service.StartAsync(throwIfBindFails);

                Console.CancelKeyPress += delegate (object? sender, ConsoleCancelEventArgs e)
                {
                    e.Cancel = true;
                    waitHandle.Set();
                };

                AppDomain.CurrentDomain.ProcessExit += delegate (object? sender, EventArgs e)
                {
                    waitHandle.Set();
                    exitHandle.WaitOne();
                };

                Console.WriteLine("Technitium DNS Server was started successfully.\r\nUsing config folder: " + service.ConfigFolder + "\r\n\r\nNote: Open http://" + Environment.MachineName.ToLowerInvariant() + ":" + service.WebServiceHttpPort + "/ in web browser to access web console.\r\n\r\nPress [CTRL + C] to stop...");

                waitHandle.WaitOne();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                Console.WriteLine("\r\nTechnitium DNS Server is stopping...");

                service?.Dispose();

                Console.WriteLine("Technitium DNS Server was stopped successfully.");
                exitHandle.Set();
            }
        }
    }
}
