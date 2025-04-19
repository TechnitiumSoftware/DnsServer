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

namespace DnsServerApp
{
    class Program
    {
        static void Main(string[] args)
        {
            string configFolder = null;

            if (args.Length == 1)
            {
                if (args[0] == "--icu-test")
                {
                    _ = System.Globalization.CultureInfo.CurrentCulture;
                    return;
                }

                configFolder = args[0];
            }

            ManualResetEvent waitHandle = new ManualResetEvent(false);
            ManualResetEvent exitHandle = new ManualResetEvent(false);
            DnsWebService service = null;

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

                service = new DnsWebService(configFolder, updateCheckUri, new Uri("https://go.technitium.com/?id=44"));
                service.Start();

                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e)
                {
                    e.Cancel = true;
                    waitHandle.Set();
                };

                AppDomain.CurrentDomain.ProcessExit += delegate (object sender, EventArgs e)
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

                if (service != null)
                    service.Dispose();

                Console.WriteLine("Technitium DNS Server was stopped successfully.");
                exitHandle.Set();
            }
        }
    }
}
