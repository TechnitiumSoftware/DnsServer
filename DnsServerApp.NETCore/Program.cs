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
                configFolder = args[0];

            WebService service = null;

            try
            {
                service = new WebService(configFolder, new Uri("https://go.technitium.com/?id=21"));
                service.Start();

                Console.WriteLine("Technitium DNS Server was started successfully.");
                Console.WriteLine("Using config folder: " + service.ConfigFolder);
                Console.WriteLine("");
                Console.WriteLine("Note: Open http://" + service.WebServiceHostname + ":" + service.WebServicePort + "/ in web browser to access web console.");
                Console.WriteLine("");
                Console.WriteLine("Press [CTRL + C] to stop...");

                Thread main = Thread.CurrentThread;

                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e)
                {
                    e.Cancel = true;
                    main.Interrupt();
                };

                AppDomain.CurrentDomain.ProcessExit += delegate (object sender, EventArgs e)
                {
                    if (service != null)
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Technitium DNS Server is stopping...");
                        service.Dispose();
                        service = null;
                        Console.WriteLine("Technitium DNS Server was stopped successfully.");
                    }
                };

                Thread.Sleep(Timeout.Infinite);
            }
            catch (ThreadInterruptedException)
            { }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                if (service != null)
                {
                    Console.WriteLine("");
                    Console.WriteLine("Technitium DNS Server is stopping...");
                    service.Dispose();
                    service = null;
                    Console.WriteLine("Technitium DNS Server was stopped successfully.");
                }
            }
        }
    }
}
