/*
Technitium DNS Server
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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

namespace DnsServerApp
{
    class Program
    {
        static void Main(string[] args)
        {
            string configFolder = null;

            if (args.Length == 1)
                configFolder = args[0];

            DnsWebService service = new DnsWebService(configFolder, new Uri("https://technitium.com/download/dns/updateca.bin"));

            service.Start();
            Console.WriteLine("Technitium DNS Server was started successfully.");
            Console.WriteLine("Using config folder: " + service.ConfigFolder);
            Console.WriteLine("");
            Console.WriteLine("Note: Open http://localhost:" + service.WebServicePort + "/ in web browser to access web console.");
            Console.WriteLine("");
            Console.WriteLine("Press [CTRL + X] to stop...");

            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);

                if (key.Modifiers == ConsoleModifiers.Control && key.Key == ConsoleKey.X)
                    break;
            }

            service.Stop();
            Console.WriteLine("Technitium DNS Server was stopped successfully.");
        }
    }
}
