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
            if (args.Length == 0)
            {
                Console.WriteLine("Technitium DNS Server");
                Console.WriteLine("Error! Expected command line parameter 'configFolder' is missing.");
                Console.WriteLine("");
                Console.WriteLine("Note: Create an empty folder and pass the folder path as parameter. This folder will store DNS config and zone data for this app instance.");
                Console.WriteLine("Example: DnsServerApp.exe \"C:\\DnsConfig\\\"");
                return;
            }

            DnsWebService service = new DnsWebService(args[0]);

            service.Start();
            Console.WriteLine("Technitium DNS Server was started");
            Console.WriteLine("Press any key to stop...");
            Console.ReadKey();

            service.Stop();
            Console.WriteLine("Technitium DNS Server was stopped.");
        }
    }
}
