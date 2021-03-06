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
using System.ServiceProcess;

namespace DnsService
{
    public partial class DnsService : ServiceBase
    {
        WebService _service;

        public DnsService()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            _service = new WebService(getConfigFolder(), new Uri("https://go.technitium.com/?id=22"));
            _service.Start();
        }

        /// <summary>
        /// If the service file path has the configuration files, use it, otherwise use the localapppath folder.
        /// </summary>
        /// <returns>The configuration path.</returns>
        private string getConfigFolder()
        {
            string userConfigFolder = String.Concat(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"\Technitium\DNSServer");

            if (System.IO.Directory.Exists(Environment.CurrentDirectory))
            {
                return Environment.CurrentDirectory;
            }
            return userConfigFolder;
        }

        protected override void OnStop()
        {
            _service.Dispose();
        }
    }
}
