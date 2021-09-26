/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading.Tasks;

namespace DnsServerCore.ApplicationCommon
{
    /// <summary>
    /// Allows an application to initialize itself using the DNS app config.
    /// </summary>
    public interface IDnsApplication : IDisposable
    {
        /// <summary>
        /// Allows initializing the DNS application with a config. This function is also called when the config is updated to allow reloading.
        /// </summary>
        /// <param name="dnsServer">The DNS server interface object that allows access to DNS server properties.</param>
        /// <param name="config">The DNS application config stored in the <c>dnsApp.config</c> file.</param>
        Task InitializeAsync(IDnsServer dnsServer, string config);

        /// <summary>
        /// The description about this app to be shown in the Apps section of the DNS web console.
        /// </summary>
        string Description { get; }
    }
}
