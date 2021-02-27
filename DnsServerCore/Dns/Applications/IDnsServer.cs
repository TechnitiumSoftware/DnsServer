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

using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore.Dns
{
    public interface IDnsServer
    {
        Task<DnsDatagram> DirectQueryAsync(DnsQuestionRecord question, int timeout = 2000);

        string ServerDomain { get; }

        string PackageFolder { get; }

        IDnsCache DnsCache { get; }

        NetProxy Proxy { get; }

        bool PreferIPv6 { get; }
    }
}
