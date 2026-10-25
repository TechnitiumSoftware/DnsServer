/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

namespace DnsServerCore.Dhcp
{
    interface IDhcpFailoverHandler
    {
        void OnLeaseChanged(string scopeName, Lease lease, bool removed);

        //when false, the DHCP server stays passive and does not respond to clients
        bool IsServing { get; }

        //max lease time in seconds to allow; 0 for no limit
        uint LeaseTimeLimit { get; }
    }
}
