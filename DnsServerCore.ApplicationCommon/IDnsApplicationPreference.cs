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

namespace DnsServerCore.ApplicationCommon
{
    /// <summary>
    /// Allows an application to specify a preference value to allow the DNS server to sort all installed apps in user preferred order to be used. If an application does not implement this interface then the default preference of 100 is assumed by the DNS server.
    /// </summary>
    public interface IDnsApplicationPreference
    {
        /// <summary>
        /// Returns the preference value configured for the application.
        /// </summary>
        byte Preference { get; }
    }
}
