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

using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ResourceRecords
{
    class DnsSOARecordDataExtended : DnsSOARecordData
    {
        #region constructor

        public DnsSOARecordDataExtended(string primaryNameServer, string responsiblePerson, uint serial, uint refresh, uint retry, uint expire, uint minimum)
            : base(primaryNameServer, responsiblePerson, serial, refresh, retry, expire, minimum)
        { }

        #endregion

        #region public

        public void UpdatePrimaryNameServerAndMinimum(string primaryNameServer, uint minimum)
        {
            _primaryNameServer = primaryNameServer;
            _minimum = minimum;
        }

        #endregion
    }
}
