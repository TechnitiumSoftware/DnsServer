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

using DnsServerCore.Dns.ResourceRecords;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    abstract class SubDomainZone : AuthZone
    {
        #region variables

        readonly ApexZone _authoritativeZone;

        #endregion

        #region constructor

        protected SubDomainZone(ApexZone authoritativeZone, string name)
            : base(name)
        {
            _authoritativeZone = authoritativeZone;
        }

        #endregion

        #region public

        public void AutoUpdateState()
        {
            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
            {
                foreach (DnsResourceRecord record in entry.Value)
                {
                    if (!record.GetAuthGenericRecordInfo().Disabled)
                    {
                        Disabled = false;
                        return;
                    }
                }
            }

            Disabled = true;
        }

        #endregion

        #region properties

        public ApexZone AuthoritativeZone
        { get { return _authoritativeZone; } }

        #endregion
    }
}
