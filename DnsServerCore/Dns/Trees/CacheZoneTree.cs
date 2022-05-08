/*
Technitium DNS Server
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.Dns.Zones;

namespace DnsServerCore.Dns.Trees
{
    class CacheZoneTree : ZoneTree<CacheZone, CacheZone, CacheZone>
    {
        #region protected

        protected override void GetClosestValuesForZone(CacheZone zoneValue, out CacheZone closestSubDomain, out CacheZone closestDelegation, out CacheZone closestAuthority)
        {
            if (zoneValue.ContainsNameServerRecords())
            {
                //ns records found
                closestSubDomain = null;
                closestDelegation = zoneValue;
            }
            else
            {
                closestSubDomain = zoneValue;
                closestDelegation = null;
            }

            closestAuthority = null;
        }

        #endregion

        #region public

        public bool TryRemoveTree(string domain, out CacheZone value, out int removedEntries)
        {
            bool removed = TryRemove(domain, out value, out Node currentNode);
            if (removed)
                removedEntries = value.TotalEntries;
            else
                removedEntries = 0;

            //remove all cache zones under current zone
            Node current = currentNode;

            do
            {
                current = current.GetNextNodeWithValue(currentNode.Depth);
                if (current is null)
                    break;

                NodeValue v = current.Value;
                if (v is not null)
                {
                    CacheZone zone = v.Value;
                    if (zone is not null)
                    {
                        current.RemoveNodeValue(v.Key, out _); //remove node value
                        current.CleanThisBranch();
                        removed = true;
                        removedEntries += zone.TotalEntries;
                    }
                }
            }
            while (true);

            if (removed)
                currentNode.CleanThisBranch();

            return removed;
        }

        public CacheZone FindZone(string domain, out CacheZone closest, out CacheZone delegation)
        {
            byte[] key = ConvertToByteKey(domain);

            CacheZone zoneValue = FindZoneNode(key, false, out _, out _, out _, out CacheZone closestSubDomain, out CacheZone closestDelegation, out _);
            if (zoneValue is null)
            {
                //zone not found
                closest = closestSubDomain; //required for DNAME
                delegation = closestDelegation;

                return null;
            }
            else
            {
                //zone found
                closest = null; //not required

                if (zoneValue.ContainsNameServerRecords())
                    delegation = zoneValue;
                else if (closestDelegation is not null)
                    delegation = closestDelegation;
                else
                    delegation = null;

                return zoneValue;
            }
        }

        #endregion
    }
}
