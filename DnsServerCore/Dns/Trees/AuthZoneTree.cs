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

using DnsServerCore.Dns.ZoneManagers;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.Threading;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Trees
{
    class AuthZoneTree : ZoneTree<AuthZoneNode, SubDomainZone, ApexZone>
    {
        #region variables

        static readonly char[] _starPeriodTrimChars = new char[] { '*', '.' };

        #endregion

        #region private

        private static Node GetPreviousSubDomainZoneNode(byte[] key, Node currentNode, int baseDepth)
        {
            int k;

            NodeValue currentValue = currentNode.Value;
            if (currentValue is null)
            {
                //key value does not exists
                if (currentNode.Children is null)
                {
                    //no children available; move to previous sibling
                    k = currentNode.K - 1; //find previous node from sibling starting at k - 1
                    currentNode = currentNode.Parent;
                }
                else
                {
                    if (key.Length == currentNode.Depth)
                    {
                        //current node belongs to the key
                        k = currentNode.K - 1; //find previous node from sibling starting at k - 1
                        currentNode = currentNode.Parent;
                    }
                    else
                    {
                        //find the previous node for the given k in current node's children
                        k = key[currentNode.Depth];
                    }
                }
            }
            else
            {
                int x = DnsNSECRecordData.CanonicalComparison(currentValue.Key, key);
                if (x == 0)
                {
                    //current node value matches the key
                    k = currentNode.K - 1; //find previous node from sibling starting at k - 1
                    currentNode = currentNode.Parent;
                }
                else if (x > 0)
                {
                    //current node value is larger for the key
                    k = currentNode.K - 1; //find previous node from sibling starting at k - 1
                    currentNode = currentNode.Parent;
                }
                else
                {
                    //current node value is smaller for the key
                    if (currentNode.Children is null)
                    {
                        //the current node is previous node since no children exists and value is smaller for the key
                        return currentNode;
                    }
                    else
                    {
                        //find the previous node for the given k in current node's children
                        k = key[currentNode.Depth];
                    }
                }
            }

            //start reverse tree traversal
            while ((currentNode is not null) && (currentNode.Depth >= baseDepth))
            {
                Node[] children = currentNode.Children;
                if (children is not null)
                {
                    //find previous child node
                    Node child = null;

                    for (int i = k; i > -1; i--)
                    {
                        child = Volatile.Read(ref children[i]);
                        if (child is not null)
                        {
                            bool childNodeHasApexZone = false;

                            NodeValue childValue = child.Value;
                            if (childValue is not null)
                            {
                                AuthZoneNode authZoneNode = childValue.Value;
                                if (authZoneNode is not null)
                                {
                                    if (authZoneNode.ApexZone is not null)
                                        childNodeHasApexZone = true; //must stop checking children of the apex of the sub zone
                                }
                            }

                            if (!childNodeHasApexZone && child.Children is not null)
                                break; //child has further children so check them first

                            if (childValue is not null)
                            {
                                AuthZoneNode authZoneNode = childValue.Value;
                                if (authZoneNode is not null)
                                {
                                    if (authZoneNode.ParentSideZone is not null)
                                    {
                                        //is sub domain zone
                                        return child; //child has value so return it
                                    }

                                    if (authZoneNode.ApexZone is not null)
                                    {
                                        //is apex zone
                                        //skip to next child to avoid listing this auth zone's sub domains
                                        child = null; //set null to avoid child being set as current after the loop
                                    }
                                }
                            }
                        }
                    }

                    if (child is not null)
                    {
                        //make found child as current
                        k = children.Length - 1;
                        currentNode = child;
                        continue; //start over
                    }
                }

                //no child node available; check for current node value
                {
                    NodeValue value = currentNode.Value;
                    if (value is not null)
                    {
                        AuthZoneNode authZoneNode = value.Value;
                        if (authZoneNode is not null)
                        {
                            if ((authZoneNode.ApexZone is not null) && (currentNode.Depth == baseDepth))
                            {
                                //current node contains apex zone for the base depth i.e. current zone; return it
                                return currentNode;
                            }

                            if (authZoneNode.ParentSideZone is not null)
                            {
                                //current node contains sub domain zone; return it
                                return currentNode;
                            }
                        }
                    }
                }

                //move up to parent node for previous sibling
                k = currentNode.K - 1;
                currentNode = currentNode.Parent;
            }

            return null;
        }

        private static Node GetNextSubDomainZoneNode(byte[] key, Node currentNode, int baseDepth)
        {
            int k;

            NodeValue currentValue = currentNode.Value;
            if (currentValue is null)
            {
                //key value does not exists
                if (currentNode.Children is null)
                {
                    //no children available; move to next sibling
                    k = currentNode.K + 1; //find next node from sibling starting at k + 1
                    currentNode = currentNode.Parent;
                }
                else
                {
                    if (key.Length == currentNode.Depth)
                    {
                        //current node belongs to the key
                        k = 0; //find next node from first child of current node
                    }
                    else
                    {
                        //find next node for the given k in current node's children
                        k = key[currentNode.Depth];
                    }
                }
            }
            else
            {
                //check if node contains apex zone
                bool foundApexZone = false;

                if (currentNode.Depth > baseDepth)
                {
                    AuthZoneNode authZoneNode = currentValue.Value;
                    if (authZoneNode is not null)
                    {
                        ApexZone apexZone = authZoneNode.ApexZone;
                        if (apexZone is not null)
                            foundApexZone = true;
                    }
                }

                if (foundApexZone)
                {
                    //current contains apex for a sub zone; move up to parent node
                    k = currentNode.K + 1; //find next node from sibling starting at k + 1
                    currentNode = currentNode.Parent;
                }
                else
                {
                    int x = DnsNSECRecordData.CanonicalComparison(currentValue.Key, key);
                    if (x == 0)
                    {
                        //current node value matches the key
                        k = 0; //find next node from children starting at k
                    }
                    else if (x > 0)
                    {
                        //current node value is larger for the key thus current is the next node
                        return currentNode;
                    }
                    else
                    {
                        //current node value is smaller for the key
                        k = key[currentNode.Depth]; //find next node from children starting at k = key[depth]
                    }
                }
            }

            //start tree traversal
            while ((currentNode is not null) && (currentNode.Depth >= baseDepth))
            {
                Node[] children = currentNode.Children;
                if (children is not null)
                {
                    //find next child node
                    Node child = null;

                    for (int i = k; i < children.Length; i++)
                    {
                        child = Volatile.Read(ref children[i]);
                        if (child is not null)
                        {
                            NodeValue childValue = child.Value;
                            if (childValue is not null)
                            {
                                AuthZoneNode authZoneNode = childValue.Value;
                                if (authZoneNode is not null)
                                {
                                    if (authZoneNode.ParentSideZone is not null)
                                    {
                                        //is sub domain zone
                                        return child; //child has value so return it
                                    }

                                    if (authZoneNode.ApexZone is not null)
                                    {
                                        //is apex zone
                                        //skip to next child to avoid listing this auth zone's sub domains
                                        child = null; //set null to avoid child being set as current after the loop
                                        continue;
                                    }
                                }
                            }

                            if (child.Children is not null)
                                break;
                        }
                    }

                    if (child is not null)
                    {
                        //make found child as current
                        k = 0;
                        currentNode = child;
                        continue; //start over
                    }
                }

                //no child nodes available; move up to parent node
                k = currentNode.K + 1;
                currentNode = currentNode.Parent;
            }

            return null;
        }

        private static bool SubDomainExists(byte[] key, Node currentNode)
        {
            Node[] children = currentNode.Children;
            if (children is not null)
            {
                Node child = Volatile.Read(ref children[1]); //[*]
                if (child is not null)
                    return true; //wildcard exists so subdomain name exists: RFC 4592 section 4.9
            }

            Node nextSubDomain = GetNextSubDomainZoneNode(key, currentNode, currentNode.Depth);
            if (nextSubDomain is null)
                return false;

            NodeValue value = nextSubDomain.Value;
            if (value is null)
                return false;

            return IsKeySubDomain(key, value.Key, false);
        }

        private static AuthZone GetAuthZoneFromNode(Node node, string zoneName)
        {
            NodeValue value = node.Value;
            if (value is not null)
            {
                AuthZoneNode authZoneNode = value.Value;
                if (authZoneNode is not null)
                    return authZoneNode.GetAuthZone(zoneName);
            }

            return null;
        }

        private void RemoveAllSubDomains(string domain, Node currentNode)
        {
            //remove all sub domains under current zone
            Node current = currentNode;
            byte[] currentKey = ConvertToByteKey(domain);

            do
            {
                current = GetNextSubDomainZoneNode(currentKey, current, currentNode.Depth);
                if (current is null)
                    break;

                NodeValue v = current.Value;
                if (v is not null)
                {
                    AuthZoneNode z = v.Value;
                    if (z is not null)
                    {
                        if (z.ApexZone is null)
                        {
                            //no apex zone at this node; remove complete zone node
                            current.RemoveNodeValue(v.Key, out _); //remove node value
                            current.CleanThisBranch();
                        }
                        else
                        {
                            //apex node exists; remove parent size sub domain
                            z.TryRemove(out SubDomainZone _);
                        }
                    }

                    currentKey = v.Key;
                }
            }
            while (true);
        }

        #endregion

        #region protected

        protected override void GetClosestValuesForZone(AuthZoneNode zoneValue, out SubDomainZone closestSubDomain, out SubDomainZone closestDelegation, out ApexZone closestAuthority)
        {
            ApexZone apexZone = zoneValue.ApexZone;
            if (apexZone is not null)
            {
                //hosted primary/secondary/stub/forwarder zone found
                closestSubDomain = null;
                closestDelegation = zoneValue.ParentSideZone;
                closestAuthority = apexZone;
            }
            else
            {
                //hosted sub domain
                SubDomainZone subDomainZone = zoneValue.ParentSideZone;

                if (subDomainZone.ContainsNameServerRecords())
                {
                    //delegated sub domain found
                    closestSubDomain = null;
                    closestDelegation = subDomainZone;
                }
                else
                {
                    closestSubDomain = subDomainZone;
                    closestDelegation = null;
                }

                closestAuthority = null;
            }
        }

        #endregion

        #region public

        public bool TryAdd(ApexZone zone)
        {
            AuthZoneNode zoneNode = GetOrAdd(zone.Name, delegate (string key)
            {
                return new AuthZoneNode(null, zone);
            });

            if (ReferenceEquals(zoneNode.ApexZone, zone))
                return true; //added successfully

            return zoneNode.TryAdd(zone);
        }

        public bool TryGet(string zoneName, string domain, out AuthZone authZone)
        {
            if (TryGet(domain, out AuthZoneNode authZoneNode))
            {
                authZone = authZoneNode.GetAuthZone(zoneName);
                return authZone is not null;
            }

            authZone = null;
            return false;
        }

        public bool TryGet(string zoneName, out ApexZone apexZone)
        {
            if (TryGet(zoneName, out AuthZoneNode authZoneNode) && (authZoneNode.ApexZone is not null))
            {
                apexZone = authZoneNode.ApexZone;
                return true;
            }

            apexZone = null;
            return false;
        }

        public bool TryRemove(string domain, out ApexZone apexZone)
        {
            if (!TryGet(domain, out AuthZoneNode authZoneNode, out Node currentNode) || (authZoneNode.ApexZone is null))
            {
                apexZone = null;
                return false;
            }

            apexZone = authZoneNode.ApexZone;

            if (authZoneNode.ParentSideZone is null)
            {
                //remove complete zone node
                if (!base.TryRemove(domain, out AuthZoneNode _))
                {
                    apexZone = null;
                    return false;
                }
            }
            else
            {
                //parent side sub domain exists; remove only apex zone from zone node
                if (!authZoneNode.TryRemove(out ApexZone _))
                {
                    apexZone = null;
                    return false;
                }
            }

            //remove all sub domains under current apex zone
            RemoveAllSubDomains(domain, currentNode);

            currentNode.CleanThisBranch();
            return true;
        }

        public bool TryRemove(string domain, out SubDomainZone subDomainZone, bool removeAllSubDomains = false)
        {
            if (!TryGet(domain, out AuthZoneNode zoneNode, out Node currentNode) || (zoneNode.ParentSideZone is null))
            {
                subDomainZone = null;
                return false;
            }

            subDomainZone = zoneNode.ParentSideZone;

            if (zoneNode.ApexZone is null)
            {
                //remove complete zone node
                if (!base.TryRemove(domain, out AuthZoneNode _))
                {
                    subDomainZone = null;
                    return false;
                }
            }
            else
            {
                //apex zone exists; remove only parent side sub domain from zone node
                if (!zoneNode.TryRemove(out SubDomainZone _))
                {
                    subDomainZone = null;
                    return false;
                }
            }

            if (removeAllSubDomains)
                RemoveAllSubDomains(domain, currentNode); //remove all sub domains under current subdomain zone

            currentNode.CleanThisBranch();
            return true;
        }

        public override bool TryRemove(string key, out AuthZoneNode authZoneNode)
        {
            throw new InvalidOperationException();
        }

        public IReadOnlyList<AuthZone> GetApexZoneWithSubDomainZones(string zoneName)
        {
            List<AuthZone> zones = new List<AuthZone>();

            byte[] key = ConvertToByteKey(zoneName);

            NodeValue nodeValue = _root.FindNodeValue(key, out Node currentNode);
            if (nodeValue is not null)
            {
                AuthZoneNode authZoneNode = nodeValue.Value;
                if (authZoneNode is not null)
                {
                    ApexZone apexZone = authZoneNode.ApexZone;
                    if (apexZone is not null)
                    {
                        zones.Add(apexZone);

                        Node current = currentNode;
                        byte[] currentKey = key;

                        do
                        {
                            current = GetNextSubDomainZoneNode(currentKey, current, currentNode.Depth);
                            if (current is null)
                                break;

                            NodeValue value = current.Value;
                            if (value is not null)
                            {
                                authZoneNode = value.Value;
                                if (authZoneNode is not null)
                                    zones.Add(authZoneNode.ParentSideZone);

                                currentKey = value.Key;
                            }
                        }
                        while (true);
                    }
                }
            }

            return zones;
        }

        public IReadOnlyList<AuthZone> GetSubDomainZoneWithSubDomainZones(string domain)
        {
            List<AuthZone> zones = new List<AuthZone>();

            byte[] key = ConvertToByteKey(domain);

            NodeValue nodeValue = _root.FindNodeValue(key, out Node currentNode);
            if (nodeValue is not null)
            {
                AuthZoneNode authZoneNode = nodeValue.Value;
                if (authZoneNode is not null)
                {
                    SubDomainZone subDomainZone = authZoneNode.ParentSideZone;
                    if (subDomainZone is not null)
                    {
                        zones.Add(subDomainZone);

                        Node current = currentNode;
                        byte[] currentKey = key;

                        do
                        {
                            current = GetNextSubDomainZoneNode(currentKey, current, currentNode.Depth);
                            if (current is null)
                                break;

                            NodeValue value = current.Value;
                            if (value is not null)
                            {
                                authZoneNode = value.Value;
                                if (authZoneNode is not null)
                                    zones.Add(authZoneNode.ParentSideZone);

                                currentKey = value.Key;
                            }
                        }
                        while (true);
                    }
                }
            }

            return zones;
        }

        public AuthZone GetOrAddSubDomainZone(string zoneName, string domain, Func<SubDomainZone> valueFactory)
        {
            bool isApex = zoneName.Equals(domain, StringComparison.OrdinalIgnoreCase);

            AuthZoneNode authZoneNode = GetOrAdd(domain, delegate (string key)
            {
                if (isApex)
                    throw new DnsServerException("Zone was not found for domain: " + key);

                return new AuthZoneNode(valueFactory(), null);
            });

            if (isApex)
            {
                if (authZoneNode.ApexZone is null)
                    throw new DnsServerException("Zone was not found: " + zoneName);

                return authZoneNode.ApexZone;
            }
            else
            {
                return authZoneNode.GetOrAddParentSideZone(valueFactory);
            }
        }

        public AuthZone GetAuthZone(string zoneName, string domain)
        {
            if (TryGet(domain, out AuthZoneNode authZoneNode))
                return authZoneNode.GetAuthZone(zoneName);

            return null;
        }

        public ApexZone GetApexZone(string zoneName)
        {
            if (TryGet(zoneName, out AuthZoneNode authZoneNode))
                return authZoneNode.ApexZone;

            return null;
        }

        public AuthZone FindZone(string domain, out SubDomainZone closest, out SubDomainZone delegation, out ApexZone authority, out bool hasSubDomains)
        {
            byte[] key = ConvertToByteKey(domain);

            AuthZoneNode authZoneNode = FindZoneNode(key, true, out Node currentNode, out Node closestSubDomainNode, out _, out SubDomainZone closestSubDomain, out SubDomainZone closestDelegation, out ApexZone closestAuthority);
            if (authZoneNode is null)
            {
                //zone not found
                closest = closestSubDomain;
                delegation = closestDelegation;
                authority = closestAuthority;

                if (authority is null)
                {
                    //no authority so no sub domains
                    hasSubDomains = false;
                }
                else if ((closestSubDomainNode is not null) && !closestSubDomainNode.HasChildren)
                {
                    //closest sub domain node does not have any children so no sub domains
                    hasSubDomains = false;
                }
                else
                {
                    //check if current node has sub domains
                    hasSubDomains = SubDomainExists(key, currentNode);
                }

                return null;
            }
            else
            {
                //zone found
                AuthZone zone;

                ApexZone apexZone = authZoneNode.ApexZone;
                if (apexZone is not null)
                {
                    zone = apexZone;
                    closest = null;
                    delegation = authZoneNode.ParentSideZone;
                    authority = apexZone;
                }
                else
                {
                    SubDomainZone subDomainZone = authZoneNode.ParentSideZone;

                    zone = subDomainZone;

                    if (zone == closestSubDomain)
                        closest = null;
                    else
                        closest = closestSubDomain;

                    if (closestDelegation is not null)
                        delegation = closestDelegation;
                    else if (subDomainZone.ContainsNameServerRecords())
                        delegation = subDomainZone;
                    else
                        delegation = null;

                    authority = closestAuthority;
                }

                if (zone.Disabled)
                {
                    if ((closestSubDomainNode is not null) && !closestSubDomainNode.HasChildren)
                    {
                        //closest sub domain node does not have any children so no sub domains
                        hasSubDomains = false;
                    }
                    else
                    {
                        //check if current node has sub domains
                        hasSubDomains = SubDomainExists(key, currentNode);
                    }
                }
                else
                {
                    //since zone is found, it does not matter if subdomain exists or not
                    hasSubDomains = false;
                }

                return zone;
            }
        }

        public AuthZone FindPreviousSubDomainZone(string zoneName, string domain)
        {
            byte[] key = ConvertToByteKey(domain);

            AuthZoneNode authZoneNode = FindZoneNode(key, false, out Node currentNode, out _, out Node closestAuthorityNode, out _, out _, out _);
            if (authZoneNode is not null)
            {
                //zone exists
                ApexZone apexZone = authZoneNode.ApexZone;
                SubDomainZone parentSideZone = authZoneNode.ParentSideZone;

                if ((apexZone is not null) && (parentSideZone is not null))
                {
                    //found ambiguity between apex zone and sub domain zone
                    if (!apexZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    {
                        //zone name does not match with apex zone and thus not match with closest authority node
                        //find the closest authority zone for given zone name
                        if (!TryGet(zoneName, out _, out Node closestNodeForZoneName))
                            throw new InvalidOperationException();

                        closestAuthorityNode = closestNodeForZoneName;
                    }
                }
            }

            Node previousNode = GetPreviousSubDomainZoneNode(key, currentNode, closestAuthorityNode.Depth);
            if (previousNode is not null)
            {
                AuthZone authZone = GetAuthZoneFromNode(previousNode, zoneName);
                if (authZone is not null)
                    return authZone;
            }

            return null;
        }

        public AuthZone FindNextSubDomainZone(string zoneName, string domain)
        {
            byte[] key = ConvertToByteKey(domain);

            AuthZoneNode authZoneNode = FindZoneNode(key, false, out Node currentNode, out _, out Node closestAuthorityNode, out _, out _, out _);
            if (authZoneNode is not null)
            {
                //zone exists
                ApexZone apexZone = authZoneNode.ApexZone;
                SubDomainZone parentSideZone = authZoneNode.ParentSideZone;

                if ((apexZone is not null) && (parentSideZone is not null))
                {
                    //found ambiguity between apex zone and sub domain zone
                    if (!apexZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                    {
                        //zone name does not match with apex zone and thus not match with closest authority node
                        //find the closest authority zone for given zone name
                        if (!TryGet(zoneName, out _, out Node closestNodeForZoneName))
                            throw new InvalidOperationException();

                        closestAuthorityNode = closestNodeForZoneName;
                    }
                }
            }

            Node nextNode = GetNextSubDomainZoneNode(key, currentNode, closestAuthorityNode.Depth);
            if (nextNode is not null)
            {
                AuthZone authZone = GetAuthZoneFromNode(nextNode, zoneName);
                if (authZone is not null)
                    return authZone;
            }

            return null;
        }

        public bool SubDomainExistsFor(string zoneName, string domain)
        {
            AuthZone nextAuthZone = FindNextSubDomainZone(zoneName, domain);
            if (nextAuthZone is null)
                return false;

            return nextAuthZone.Name.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
        }

        #endregion

        #region DNSSEC

        public IReadOnlyList<DnsResourceRecord> FindNSecProofOfNonExistenceNxDomain(string domain, bool isWildcardAnswer)
        {
            List<DnsResourceRecord> nsecRecords = new List<DnsResourceRecord>(2 * 2);

            //add proof of cover for domain
            NSecAddProofOfCoverFor(domain, nsecRecords);

            if (isWildcardAnswer)
                return nsecRecords;

            //add proof of cover for wildcard
            if (nsecRecords.Count > 0)
            {
                //add wildcard proof to prove that a wildcard expansion was not possible
                DnsResourceRecord nsecRecord = nsecRecords[0];
                DnsNSECRecordData nsec = nsecRecord.RDATA as DnsNSECRecordData;
                string wildcardName = DnsNSECRecordData.GetWildcardFor(nsecRecord, domain);

                if (!DnsNSECRecordData.IsDomainCovered(nsecRecord.Name, nsec.NextDomainName, wildcardName))
                    NSecAddProofOfCoverFor(wildcardName, nsecRecords);
            }

            return nsecRecords;
        }

        public IReadOnlyList<DnsResourceRecord> FindNSec3ProofOfNonExistenceNxDomain(string domain, bool isWildcardAnswer)
        {
            List<DnsResourceRecord> nsec3Records = new List<DnsResourceRecord>(3 * 2);

            byte[] key = ConvertToByteKey(domain);
            string closestEncloser;

            AuthZoneNode authZoneNode = FindZoneNode(key, isWildcardAnswer, out _, out _, out _, out SubDomainZone closestSubDomain, out _, out ApexZone closestAuthority);
            if (authZoneNode is not null)
            {
                if (isWildcardAnswer && (closestSubDomain is not null) && closestSubDomain.Name.StartsWith('*'))
                {
                    closestEncloser = closestSubDomain.Name.TrimStart(_starPeriodTrimChars);
                }
                else
                {
                    //subdomain that contains only NSEC3 record does not really exists: RFC5155 section 7.2.8    
                    if ((authZoneNode.ApexZone is not null) || ((authZoneNode.ParentSideZone is not null) && !authZoneNode.ParentSideZone.HasOnlyNSec3Records()))
                        throw new InvalidOperationException($"Cannot prove non-existence: The domain name '{domain}' exists and probably got added just now."); //domain exists! cannot prove non-existence

                    //continue to prove non-existence of this nsec3 owner name
                    closestEncloser = closestAuthority.Name;
                }
            }
            else
            {
                if (closestSubDomain is not null)
                    closestEncloser = closestSubDomain.Name;
                else if (closestAuthority is not null)
                    closestEncloser = closestAuthority.Name;
                else
                    throw new InvalidOperationException(); //cannot find closest encloser
            }

            IReadOnlyList<DnsResourceRecord> nsec3ParamRecords = closestAuthority.GetRecords(DnsResourceRecordType.NSEC3PARAM);
            if (nsec3ParamRecords.Count == 0)
                throw new InvalidOperationException("Zone does not have NSEC3 deployed.");

            DnsNSEC3PARAMRecordData nsec3Param = nsec3ParamRecords[0].RDATA as DnsNSEC3PARAMRecordData;

            //find correct closest encloser
            string hashedNextCloserName;

            while (true)
            {
                string nextCloserName = DnsNSEC3RecordData.GetNextCloserName(domain, closestEncloser);
                hashedNextCloserName = nsec3Param.ComputeHashedOwnerNameBase32HexString(nextCloserName) + (closestAuthority.Name.Length > 0 ? "." + closestAuthority.Name : "");

                AuthZone nsec3Zone = GetAuthZone(closestAuthority.Name, hashedNextCloserName);
                if (nsec3Zone is null)
                    break; //next closer name does not exists

                //next closer name exists as an ENT
                closestEncloser = nextCloserName;

                if (domain.Equals(closestEncloser, StringComparison.OrdinalIgnoreCase))
                {
                    //domain exists as an ENT; return no data proof
                    return FindNSec3ProofOfNonExistenceNoData(nsec3Zone);
                }
            }

            if (isWildcardAnswer)
            {
                //add proof of cover for the domain to prove non-existence (wildcard)
                NSec3AddProofOfCoverFor(hashedNextCloserName, closestAuthority.Name, nsec3Records);
            }
            else
            {
                //add closest encloser proof
                string hashedClosestEncloser = nsec3Param.ComputeHashedOwnerNameBase32HexString(closestEncloser) + (closestAuthority.Name.Length > 0 ? "." + closestAuthority.Name : "");

                AuthZone nsec3Zone = GetAuthZone(closestAuthority.Name, hashedClosestEncloser);
                if (nsec3Zone is null)
                    throw new InvalidOperationException();

                IReadOnlyList<DnsResourceRecord> closestEncloserProofRecords = nsec3Zone.QueryRecords(DnsResourceRecordType.NSEC3, true);
                if (closestEncloserProofRecords.Count == 0)
                    throw new InvalidOperationException();

                nsec3Records.AddRange(closestEncloserProofRecords);

                DnsResourceRecord closestEncloserProofRecord = closestEncloserProofRecords[0];
                DnsNSEC3RecordData closestEncloserProof = closestEncloserProofRecord.RDATA as DnsNSEC3RecordData;

                //add proof of cover for the next closer name
                if (!DnsNSECRecordData.IsDomainCovered(closestEncloserProofRecord.Name, closestEncloserProof.NextHashedOwnerName + (closestAuthority.Name.Length > 0 ? "." + closestAuthority.Name : ""), hashedNextCloserName))
                    NSec3AddProofOfCoverFor(hashedNextCloserName, closestAuthority.Name, nsec3Records);

                //add proof of cover to prove that a wildcard expansion was not possible
                string wildcardDomain = closestEncloser.Length > 0 ? "*." + closestEncloser : "*";
                string hashedWildcardDomainName = nsec3Param.ComputeHashedOwnerNameBase32HexString(wildcardDomain) + (closestAuthority.Name.Length > 0 ? "." + closestAuthority.Name : "");

                if (!DnsNSECRecordData.IsDomainCovered(closestEncloserProofRecord.Name, closestEncloserProof.NextHashedOwnerName + (closestAuthority.Name.Length > 0 ? "." + closestAuthority.Name : ""), hashedWildcardDomainName))
                    NSec3AddProofOfCoverFor(hashedWildcardDomainName, closestAuthority.Name, nsec3Records);
            }

            return nsec3Records;
        }

        public IReadOnlyList<DnsResourceRecord> FindNSecProofOfNonExistenceNoData(string domain, AuthZone zone)
        {
            List<DnsResourceRecord> nsecRecords = null;

            if (zone.Name.StartsWith("*.") || zone.Name.Equals('*'))
            {
                //for wildcard case, we need to add proof of cover since validator wont be able to match qname to the NO DATA NSEC record
                nsecRecords = new List<DnsResourceRecord>(4);

                NSecAddProofOfCoverFor(domain, nsecRecords);
            }

            IReadOnlyList<DnsResourceRecord> nsecRecordsNoData = zone.QueryRecords(DnsResourceRecordType.NSEC, true);
            if (nsecRecordsNoData.Count == 0)
                throw new InvalidOperationException("Zone does not have NSEC deployed correctly.");

            if (nsecRecords is null)
                return nsecRecordsNoData;

            foreach (DnsResourceRecord nsecRecord in nsecRecordsNoData)
            {
                if (!nsecRecords.Contains(nsecRecord))
                    nsecRecords.Add(nsecRecord);
            }

            return nsecRecords;
        }

        public IReadOnlyList<DnsResourceRecord> FindNSec3ProofOfNonExistenceNoData(string domain, AuthZone zone, ApexZone apexZone)
        {
            IReadOnlyList<DnsResourceRecord> nsec3ParamRecords = apexZone.GetRecords(DnsResourceRecordType.NSEC3PARAM);
            if (nsec3ParamRecords.Count == 0)
                throw new InvalidOperationException("Zone does not have NSEC3 deployed.");

            DnsNSEC3PARAMRecordData nsec3Param = nsec3ParamRecords[0].RDATA as DnsNSEC3PARAMRecordData;
            List<DnsResourceRecord> nsec3Records = null;

            if (zone.Name.StartsWith("*.") || zone.Name.Equals('*'))
            {
                //for wildcard case, we need to add the closest encloser and add proof of cover since validator wont be able to match qname hashed owner name to the NO DATA NSEC3 record
                string closestEncloser = AuthZoneManager.GetParentZone(zone.Name);
                if (closestEncloser is null)
                    closestEncloser = "";

                string closestEncloserHashedOwnerName = nsec3Param.ComputeHashedOwnerNameBase32HexString(closestEncloser) + (apexZone.Name.Length > 0 ? "." + apexZone.Name : "");

                AuthZone nsec3ZoneClosestEncloser = GetAuthZone(apexZone.Name, closestEncloserHashedOwnerName);
                if (nsec3ZoneClosestEncloser is not null)
                {
                    nsec3Records = new List<DnsResourceRecord>(4);
                    nsec3Records.AddRange(FindNSec3ProofOfNonExistenceNoData(nsec3ZoneClosestEncloser));

                    string qnameHashedOwnerName = nsec3Param.ComputeHashedOwnerNameBase32HexString(domain) + (apexZone.Name.Length > 0 ? "." + apexZone.Name : "");
                    NSec3AddProofOfCoverFor(qnameHashedOwnerName, apexZone.Name, nsec3Records);
                }
            }

            string hashedOwnerName = nsec3Param.ComputeHashedOwnerNameBase32HexString(zone.Name) + (apexZone.Name.Length > 0 ? "." + apexZone.Name : "");

            AuthZone nsec3Zone = GetAuthZone(apexZone.Name, hashedOwnerName);
            if (nsec3Zone is null)
            {
                //this is probably since the domain in request is for an nsec3 record owner name
                return FindNSec3ProofOfNonExistenceNxDomain(zone.Name, false);
            }

            IReadOnlyList<DnsResourceRecord> nsec3RecordsNoData = FindNSec3ProofOfNonExistenceNoData(nsec3Zone);

            if (nsec3Records is null)
                return nsec3RecordsNoData;

            foreach (DnsResourceRecord nsec3Record in nsec3RecordsNoData)
            {
                if (!nsec3Records.Contains(nsec3Record))
                    nsec3Records.Add(nsec3Record);
            }

            return nsec3Records;
        }

        private static IReadOnlyList<DnsResourceRecord> FindNSec3ProofOfNonExistenceNoData(AuthZone nsec3Zone)
        {
            IReadOnlyList<DnsResourceRecord> nsec3Records = nsec3Zone.QueryRecords(DnsResourceRecordType.NSEC3, true);
            if (nsec3Records.Count > 0)
                return nsec3Records;

            return Array.Empty<DnsResourceRecord>();
        }

        private void NSecAddProofOfCoverFor(string domain, List<DnsResourceRecord> nsecRecords)
        {
            byte[] key = ConvertToByteKey(domain);

            AuthZoneNode authZoneNode = FindZoneNode(key, false, out Node currentNode, out _, out Node closestAuthorityNode, out _, out _, out ApexZone closestAuthority);
            if (authZoneNode is not null)
                throw new InvalidOperationException($"Cannot prove non-existence: The domain name '{domain}' exists and probably got added just now."); //domain exists! cannot prove non-existence

            Node previousNode = GetPreviousSubDomainZoneNode(key, currentNode, closestAuthorityNode.Depth);
            if (previousNode is not null)
            {
                AuthZone authZone = GetAuthZoneFromNode(previousNode, closestAuthority.Name);
                if (authZone is not null)
                {
                    IReadOnlyList<DnsResourceRecord> proofOfCoverRecords = authZone.QueryRecords(DnsResourceRecordType.NSEC, true);

                    foreach (DnsResourceRecord proofOfCoverRecord in proofOfCoverRecords)
                    {
                        if (!nsecRecords.Contains(proofOfCoverRecord))
                            nsecRecords.Add(proofOfCoverRecord);
                    }
                }
            }
        }

        private void NSec3AddProofOfCoverFor(string hashedOwnerName, string zoneName, List<DnsResourceRecord> nsec3Records)
        {
            IReadOnlyList<DnsResourceRecord> TryFindPreviousNSec3Records(string ownerName)
            {
                while (true)
                {
                    AuthZone zone = FindPreviousSubDomainZone(zoneName, ownerName);
                    if (zone is null)
                        return null; //no previous auth zone found

                    IReadOnlyList<DnsResourceRecord> previousNSec3Records = zone.QueryRecords(DnsResourceRecordType.NSEC3, true);
                    if (previousNSec3Records.Count > 0)
                        return previousNSec3Records; //found proof of cover

                    ownerName = zone.Name;
                }
            }

            //find previous NSEC3 for the hashed owner name
            IReadOnlyList<DnsResourceRecord> proofOfCoverRecords = TryFindPreviousNSec3Records(hashedOwnerName);

            if (proofOfCoverRecords is null)
            {
                //didnt find previous NSEC3; find the last NSEC3 which will give the proof of cover
                proofOfCoverRecords = TryFindPreviousNSec3Records("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0" + (zoneName.Length > 0 ? "." + zoneName : ""));
            }

            if (proofOfCoverRecords is null)
                throw new InvalidOperationException();

            foreach (DnsResourceRecord proofOfCoverRecord in proofOfCoverRecords)
            {
                if (!nsec3Records.Contains(proofOfCoverRecord))
                    nsec3Records.Add(proofOfCoverRecord);
            }
        }

        #endregion
    }
}
