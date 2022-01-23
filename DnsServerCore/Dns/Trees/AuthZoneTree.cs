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
using System;
using System.Collections.Generic;
using System.Threading;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Trees
{
    class AuthZoneTree : ZoneTree<AuthZoneNode, SubDomainZone, ApexZone>
    {
        #region private

        private static Node GetPreviousSubDomainZoneNode(byte[] key, Node current, int baseDepth)
        {
            int k = key[current.Depth];

            while ((current is not null) && (current.Depth >= baseDepth))
            {
                Node[] children = current.Children;
                if (children is not null)
                {
                    //find previous child node
                    Node child = null;

                    for (int i = k; i > -1; i--)
                    {
                        child = Volatile.Read(ref children[i]);
                        if (child is not null)
                        {
                            NodeValue value = child.Value;
                            if (value is not null)
                            {
                                AuthZoneNode zoneNode = value.Value;
                                if (zoneNode is not null)
                                {
                                    if (zoneNode.ParentSideZone is not null)
                                    {
                                        //is sub domain zone
                                        return child; //child has value so return it
                                    }
                                    else
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
                        k = children.Length - 1;
                        current = child;
                        continue; //start over
                    }
                }

                //no child node found; check for current node value
                {
                    NodeValue value = current.Value;
                    if (value is not null)
                    {
                        AuthZoneNode zoneNode = value.Value;
                        if (zoneNode is not null)
                        {
                            ApexZone apexZone = zoneNode.ApexZone;
                            if (apexZone is not null)
                            {
                                //current contains apex zone; return it
                                return current;
                            }
                        }
                    }
                }

                //no child nodes available; move up to parent node
                k = current.K - 1;
                current = current.Parent;
            }

            return null;
        }

        private static Node GetNextSubDomainZoneNode(Node current, int baseDepth)
        {
            int k = 0;

            while ((current is not null) && (current.Depth >= baseDepth))
            {
                if (current.Depth > baseDepth)
                {
                    NodeValue value = current.Value;
                    if (value is not null)
                    {
                        AuthZoneNode zoneNode = value.Value;
                        if (zoneNode is not null)
                        {
                            ApexZone apexZone = zoneNode.ApexZone;
                            if (apexZone is not null)
                            {
                                //current contains apex for a sub zone; move up to parent node
                                k = current.K + 1;
                                current = current.Parent;
                                continue;
                            }
                        }
                    }
                }

                Node[] children = current.Children;
                if (children is not null)
                {
                    //find next child node
                    Node child = null;

                    for (int i = k; i < children.Length; i++)
                    {
                        child = Volatile.Read(ref children[i]);
                        if (child is not null)
                        {
                            NodeValue value = child.Value;
                            if (value is not null)
                            {
                                AuthZoneNode zoneNode = value.Value;
                                if (zoneNode is not null)
                                {
                                    if (zoneNode.ParentSideZone is not null)
                                    {
                                        //is sub domain zone
                                        return child; //child has value so return it
                                    }
                                    else
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
                        current = child;
                        continue; //start over
                    }
                }

                //no child nodes available; move up to parent node
                k = current.K + 1;
                current = current.Parent;
            }

            return null;
        }

        private static bool SubDomainExists(byte[] key, Node closestNode)
        {
            if (!closestNode.HasChildren)
                return false;

            Node nextSubDomain = GetNextSubDomainZoneNode(closestNode, closestNode.Depth);
            if (nextSubDomain is null)
                return false;

            NodeValue value = nextSubDomain.Value;
            if (value is null)
                return false;

            return IsKeySubDomain(key, value.Key);
        }

        private static AuthZone GetAuthZoneFromNode(Node node, string domain, DnsResourceRecordType type)
        {
            NodeValue value = node.Value;
            if (value is not null)
            {
                AuthZoneNode zoneNode = value.Value;
                if (zoneNode is not null)
                {
                    ApexZone apexZone = zoneNode.ApexZone;
                    if ((apexZone is not null) && (type != DnsResourceRecordType.DS) && (DnsNSECRecord.CanonicalComparison(apexZone.Name, domain) < 0))
                        return apexZone;

                    SubDomainZone parentSideZone = zoneNode.ParentSideZone;
                    if ((parentSideZone is not null) && (DnsNSECRecord.CanonicalComparison(parentSideZone.Name, domain) < 0))
                        return parentSideZone;
                }
            }

            return null;
        }

        #endregion

        #region protected

        protected override void GetClosestValuesForZone(AuthZoneNode zoneValue, ref SubDomainZone closestSubDomain, ref SubDomainZone closestDelegation, ref ApexZone closestAuthority)
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

                if ((closestDelegation is null) && subDomainZone.ContainsNameServerRecords())
                    closestDelegation = subDomainZone; //delegated sub domain found
                else
                    closestSubDomain = subDomainZone;
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
            if (TryGet(domain, out AuthZoneNode zoneNode))
            {
                if (zoneName.Equals(domain, StringComparison.OrdinalIgnoreCase))
                {
                    if (zoneNode.ApexZone is not null)
                    {
                        authZone = zoneNode.ApexZone;
                        return true;
                    }
                }
                else
                {
                    if (zoneNode.ParentSideZone is not null)
                    {
                        authZone = zoneNode.ParentSideZone;
                        return true;
                    }
                }
            }

            authZone = null;
            return false;
        }

        public AuthZone GetOrAddSubDomainZone(string zoneName, string domain, Func<SubDomainZone> valueFactory)
        {
            bool isApex = zoneName.Equals(domain, StringComparison.OrdinalIgnoreCase);

            AuthZoneNode zoneNode = GetOrAdd(domain, delegate (string key)
            {
                if (isApex)
                    throw new DnsServerException("Zone was not found for domain: " + key);

                return new AuthZoneNode(valueFactory(), null);
            });

            if (isApex)
            {
                if (zoneNode.ApexZone is null)
                    throw new DnsServerException("Zone was not found: " + zoneName);

                return zoneNode.ApexZone;
            }
            else
            {
                return zoneNode.GetOrAddParentSideZone(valueFactory);
            }
        }

        public bool TryRemove(string domain, out ApexZone value)
        {
            if (!TryGet(domain, out AuthZoneNode zoneNode, out Node closestNode) || (zoneNode.ApexZone is null))
            {
                value = null;
                return false;
            }

            value = zoneNode.ApexZone;

            if (zoneNode.ParentSideZone is null)
            {
                //remove complete zone node
                if (!base.TryRemove(domain, out AuthZoneNode _))
                {
                    value = null;
                    return false;
                }
            }
            else
            {
                //parent side sub domain exists; remove only apex zone from zone node
                if (!zoneNode.TryRemove(out ApexZone _))
                {
                    value = null;
                    return false;
                }
            }

            //remove all sub domains under current zone
            Node current = closestNode;

            do
            {
                current = GetNextSubDomainZoneNode(current, closestNode.Depth);
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
                }
            }
            while (true);

            closestNode.CleanThisBranch();
            return true;
        }

        public bool TryRemove(string domain, out SubDomainZone value)
        {
            if (!TryGet(domain, out AuthZoneNode zoneNode, out Node closestNode) || (zoneNode.ParentSideZone is null))
            {
                value = null;
                return false;
            }

            value = zoneNode.ParentSideZone;

            if (zoneNode.ApexZone is null)
            {
                //remove complete zone node
                if (!base.TryRemove(domain, out AuthZoneNode _))
                {
                    value = null;
                    return false;
                }
            }
            else
            {
                //apex zone exists; remove only parent side sub domain from zone node
                if (!zoneNode.TryRemove(out SubDomainZone _))
                {
                    value = null;
                    return false;
                }
            }

            closestNode.CleanThisBranch();
            return true;
        }

        public override bool TryRemove(string key, out AuthZoneNode value)
        {
            throw new InvalidOperationException();
        }

        public List<AuthZone> GetZoneWithSubDomainZones(string zoneName)
        {
            if (zoneName is null)
                throw new ArgumentNullException(nameof(zoneName));

            List<AuthZone> zones = new List<AuthZone>();

            byte[] bKey = ConvertToByteKey(zoneName);

            NodeValue nodeValue = _root.FindNodeValue(bKey, out Node closestNode);
            if (nodeValue is not null)
            {
                AuthZoneNode zoneNode = nodeValue.Value;
                if (zoneNode is not null)
                {
                    ApexZone apexZone = zoneNode.ApexZone;
                    if (apexZone is not null)
                    {
                        zones.Add(apexZone);

                        Node current = closestNode;

                        do
                        {
                            current = GetNextSubDomainZoneNode(current, closestNode.Depth);
                            if (current is null)
                                break;

                            NodeValue value = current.Value;
                            if (value is not null)
                            {
                                zoneNode = value.Value;
                                if (zoneNode is not null)
                                    zones.Add(zoneNode.ParentSideZone);
                            }
                        }
                        while (true);
                    }
                }
            }

            return zones;
        }

        public AuthZone FindZone(string domain, out SubDomainZone closest, out SubDomainZone delegation, out ApexZone authority, out bool hasSubDomains)
        {
            if (domain is null)
                throw new ArgumentNullException(nameof(domain));

            byte[] key = ConvertToByteKey(domain);

            AuthZoneNode zoneNode = FindZone(key, out Node closestNode, out _, out SubDomainZone closestSubDomain, out SubDomainZone closestDelegation, out ApexZone closestAuthority);
            if (zoneNode is null)
            {
                //zone not found
                closest = closestSubDomain;
                delegation = closestDelegation;
                authority = closestAuthority;

                if (authority is null)
                {
                    //no authority so no subdomains
                    hasSubDomains = false;
                }
                else
                {
                    //check if current node has sub domains
                    NodeValue value = closestNode.Value;
                    if (value is null)
                        hasSubDomains = SubDomainExists(key, closestNode);
                    else
                        hasSubDomains = IsKeySubDomain(key, value.Key);
                }

                return null;
            }
            else
            {
                //zone found
                AuthZone zone;

                ApexZone apexZone = zoneNode.ApexZone;
                if (apexZone is not null)
                {
                    zone = apexZone;
                    closest = null;
                    delegation = zoneNode.ParentSideZone;
                    authority = apexZone;
                }
                else
                {
                    SubDomainZone subDomainZone = zoneNode.ParentSideZone;

                    zone = subDomainZone;
                    closest = closestSubDomain;

                    if (closestDelegation is not null)
                        delegation = closestDelegation;
                    else if (subDomainZone.ContainsNameServerRecords())
                        delegation = subDomainZone;
                    else
                        delegation = null;

                    authority = closestAuthority;
                }

                hasSubDomains = false; //since zone is found, it does not matter if subdomain exists or not

                return zone;
            }
        }

        public IReadOnlyList<DnsResourceRecord> FindNSECProofOfNonExistenceNxDomain(string domain, DnsResourceRecordType type, bool isWildcardAnswer)
        {
            if (domain is null)
                throw new ArgumentNullException(nameof(domain));

            List<DnsResourceRecord> nsecRecords = new List<DnsResourceRecord>(2 * 2);

            void AddProofOfCoverFor(string domain)
            {
                byte[] key = ConvertToByteKey(domain);

                AuthZoneNode zoneNode = FindZone(key, out Node closestNode, out Node closestAuthorityNode, out _, out _, out _);
                if (zoneNode is not null)
                    return; //domain exists! cannot prove non-existence

                //check for value at closest node
                AuthZone authZone = GetAuthZoneFromNode(closestNode, domain, type);
                if (authZone is null)
                {
                    Node previousNode = GetPreviousSubDomainZoneNode(key, closestNode, closestAuthorityNode.Depth);
                    if (previousNode is not null)
                        authZone = GetAuthZoneFromNode(previousNode, domain, type);
                }

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

            //add proof of cover for domain
            AddProofOfCoverFor(domain);

            if (isWildcardAnswer)
                return nsecRecords;

            //add proof of cover for wildcard
            if ((nsecRecords.Count > 0) && (nsecRecords[0].Type == DnsResourceRecordType.NSEC))
            {
                DnsResourceRecord nsecRecord = nsecRecords[0];
                DnsNSECRecord nsec = nsecRecord.RDATA as DnsNSECRecord;

                if (!nsec.NextDomainName.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                {
                    //add wildcard proof to prove that a wildcard expansion was not possible
                    string wildcardName = DnsNSECRecord.GetWildcardFor(nsecRecord.Name, nsec.NextDomainName);

                    AddProofOfCoverFor(wildcardName);
                }
            }

            return nsecRecords;
        }

        public IReadOnlyList<DnsResourceRecord> FindNSEC3ProofOfNonExistenceNxDomain(string domain, DnsResourceRecordType type, bool isWildcardAnswer)
        {
            if (domain is null)
                throw new ArgumentNullException(nameof(domain));

            List<DnsResourceRecord> nsec3Records = new List<DnsResourceRecord>(3 * 2);
            string closestEncloser;
            string hashedNextCloserName;
            string hashedWildcardDomainName = null;

            //get closest encloser proof
            {
                byte[] key = ConvertToByteKey(domain);

                AuthZoneNode zoneNode = FindZone(key, out _, out _, out SubDomainZone closestSubDomain, out _, out ApexZone closestAuthority);
                if (zoneNode is not null)
                {
                    //subdomain that contains only NSEC3 record does not really exists: RFC5155 section 7.2.8

                    //TO DO: check for record types before claiming that domain exists!

                    return nsec3Records; //domain exists! cannot prove non-existence
                }

                if (closestSubDomain is not null)
                    closestEncloser = closestSubDomain.Name;
                else if (closestAuthority is not null)
                    closestEncloser = closestAuthority.Name;
                else
                    return nsec3Records; //cannot find closest encloser

                IReadOnlyList<DnsResourceRecord> nsec3ParamRecords = closestAuthority.GetRecords(DnsResourceRecordType.NSEC3PARAM);
                if (nsec3ParamRecords.Count == 0)
                    return nsec3Records; //zone does not have NSEC3 deployed

                DnsNSEC3PARAMRecord nsec3Param = nsec3ParamRecords[0].RDATA as DnsNSEC3PARAMRecord;
                string hashedClosestEncloser = nsec3Param.GetHashedOwnerName(closestEncloser) + "." + closestAuthority.Name;

                if (!TryGet(closestAuthority.Name, hashedClosestEncloser, out AuthZone authZone))
                    return nsec3Records;

                IReadOnlyList<DnsResourceRecord> closestEncloserProofRecords = authZone.QueryRecords(DnsResourceRecordType.NSEC3, true);
                if (closestEncloserProofRecords.Count == 0)
                    return nsec3Records;

                nsec3Records.AddRange(closestEncloserProofRecords);

                string nextCloserName = DnsNSEC3Record.GetNextCloserName(domain, closestEncloser);
                hashedNextCloserName = nsec3Param.GetHashedOwnerName(nextCloserName) + "." + closestAuthority.Name;

                if (!isWildcardAnswer)
                {
                    string wildcardDomain = closestEncloser.Length > 0 ? "*." + closestEncloser : "*";
                    hashedWildcardDomainName = nsec3Param.GetHashedOwnerName(wildcardDomain) + "." + closestAuthority.Name;
                }
            }

            void AddProofOfCoverFor(string domain)
            {
                byte[] key = ConvertToByteKey(domain);

                AuthZoneNode zoneNode = FindZone(key, out Node closestNode, out Node closestAuthorityNode, out _, out _, out _);
                if (zoneNode is not null)
                    return; //domain exists! cannot find proof of cover

                while (true)
                {
                    AuthZone authZone = GetAuthZoneFromNode(closestNode, domain, type);
                    if (authZone is not null)
                    {
                        IReadOnlyList<DnsResourceRecord> proofOfCoverRecords = authZone.QueryRecords(DnsResourceRecordType.NSEC3, true);
                        if (proofOfCoverRecords.Count > 0)
                        {
                            foreach (DnsResourceRecord proofOfCoverRecord in proofOfCoverRecords)
                            {
                                if (!nsec3Records.Contains(proofOfCoverRecord))
                                    nsec3Records.Add(proofOfCoverRecord);
                            }

                            break;
                        }
                    }

                    Node previousNode = GetPreviousSubDomainZoneNode(key, closestNode, closestAuthorityNode.Depth);
                    if (previousNode is null)
                        break;

                    closestNode = previousNode;
                }
            }

            //add proof of cover for the hashed next closer name
            AddProofOfCoverFor(hashedNextCloserName);

            if (isWildcardAnswer)
                return nsec3Records;

            //add proof of cover to prove that a wildcard expansion was not possible
            AddProofOfCoverFor(hashedWildcardDomainName);

            return nsec3Records;
        }

        #endregion
    }
}
