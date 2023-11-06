/*
Technitium DNS Server
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Generic;
using System.Threading;

namespace DnsServerCore.Dns.Trees
{
    abstract class ZoneTree<TNode, TSubDomainZone, TApexZone> : DomainTree<TNode> where TNode : class where TSubDomainZone : Zone where TApexZone : Zone
    {
        #region private

        private static Node GetNextChildZoneNode(Node current, int baseDepth)
        {
            int k = 0;

            while ((current is not null) && (current.Depth >= baseDepth))
            {
                if ((current.K != 0) || (current.Depth == baseDepth)) //[.] skip this node's children as its last for current sub zone
                {
                    Node[] children = current.Children;
                    if (children is not null)
                    {
                        //find child node
                        Node child = null;

                        for (int i = k; i < children.Length; i++)
                        {
                            child = Volatile.Read(ref children[i]);
                            if (child is not null)
                            {
                                if (child.Value is not null)
                                    return child; //child has value so return it

                                if (child.K == 0) //[.]
                                    return child; //child node is last for current sub zone

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
                }

                //no child nodes available; move up to parent node
                k = current.K + 1;
                current = current.Parent;
            }

            return null;
        }

        private static byte[] GetNodeKey(Node node)
        {
            byte[] key = new byte[node.Depth];
            int i = node.Depth - 1;

            while (i > -1)
            {
                key[i--] = node.K;
                node = node.Parent;
            }

            return key;
        }

        private static bool KeysMatch(byte[] mainKey, byte[] testKey, bool matchWildcard)
        {
            if (matchWildcard)
            {
                //com.example.*.
                //com.example.*.www.
                //com.example.abc.www.

                int i = 0;
                int j = 0;

                while ((i < mainKey.Length) && (j < testKey.Length))
                {
                    if (mainKey[i] == 1) //[*]
                    {
                        if (i == mainKey.Length - 2)
                            return true; //last label, valid wildcard
                    }

                    if (mainKey[i] != testKey[j])
                        return false;

                    i++;
                    j++;
                }

                return (i == mainKey.Length) && (j == testKey.Length);
            }
            else
            {
                //exact match
                if (mainKey.Length != testKey.Length)
                    return false;

                for (int i = 0; i < mainKey.Length; i++)
                {
                    if (mainKey[i] != testKey[i])
                        return false;
                }

                return true;
            }
        }

        #endregion

        #region protected

        protected static bool IsKeySubDomain(byte[] mainKey, byte[] testKey, bool matchWildcard)
        {
            if (matchWildcard)
            {
                //com.example.*.
                //com.example.*.www.
                //com.example.abc.www.

                int i = 0;
                int j = 0;

                while ((i < mainKey.Length) && (j < testKey.Length))
                {
                    if (mainKey[i] == 1) //[*]
                    {
                        if (i == mainKey.Length - 2)
                            return false; //last label, valid wildcard; wildcard is sibling, cannot have subdomain
                    }

                    if (mainKey[i] != testKey[j])
                        return false;

                    i++;
                    j++;
                }

                return (i == mainKey.Length) && (j < testKey.Length);
            }
            else
            {
                //exact match
                if (mainKey.Length > testKey.Length)
                    return false;

                for (int i = 0; i < mainKey.Length; i++)
                {
                    if (mainKey[i] != testKey[i])
                        return false;
                }

                return mainKey.Length < testKey.Length;
            }
        }

        protected TNode FindZoneNode(byte[] key, bool matchWildcard, out Node currentNode, out Node closestSubDomainNode, out Node closestAuthorityNode, out TSubDomainZone closestSubDomain, out TSubDomainZone closestDelegation, out TApexZone closestAuthority)
        {
            currentNode = _root;
            closestSubDomainNode = null;
            closestAuthorityNode = null;
            closestSubDomain = null;
            closestDelegation = null;
            closestAuthority = null;
            Node wildcard = null;
            int i = 0;

            while (i <= key.Length)
            {
                //inspect the current node
                NodeValue value = currentNode.Value;
                if ((value is not null) && (value.Key.Length <= key.Length))
                {
                    TNode zoneNode = value.Value;
                    if ((zoneNode is not null) && IsKeySubDomain(value.Key, key, matchWildcard))
                    {
                        //find closest values
                        GetClosestValuesForZone(zoneNode, out TSubDomainZone subDomain, out TSubDomainZone delegation, out TApexZone authority);

                        if (subDomain is not null)
                        {
                            closestSubDomain = subDomain;
                            closestSubDomainNode = currentNode;

                            wildcard = null; //clear previous wildcard node
                        }

                        if (delegation is not null)
                        {
                            closestDelegation = delegation;

                            wildcard = null; //clear previous wildcard node
                        }

                        if (authority is not null)
                        {
                            closestAuthority = authority;
                            closestAuthorityNode = currentNode;

                            closestSubDomain = null; //clear previous closest sub domain
                            closestSubDomainNode = null;
                            wildcard = null; //clear previous wildcard node
                        }
                    }
                }

                if (i == key.Length)
                    break;

                Node[] children = currentNode.Children;
                if (children is null)
                    break;

                Node child;

                if (matchWildcard)
                {
                    child = Volatile.Read(ref children[1]); //[*]
                    if (child is not null)
                        wildcard = child;
                }

                child = Volatile.Read(ref children[key[i]]);
                if (child is null)
                {
                    //no child found
                    if (wildcard is null)
                        return null; //no child or wildcard found

                    //use wildcard node
                    break;
                }

                currentNode = child;
                i++;
            }

            {
                NodeValue value = currentNode.Value;
                if (value is not null)
                {
                    //match exact + wildcard keys
                    if (KeysMatch(value.Key, key, matchWildcard))
                    {
                        //find closest values since the matched zone may be apex zone
                        TNode zoneNode = value.Value;
                        if (zoneNode is not null)
                        {
                            GetClosestValuesForZone(zoneNode, out TSubDomainZone subDomain, out TSubDomainZone delegation, out TApexZone authority);

                            if (subDomain is not null)
                            {
                                closestSubDomain = subDomain;
                                closestSubDomainNode = currentNode;
                            }

                            if (delegation is not null)
                                closestDelegation = delegation;

                            if (authority is not null)
                            {
                                closestAuthority = authority;
                                closestAuthorityNode = currentNode;

                                closestSubDomain = null; //clear previous closest sub domain
                                closestSubDomainNode = null;
                            }
                        }

                        return value.Value; //found matching value
                    }
                }
            }

            if (wildcard is not null)
            {
                //inspect wildcard node value
                NodeValue value = wildcard.Value;
                if (value is null)
                {
                    //find value from next [.] node
                    Node[] children = wildcard.Children;
                    if (children is not null)
                    {
                        Node child = Volatile.Read(ref children[0]); //[.]
                        if (child is not null)
                        {
                            value = child.Value;
                            if (value is not null)
                            {
                                //match wildcard keys
                                if (KeysMatch(value.Key, key, true))
                                {
                                    //find closest values
                                    TNode zoneNode = value.Value;
                                    if (zoneNode is not null)
                                    {
                                        GetClosestValuesForZone(zoneNode, out TSubDomainZone subDomain, out TSubDomainZone delegation, out TApexZone authority);

                                        if (subDomain is not null)
                                        {
                                            closestSubDomain = subDomain;
                                            closestSubDomainNode = currentNode;
                                        }

                                        if (delegation is not null)
                                            closestDelegation = delegation;

                                        if (authority is not null)
                                        {
                                            closestAuthority = authority;
                                            closestAuthorityNode = currentNode;

                                            closestSubDomain = null; //clear previous closest sub domain
                                            closestSubDomainNode = null;
                                        }
                                    }

                                    return value.Value; //found matching wildcard value
                                }
                            }
                        }
                    }
                }
                else
                {
                    //match wildcard keys
                    if (KeysMatch(value.Key, key, true))
                    {
                        //find closest values
                        TNode zoneNode = value.Value;
                        if (zoneNode is not null)
                        {
                            GetClosestValuesForZone(zoneNode, out TSubDomainZone subDomain, out TSubDomainZone delegation, out TApexZone authority);

                            if (subDomain is not null)
                            {
                                closestSubDomain = subDomain;
                                closestSubDomainNode = currentNode;
                            }

                            if (delegation is not null)
                                closestDelegation = delegation;

                            if (authority is not null)
                            {
                                closestAuthority = authority;
                                closestAuthorityNode = currentNode;

                                closestSubDomain = null; //clear previous closest sub domain
                                closestSubDomainNode = null;
                            }
                        }

                        return value.Value; //found matching wildcard value
                    }
                }
            }

            //value not found
            return null;
        }

        protected abstract void GetClosestValuesForZone(TNode zoneValue, out TSubDomainZone closestSubDomain, out TSubDomainZone closestDelegation, out TApexZone closestAuthority);

        #endregion

        #region public

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            byte[] bKey = ConvertToByteKey(domain);

            _ = _root.FindNodeValue(bKey, out Node currentNode);
            Node current = currentNode;
            NodeValue value;

            do
            {
                value = current.Value;
                if (value is not null)
                {
                    if (IsKeySubDomain(bKey, value.Key, false))
                    {
                        string label = ConvertKeyToLabel(value.Key, bKey.Length);
                        if (label is not null)
                            subDomains.Add(label);
                    }
                }
                else if ((current.K == 0) && (current.Depth > currentNode.Depth)) //[.]
                {
                    byte[] nodeKey = GetNodeKey(current);
                    if (IsKeySubDomain(bKey, nodeKey, false))
                    {
                        string label = ConvertKeyToLabel(nodeKey, bKey.Length);
                        if (label is not null)
                            subDomains.Add(label);
                    }
                }

                current = GetNextChildZoneNode(current, currentNode.Depth);
            }
            while (current is not null);
        }

        #endregion
    }
}
