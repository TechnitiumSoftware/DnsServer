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

using System;
using System.Collections.Generic;
using System.Threading;

namespace DnsServerCore.Dns.Zones
{
    abstract class ZoneTree<TNode, TSubDomainZone, TApexZone> : DomainTree<TNode> where TNode : Zone where TSubDomainZone : Zone where TApexZone : Zone
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

        private static bool KeysMatch(byte[] key1, byte[] key2)
        {
            //com.example.*.
            //com.example.*.www.
            //com.example.abc.www.

            int i = 0;
            int j = 0;

            while ((i < key1.Length) && (j < key2.Length))
            {
                if (key1[i] == 1) //[*]
                {
                    if (i == key1.Length - 2)
                        return true;

                    //skip j to next label
                    while (j < key2.Length)
                    {
                        if (key2[j] == 0) //[.]
                            break;

                        j++;
                    }

                    i++;
                    continue;
                }

                if (key2[j] == 1) //[*]
                {
                    if (j == key2.Length - 2)
                        return true;

                    //skip i to next label
                    while (i < key1.Length)
                    {
                        if (key1[i] == 0) //[.]
                            break;

                        i++;
                    }

                    j++;
                    continue;
                }

                if (key1[i] != key2[j])
                    return false;

                i++;
                j++;
            }

            return (i == key1.Length) && (j == key2.Length);
        }

        #endregion

        #region protected

        protected static bool IsKeySubDomain(byte[] mainKey, byte[] testKey)
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
                        return true;

                    //skip j to next label
                    while (j < testKey.Length)
                    {
                        if (testKey[j] == 0) //[.]
                            break;

                        j++;
                    }

                    i++;
                    continue;
                }

                if (mainKey[i] != testKey[j])
                    return false;

                i++;
                j++;
            }

            return (i == mainKey.Length) && (j < testKey.Length);
        }

        protected TNode FindZone(byte[] key, out Node closestNode, out Node closestAuthorityNode, out TSubDomainZone closestSubDomain, out TSubDomainZone closestDelegation, out TApexZone closestAuthority)
        {
            closestNode = _root;
            closestAuthorityNode = null;
            closestSubDomain = null;
            closestDelegation = null;
            closestAuthority = null;

            Node wildcard = null;
            int i = 0;

            while (i <= key.Length)
            {
                //find authority zone
                NodeValue value = closestNode.Value;
                if (value is not null)
                {
                    TNode zoneValue = value.Value;
                    if ((zoneValue is not null) && IsKeySubDomain(value.Key, key))
                    {
                        TApexZone authority = null;

                        GetClosestValuesForZone(zoneValue, ref closestSubDomain, ref closestDelegation, ref authority);

                        if (authority is not null)
                        {
                            closestAuthority = authority;
                            closestAuthorityNode = closestNode;
                        }
                    }
                }

                if (i == key.Length)
                    break;

                Node[] children = closestNode.Children;
                if (children is null)
                    break;

                Node child = Volatile.Read(ref children[1]); //[*]
                if (child is not null)
                    wildcard = child;

                child = Volatile.Read(ref children[key[i]]);
                if (child is null)
                {
                    //no child found
                    if (wildcard is null)
                        return null; //no child or wildcard found

                    //use wildcard node
                    //skip to next label
                    while (++i < key.Length)
                    {
                        if (key[i] == 0) //[.]
                            break;
                    }

                    closestNode = wildcard;
                    wildcard = null;
                    continue;
                }

                closestNode = child;
                i++;
            }

            {
                NodeValue value = closestNode.Value;
                if (value is not null)
                {
                    //match exact + wildcard keys
                    if (KeysMatch(key, value.Key))
                        return value.Value; //found matching value
                }
            }

            if (wildcard is not null)
            {
                //wildcard node found
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
                                if (KeysMatch(key, value.Key))
                                    return value.Value; //found matching wildcard value
                            }
                        }
                    }
                }
                else
                {
                    //match wildcard keys
                    if (KeysMatch(key, value.Key))
                        return value.Value; //found matching wildcard value
                }
            }

            //value not found
            return null;
        }

        protected abstract void GetClosestValuesForZone(TNode zoneValue, ref TSubDomainZone closestSubDomain, ref TSubDomainZone closestDelegation, ref TApexZone closestAuthority);

        #endregion

        #region public

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            if (domain is null)
                throw new ArgumentNullException(nameof(domain));

            byte[] bKey = ConvertToByteKey(domain);

            _ = _root.FindNodeValue(bKey, out Node closestNode);
            Node current = closestNode;
            NodeValue value;

            do
            {
                value = current.Value;
                if (value is not null)
                {
                    if (IsKeySubDomain(bKey, value.Key))
                    {
                        string label = ConvertKeyToLabel(value.Key, bKey.Length);
                        if (label is not null)
                            subDomains.Add(label);
                    }
                }
                else if ((current.K == 0) && (current.Depth > closestNode.Depth)) //[.]
                {
                    byte[] nodeKey = GetNodeKey(current);
                    if (IsKeySubDomain(bKey, nodeKey))
                    {
                        string label = ConvertKeyToLabel(nodeKey, bKey.Length);
                        if (label is not null)
                            subDomains.Add(label);
                    }
                }

                current = GetNextChildZoneNode(current, closestNode.Depth);
            }
            while (current is not null);
        }

        #endregion
    }
}
