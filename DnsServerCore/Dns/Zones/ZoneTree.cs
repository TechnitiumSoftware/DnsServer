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

using System;
using System.Collections.Generic;
using System.Threading;

namespace DnsServerCore.Dns.Zones
{
    class ZoneTree<T> : DomainTree<T> where T : Zone
    {
        #region private

        private Node GetNextSubDomainZoneNode(Node current, int baseDepth)
        {
            int k = 0;

            while ((current != null) && (current.Depth >= baseDepth))
            {
                Node[] children = current.Children;
                if (children != null)
                {
                    //find child node
                    Node child = null;

                    for (int i = k; i < children.Length; i++)
                    {
                        child = Volatile.Read(ref children[i]);
                        if (child != null)
                        {
                            NodeValue value = child.Value;
                            if (value != null)
                            {
                                T zone = value.Value;
                                if (zone != null)
                                {
                                    if (zone is SubDomainZone)
                                        return child; //child has value so return it

                                    if ((zone is PrimaryZone) || (zone is SecondaryZone) || (zone is StubZone) || (zone is ForwarderZone))
                                    {
                                        //skip to next child to avoid listing this auth zone's sub domains
                                        child = null; //set null to avoid child being set as current after the loop
                                        continue;
                                    }
                                }
                            }

                            if (child.Children != null)
                                break;
                        }
                    }

                    if (child != null)
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

        private Node GetNextChildZoneNode(Node current, int baseDepth)
        {
            int k = 0;

            while ((current != null) && (current.Depth >= baseDepth))
            {
                if ((current.K != 39) || (current.Depth == baseDepth)) //[.] skip this node's children as its last for current sub zone
                {
                    Node[] children = current.Children;
                    if (children != null)
                    {
                        //find child node
                        Node child = null;

                        for (int i = k; i < children.Length; i++)
                        {
                            child = Volatile.Read(ref children[i]);
                            if (child != null)
                            {
                                if (child.Value != null)
                                    return child; //child has value so return it

                                if (child.K == 39) //[.]
                                    return child; //child node is last for current sub zone

                                if (child.Children != null)
                                    break;
                            }
                        }

                        if (child != null)
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

        private byte[] GetNodeKey(Node node)
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
                if (key1[i] == 38) //[*]
                {
                    if (i == key1.Length - 2)
                        return true;

                    //skip j to next label
                    while (j < key2.Length)
                    {
                        if (key2[j] == 39) //[.]
                            break;

                        j++;
                    }

                    i++;
                    continue;
                }

                if (key2[j] == 38) //[*]
                {
                    if (j == key2.Length - 2)
                        return true;

                    //skip i to next label
                    while (i < key1.Length)
                    {
                        if (key1[i] == 39) //[.]
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

        private static bool IsKeySubDomain(byte[] mainKey, byte[] testKey)
        {
            //com.example.*.
            //com.example.*.www.
            //com.example.abc.www.

            int i = 0;
            int j = 0;

            while ((i < mainKey.Length) && (j < testKey.Length))
            {
                if (mainKey[i] == 38) //[*]
                {
                    if (i == mainKey.Length - 2)
                        return true;

                    //skip j to next label
                    while (j < testKey.Length)
                    {
                        if (testKey[j] == 39) //[.]
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

        private NodeValue FindNodeValue(byte[] key, out Node closestNode, out NodeValue closestDelegation, out NodeValue closestAuthority)
        {
            closestNode = _root;
            closestDelegation = null;
            closestAuthority = null;

            Node wildcard = null;
            int i = 0;

            while (i <= key.Length)
            {
                //find authority zone
                NodeValue value = closestNode.Value;
                if (value != null)
                {
                    T zoneValue = value.Value;
                    if (zoneValue != null)
                    {
                        if (zoneValue is AuthZone)
                        {
                            if ((zoneValue is PrimaryZone) || (zoneValue is SecondaryZone) || (zoneValue is StubZone) || (zoneValue is ForwarderZone))
                            {
                                if (IsKeySubDomain(value.Key, key))
                                {
                                    //hosted primary/secondary/stub/forwarder zone found
                                    closestDelegation = null;
                                    closestAuthority = value;
                                }
                            }
                            else if ((zoneValue is SubDomainZone) && (closestDelegation == null) && zoneValue.ContainsNameServerRecords())
                            {
                                if (IsKeySubDomain(value.Key, key))
                                {
                                    //delegated sub domain found
                                    closestDelegation = value;
                                }
                            }
                        }
                        else if ((zoneValue is CacheZone) && zoneValue.ContainsNameServerRecords())
                        {
                            if (IsKeySubDomain(value.Key, key))
                            {
                                closestDelegation = value;
                            }
                        }
                    }
                }

                if (i == key.Length)
                    break;

                Node[] children = closestNode.Children;
                if (children == null)
                    break;

                Node child = Volatile.Read(ref children[38]); //[*]
                if (child != null)
                    wildcard = child;

                child = Volatile.Read(ref children[key[i]]);
                if (child == null)
                {
                    //no child found
                    if (wildcard == null)
                        return null; //no child or wildcard found

                    //use wildcard node
                    //skip to next label
                    do
                    {
                        i++;
                        if (key[i] == 39) //[.]
                            break;
                    }
                    while (i < key.Length);

                    closestNode = wildcard;
                    wildcard = null;
                    continue;
                }

                closestNode = child;
                i++;
            }

            {
                NodeValue value = closestNode.Value;
                if (value != null)
                {
                    //match exact + wildcard keys
                    if (KeysMatch(key, value.Key))
                        return value; //found matching value
                }
            }

            if (wildcard != null)
            {
                //wildcard node found
                NodeValue value = wildcard.Value;
                if (value == null)
                {
                    //find value from next [.] node
                    Node[] children = wildcard.Children;
                    if (children != null)
                    {
                        Node child = Volatile.Read(ref children[39]); //[.]
                        if (child != null)
                        {
                            value = child.Value;
                            if (value != null)
                            {
                                //match wildcard keys
                                if (KeysMatch(key, value.Key))
                                    return value; //found matching wildcard value
                            }
                        }
                    }
                }
                else
                {
                    //match wildcard keys
                    if (KeysMatch(key, value.Key))
                        return value; //found matching wildcard value
                }
            }

            //value not found
            return null;
        }

        private bool SubDomainExists(byte[] key, Node closestNode)
        {
            if (!closestNode.HasChildren)
                return false;

            Node nextSubDomain = GetNextSubDomainZoneNode(closestNode, closestNode.Depth);
            if (nextSubDomain == null)
                return false;

            NodeValue value = nextSubDomain.Value;
            if (value == null)
                return false;

            return IsKeySubDomain(key, value.Key);
        }

        #endregion

        #region public

        public bool TryAdd(T zone)
        {
            return TryAdd(zone.Name, zone);
        }

        public override bool TryRemove(string domain, out T value)
        {
            if (typeof(T) == typeof(CacheZone))
            {
                bool removed = TryRemove(domain, out value, out Node closestNode);

                //remove all cache zones under current zone
                Node current = closestNode;

                do
                {
                    current = current.GetNextNodeWithValue(closestNode.Depth);
                    if (current == null)
                        break;

                    NodeValue v = current.Value;
                    if (v != null)
                    {
                        T zone = v.Value;
                        if (zone != null)
                        {
                            current.RemoveNodeValue(v.Key, out _); //remove node value
                            current.CleanThisBranch();
                            removed = true;
                        }
                    }
                }
                while (true);

                if (removed)
                    closestNode.CleanThisBranch();

                return removed;
            }
            else
            {
                if (TryRemove(domain, out value, out Node closestNode))
                {
                    if ((value != null) && ((value is PrimaryZone) || (value is SecondaryZone) || (value is StubZone) || (value is ForwarderZone)))
                    {
                        //remove all sub domains under current zone
                        Node current = closestNode;

                        do
                        {
                            current = GetNextSubDomainZoneNode(current, closestNode.Depth);
                            if (current == null)
                                break;

                            NodeValue v = current.Value;
                            if (v != null)
                            {
                                T zone = v.Value;
                                if (zone != null)
                                {
                                    current.RemoveNodeValue(v.Key, out _); //remove node value
                                    current.CleanThisBranch();
                                }
                            }
                        }
                        while (true);
                    }

                    closestNode.CleanThisBranch();
                    return true;
                }

                return false;
            }
        }

        public List<T> GetZoneWithSubDomainZones(string domain)
        {
            if (domain == null)
                throw new ArgumentNullException(nameof(domain));

            List<T> zones = new List<T>();

            byte[] bKey = ConvertToByteKey(domain);

            NodeValue nodeValue = _root.FindNodeValue(bKey, out Node closestNode);
            if (nodeValue != null)
            {
                T zone = nodeValue.Value;
                if (zone != null)
                {
                    if ((zone is PrimaryZone) || (zone is SecondaryZone) || (zone is StubZone) || (zone is ForwarderZone))
                    {
                        zones.Add(zone);

                        Node current = closestNode;

                        do
                        {
                            current = GetNextSubDomainZoneNode(current, closestNode.Depth);
                            if (current == null)
                                break;

                            NodeValue value = current.Value;
                            if (value != null)
                            {
                                zone = value.Value;
                                if (zone != null)
                                    zones.Add(zone);
                            }
                        }
                        while (true);
                    }
                }
            }

            return zones;
        }

        public List<string> ListSubDomains(string domain)
        {
            if (domain == null)
                throw new ArgumentNullException(nameof(domain));

            List<string> subDomains = new List<string>();

            byte[] bKey = ConvertToByteKey(domain);

            _ = _root.FindNodeValue(bKey, out Node closestNode);
            Node current = closestNode;
            NodeValue value;

            do
            {
                value = current.Value;
                if (value != null)
                {
                    if (IsKeySubDomain(bKey, value.Key))
                    {
                        string label = ConvertKeyToLabel(value.Key, bKey.Length);
                        if (label != null)
                            subDomains.Add(label);
                    }
                }
                else if ((current.K == 39) && (current.Depth > closestNode.Depth))
                {
                    byte[] nodeKey = GetNodeKey(current);
                    if (IsKeySubDomain(bKey, nodeKey))
                    {
                        string label = ConvertKeyToLabel(nodeKey, bKey.Length);
                        if (label != null)
                            subDomains.Add(label);
                    }
                }

                current = GetNextChildZoneNode(current, closestNode.Depth);
            }
            while (current != null);

            return subDomains;
        }

        public T FindZone(string domain, out T delegation, out T authority, out bool hasSubDomains)
        {
            if (domain == null)
                throw new ArgumentNullException(nameof(domain));

            byte[] key = ConvertToByteKey(domain);

            NodeValue nodeValue = FindNodeValue(key, out Node closestNode, out NodeValue closestDelegation, out NodeValue closestAuthority);
            if (nodeValue == null)
            {
                //zone not found
                if (closestDelegation != null)
                    delegation = closestDelegation.Value;
                else
                    delegation = null;

                if (closestAuthority != null)
                    authority = closestAuthority.Value;
                else
                    authority = null;

                if (authority == null)
                {
                    //no authority so no subdomains
                    hasSubDomains = false;
                }
                else
                {
                    //check if current node has sub domains
                    NodeValue value = closestNode.Value;
                    if (value == null)
                        hasSubDomains = SubDomainExists(key, closestNode);
                    else
                        hasSubDomains = IsKeySubDomain(key, value.Key);
                }

                return null;
            }

            T zoneValue = nodeValue.Value;
            if (zoneValue == null)
            {
                //zone value missing!
                delegation = null;
                authority = null;
                hasSubDomains = false;
                return null;
            }

            //zone found
            if (zoneValue is AuthZone)
            {
                if ((zoneValue is PrimaryZone) || (zoneValue is SecondaryZone) || (zoneValue is StubZone) || (zoneValue is ForwarderZone))
                {
                    delegation = null;
                    authority = zoneValue;
                }
                else
                {
                    if (closestDelegation != null)
                        delegation = closestDelegation.Value;
                    else if ((zoneValue is SubDomainZone) && zoneValue.ContainsNameServerRecords())
                        delegation = zoneValue;
                    else
                        delegation = null;

                    if (closestAuthority != null)
                        authority = closestAuthority.Value;
                    else
                        authority = null;
                }

                hasSubDomains = SubDomainExists(key, closestNode);
            }
            else if (zoneValue is CacheZone)
            {
                if (zoneValue.ContainsNameServerRecords())
                    delegation = zoneValue;
                else if (closestDelegation != null)
                    delegation = closestDelegation.Value;
                else
                    delegation = null;

                authority = null; //cache does not use this value
                hasSubDomains = false; //cache does not use this value
            }
            else
            {
                throw new InvalidOperationException();
            }

            return zoneValue;
        }

        #endregion
    }
}
