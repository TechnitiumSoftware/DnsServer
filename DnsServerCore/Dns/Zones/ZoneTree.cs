using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using TechnitiumLibrary.ByteTree;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns.Zones
{
    public class ZoneTree<T> : ByteTree<string, T> where T : Zone
    {
        #region variables

        readonly static byte[] _keyMap;
        readonly static byte[] _reverseKeyMap;

        #endregion

        #region constructor

        static ZoneTree()
        {
            _keyMap = new byte[256];
            _reverseKeyMap = new byte[40];

            for (int i = 0; i < _keyMap.Length; i++)
            {
                if ((i >= 97) && (i <= 122)) //[a-z]
                {
                    _keyMap[i] = (byte)(i - 97);
                    _reverseKeyMap[_keyMap[i]] = (byte)i;
                }
                else if ((i >= 65) && (i <= 90)) //[a-z]
                {
                    _keyMap[i] = (byte)(i - 65);
                    _reverseKeyMap[_keyMap[i]] = (byte)i;
                }
                else if ((i >= 48) && (i <= 57)) //[0-9]
                {
                    _keyMap[i] = (byte)(26 + i - 48);
                    _reverseKeyMap[_keyMap[i]] = (byte)i;
                }
                else if (i == 45) //[-]
                {
                    _keyMap[i] = 36;
                    _reverseKeyMap[36] = 45;
                }
                else if (i == 95) //[_]
                {
                    _keyMap[i] = 37;
                    _reverseKeyMap[37] = 95;
                }
                else if (i == 42) //[*]
                {
                    _keyMap[i] = 0xff; //skipped value 38 for optimization
                    _reverseKeyMap[38] = 42;
                }
                else if (i == 46) //[.]
                {
                    _keyMap[i] = 39;
                    _reverseKeyMap[39] = 46;
                }
                else
                {
                    _keyMap[i] = 0xff;
                }
            }
        }

        public ZoneTree()
            : base(40)
        { }

        #endregion

        #region protected

        protected override byte[] ConvertToByteKey(string domain)
        {
            if (domain == null)
                throw new ArgumentNullException(nameof(domain));

            if (domain.Length == 0)
                return Array.Empty<byte>();

            if (domain.Length > 255)
                throw new DnsClientException("Invalid domain name [" + domain + "]: length cannot exceed 255 bytes.");

            byte[] key = new byte[domain.Length + 1];
            int keyOffset = 0;
            int labelStart;
            int labelEnd = domain.Length - 1;
            int labelLength;
            int labelChar;
            byte labelKeyCode;
            int i;

            do
            {
                if (labelEnd < 0)
                    labelEnd = 0;

                labelStart = domain.LastIndexOf('.', labelEnd);
                labelLength = labelEnd - labelStart;

                if (labelLength == 0)
                    throw new DnsClientException("Invalid domain name [" + domain + "]: label length cannot be 0 byte.");

                if (labelLength > 63)
                    throw new DnsClientException("Invalid domain name [" + domain + "]: label length cannot exceed 63 bytes.");

                if (domain[labelStart + 1] == '-')
                    throw new DnsClientException("Invalid domain name [" + domain + "]: label cannot start with hyphen.");

                if (domain[labelEnd] == '-')
                    throw new DnsClientException("Invalid domain name [" + domain + "]: label cannot end with hyphen.");

                if ((labelLength == 1) && (domain[labelStart + 1] == '*'))
                {
                    key[keyOffset++] = 38;
                }
                else
                {
                    for (i = labelStart + 1; i <= labelEnd; i++)
                    {
                        labelChar = domain[i];
                        if (labelChar >= _keyMap.Length)
                            throw new DnsClientException("Invalid domain name [" + domain + "]: invalid character [" + labelChar + "] was found.");

                        labelKeyCode = _keyMap[labelChar];
                        if (labelKeyCode == 0xff)
                            throw new DnsClientException("Invalid domain name [" + domain + "]: invalid character [" + labelChar + "] was found.");

                        key[keyOffset++] = labelKeyCode;
                    }
                }

                key[keyOffset++] = 39;
                labelEnd = labelStart - 1;
            }
            while (labelStart > -1);

            return key;
        }

        #endregion

        #region private

        private static string ConvertKeyToLabel(byte[] key, int startIndex)
        {
            byte[] domain = new byte[key.Length - startIndex];
            int i;
            int k;

            for (i = 0; i < domain.Length; i++)
            {
                k = key[i + startIndex];
                if (k == 39)
                    break;

                domain[i] = _reverseKeyMap[k];
            }

            return Encoding.ASCII.GetString(domain, 0, i);
        }

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
                                if ((zone != null) && (zone is SubDomainZone))
                                    return child; //child has value so return it
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

        private Node GetNextSubDomainNode(Node current, int baseDepth)
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

            while (i < key.Length)
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
                            if ((zoneValue is PrimaryZone) || (zoneValue is SecondaryZone) || (zoneValue is StubZone))
                            {
                                //hosted primary/secondary/stub zone found
                                closestDelegation = null;
                                closestAuthority = value;
                            }
                            else if ((zoneValue is SubDomainZone) && (closestDelegation == null) && zoneValue.ContainsNameServerRecords())
                            {
                                //delegated sub domain found
                                closestDelegation = value;
                            }
                        }
                        else if ((zoneValue is CacheZone) && zoneValue.ContainsNameServerRecords())
                        {
                            closestDelegation = value;
                        }
                    }
                }

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

        #endregion

        #region public

        public bool TryAdd(T zone)
        {
            return TryAdd(zone.Name, zone);
        }

        public new bool TryRemove(string domain, out T value)
        {
            byte[] bKey = ConvertToByteKey(domain);

            Node closestNode = FindClosestNode(bKey);
            NodeValue removedValue = closestNode.RemoveValue(bKey);
            if (removedValue == null)
            {
                value = default;
                return false;
            }

            value = removedValue.Value;

            if ((value != null) && !(value is SubDomainZone))
            {
                //remove all sub domain or cache zones
                Node current = closestNode;

                while (true)
                {
                    current = current.GetNextNodeWithValue(closestNode.Depth);
                    if (current == null)
                        break;

                    NodeValue v = current.Value;
                    if (v != null)
                    {
                        T zone = v.Value;
                        if ((zone != null) && ((zone is SubDomainZone) || (zone is CacheZone)))
                        {
                            current.RemoveValue(v.Key); //remove node value
                            current.CleanUp();
                        }
                    }
                }
            }

            closestNode.CleanUp();

            return true;
        }

        public List<T> GetZoneWithSubDomainZones(string domain)
        {
            List<T> zones = new List<T>();

            byte[] bKey = ConvertToByteKey(domain);
            Node closestNode = FindClosestNode(bKey);
            NodeValue nodeValue = closestNode.GetValue(bKey);
            if (nodeValue != null)
            {
                T zone = nodeValue.Value;
                if (zone != null)
                {
                    if ((zone is PrimaryZone) || (zone is SecondaryZone))
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
                    else if (zone is StubZone)
                    {
                        zones.Add(zone);
                    }
                }
            }

            return zones;
        }

        public List<string> ListSubDomains(string domain)
        {
            List<string> zones = new List<string>();

            byte[] bKey = ConvertToByteKey(domain);
            Node closestNode = FindClosestNode(bKey);
            Node current = closestNode;
            NodeValue value;

            do
            {
                value = current.Value;
                if (value != null)
                {
                    if (bKey.Length < value.Key.Length)
                        zones.Add(ConvertKeyToLabel(value.Key, bKey.Length));
                }
                else if ((current.K == 39) && (current.Depth > closestNode.Depth))
                {
                    zones.Add(ConvertKeyToLabel(GetNodeKey(current), bKey.Length));
                }

                current = GetNextSubDomainNode(current, closestNode.Depth);
            }
            while (current != null);

            return zones;
        }

        public T FindZone(string domain, out T delegation, out T authority, out bool hasSubDomains)
        {
            byte[] key = ConvertToByteKey(domain);

            NodeValue nodeValue = FindNodeValue(key, out Node closestNode, out NodeValue closestDelegation, out NodeValue closestAuthority);
            if (nodeValue == null)
            {
                //zone not found
                if ((closestDelegation != null) && IsKeySubDomain(closestDelegation.Key, key))
                    delegation = closestDelegation.Value;
                else
                    delegation = null;

                if ((closestAuthority != null) && IsKeySubDomain(closestAuthority.Key, key))
                    authority = closestAuthority.Value;
                else
                    authority = null;

                //check if current node has sub domains
                NodeValue value = closestNode.Value;
                if (value == null)
                    hasSubDomains = closestNode.Children != null;
                else
                    hasSubDomains = IsKeySubDomain(key, value.Key);

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
            if ((zoneValue is SubDomainZone) && zoneValue.ContainsNameServerRecords())
                delegation = zoneValue;
            else if ((zoneValue is CacheZone) && zoneValue.ContainsNameServerRecords())
                delegation = zoneValue;
            else if ((closestDelegation != null) && IsKeySubDomain(closestDelegation.Key, key))
                delegation = closestDelegation.Value;
            else
                delegation = null;

            if ((zoneValue is PrimaryZone) || (zoneValue is SecondaryZone) || (zoneValue is StubZone))
                authority = zoneValue;
            else if ((closestAuthority != null) && IsKeySubDomain(closestAuthority.Key, key))
                authority = closestAuthority.Value;
            else
                authority = null;

            hasSubDomains = closestNode.Children != null;
            return zoneValue;
        }

        #endregion
    }
}
