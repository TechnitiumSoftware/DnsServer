/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net;

namespace DnsServerCore.Dns.Security
{
    /// <summary>
    /// An immutable, allocation-free IP address containment matcher compiled from a set of
    /// network prefixes. Originally built for the UDP response-rate-limiter bypass list; the
    /// matcher itself has no rate-limiting dependency and is general-purpose CIDR containment.
    /// </summary>
    public sealed class NetworkPrefixMatcher
    {
        const int IPV4_BIT_WIDTH = 32;
        const int IPV4_BYTE_WIDTH = 4;
        const int IPV6_BIT_WIDTH = 128;
        const int IPV6_BYTE_WIDTH = 16;
        const byte IPV4_MAPPED_PREFIX_LENGTH = IPV6_BIT_WIDTH - IPV4_BIT_WIDTH;

        public static readonly NetworkPrefixMatcher Empty = new NetworkPrefixMatcher(Array.Empty<Node>(), Array.Empty<Node>());

        readonly Node[] _ipv4Nodes;
        readonly Node[] _ipv6Nodes;

        private NetworkPrefixMatcher(Node[] ipv4Nodes, Node[] ipv6Nodes)
        {
            _ipv4Nodes = ipv4Nodes;
            _ipv6Nodes = ipv6Nodes;
        }

        /// <summary>
        /// Compiles normalized network prefixes into separate immutable IPv4 and IPv6 radix
        /// trees. IPv4-mapped IPv6 prefixes are represented as IPv4 prefixes, duplicate and
        /// contained prefixes are omitted, and a lookup succeeds when any stored prefix
        /// contains the normalized address. Since this is a Boolean containment matcher rather
        /// than a route selector, a more-specific (longest) prefix cannot change the result and
        /// the first containing prefix ends the radix walk.
        /// </summary>
        public static NetworkPrefixMatcher Create(IReadOnlyCollection<NetworkAddress> networks, out ImmutableArray<NetworkAddress> normalizedNetworks)
        {
            if ((networks is null) || (networks.Count == 0))
            {
                normalizedNetworks = ImmutableArray<NetworkAddress>.Empty;
                return Empty;
            }

            NetworkAddress[] candidates = new NetworkAddress[networks.Count];
            int candidateIndex = 0;
            foreach (NetworkAddress network in networks)
                candidates[candidateIndex++] = NormalizeNetwork(network);

            Array.Sort(candidates, static (x, y) =>
            {
                int familyComparison = x.AddressFamily.CompareTo(y.AddressFamily);
                return familyComparison != 0 ? familyComparison : x.PrefixLength.CompareTo(y.PrefixLength);
            });

            TrieBuilder ipv4Builder = new TrieBuilder();
            TrieBuilder ipv6Builder = new TrieBuilder();
            ImmutableArray<NetworkAddress>.Builder normalizedBuilder = ImmutableArray.CreateBuilder<NetworkAddress>(candidates.Length);
            foreach (NetworkAddress network in candidates)
            {
                byte[] bytes = network.Address.GetAddressBytes();
                TrieBuilder builder = network.AddressFamily == AddressFamily.InterNetwork ? ipv4Builder : ipv6Builder;
                if (builder.Add(bytes, network.PrefixLength))
                    normalizedBuilder.Add(network);
            }

            normalizedNetworks = normalizedBuilder.MoveToImmutable();
            return new NetworkPrefixMatcher(ipv4Builder.ToArray(), ipv6Builder.ToArray());
        }

        /// <summary>
        /// Tests prefix containment without allocations. IPv4-mapped IPv6 addresses are
        /// normalized to IPv4 before selecting a tree; traversal is bounded by 32 bits for
        /// IPv4 and 128 bits for IPv6.
        /// </summary>
        public bool IsMatch(IPAddress address)
        {
            if (address.IsIPv4MappedToIPv6)
            {
                Span<byte> mappedBytes = stackalloc byte[IPV6_BYTE_WIDTH];
                return address.TryWriteBytes(mappedBytes, out int bytesWritten) && (bytesWritten == IPV6_BYTE_WIDTH) &&
                    IsMatch(_ipv4Nodes, mappedBytes.Slice(IPV4_MAPPED_PREFIX_LENGTH / 8), IPV4_BIT_WIDTH);
            }

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                Span<byte> bytes = stackalloc byte[IPV4_BYTE_WIDTH];
                return address.TryWriteBytes(bytes, out int bytesWritten) && (bytesWritten == IPV4_BYTE_WIDTH) && IsMatch(_ipv4Nodes, bytes, IPV4_BIT_WIDTH);
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Span<byte> bytes = stackalloc byte[IPV6_BYTE_WIDTH];
                return address.TryWriteBytes(bytes, out int bytesWritten) && (bytesWritten == IPV6_BYTE_WIDTH) && IsMatch(_ipv6Nodes, bytes, IPV6_BIT_WIDTH);
            }

            return false;
        }

        private static NetworkAddress NormalizeNetwork(NetworkAddress network)
        {
            IPAddress address = network.Address;
            byte prefixLength = network.PrefixLength;
            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
                prefixLength = (byte)Math.Max(0, prefixLength - IPV4_MAPPED_PREFIX_LENGTH);
            }

            return new NetworkAddress(address, prefixLength);
        }

        private static bool IsMatch(Node[] nodes, ReadOnlySpan<byte> address, int bitWidth)
        {
            if (nodes.Length == 0)
                return false;

            int nodeIndex = 0;
            for (int bitIndex = 0; bitIndex < bitWidth; bitIndex++)
            {
                Node node = nodes[nodeIndex];
                if (node.IsPrefix)
                    return true;

                int bit = (address[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1;
                nodeIndex = bit == 0 ? node.Zero : node.One;
                if (nodeIndex < 0)
                    return false;
            }

            return nodes[nodeIndex].IsPrefix;
        }

        private readonly struct Node
        {
            public Node(int zero, int one, bool isPrefix)
            {
                Zero = zero;
                One = one;
                IsPrefix = isPrefix;
            }

            public int Zero { get; }
            public int One { get; }
            public bool IsPrefix { get; }
        }

        private sealed class TrieBuilder
        {
            readonly List<Node> _nodes = new List<Node>();

            public bool Add(ReadOnlySpan<byte> address, int prefixLength)
            {
                if (_nodes.Count == 0)
                    _nodes.Add(new Node(-1, -1, false));

                int nodeIndex = 0;
                for (int bitIndex = 0; bitIndex < prefixLength; bitIndex++)
                {
                    Node node = _nodes[nodeIndex];
                    if (node.IsPrefix)
                        return false;

                    int bit = (address[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1;
                    int childIndex = bit == 0 ? node.Zero : node.One;
                    if (childIndex < 0)
                    {
                        childIndex = _nodes.Count;
                        _nodes.Add(new Node(-1, -1, false));
                        _nodes[nodeIndex] = bit == 0
                            ? new Node(childIndex, node.One, false)
                            : new Node(node.Zero, childIndex, false);
                    }

                    nodeIndex = childIndex;
                }

                if (_nodes[nodeIndex].IsPrefix)
                    return false;

                _nodes[nodeIndex] = new Node(-1, -1, true);
                return true;
            }

            public Node[] ToArray() => _nodes.ToArray();
        }
    }
}
