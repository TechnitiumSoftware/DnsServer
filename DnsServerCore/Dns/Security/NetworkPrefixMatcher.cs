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
    /// An immutable IP address containment matcher compiled from a set of network prefixes.
    /// Originally built for the UDP response-rate-limiter bypass list; the matcher itself has no
    /// rate-limiting dependency and is general-purpose CIDR containment. Lookups (<see
    /// cref="IsMatch"/>) are allocation-free; building a matcher (<see cref="Create"/>) is not.
    /// </summary>
    /// <remarks>
    /// An instance is fully built before it is returned from <see cref="Create"/> and never
    /// mutated afterward, so concurrent lookups need no lock. That safety depends on how a holder
    /// publishes and reads the reference: publish with <c>Volatile.Write</c> (or a <c>volatile</c>
    /// field), and read it into a local exactly once per decision with <c>Volatile.Read</c> before
    /// calling <see cref="IsMatch"/> -- a plain field write is not guaranteed visible to other
    /// threads under a weak memory model, and reading the field twice during one decision can
    /// observe two different published instances if a concurrent rebuild lands in between.
    /// <see cref="DnsResponseRateLimiterRuntime.Evaluate"/> is the current example of this
    /// contract.
    /// </remarks>
    public sealed class NetworkPrefixMatcher
    {
        const int IPV4_BIT_WIDTH = 32;
        const int IPV4_BYTE_WIDTH = 4;
        const int IPV6_BIT_WIDTH = 128;
        const int IPV6_BYTE_WIDTH = 16;
        const byte IPV4_MAPPED_PREFIX_LENGTH = IPV6_BIT_WIDTH - IPV4_BIT_WIDTH;

        // ::ffff:0:0/96, as bytes. A stored IPv6 prefix can ever match an IPv4-mapped probe
        // address only if the prefix itself is a prefix of this range (see ContainsIPv4MappedRange).
        static readonly byte[] IPV4_MAPPED_PREFIX_BYTES = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };

        public static readonly NetworkPrefixMatcher Empty = new NetworkPrefixMatcher(Array.Empty<Node>(), Array.Empty<Node>(), false);

        readonly Node[] _ipv4Nodes;
        readonly Node[] _ipv6Nodes;
        readonly bool _isEmpty;

        // Whether any stored IPv6 prefix could contain an IPv4-mapped address. False for every
        // configuration that stores no IPv6 prefix shorter than /96 aligned with ::ffff:0:0/96 --
        // which is the overwhelming majority of bypass lists -- so a mapped-address lookup can
        // skip the second (IPv6 tree) walk entirely instead of performing it on every query.
        readonly bool _ipv6MayContainMapped;

        private NetworkPrefixMatcher(Node[] ipv4Nodes, Node[] ipv6Nodes, bool ipv6MayContainMapped)
        {
            _ipv4Nodes = ipv4Nodes;
            _ipv6Nodes = ipv6Nodes;
            _isEmpty = (ipv4Nodes.Length == 0) && (ipv6Nodes.Length == 0);
            _ipv6MayContainMapped = ipv6MayContainMapped;
        }

        /// <summary>
        /// Compiles normalized network prefixes into separate immutable IPv4 and IPv6 binary
        /// tries (unlike a radix/PATRICIA tree, there is no path compression). IPv4-mapped IPv6
        /// prefixes of /96 or shorter are represented as IPv4 prefixes; shorter IPv6 prefixes that
        /// happen to be mapped-range-aligned are kept as IPv6 prefixes, since collapsing them to
        /// IPv4 would silently widen what they match (see <see cref="NormalizeNetwork"/>).
        /// Duplicate and already-contained prefixes are omitted, and a lookup succeeds when any
        /// stored prefix contains the normalized address. Since this is a Boolean containment
        /// matcher rather than a route selector, a more-specific (longest) prefix cannot change
        /// the result and the first containing prefix ends the walk.
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
                if (familyComparison != 0)
                    return familyComparison;

                int prefixComparison = x.PrefixLength.CompareTo(y.PrefixLength);
                if (prefixComparison != 0)
                    return prefixComparison;

                // Total tiebreak for equal family and prefix length. NetworkAddress masks host
                // bits at construction, so this compares network addresses only. Without it,
                // Array.Sort's unstable ordering of equal keys can vary the compiled trie's node
                // layout and normalizedNetworks' order from run to run for the same input set.
                return CompareAddressBytes(x.Address, y.Address);
            });

            // Sized to the worst case of one new trie node per prefix bit (no shared path
            // segments) plus a root, so TrieBuilder never needs to grow its backing list.
            int ipv4CapacityHint = 1;
            int ipv6CapacityHint = 1;
            foreach (NetworkAddress network in candidates)
            {
                if (network.AddressFamily == AddressFamily.InterNetwork)
                    ipv4CapacityHint += network.PrefixLength;
                else
                    ipv6CapacityHint += network.PrefixLength;
            }

            TrieBuilder ipv4Builder = new TrieBuilder(ipv4CapacityHint);
            TrieBuilder ipv6Builder = new TrieBuilder(ipv6CapacityHint);
            bool ipv6MayContainMapped = false;
            ImmutableArray<NetworkAddress>.Builder normalizedBuilder = ImmutableArray.CreateBuilder<NetworkAddress>(candidates.Length);
            foreach (NetworkAddress network in candidates)
            {
                bool isIPv4 = network.AddressFamily == AddressFamily.InterNetwork;
                ValidatePrefixLength(network, isIPv4 ? IPV4_BIT_WIDTH : IPV6_BIT_WIDTH);

                byte[] bytes = network.Address.GetAddressBytes();
                TrieBuilder builder = isIPv4 ? ipv4Builder : ipv6Builder;
                if (builder.Add(bytes, network.PrefixLength))
                {
                    normalizedBuilder.Add(network);

                    if (!isIPv4 && ContainsIPv4MappedRange(network))
                        ipv6MayContainMapped = true;
                }
            }

            // Add() returns false for a duplicate or already-contained prefix, so
            // normalizedBuilder.Count is routinely less than its initial Capacity;
            // MoveToImmutable() requires them equal.
            normalizedBuilder.Capacity = normalizedBuilder.Count;
            normalizedNetworks = normalizedBuilder.MoveToImmutable();
            return new NetworkPrefixMatcher(ipv4Builder.ToArray(), ipv6Builder.ToArray(), ipv6MayContainMapped);
        }

        /// <summary>
        /// Tests prefix containment without allocations. An empty matcher (the common case for
        /// the default configuration) returns false immediately. IPv4-mapped IPv6 addresses are
        /// tested against the IPv4 tree, and against the IPv6 tree too only when the compiled
        /// matcher actually stores a mapped-range-aligned IPv6 prefix; a native IPv4 address is
        /// never tested against IPv6 prefixes. Traversal is bounded by the depth of the deepest
        /// stored prefix that shares a path with the probe address, not by the address width --
        /// a matcher holding only /24s or shorter never walks more than 24 bits.
        /// </summary>
        public bool IsMatch(IPAddress address)
        {
            if (_isEmpty)
                return false;

            if (address.IsIPv4MappedToIPv6)
            {
                Span<byte> mappedBytes = stackalloc byte[IPV6_BYTE_WIDTH];
                if (!address.TryWriteBytes(mappedBytes, out int bytesWritten) || (bytesWritten != IPV6_BYTE_WIDTH))
                    return false;

                if (IsMatch(_ipv4Nodes, mappedBytes.Slice(IPV4_MAPPED_PREFIX_LENGTH / 8), IPV4_BIT_WIDTH))
                    return true;

                return _ipv6MayContainMapped && IsMatch(_ipv6Nodes, mappedBytes, IPV6_BIT_WIDTH);
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

        /// <summary>
        /// Maps an IPv4-mapped IPv6 prefix of /96 or shorter down to the IPv4 prefix it denotes.
        /// A shorter (broader) mapped-range-aligned prefix -- e.g. ::ffff:0:0/64 -- is left as an
        /// IPv6 prefix instead: collapsing it would silently turn a partial, malformed-looking
        /// configuration entry into "match all of IPv4", and would stop it from matching the IPv6
        /// addresses outside the mapped range that it also covers.
        /// </summary>
        private static NetworkAddress NormalizeNetwork(NetworkAddress network)
        {
            IPAddress address = network.Address;
            byte prefixLength = network.PrefixLength;
            if (address.IsIPv4MappedToIPv6 && (prefixLength >= IPV4_MAPPED_PREFIX_LENGTH))
            {
                address = address.MapToIPv4();
                prefixLength -= IPV4_MAPPED_PREFIX_LENGTH;
            }

            return new NetworkAddress(address, prefixLength);
        }

        /// <summary>
        /// NetworkAddress.GetNetworkAddress already throws ArgumentOutOfRangeException for a
        /// prefix length exceeding its address family's width at every NetworkAddress
        /// construction path, including the internal one used by ReadFrom/TryParse, so this
        /// should be unreachable. Guarded anyway (cheaply) so a violation -- from this type
        /// gaining a new construction path, or from a future caller of this class that doesn't
        /// go through NetworkAddress -- surfaces as a clear ArgumentException naming the network,
        /// not an IndexOutOfRangeException from deep inside the trie builder.
        /// </summary>
        private static void ValidatePrefixLength(NetworkAddress network, int bitWidth)
        {
            if (network.PrefixLength > bitWidth)
                throw new ArgumentException($"Network '{network}' has a prefix length longer than its address family's {bitWidth}-bit width.", nameof(network));
        }

        /// <summary>
        /// True when <paramref name="network"/> (already normalized: /96 or shorter, so it was
        /// not collapsed to IPv4 by <see cref="NormalizeNetwork"/>) is itself a prefix of
        /// ::ffff:0:0/96 -- meaning an IPv4-mapped probe address could fall inside it.
        /// </summary>
        private static bool ContainsIPv4MappedRange(NetworkAddress network)
        {
            if ((network.AddressFamily != AddressFamily.InterNetworkV6) || (network.PrefixLength > IPV4_MAPPED_PREFIX_LENGTH))
                return false;

            byte[] bytes = network.Address.GetAddressBytes();
            for (int bitIndex = 0; bitIndex < network.PrefixLength; bitIndex++)
            {
                int mask = 1 << (7 - (bitIndex & 7));
                if (((bytes[bitIndex >> 3] ^ IPV4_MAPPED_PREFIX_BYTES[bitIndex >> 3]) & mask) != 0)
                    return false;
            }

            return true;
        }

        private static int CompareAddressBytes(IPAddress x, IPAddress y)
        {
            Span<byte> xBytes = stackalloc byte[IPV6_BYTE_WIDTH];
            Span<byte> yBytes = stackalloc byte[IPV6_BYTE_WIDTH];
            x.TryWriteBytes(xBytes, out int xLength);
            y.TryWriteBytes(yBytes, out int yLength);
            return xBytes.Slice(0, xLength).SequenceCompareTo(yBytes.Slice(0, yLength));
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
            readonly List<Node> _nodes;

            public TrieBuilder(int capacityHint)
            {
                _nodes = new List<Node>(capacityHint);
            }

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

                // Preserve any children already hanging off this node. In the current caller
                // this node is always a fresh leaf -- ascending prefix-length sort order in
                // Create() guarantees a broader prefix is added first and short-circuits every
                // descendant -- but Add()'s own correctness should not depend on a comparator
                // in a different method, and preserving children costs nothing.
                Node terminal = _nodes[nodeIndex];
                if (terminal.IsPrefix)
                    return false;

                _nodes[nodeIndex] = new Node(terminal.Zero, terminal.One, true);
                return true;
            }

            public Node[] ToArray() => _nodes.ToArray();
        }
    }
}
