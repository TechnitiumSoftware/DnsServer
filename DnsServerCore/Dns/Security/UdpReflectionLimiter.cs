/*
 * Technitium DNS Server
 * Copyright (C) 2026 Shreyas Zare (shreyas@technitium.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace DnsServerCore.Dns.Security
{
    /// <summary>
    /// The action selected by the early, source-prefix-based UDP reflection limiter.
    /// This limiter deliberately makes no response-equivalence decision; that work belongs
    /// to the separate post-response DNS response-rate limiter.
    /// </summary>
    internal enum UdpReflectionLimitResult
    {
        Allowed,
        LimitedDrop,
        LimitedSlip
    }

    /// <summary>
    /// Bounded pre-response admission control for spoofable UDP requests. Its fixed-size,
    /// keyed table limits unverified traffic before DNS resolution or response construction.
    /// The implementation is intentionally independent of DNS Cookie secrets, QPM, and the
    /// post-response DNS response-rate limiter.
    /// </summary>
    internal sealed class UdpReflectionLimiter
    {
        private const int BucketCount = 16_384;
        private const int ShardCount = 64;
        private const int BucketsPerShard = BucketCount / ShardCount;
        private const int MaximumProbes = 8;
        private const uint IdleEvictionSeconds = 120;
        private const int BurstLimit = 30;
        private const int RefillPerSecond = 3;
        private const uint SlipEvery = 4;
        private const int IPv4PrefixLength = 24;
        private const int IPv6PrefixLength = 56;

        private struct Bucket
        {
            internal ulong SourcePrefixHash;
            internal uint LastRefillSecond;
            internal uint LastSeenSecond;
            internal int Tokens;
            internal uint LimitedCount;
        }

        private readonly Bucket[] _buckets = new Bucket[BucketCount];
        private readonly object[] _shards = CreateShards();
        private readonly byte[] _hashKey = RandomNumberGenerator.GetBytes(16);

        public UdpReflectionLimitResult Evaluate(IPAddress sourceAddress)
        {
            ArgumentNullException.ThrowIfNull(sourceAddress);

            ulong sourcePrefixHash = GetSourcePrefixHash(sourceAddress);
            uint now = unchecked((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            int shardIndex = (int)(sourcePrefixHash & (ShardCount - 1));
            int firstBucket = (int)((sourcePrefixHash >> 8) & (BucketsPerShard - 1));
            int shardOffset = shardIndex * BucketsPerShard;

            lock (_shards[shardIndex])
            {
                int selectedIndex = -1;
                int staleIndex = -1;

                for (int probe = 0; probe < MaximumProbes; probe++)
                {
                    int index = shardOffset + ((firstBucket + probe) & (BucketsPerShard - 1));
                    ref Bucket bucket = ref _buckets[index];

                    if (bucket.SourcePrefixHash == sourcePrefixHash)
                    {
                        selectedIndex = index;
                        break;
                    }

                    if (bucket.SourcePrefixHash == 0)
                    {
                        selectedIndex = index;
                        break;
                    }

                    if (staleIndex < 0 && unchecked(now - bucket.LastSeenSecond) >= IdleEvictionSeconds)
                        staleIndex = index;
                }

                if (selectedIndex < 0)
                    selectedIndex = staleIndex;

                // Under table pressure, fail closed rather than allocating or permitting an
                // attacker to turn collisions into an amplification path.
                if (selectedIndex < 0)
                    return UdpReflectionLimitResult.LimitedDrop;

                ref Bucket state = ref _buckets[selectedIndex];
                if (state.SourcePrefixHash != sourcePrefixHash)
                {
                    state.SourcePrefixHash = sourcePrefixHash;
                    state.LastRefillSecond = now;
                    state.LastSeenSecond = now;
                    state.Tokens = BurstLimit;
                    state.LimitedCount = 0;
                }
                else
                {
                    uint elapsed = unchecked(now - state.LastRefillSecond);
                    if (elapsed > 0)
                    {
                        int refill = (int)Math.Min((uint)int.MaxValue, elapsed * (uint)RefillPerSecond);
                        state.Tokens = Math.Min(BurstLimit, state.Tokens + refill);
                        state.LastRefillSecond = now;
                    }

                    state.LastSeenSecond = now;
                }

                if (state.Tokens > 0)
                {
                    state.Tokens--;
                    return UdpReflectionLimitResult.Allowed;
                }

                if (state.LimitedCount < uint.MaxValue)
                    state.LimitedCount++;

                return state.LimitedCount % SlipEvery == 0
                    ? UdpReflectionLimitResult.LimitedSlip
                    : UdpReflectionLimitResult.LimitedDrop;
            }
        }

        private ulong GetSourcePrefixHash(IPAddress sourceAddress)
        {
            Span<byte> keyMaterial = stackalloc byte[17];
            int addressLength;
            int prefixLength;

            if (sourceAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                keyMaterial[0] = 4;
                addressLength = 4;
                prefixLength = IPv4PrefixLength;
                sourceAddress.TryWriteBytes(keyMaterial[1..5], out _);
            }
            else if (sourceAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (sourceAddress.IsIPv4MappedToIPv6)
                    return GetSourcePrefixHash(sourceAddress.MapToIPv4());

                keyMaterial[0] = 6;
                addressLength = 16;
                prefixLength = IPv6PrefixLength;
                sourceAddress.TryWriteBytes(keyMaterial[1..], out _);
            }
            else
            {
                throw new ArgumentException("Only IPv4 and IPv6 source addresses are supported.", nameof(sourceAddress));
            }

            MaskHostBits(keyMaterial.Slice(1, addressLength), prefixLength);
            ulong hash = SipHash24.Compute(_hashKey, keyMaterial[..(addressLength + 1)]);
            return hash == 0 ? 1UL : hash;
        }

        private static void MaskHostBits(Span<byte> address, int prefixLength)
        {
            int wholeBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            if (remainingBits != 0 && wholeBytes < address.Length)
            {
                address[wholeBytes] &= (byte)(0xff << (8 - remainingBits));
                wholeBytes++;
            }

            address[wholeBytes..].Clear();
        }

        private static object[] CreateShards()
        {
            object[] shards = new object[ShardCount];
            for (int i = 0; i < shards.Length; i++)
                shards[i] = new object();

            return shards;
        }
    }
}
