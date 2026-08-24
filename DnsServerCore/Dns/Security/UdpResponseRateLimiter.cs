#nullable enable

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Numerics;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace DnsServerCore.Dns.Security
{
    public enum UdpResponseRateLimitResult
    {
        Allowed,
        LimitedDrop,
        LimitedSlip
    }

    public sealed class UdpResponseRateLimiterOptions
    {
        public int Capacity { get; init; } = 65536;
        public int ShardCount { get; init; } = 16;
        public double SustainedRate { get; init; } = 100;
        public TimeSpan DecayTime { get; init; } = TimeSpan.FromSeconds(1);
        public int InstantLimit { get; init; } = 200;
        public TimeSpan InstantWindow { get; init; } = TimeSpan.FromSeconds(1);
        public int SlipEvery { get; init; } = 2;
        public IReadOnlyList<int> IPv4PrefixLengths { get; init; } = new[] { 32, 24 };
        public IReadOnlyList<int> IPv6PrefixLengths { get; init; } = new[] { 128, 64, 56 };
    }

    /// <summary>
    /// A fixed-size, keyed, two-choice table for UDP response rate limiting.
    /// This class is deliberately independent of query-per-minute and DNS Cookie state.
    /// </summary>
    public sealed class UdpResponseRateLimiter
    {
        private sealed class Shard
        {
            internal readonly object SyncRoot = new object();
            internal readonly Entry[] Entries;

            internal Shard(int capacity) => Entries = new Entry[capacity];
        }

        private struct Entry
        {
            internal ulong Fingerprint;
            internal long LastTimestamp;
            internal long WindowStart;
            internal double Load;
            internal int InstantCount;
            internal uint LimitedCount;
            internal bool Occupied;
        }

        private readonly Shard[] _shards;
        private readonly int[] _ipv4PrefixLengths;
        private readonly int[] _ipv6PrefixLengths;
        private readonly ulong _hashKey0;
        private readonly ulong _hashKey1;
        private readonly double _sustainedCapacity;
        private readonly double _decayTimestampUnits;
        private readonly long _instantWindowTimestampUnits;
        private readonly int _instantLimit;
        private readonly int _slipEvery;
        private readonly TimeProvider _timeProvider;

        public UdpResponseRateLimiter(UdpResponseRateLimiterOptions options, TimeProvider? timeProvider = null)
            : this(options, RandomNumberGenerator.GetBytes(16), timeProvider)
        {
        }

        internal UdpResponseRateLimiter(UdpResponseRateLimiterOptions options, ReadOnlySpan<byte> hashKey, TimeProvider? timeProvider = null)
        {
            ArgumentNullException.ThrowIfNull(options);
            if (options.Capacity < 1)
                throw new ArgumentOutOfRangeException(nameof(options.Capacity));
            if (options.ShardCount < 1 || options.ShardCount > options.Capacity)
                throw new ArgumentOutOfRangeException(nameof(options.ShardCount));
            if (!(options.SustainedRate > 0) || options.DecayTime <= TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(options.SustainedRate));
            if (options.InstantLimit < 1 || options.InstantWindow <= TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(options.InstantLimit));
            if (options.SlipEvery < 0)
                throw new ArgumentOutOfRangeException(nameof(options.SlipEvery));
            if (hashKey.Length != 16)
                throw new ArgumentException("The limiter hash key must be 16 bytes.", nameof(hashKey));

            _timeProvider = timeProvider ?? TimeProvider.System;
            _decayTimestampUnits = options.DecayTime.TotalSeconds * _timeProvider.TimestampFrequency;
            _instantWindowTimestampUnits = checked((long)(options.InstantWindow.TotalSeconds * _timeProvider.TimestampFrequency));
            _sustainedCapacity = options.SustainedRate * options.DecayTime.TotalSeconds;
            _instantLimit = options.InstantLimit;
            _slipEvery = options.SlipEvery;
            _hashKey0 = BinaryPrimitives.ReadUInt64LittleEndian(hashKey);
            _hashKey1 = BinaryPrimitives.ReadUInt64LittleEndian(hashKey[8..]);
            _ipv4PrefixLengths = ValidatePrefixes(options.IPv4PrefixLengths, 32, nameof(options.IPv4PrefixLengths));
            _ipv6PrefixLengths = ValidatePrefixes(options.IPv6PrefixLengths, 128, nameof(options.IPv6PrefixLengths));

            _shards = new Shard[options.ShardCount];
            int baseCapacity = options.Capacity / options.ShardCount;
            int remainder = options.Capacity % options.ShardCount;
            for (int i = 0; i < _shards.Length; i++)
                _shards[i] = new Shard(baseCapacity + (i < remainder ? 1 : 0));
        }

        public int Capacity
        {
            get
            {
                int capacity = 0;
                foreach (Shard shard in _shards)
                    capacity += shard.Entries.Length;
                return capacity;
            }
        }

        public int OccupiedEntryCount
        {
            get
            {
                int count = 0;
                foreach (Shard shard in _shards)
                {
                    lock (shard.SyncRoot)
                    {
                        foreach (Entry entry in shard.Entries)
                            if (entry.Occupied)
                                count++;
                    }
                }
                return count;
            }
        }

        public int MaximumEntriesExaminedPerRequest => 2 * Math.Max(_ipv4PrefixLengths.Length, _ipv6PrefixLengths.Length);

        public UdpResponseRateLimitResult Evaluate(IPAddress sourceAddress)
        {
            ArgumentNullException.ThrowIfNull(sourceAddress);
            Span<byte> addressBytes = stackalloc byte[16];
            int addressLength;
            int[] prefixLengths;
            byte family;
            if (sourceAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                addressLength = 4;
                prefixLengths = _ipv4PrefixLengths;
                family = 4;
            }
            else if (sourceAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                addressLength = 16;
                prefixLengths = _ipv6PrefixLengths;
                family = 6;
            }
            else
            {
                throw new ArgumentException("Only IPv4 and IPv6 addresses are supported.", nameof(sourceAddress));
            }

            sourceAddress.TryWriteBytes(addressBytes, out _);
            long now = _timeProvider.GetTimestamp();
            UdpResponseRateLimitResult result = UdpResponseRateLimitResult.Allowed;
            Span<byte> key = stackalloc byte[18];
            foreach (int prefixLength in prefixLengths)
            {
                key.Clear();
                key[0] = family;
                key[1] = (byte)prefixLength;
                addressBytes[..addressLength].CopyTo(key[2..]);
                MaskHostBits(key.Slice(2, addressLength), prefixLength);
                UdpResponseRateLimitResult levelResult = Update(key[..(addressLength + 2)], now);
                if (levelResult == UdpResponseRateLimitResult.LimitedSlip)
                    result = levelResult;
                else if (levelResult == UdpResponseRateLimitResult.LimitedDrop && result == UdpResponseRateLimitResult.Allowed)
                    result = levelResult;
            }
            return result;
        }

        internal (int Shard, int First, int Second) GetPlacement(IPAddress address, int prefixLength)
        {
            Span<byte> bytes = stackalloc byte[16];
            address.TryWriteBytes(bytes, out int length);
            Span<byte> key = stackalloc byte[18];
            key[0] = address.AddressFamily == AddressFamily.InterNetwork ? (byte)4 : (byte)6;
            key[1] = (byte)prefixLength;
            bytes[..length].CopyTo(key[2..]);
            MaskHostBits(key.Slice(2, length), prefixLength);
            return Locate(key[..(length + 2)]);
        }

        private UdpResponseRateLimitResult Update(ReadOnlySpan<byte> key, long now)
        {
            ulong fingerprint = SipHash24(key, _hashKey0, _hashKey1);
            (int shardIndex, int first, int second) = Locate(key, fingerprint);
            Shard shard = _shards[shardIndex];
            lock (shard.SyncRoot)
            {
                ref Entry entry = ref SelectEntry(shard.Entries, first, second, fingerprint);
                if (!entry.Occupied || entry.Fingerprint != fingerprint)
                    entry = new Entry { Occupied = true, Fingerprint = fingerprint, LastTimestamp = now, WindowStart = now };

                long elapsed = Math.Max(0, now - entry.LastTimestamp);
                entry.Load = entry.Load * Math.Exp(-elapsed / _decayTimestampUnits) + 1;
                entry.LastTimestamp = now;
                if (now - entry.WindowStart >= _instantWindowTimestampUnits)
                {
                    entry.WindowStart = now;
                    entry.InstantCount = 0;
                }
                entry.InstantCount++;

                if (entry.Load <= _sustainedCapacity && entry.InstantCount <= _instantLimit)
                    return UdpResponseRateLimitResult.Allowed;

                entry.LimitedCount++;
                return _slipEvery > 0 && entry.LimitedCount % _slipEvery == 0
                    ? UdpResponseRateLimitResult.LimitedSlip
                    : UdpResponseRateLimitResult.LimitedDrop;
            }
        }

        private (int Shard, int First, int Second) Locate(ReadOnlySpan<byte> key) => Locate(key, SipHash24(key, _hashKey0, _hashKey1));

        private (int Shard, int First, int Second) Locate(ReadOnlySpan<byte> key, ulong firstHash)
        {
            int shardIndex = (int)(firstHash % (uint)_shards.Length);
            int length = _shards[shardIndex].Entries.Length;
            int first = (int)((firstHash >> 32) % (uint)length);
            ulong secondHash = SipHash24(key, _hashKey0 ^ 0xa5a5a5a5a5a5a5a5UL, _hashKey1 ^ firstHash);
            int second = (int)(secondHash % (uint)length);
            return (shardIndex, first, second);
        }

        private static ref Entry SelectEntry(Entry[] entries, int first, int second, ulong fingerprint)
        {
            if (entries[first].Occupied && entries[first].Fingerprint == fingerprint)
                return ref entries[first];
            if (entries[second].Occupied && entries[second].Fingerprint == fingerprint)
                return ref entries[second];
            if (!entries[first].Occupied)
                return ref entries[first];
            if (!entries[second].Occupied)
                return ref entries[second];
            return ref (entries[first].LastTimestamp <= entries[second].LastTimestamp ? ref entries[first] : ref entries[second]);
        }

        private static int[] ValidatePrefixes(IReadOnlyList<int> prefixes, int maximum, string parameterName)
        {
            ArgumentNullException.ThrowIfNull(prefixes);
            if (prefixes.Count == 0)
                throw new ArgumentException("At least one prefix is required.", parameterName);
            int[] copy = new int[prefixes.Count];
            HashSet<int> seen = new HashSet<int>();
            for (int i = 0; i < copy.Length; i++)
            {
                int prefix = prefixes[i];
                if (prefix < 0 || prefix > maximum || !seen.Add(prefix))
                    throw new ArgumentOutOfRangeException(parameterName);
                copy[i] = prefix;
            }
            return copy;
        }

        private static void MaskHostBits(Span<byte> bytes, int prefixLength)
        {
            int wholeBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;
            if (remainingBits != 0)
                bytes[wholeBytes++] &= (byte)(0xff << (8 - remainingBits));
            bytes[wholeBytes..].Clear();
        }

        // SipHash-2-4 is keyed and deliberately used instead of attacker-predictable runtime hashes.
        private static ulong SipHash24(ReadOnlySpan<byte> data, ulong key0, ulong key1)
        {
            ulong v0 = 0x736f6d6570736575UL ^ key0;
            ulong v1 = 0x646f72616e646f6dUL ^ key1;
            ulong v2 = 0x6c7967656e657261UL ^ key0;
            ulong v3 = 0x7465646279746573UL ^ key1;
            int offset = 0;
            while (offset + 8 <= data.Length)
            {
                ulong word = BinaryPrimitives.ReadUInt64LittleEndian(data[offset..]);
                v3 ^= word;
                SipRound(ref v0, ref v1, ref v2, ref v3); SipRound(ref v0, ref v1, ref v2, ref v3);
                v0 ^= word;
                offset += 8;
            }
            ulong tail = (ulong)data.Length << 56;
            for (int i = 0; offset + i < data.Length; i++)
                tail |= (ulong)data[offset + i] << (8 * i);
            v3 ^= tail;
            SipRound(ref v0, ref v1, ref v2, ref v3); SipRound(ref v0, ref v1, ref v2, ref v3);
            v0 ^= tail;
            v2 ^= 0xff;
            for (int i = 0; i < 4; i++) SipRound(ref v0, ref v1, ref v2, ref v3);
            return v0 ^ v1 ^ v2 ^ v3;
        }

        private static void SipRound(ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3)
        {
            v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
            v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
            v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
            v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);
        }
    }
}
