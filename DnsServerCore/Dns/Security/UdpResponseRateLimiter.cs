#nullable enable

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DnsServerCore.Dns.Security
{
    public enum ReflectionRrlRequestTrust
    {
        Unverified,
        ValidServerCookie
    }

    /// <summary>
    /// Defines the narrow DNS Cookie exemption from UDP reflection RRL.
    /// Other admission and resource limits are intentionally outside this policy.
    /// </summary>
    public static class ReflectionRrlPolicy
    {
        public static bool ShouldEvaluate(bool enabled, bool isUdp, ReflectionRrlRequestTrust trust) =>
            enabled && isUdp && trust != ReflectionRrlRequestTrust.ValidServerCookie;
    }

    public enum UdpResponseRateLimitResult
    {
        Allowed,
        LimitedDrop,
        LimitedSlip
    }

    /// <summary>
    /// Classifies responses into security-relevant equivalence groups used by UDP RRL.
    /// Values are flags so policy can name sets of responses without numeric literals.
    /// </summary>
    [Flags]
    public enum ResponseRateLimitCategory : byte
    {
        Positive = 1 << 0,
        NxDomain = 1 << 1,
        NoData = 1 << 2,
        Referral = 1 << 3,
        ServerError = 1 << 4,
        Wildcard = 1 << 5
    }

    /// <summary>
    /// Fixed-size packet-path key identifying a client network and an equivalent DNS response.
    /// The network is already normalized to <see cref="PrefixLength"/> and
    /// <see cref="ResponseIdentity"/> is a process-keyed hash of the canonical question identity.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public readonly struct ResponseRateLimitKey
    {
        public readonly ulong NetworkHigh;
        public readonly ulong NetworkLow;
        public readonly ulong ResponseIdentity;
        public readonly ushort QueryType;
        public readonly ushort QueryClass;
        public readonly ResponseRateLimitCategory Category;
        public readonly byte AddressFamily;
        public readonly byte PrefixLength;
        private readonly byte _reserved;

        internal ResponseRateLimitKey(ulong networkHigh, ulong networkLow, ulong responseIdentity,
            ushort queryType, ushort queryClass, ResponseRateLimitCategory category, byte addressFamily, byte prefixLength)
        {
            NetworkHigh = networkHigh;
            NetworkLow = networkLow;
            ResponseIdentity = responseIdentity;
            QueryType = queryType;
            QueryClass = queryClass;
            Category = category;
            AddressFamily = addressFamily;
            PrefixLength = prefixLength;
            _reserved = 0;
        }
    }

    /// <summary>Defines which limited response categories may be replaced by a truncated slip response.</summary>
    public static class ResponseRateLimitSlipPolicy
    {
        private const ResponseRateLimitCategory EligibleCategories =
            ResponseRateLimitCategory.Positive | ResponseRateLimitCategory.NxDomain |
            ResponseRateLimitCategory.NoData | ResponseRateLimitCategory.Referral |
            ResponseRateLimitCategory.Wildcard;

        public static bool IsEligible(ResponseRateLimitCategory category) => (EligibleCategories & category) != 0;
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
            internal long Tokens;
            internal long RefillRemainder;
            internal int InstantCount;
            internal uint LimitedCount;
            internal bool Occupied;
        }

        private readonly Shard[] _shards;
        private readonly int[] _ipv4PrefixLengths;
        private readonly int[] _ipv6PrefixLengths;
        private readonly byte[] _hashKey;
        private const long TokenScale = 1_000_000;
        private readonly long _tokenCapacity;
        private readonly long _tokensPerSecond;
        private readonly long _timestampFrequency;
        private readonly long _instantWindowTimestampUnits;
        private readonly int _instantLimit;
        private readonly int _slipEvery;
        private readonly TimeProvider _timeProvider;
        private const int HashKeyWidthBytes = 16;
        private const int MaximumCanonicalDnsNameBytes = 255;
        private const byte IPv4AddressFamilyCode = 4;
        private const byte IPv6AddressFamilyCode = 6;

        public UdpResponseRateLimiter(UdpResponseRateLimiterOptions options, TimeProvider? timeProvider = null)
            : this(options, RandomNumberGenerator.GetBytes(HashKeyWidthBytes), timeProvider)
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
            if (hashKey.Length != HashKeyWidthBytes)
                throw new ArgumentException("The limiter hash key must be 16 bytes.", nameof(hashKey));

            _timeProvider = timeProvider ?? TimeProvider.System;
            _timestampFrequency = _timeProvider.TimestampFrequency;
            _instantWindowTimestampUnits = checked((long)(options.InstantWindow.TotalSeconds * _timeProvider.TimestampFrequency));
            _tokenCapacity = checked((long)Math.Ceiling(options.SustainedRate * options.DecayTime.TotalSeconds * TokenScale));
            _tokensPerSecond = checked((long)Math.Ceiling(options.SustainedRate * TokenScale));
            _instantLimit = options.InstantLimit;
            _slipEvery = options.SlipEvery;
            _hashKey = hashKey.ToArray();
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

        public UdpResponseRateLimitResult Evaluate(IPAddress sourceAddress, ResponseRateLimitCategory category,
            ushort queryType, ushort queryClass, string canonicalName)
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
                family = IPv4AddressFamilyCode;
            }
            else if (sourceAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                addressLength = 16;
                prefixLengths = _ipv6PrefixLengths;
                family = IPv6AddressFamilyCode;
            }
            else
            {
                throw new ArgumentException("Only IPv4 and IPv6 addresses are supported.", nameof(sourceAddress));
            }

            sourceAddress.TryWriteBytes(addressBytes, out _);
            ulong responseIdentity = ComputeResponseIdentity(category, queryType, queryClass, canonicalName);
            long now = _timeProvider.GetTimestamp();
            UdpResponseRateLimitResult result = UdpResponseRateLimitResult.Allowed;
            Span<byte> network = stackalloc byte[16];
            foreach (int prefixLength in prefixLengths)
            {
                network.Clear();
                addressBytes[..addressLength].CopyTo(network);
                MaskHostBits(network[..addressLength], prefixLength);
                ResponseRateLimitKey key = new ResponseRateLimitKey(
                    MemoryMarshal.Read<ulong>(network), MemoryMarshal.Read<ulong>(network[8..]), responseIdentity,
                    queryType, queryClass, category, family, (byte)prefixLength);
                UdpResponseRateLimitResult levelResult = Update(MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref key, 1)), now);
                if (levelResult == UdpResponseRateLimitResult.LimitedDrop)
                    result = levelResult;
                else if (levelResult == UdpResponseRateLimitResult.LimitedSlip && result == UdpResponseRateLimitResult.Allowed)
                    result = levelResult;
            }
            return result;
        }

        private ulong ComputeResponseIdentity(ResponseRateLimitCategory category, ushort queryType, ushort queryClass, string canonicalName)
        {
            // DNS wire names are at most 255 octets. Domain names in DnsDatagram are
            // already canonical ASCII/punycode, so encoding them directly avoids a
            // temporary string or byte array on the packet path.
            Span<byte> identity = stackalloc byte[MaximumCanonicalDnsNameBytes + 5];
            identity[0] = (byte)category;
            identity[1] = (byte)queryType;
            identity[2] = (byte)(queryType >> 8);
            identity[3] = (byte)queryClass;
            identity[4] = (byte)(queryClass >> 8);
            int length = Math.Min(canonicalName.Length, MaximumCanonicalDnsNameBytes);
            for (int i = 0; i < length; i++)
            {
                char value = canonicalName[i];
                identity[i + 5] = value is >= 'A' and <= 'Z' ? (byte)(value + ('a' - 'A')) : (byte)value;
            }
            return SipHash24.Compute(_hashKey, identity[..(length + 5)]);
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
            ulong fingerprint = SipHash24.Compute(_hashKey, key);
            (int shardIndex, int first, int second) = Locate(key, fingerprint);
            Shard shard = _shards[shardIndex];
            lock (shard.SyncRoot)
            {
                ref Entry entry = ref SelectEntry(shard.Entries, first, second, fingerprint);
                if (!entry.Occupied || entry.Fingerprint != fingerprint)
                    entry = new Entry
                    {
                        Occupied = true,
                        Fingerprint = fingerprint,
                        LastTimestamp = now,
                        WindowStart = now,
                        Tokens = _tokenCapacity
                    };

                long elapsed = Math.Max(0, now - entry.LastTimestamp);
                if (elapsed > 0)
                {
                    // Saturate before multiplying so long-idle entries cannot overflow.
                    long refillHorizon = _tokenCapacity / _tokensPerSecond + 1;
                    long maximumElapsed = refillHorizon >= long.MaxValue / _timestampFrequency
                        ? long.MaxValue
                        : refillHorizon * _timestampFrequency;
                    long boundedElapsed = Math.Min(elapsed, maximumElapsed);
                    UInt128 refillNumerator = (UInt128)(ulong)boundedElapsed * (ulong)_tokensPerSecond +
                        (ulong)entry.RefillRemainder;
                    UInt128 refillValue = refillNumerator / (ulong)_timestampFrequency;
                    long refill = refillValue >= (UInt128)(ulong)_tokenCapacity
                        ? _tokenCapacity
                        : (long)refillValue;
                    if (refill >= _tokenCapacity - entry.Tokens)
                    {
                        entry.Tokens = _tokenCapacity;
                        entry.RefillRemainder = 0;
                    }
                    else
                    {
                        entry.Tokens += refill;
                        entry.RefillRemainder = (long)(refillNumerator % (ulong)_timestampFrequency);
                    }
                }
                entry.LastTimestamp = now;
                if (now - entry.WindowStart >= _instantWindowTimestampUnits)
                {
                    entry.WindowStart = now;
                    entry.InstantCount = 0;
                }
                entry.InstantCount++;

                bool sustainedAllowed = entry.Tokens >= TokenScale;
                if (sustainedAllowed)
                    entry.Tokens -= TokenScale;

                if (sustainedAllowed && entry.InstantCount <= _instantLimit)
                    return UdpResponseRateLimitResult.Allowed;

                entry.LimitedCount++;
                return _slipEvery > 0 && entry.LimitedCount % _slipEvery == 0
                    ? UdpResponseRateLimitResult.LimitedSlip
                    : UdpResponseRateLimitResult.LimitedDrop;
            }
        }

        private (int Shard, int First, int Second) Locate(ReadOnlySpan<byte> key) => Locate(key, SipHash24.Compute(_hashKey, key));

        private (int Shard, int First, int Second) Locate(ReadOnlySpan<byte> key, ulong firstHash)
        {
            int shardIndex = (int)(firstHash % (uint)_shards.Length);
            int length = _shards[shardIndex].Entries.Length;
            int first = (int)((firstHash >> 32) % (uint)length);
            // One keyed PRF supplies the attacker-resistant fingerprint and first
            // placement. SplitMix-style finalization cheaply derives a second choice.
            ulong mixed = firstHash + 0x9e3779b97f4a7c15UL;
            mixed = (mixed ^ (mixed >> 30)) * 0xbf58476d1ce4e5b9UL;
            mixed = (mixed ^ (mixed >> 27)) * 0x94d049bb133111ebUL;
            mixed ^= mixed >> 31;
            int second = (int)(mixed % (uint)length);
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
    }
}
