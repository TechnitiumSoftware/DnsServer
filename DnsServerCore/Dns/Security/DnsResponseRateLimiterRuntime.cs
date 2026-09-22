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
using System.Threading;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Security
{
    /// <summary>
    /// The response-rate-limiting settings a caller configures. Immutable and comparable so a
    /// settings update can detect whether anything actually changed before rebuilding state.
    /// </summary>
    public readonly record struct ResponseRateLimitingOptions(bool Enabled, int SustainedRate, int InstantLimit, int SlipEvery, int TableSize, IReadOnlyCollection<NetworkAddress> BypassList);

    enum RrlKeyInterpretation
    {
        ResponseIdentityV1
    }

    readonly record struct RrlLimiterSemanticSettings(
        int Capacity,
        int ShardCount,
        int SustainedRatePerSecond,
        long ScaledTokenCapacity,
        long ScaledTokensPerSecond,
        int InstantLimit,
        long InstantWindowTimestampUnits,
        int SlipEvery,
        ImmutableArray<int> IPv4PrefixLengths,
        ImmutableArray<int> IPv6PrefixLengths,
        RrlKeyInterpretation KeyInterpretation)
    {
        /// <summary>
        /// Determines whether a change alters the table layout, token/window accounting, slip
        /// counters, address aggregation, or response-identity keys stored in limiter history.
        /// </summary>
        public bool RequiresHistoryRebuild(in RrlLimiterSemanticSettings other)
        {
            return Capacity != other.Capacity ||
                ShardCount != other.ShardCount ||
                ScaledTokensPerSecond != other.ScaledTokensPerSecond ||
                ScaledTokenCapacity != other.ScaledTokenCapacity ||
                InstantLimit != other.InstantLimit ||
                InstantWindowTimestampUnits != other.InstantWindowTimestampUnits ||
                SlipEvery != other.SlipEvery ||
                !IPv4PrefixLengths.AsSpan().SequenceEqual(other.IPv4PrefixLengths.AsSpan()) ||
                !IPv6PrefixLengths.AsSpan().SequenceEqual(other.IPv6PrefixLengths.AsSpan()) ||
                KeyInterpretation != other.KeyInterpretation;
        }

        public NormalizedDnsResponseRateLimiterOptions ToLimiterOptions() => new NormalizedDnsResponseRateLimiterOptions(
            Capacity, ShardCount, ScaledTokenCapacity, ScaledTokensPerSecond, TimeProvider.System.TimestampFrequency,
            InstantWindowTimestampUnits, InstantLimit, SlipEvery, IPv4PrefixLengths, IPv6PrefixLengths);
    }

    /// <summary>
    /// An immutable RRL policy generation. Instances are completely constructed before a
    /// single atomic publication and neither their options nor bypass list are mutated
    /// afterward; readers must capture the published reference once and use only that
    /// instance for the entire decision.
    /// </summary>
    sealed class RrlRuntimeState
    {
        public RrlRuntimeState(ResponseRateLimitingOptions options, RrlLimiterSemanticSettings limiterSettings,
            DnsResponseRateLimiter limiter, DnsResponseRateLimiter errorLeakLimiter, ImmutableArray<NetworkAddress> bypassList, ulong generation)
        {
            Options = options;
            LimiterSettings = limiterSettings;
            Limiter = limiter ?? throw new ArgumentNullException(nameof(limiter));
            ErrorLeakLimiter = errorLeakLimiter ?? throw new ArgumentNullException(nameof(errorLeakLimiter));
            BypassList = bypassList;
            Generation = generation;
        }

        public bool Enabled => Options.Enabled;
        public DnsResponseRateLimiter Limiter { get; }
        public DnsResponseRateLimiter ErrorLeakLimiter { get; }
        public RrlLimiterSemanticSettings LimiterSettings { get; }
        public ImmutableArray<NetworkAddress> BypassList { get; }
        public ResponseRateLimitingOptions Options { get; }
        public ulong Generation { get; }
    }

    /// <summary>
    /// Owns the UDP response-rate-limiting policy: normalizing configured options, atomically
    /// publishing a new immutable runtime generation whenever they change, and evaluating
    /// individual responses against the currently published generation. <see cref="DnsServer"/>
    /// holds one instance and only ever talks to it through this surface.
    /// </summary>
    public readonly record struct DnsResponseRateLimitIdentity(
        DnsResponseRateLimitClass ResponseClass, string CanonicalName, ushort QueryType, ushort QueryClass);

    public sealed class DnsResponseRateLimiterRuntime
    {
        const ulong INITIAL_GENERATION = 0;
        private const int ErrorLeakTableSize = 4096;
        private const int ErrorLeakRatePerSecond = 1;
        private const int ErrorLeakInstantLimit = 2;

        public const int TableSizeMinimum = 16;

        // Eight times the default capacity. This keeps worst-case allocation bounded while
        // allowing deployments to scale to the same order of magnitude as Knot Resolver.
        public const int TableSizeMaximum = 524288;

        public static readonly int SustainedRateMaximum = (int)Math.Min(int.MaxValue, DnsResponseRateLimiter.MaximumSupportedRate);

        readonly Lock _lock = new Lock();
        RrlRuntimeState _state;
        long _rebuildCount;

        public DnsResponseRateLimiterRuntime()
        {
            ResponseRateLimitingOptions initialOptions = new ResponseRateLimitingOptions(false, 100, 200, 2, 65536, ImmutableArray<NetworkAddress>.Empty);
            _state = CreateRuntimeState(initialOptions, INITIAL_GENERATION);
        }

        public ResponseRateLimitingOptions CurrentOptions => Volatile.Read(ref _state).Options;

        public bool Enabled => Volatile.Read(ref _state).Enabled;

        // Diagnostic hook: callers can compare this value around a settings update.
        public long RebuildCount => Interlocked.Read(ref _rebuildCount);

        public void Apply(ResponseRateLimitingOptions options)
        {
            lock (_lock)
            {
                RrlRuntimeState current = Volatile.Read(ref _state);
                ResponseRateLimitingOptions normalizedOptions = NormalizeOptions(options, out ImmutableArray<NetworkAddress> bypassList);
                RrlLimiterSemanticSettings limiterSettings = CreateLimiterSettings(normalizedOptions);
                bool rebuild = current.LimiterSettings.RequiresHistoryRebuild(limiterSettings);
                DnsResponseRateLimiter limiter = rebuild
                    ? new DnsResponseRateLimiter(limiterSettings.ToLimiterOptions())
                    : current.Limiter;
                DnsResponseRateLimiter errorLeakLimiter = rebuild
                    ? CreateErrorLeakLimiter(limiterSettings)
                    : current.ErrorLeakLimiter;
                RrlRuntimeState replacement = new RrlRuntimeState(normalizedOptions, limiterSettings, limiter,
                    errorLeakLimiter, bypassList, GetNextGeneration(current.Generation));

                // The previous generation remains published if any construction step above fails.
                Volatile.Write(ref _state, replacement);
                if (rebuild)
                    Interlocked.Increment(ref _rebuildCount);
            }
        }

        /// <summary>
        /// Captures the currently published generation once and evaluates a single response
        /// against it. Callers that need <see cref="DnsResponseRrlPolicy.ShouldEvaluate"/> first
        /// should read <see cref="Enabled"/> for that check and then call this method - both
        /// observe the same generation only if no concurrent <see cref="Apply"/> lands between
        /// the two reads, which is acceptable since a policy update racing a single request is
        /// not a correctness issue here.
        /// </summary>
        public DnsResponseRateLimitResult Evaluate(IPAddress remoteIP, in DnsResponseRateLimitIdentity identity, out bool errorLeakAllowed)
        {
            errorLeakAllowed = false;
            RrlRuntimeState state = Volatile.Read(ref _state);
            if (IsBypassed(state.BypassList, remoteIP))
                return DnsResponseRateLimitResult.Allowed;

            DnsResponseRateLimitResult classResult = state.Limiter.Evaluate(remoteIP, identity.ResponseClass,
                identity.QueryType, identity.QueryClass, identity.CanonicalName);
            DnsResponseRateLimitResult allResult = state.Limiter.Evaluate(remoteIP, DnsResponseRateLimitClass.All, 0, 0, string.Empty);
            DnsResponseRateLimitResult result = classResult == DnsResponseRateLimitResult.LimitedDrop || allResult == DnsResponseRateLimitResult.LimitedDrop
                ? DnsResponseRateLimitResult.LimitedDrop
                : classResult == DnsResponseRateLimitResult.LimitedSlip || allResult == DnsResponseRateLimitResult.LimitedSlip
                    ? DnsResponseRateLimitResult.LimitedSlip
                    : DnsResponseRateLimitResult.Allowed;

            if (result == DnsResponseRateLimitResult.LimitedDrop && identity.ResponseClass == DnsResponseRateLimitClass.Error &&
                state.ErrorLeakLimiter.Evaluate(remoteIP, DnsResponseRateLimitClass.Error, 0, identity.QueryClass, string.Empty) == DnsResponseRateLimitResult.Allowed)
            {
                errorLeakAllowed = true;
                return DnsResponseRateLimitResult.Allowed;
            }

            return result;
        }

        public static DnsResponseRateLimitIdentity BuildResponseIdentity(DnsDatagram response, DnsQuestionRecord question)
        {
            if (response.RCODE == DnsResponseCode.NxDomain)
                return new DnsResponseRateLimitIdentity(DnsResponseRateLimitClass.NxDomain, question.Name, 0, (ushort)question.Class);

            if (response.RCODE != DnsResponseCode.NoError)
                return new DnsResponseRateLimitIdentity(DnsResponseRateLimitClass.Error, question.Name, (ushort)question.Type, (ushort)question.Class);

            if (response.Answer.Count == 0)
            {
                for (int i = 0; i < response.Authority.Count; i++)
                {
                    DnsResourceRecord record = response.Authority[i];
                    if (record.Type == DnsResourceRecordType.NS)
                        return new DnsResponseRateLimitIdentity(DnsResponseRateLimitClass.Referral, record.Name, 0, (ushort)question.Class);
                }

                return new DnsResponseRateLimitIdentity(DnsResponseRateLimitClass.NoData, question.Name, 0, (ushort)question.Class);
            }

            for (int i = 0; i < response.Answer.Count; i++)
            {
                DnsResourceRecord record = response.Answer[i];
                if (record.Type == DnsResourceRecordType.RRSIG &&
                    DnsRRSIGRecordData.IsWildcard(record) &&
                    record.RDATA is DnsRRSIGRecordData rrsig &&
                    !string.IsNullOrEmpty(rrsig.SignersName))
                {
                    return new DnsResponseRateLimitIdentity(DnsResponseRateLimitClass.Query, rrsig.SignersName,
                        (ushort)question.Type, (ushort)question.Class);
                }
            }

            return new DnsResponseRateLimitIdentity(DnsResponseRateLimitClass.Query, question.Name,
                (ushort)question.Type, (ushort)question.Class);
        }

        private static ulong GetNextGeneration(ulong generation) => generation == ulong.MaxValue ? INITIAL_GENERATION + 1UL : generation + 1UL;

        private static RrlRuntimeState CreateRuntimeState(ResponseRateLimitingOptions options, ulong generation)
        {
            ResponseRateLimitingOptions normalizedOptions = NormalizeOptions(options, out ImmutableArray<NetworkAddress> bypassList);
            RrlLimiterSemanticSettings limiterSettings = CreateLimiterSettings(normalizedOptions);
            DnsResponseRateLimiter limiter = new DnsResponseRateLimiter(limiterSettings.ToLimiterOptions());
            return new RrlRuntimeState(normalizedOptions, limiterSettings, limiter,
                CreateErrorLeakLimiter(limiterSettings), bypassList, generation);
        }

        private static DnsResponseRateLimiter CreateErrorLeakLimiter(RrlLimiterSemanticSettings limiterSettings)
        {
            DnsResponseRateLimiterOptions options = new DnsResponseRateLimiterOptions
            {
                Capacity = Math.Min(ErrorLeakTableSize, limiterSettings.Capacity),
                ShardCount = 1,
                SustainedRate = ErrorLeakRatePerSecond,
                DecayTime = TimeSpan.FromSeconds(1),
                InstantLimit = ErrorLeakInstantLimit,
                InstantWindow = TimeSpan.FromSeconds(1),
                SlipEvery = 0,
                IPv4PrefixLengths = limiterSettings.IPv4PrefixLengths,
                IPv6PrefixLengths = limiterSettings.IPv6PrefixLengths
            };
            return new DnsResponseRateLimiter(options);
        }

        // The bypass list is operator-configured, capped at 255 entries, and rebuilt only on a
        // settings change, so it is scanned directly. This matches how the query-per-minute
        // bypass list is evaluated on the same request path.
        private static bool IsBypassed(ImmutableArray<NetworkAddress> bypassList, IPAddress remoteIP)
        {
            foreach (NetworkAddress network in bypassList)
            {
                if (network.Contains(remoteIP))
                    return true;
            }

            return false;
        }

        private static ResponseRateLimitingOptions NormalizeOptions(ResponseRateLimitingOptions options, out ImmutableArray<NetworkAddress> bypassList)
        {
            ValidateOptions(options);
            bypassList = options.BypassList is null ? ImmutableArray<NetworkAddress>.Empty : ImmutableArray.CreateRange(options.BypassList);
            return new ResponseRateLimitingOptions(options.Enabled, options.SustainedRate, options.InstantLimit,
                options.SlipEvery, options.TableSize, bypassList);
        }

        private static RrlLimiterSemanticSettings CreateLimiterSettings(ResponseRateLimitingOptions options)
        {
            ImmutableArray<int> ipv4PrefixLengths = ImmutableArray.Create(32, 24);
            ImmutableArray<int> ipv6PrefixLengths = ImmutableArray.Create(128, 64, 56);
            NormalizedDnsResponseRateLimiterOptions normalizedLimiter = new DnsResponseRateLimiterOptions
            {
                Capacity = options.TableSize,
                ShardCount = 16,
                SustainedRate = options.SustainedRate,
                DecayTime = TimeSpan.FromSeconds(1),
                InstantLimit = options.InstantLimit,
                InstantWindow = TimeSpan.FromSeconds(1),
                SlipEvery = options.SlipEvery,
                IPv4PrefixLengths = ipv4PrefixLengths,
                IPv6PrefixLengths = ipv6PrefixLengths
            }.Normalize(TimeProvider.System.TimestampFrequency);
            return new RrlLimiterSemanticSettings(
                normalizedLimiter.Capacity, normalizedLimiter.ShardCount, options.SustainedRate,
                normalizedLimiter.ScaledTokenCapacity, normalizedLimiter.ScaledTokensPerSecond,
                normalizedLimiter.InstantLimit, normalizedLimiter.InstantWindowTimestampUnits,
                normalizedLimiter.SlipEvery, ipv4PrefixLengths, ipv6PrefixLengths, RrlKeyInterpretation.ResponseIdentityV1);
        }

        // Parameter names intentionally mirror DnsServer's public ResponseRateLimit* property
        // names shown in the web UI and API, since that is what these exceptions describe.
        private static void ValidateOptions(ResponseRateLimitingOptions options)
        {
            if (options.SustainedRate < 1 || options.SustainedRate > SustainedRateMaximum)
                throw new ArgumentOutOfRangeException("ResponseRateLimit", $"Value must be between 1 and {SustainedRateMaximum} responses per second.");
            if (options.InstantLimit < 1)
                throw new ArgumentOutOfRangeException("ResponseRateLimitInstant");
            if (options.SlipEvery < 0)
                throw new ArgumentOutOfRangeException("ResponseRateLimitSlip");
            if ((options.TableSize < TableSizeMinimum) || (options.TableSize > TableSizeMaximum))
                throw new ArgumentOutOfRangeException("ResponseRateLimitTableSize", $"Value must be between {TableSizeMinimum} and {TableSizeMaximum} entries.");
            if (options.BypassList is not null && options.BypassList.Count > byte.MaxValue)
                throw new ArgumentOutOfRangeException("ResponseRateLimitBypassList");
        }
    }
}
