/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)
Copyright (C) 2025  Zafer Balkan (zafer@zaferbalkan.com)

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

using BloomFilter;
using FuzzySharp;
using Nager.PublicSuffix;
using Nager.PublicSuffix.RuleProviders;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace TyposquattingDetector
{
    public enum Reason
    { Exact, Typosquatting, NoCandidates }

    public enum Severity
    { NONE, LOW, MEDIUM, HIGH }

    public class Result
    {
        public Result(string query) => Query = query;

        public string? BestMatch { get; set; }
        public int FuzzyScore { get; set; }
        public string Query { get; }
        public Reason Reason { get; set; }
        public Severity Severity { get; set; } = Severity.NONE;
        public bool IsSuspicious { get; set; }
    }

    public class TyposquattingDetector : IDisposable
    {
        #region variables

        private static CachedHttpRuleProvider? _sharedRuleProvider;
        private readonly Dictionary<int, List<string>> _lenBuckets = new Dictionary<int, List<string>>();
        private readonly ThreadLocal<DomainParser> _normalizer;
        private readonly int _threshold;
        private IBloomFilter? _bloomFilter;
        private readonly HttpClient _httpClient = new HttpClient();
        private readonly object _reductionLock = new object();
        private static readonly object _staticInitLock = new object();
        private bool _disposedValue;
        private class MatchState
        {
            public string? BestDomain;
            public int BestScore;
        }

        #endregion variables

        #region constructor

        public TyposquattingDetector(string defaultPath, string customPath, int threshold)
        {
            _threshold = threshold;

            // Thread-safe static initialization
            lock (_staticInitLock)
            {
                if (_sharedRuleProvider == null)
                {
                    var cacheProvider = new Nager.PublicSuffix.RuleProviders.CacheProviders.LocalFileSystemCacheProvider();
                    _sharedRuleProvider = new CachedHttpRuleProvider(cacheProvider, _httpClient);
                    _sharedRuleProvider.BuildAsync().GetAwaiter().GetResult();
                }
            }

            _normalizer = new ThreadLocal<DomainParser>(() =>
                new DomainParser(_sharedRuleProvider, new Nager.PublicSuffix.DomainNormalizers.UriDomainNormalizer()));

            LoadData(defaultPath, customPath);
        }


        #endregion constructor

        #region Dispose
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    _httpClient?.Dispose();
                    _normalizer?.Dispose();
                }
                _disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion Dispose

        #region public
        public Result Check(string query)
        {
            var normalized = Normalize(query);
            var result = new Result(normalized);

            // GATE 1: Bloom Filter Prefilter (O(1))
            if (_bloomFilter is not null && _bloomFilter.Contains(normalized))
            {
                result.IsSuspicious = false;
                result.Reason = Reason.Exact;
                return result;
            }

            // GATE 2: Fuzzy Similarity Check
            return FuzzyMatch(normalized, result);
        }
        #endregion public

        #region private
        private Result FuzzyMatch(string query, Result result)
        {
            var globalState = new MatchState { BestDomain = null, BestScore = 0 };

            var bucketIndices = new[] { query.Length - 1, query.Length, query.Length + 1 };

            foreach (int len in bucketIndices)
            {
                if (!_lenBuckets.TryGetValue(len, out var bucket)) continue;

                const int SequentialCutoff = 256;
                int maxDop = Math.Max(1, Environment.ProcessorCount / 2);

                if (bucket.Count <= SequentialCutoff)
                {
                    SequentialMatch(query, globalState, bucket);
                }
                else
                {
                    ParallelMatch(query, globalState, bucket, maxDop);
                }

                if (globalState.BestScore >= 98) break;
            }

            if (globalState.BestDomain != null)
            {
                result.BestMatch = globalState.BestDomain;
                result.FuzzyScore = globalState.BestScore;
                result.IsSuspicious = true;
                result.Severity = globalState.BestScore > 90 ? Severity.HIGH : Severity.MEDIUM;
                result.Reason = Reason.Typosquatting;
            }
            else
            {
                result.IsSuspicious = false;
                result.Reason = Reason.NoCandidates;
            }

            return result;
        }

        private void SequentialMatch(string query, MatchState state, List<string> bucket)
        {
            foreach (var domain in bucket)
            {
                if (state.BestScore >= 98) break;

                if (!PassesPrefilter(query, domain, _threshold))
                    continue;

                int score = Fuzz.WeightedRatio(query, domain);

                if (score > state.BestScore)
                {
                    state.BestScore = score;
                    state.BestDomain = domain;
                }

                if (score >= 95) break;
            }
        }

        private void ParallelMatch(string query, MatchState globalState, List<string> bucket, int maxDop)
        {
            var po = new ParallelOptions { MaxDegreeOfParallelism = maxDop };

            Parallel.ForEach(
                bucket,
                po,
                () => (score: 0, dom: (string?)null), // Thread-local state
                (domain, state, local) =>
                {
                    // Volatile check for early exit
                    if (Volatile.Read(ref globalState.BestScore) >= 98)
                    {
                        state.Stop();
                        return local;
                    }

                    if (!PassesPrefilter(query, domain, _threshold))
                        return local;

                    int score = Fuzz.WeightedRatio(query, domain);

                    if (score > local.score)
                        local = (score, domain);

                    if (score >= 95) state.Stop();

                    return local;
                },
                local =>
                {
                    // Reduction phase: Merge thread-local winner into global state
                    if (local.dom != null)
                    {
                        lock (globalState) // Lock on the state object
                        {
                            if (local.score > globalState.BestScore)
                            {
                                globalState.BestScore = local.score;
                                globalState.BestDomain = local.dom;
                            }
                        }
                    }
                }
            );
        }

        private static bool PassesPrefilter(string q, string d, int threshold)
        {
            int dl = d.Length;
            int ql = q.Length;

            // reject far-length candidates
            if (Math.Abs(dl - ql) > 2)
                return false;

            // fast first-char rejection
            if (q[0] != d[0])
                return false;

            // tiny strings → go straight to Fuzz()
            if (ql < 4 || dl < 4)
                return true;

            // small trigram overlap check (no alloc)
            int hits = 0;
            for (int i = 0; i < Math.Min(ql, dl) - 2; i++)
                if (d.AsSpan().IndexOf(q.AsSpan(i, 3)) >= 0) hits++;

            // require minimal neighborhood similarity
            return hits >= 1 || threshold <= 80;
        }

        private static string? ExtractDomain(string line)
        {
            ReadOnlySpan<char> span = line.AsSpan();
            int firstComma = span.IndexOf(',');
            if (firstComma == -1) return null;
            ReadOnlySpan<char> afterFirst = span.Slice(firstComma + 1);
            int secondComma = afterFirst.IndexOf(',');
            if (secondComma == -1) return null;
            ReadOnlySpan<char> afterSecond = afterFirst.Slice(secondComma + 1);
            int thirdComma = afterSecond.IndexOf(',');
            return (thirdComma == -1 ? afterSecond : afterSecond.Slice(0, thirdComma)).ToString();
        }

        private void LoadData(string oneMilFilePath, string customPath)
        {
            // Capacity for 1M domains + custom list
            _bloomFilter = FilterBuilder.Build(1_100_000, 0.001);

            // Helper to add domains to both Bloom and Buckets
            void processDomain(string domain)
            {
                if (string.IsNullOrWhiteSpace(domain)) return;
                domain = domain.ToLowerInvariant();
                _bloomFilter.Add(domain);
                if (!_lenBuckets.TryGetValue(domain.Length, out var list))
                {
                    list = new List<string>();
                    _lenBuckets[domain.Length] = list;
                }
                // Cap fuzzy search candidates per length to keep search times predictable
                if (list.Count < 15000) list.Add(domain);
            }

            // 1. Load custom list
            if (!string.IsNullOrEmpty(customPath) && File.Exists(customPath))
            {
                foreach (var line in File.ReadLines(customPath))
                    processDomain(line.Trim());
            }

            // 2. Load Majestic 1M
            if (File.Exists(oneMilFilePath))
            {
                using var fs = new FileStream(oneMilFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024);
                using var reader = new StreamReader(fs);
                reader.ReadLine(); // Skip header

                while (reader.ReadLine() is { } line)
                {
                    var domain = ExtractDomain(line);
                    if (domain != null) processDomain(domain);
                }
            }
        }

        private string Normalize(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return s;
            try
            {
                var registrableDomain = _normalizer?.Value?.Parse(s)?.RegistrableDomain;
                return registrableDomain ?? s;
            }
            catch
            {
                var clean = s.ToLowerInvariant().Trim();
                if (clean.StartsWith("www.")) clean = clean.Substring(4);
                if (clean.StartsWith("m.")) clean = clean.Substring(2);
                return clean;
            }
        }
        #endregion private
    }
}