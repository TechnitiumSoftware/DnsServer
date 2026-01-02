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
using Nager.PublicSuffix.RuleProviders.CacheProviders;
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
    {
        Exact,
        Typosquatting,
        NoCandidates
    }

    public enum Severity
    {
        NONE,
        LOW,
        MEDIUM,
        HIGH
    }

    public class Result
    {
        public Result(string query)
        {
            Query = query;
        }

        public string? BestMatch { get; set; }
        public int FuzzyScore { get; set; }
        public bool IsSuspicious { get; set; }
        public string Query { get; }
        public Reason Reason { get; set; }
        public Severity Severity { get; set; } = Severity.NONE;
    }

     public partial class TyposquattingDetector : IDisposable
    {
        #region variables

        private static readonly HttpClient _pslHttpClient = new HttpClient();

        private static readonly Lazy<CachedHttpRuleProvider> _sharedRuleProvider =
            new Lazy<CachedHttpRuleProvider>(static () =>
            {
                LocalFileSystemCacheProvider cacheProvider = new LocalFileSystemCacheProvider();
                CachedHttpRuleProvider rp = new CachedHttpRuleProvider(cacheProvider, _pslHttpClient);
                rp.BuildAsync().GetAwaiter().GetResult();
                return rp;
            }, isThreadSafe: true);

        private readonly Dictionary<int, List<string>> _lenBuckets = new Dictionary<int, List<string>>();
        private readonly ThreadLocal<DomainParser> _normalizer;
        private readonly ParallelOptions _po;
        private readonly int _threshold;
        private IBloomFilter? _bloomFilter;
        private bool _disposedValue;

        #endregion variables

        #region constructor

        public TyposquattingDetector(string defaultPath, string customPath, int threshold)
        {
            _threshold = threshold;
            _po = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount / 2) };

            _normalizer = new ThreadLocal<DomainParser>(() =>
                new DomainParser(_sharedRuleProvider.Value, new Nager.PublicSuffix.DomainNormalizers.UriDomainNormalizer()));

            LoadData(defaultPath, customPath);
        }

        #endregion constructor

        #region Dispose

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    _normalizer?.Dispose();
                }
                _disposedValue = true;
            }
        }

        #endregion Dispose

        #region public

        public Result Check(string query)
        {
            string? normalized = Normalize(query);
            if (normalized == null)
            {
                return new Result(query)
                {
                    IsSuspicious = false,
                    Reason = Reason.NoCandidates
                };
            }

            Result result = new Result(normalized);

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

        private static bool PassesPrefilter(string q, string d, int threshold)
        {
            if (string.IsNullOrEmpty(q) || string.IsNullOrEmpty(d))
                return false;

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
            int maxTrigrams = Math.Min(10, Math.Min(ql, dl) - 2);
            for (int i = 0; i < maxTrigrams; i++)
                if (d.AsSpan().IndexOf(q.AsSpan(i, 3)) >= 0) hits++;

            // require minimal neighborhood similarity
            return hits >= 1 || threshold <= 80;
        }

        private Result FuzzyMatch(string query, Result result)
        {

            //MatchState globalState = new MatchState { BestDomain = null, BestScore = 0 };
            MatchState globalState = GetState();
            globalState.BestDomain = null;
            globalState.BestScore = 0;

            for (int delta = -1; delta <= 1; delta++)
            {
                int len = query.Length + delta;
                if (!_lenBuckets.TryGetValue(len, out var bucket)) continue;

                const int SequentialCutoff = 256;

                if (bucket.Count <= SequentialCutoff)
                    SequentialMatch(query, globalState, bucket);
                else
                    ParallelMatch(query, globalState, bucket);

                if (globalState.BestScore >= 98) break;
            }


            if (globalState.BestDomain != null)
            {
                GetSuspiciousResult(result, globalState);
            }
            else
            {
                GetNormalResult(result);
            }
            ReturnState(globalState);
            return result;
        }

        private static void GetNormalResult(Result result)
        {
            result.IsSuspicious = false;
            result.Reason = Reason.NoCandidates;
        }

        private static void GetSuspiciousResult(Result result, MatchState globalState)
        {
            result.BestMatch = globalState.BestDomain;
            result.FuzzyScore = globalState.BestScore;
            result.IsSuspicious = true;
            result.Severity = globalState.BestScore > 90 ? Severity.HIGH : Severity.MEDIUM;
            result.Reason = Reason.Typosquatting;
        }

        private void LoadData(string oneMilFilePath, string customPath)
        {
            // Capacity for 1M domains + custom list
            _bloomFilter = FilterBuilder.Build(1_100_000, 0.001);

            // Helper to add domains to both Bloom and Buckets
            void processDomain(string domain)
            {
                if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrEmpty(domain)) return;

                domain = domain.ToLowerInvariant();
                _bloomFilter.Add(domain);
                if (!_lenBuckets.TryGetValue(domain.Length, out List<string>? list))
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
                foreach (string line in File.ReadLines(customPath))
                    processDomain(line.Trim());
            }

            // 2. Load Majestic 1M
            if (File.Exists(oneMilFilePath))
            {
                using FileStream fs = new FileStream(oneMilFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024);
                using StreamReader reader = new StreamReader(fs);
                reader.ReadLine(); // Skip header

                while (reader.ReadLine() is { } line)
                {
                    string? domain = ExtractDomain(line);
                    if (domain != null) processDomain(domain);
                }
            }
        }

        private string? Normalize(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return null;

            try
            {
                string? rd = _normalizer.Value?.Parse(s)?.RegistrableDomain;
                if (string.IsNullOrWhiteSpace(rd)) rd = s;
                return rd.TrimEnd('.').ToLowerInvariant();
            }
            catch
            {
                string? clean = s.Trim().TrimEnd('.').ToLowerInvariant();
                if (clean.StartsWith("www.")) clean = clean.Substring(4);
                if (clean.StartsWith("m.")) clean = clean.Substring(2);
                return clean;
            }
        }

        private void ParallelMatch(string query, MatchState globalState, List<string> bucket)
        {
            Parallel.ForEach(
                bucket,
                _po,
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
                    if (local.dom == null)
                    {
                        return;
                    }
                    lock (globalState)
                    {
                        if (local.score <= globalState.BestScore)
                        {
                            return;
                        }
                        globalState.BestScore = local.score;
                        globalState.BestDomain = local.dom;
                    }
                }
            );
        }

        private void SequentialMatch(string query, MatchState state, List<string> bucket)
        {
            foreach (string domain in bucket)
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

        #endregion private
    }
}