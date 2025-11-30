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
    public enum DetectionStatus { Clean, Possible, Suspicious }
    public enum Severity { NONE, LOW, MEDIUM, HIGH }
    public enum Reason { BloomReject, Exact, Typosquatting, Medium, Low, NoCandidates }

    public class Result
    {
        public string Query { get; }
        public DetectionStatus Status { get; set; }
        public Severity Severity { get; set; }
        public Reason Reason { get; set; }
        public string? BestMatch { get; set; }
        public int FuzzyScore { get; set; }

        public Result(string query) => Query = query;
    }

    public class TyposquattingDetector
    {
        private static IRuleProvider _sharedRuleProvider;
        private readonly ThreadLocal<DomainParser> _normalizer;
        private IBloomFilter _bloomFilter;
        private readonly Dictionary<int, List<string>> _lenBuckets = new();
        private readonly int _threshold;

        public TyposquattingDetector(string path, int threshold)
        {
            _threshold = threshold;

            if (_sharedRuleProvider == null)
            {
                var cacheProvider = new Nager.PublicSuffix.RuleProviders.CacheProviders.LocalFileSystemCacheProvider();
                _sharedRuleProvider = new CachedHttpRuleProvider(cacheProvider, new HttpClient());
                _sharedRuleProvider.BuildAsync().GetAwaiter().GetResult();
            }

            _normalizer = new ThreadLocal<DomainParser>(() =>
                new DomainParser(_sharedRuleProvider, new Nager.PublicSuffix.DomainNormalizers.UriDomainNormalizer()));

            LoadData(path);
        }

        private void LoadData(string filePath)
        {
            _bloomFilter = FilterBuilder.Build(1_000_000, 0.01);

            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536);
            using var reader = new StreamReader(fs);
            reader.ReadLine();

            while (reader.ReadLine() is { } line)
            {
                string? domain = ExtractDomain(line);
                if (string.IsNullOrEmpty(domain)) continue;

                _bloomFilter.Add(domain);

                if (!_lenBuckets.TryGetValue(domain.Length, out var list))
                {
                    list = new List<string>();
                    _lenBuckets[domain.Length] = list;
                }
                if (list.Count < 10000) list.Add(domain);
            }
        }

        public async Task<Result> FuzzyMatchAsync(string query)
        {
            var q = Normalize(query);
            var r = new Result(q);

            // GATE 1: Known Famous Site
            // If it's in the top 1M, it's 100% clean.
            if (_bloomFilter.Contains(q))
            {
                r.Status = DetectionStatus.Clean;
                r.Reason = Reason.Exact;
                return r;
            }

            // GATE 2: Fuzzy Similarity Check
            return await Task.Run(() =>
            {
                var candidates = new List<string>();
                for (int i = -1; i <= 1; i++)
                    if (_lenBuckets.TryGetValue(q.Length + i, out var bucket))
                        candidates.AddRange(bucket);

                var best = candidates
                    .Select(d => new { d, score = Fuzz.WeightedRatio(q, d) })
                    .OrderByDescending(x => x.score)
                    .FirstOrDefault();

                // Logic: If score is [75-99], it's a suspicious lookalike.
                // If score is < 75, it's just a random domain (Clean).
                // Note: score of 100 would have been caught by the Bloom Filter.
                if (best != null && best.score >= _threshold)
                {
                    r.BestMatch = best.d;
                    r.FuzzyScore = best.score;
                    r.Status = DetectionStatus.Suspicious;
                    r.Severity = Severity.HIGH;
                    r.Reason = Reason.Typosquatting;
                }
                else
                {
                    r.Status = DetectionStatus.Clean;
                    r.Reason = Reason.BloomReject;
                }

                return r;
            });
        }

        private string Normalize(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return s;
            try
            {
                return _normalizer!.Value!.Parse(s)!.RegistrableDomain ?? s;
            }
            catch
            {
                return s.ToLowerInvariant().Trim().Replace("www.", "");
            }
        }

        private string? ExtractDomain(string line)
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
    }
}
