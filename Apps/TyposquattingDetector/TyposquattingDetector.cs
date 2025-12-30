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

namespace TyposquattingDetector
{
    public enum DetectionStatus
    { Clean, Possible, Suspicious }

    public enum Reason
    { BloomReject, Exact, Typosquatting, Medium, Low, NoCandidates }

    public enum Severity
    { NONE, LOW, MEDIUM, HIGH }

    public class Result
    {
        public Result(string query) => Query = query;

        public string? BestMatch { get; set; }
        public int FuzzyScore { get; set; }
        public string Query { get; }
        public Reason Reason { get; set; }
        public Severity Severity { get; set; }
        public DetectionStatus Status { get; set; }
    }

    public class TyposquattingDetector
    {
        private static CachedHttpRuleProvider? _sharedRuleProvider;
        private readonly Dictionary<int, List<string>> _lenBuckets = new Dictionary<int, List<string>>();
        private readonly ThreadLocal<DomainParser> _normalizer;
        private readonly int _threshold;
        private IBloomFilter? _bloomFilter;

        public TyposquattingDetector(string defaultPath, string customPath, int threshold)
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

            LoadData(defaultPath, customPath);
        }

        public Result Check(string query)
        {
            var normalized = Normalize(query);
            var result = new Result(normalized);

            // GATE 1: Known Famous Site
            (bool flowControl, Result? prefilterResult) = Prefilter(normalized, result);
            if (!flowControl)
            {
                return prefilterResult!;
            }

            // GATE 2: Fuzzy Similarity Check
            return FuzzyMatch(normalized, result);
        }

        private Result FuzzyMatch(string q, Result r)
        {
            // Remove Task.Run and the await lambda
            var candidates = new List<string>();
            for (int i = -1; i <= 1; i++)
                if (_lenBuckets.TryGetValue(q.Length + i, out var bucket))
                    candidates.AddRange(bucket);

            var best = candidates
                .Select(d => new { d, score = Fuzz.WeightedRatio(q, d) })
                .OrderByDescending(x => x.score)
                .FirstOrDefault();

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
        }

        private (bool flowControl, Result? value) Prefilter(string q, Result r)
        {
            if (_bloomFilter.Contains(q))
            {
                r.Status = DetectionStatus.Clean;
                r.Reason = Reason.Exact;
                return (flowControl: false, value: r);
            }

            return (flowControl: true, value: null);
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

        private void LoadData(string filePath, string customPath)
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

            if (!string.IsNullOrEmpty(customPath) && File.Exists(customPath))
            {
                foreach (var line in File.ReadLines(customPath))
                {
                    var domain = line.Trim();
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
    }
}