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

using System;
using System.Collections.Concurrent;
using Nager.PublicSuffix;
using Nager.PublicSuffix.RuleProviders;

namespace LogExporter
{
    /// <summary>
    /// Thread-safe cache for parsed domain information using the SIEVE eviction algorithm. 
    /// SIEVE provides better scan resistance than LRU, making it ideal for DNS workloads
    /// where one-time queries (typos, DGA domains) are common.  
    /// 
    /// Reference: "SIEVE is Simpler than LRU: an Efficient Turn-Key Eviction Algorithm for 
    /// Web Caches" (NSDI '24)
    /// </summary>
    internal sealed class DomainCache
    {
        private const int MaxSize = 10000;
        private const int StringPoolMaxSize = 10000;

        // ADR: Loading the PSL must not block or fail plugin startup. We defer
        // initialization and make it best-effort to avoid network dependencies.
        private static readonly Lazy<DomainParser?> _parser = new Lazy<DomainParser?>(InitializeParser);

        private readonly ConcurrentDictionary<string, CacheNode> _cache =
            new ConcurrentDictionary<string, CacheNode>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, string> _stringPool =
            new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _evictionLock = new object();

        // SIEVE data structures
        private CacheNode? _head;
        private CacheNode? _tail;
        private CacheNode? _hand;

        public int Count => _cache.Count;

        public DomainInfo GetOrAdd(string domainName)
        {
            if (string.IsNullOrWhiteSpace(domainName))
                return DomainInfo.Empty;

            // Fast path: try cache lookup with original name first (case-insensitive)
            if (_cache.TryGetValue(domainName, out CacheNode? node))
            {
                node.Visited = true;
                return node.Domain;
            }

            // Normalize only if needed, using string pool to reduce allocations
            string normalizedName = GetPooledNormalizedName(domainName);

            // Check cache again with normalized name (may differ from original)
            if (!ReferenceEquals(normalizedName, domainName) &&
                _cache.TryGetValue(normalizedName, out node))
            {
                node.Visited = true;
                return node.Domain;
            }

            DomainInfo domain = Parse(domainName);
            AddToCache(normalizedName, domain);
            return domain;
        }

        /// <summary>
        /// Returns a pooled, normalized version of the domain name to reduce allocations.
        /// If the name is already normalized, returns the original string.
        /// </summary>
        private string GetPooledNormalizedName(string name)
        {
            if (!NeedsNormalization(name))
                return name;

            string normalized = name.ToLowerInvariant().TrimEnd('.');

            // Try to get from pool, or add if not present
            if (_stringPool.TryGetValue(normalized, out string? pooled))
                return pooled;

            // Limit pool size to prevent unbounded growth
            if (_stringPool.Count < StringPoolMaxSize)
            {
                _stringPool.TryAdd(normalized, normalized);
            }

            return normalized;
        }

        /// <summary>
        /// Checks if the domain name needs normalization (has uppercase or trailing dot).
        /// </summary>
        private static bool NeedsNormalization(string name)
        {
            if (name.Length > 0 && name[^1] == '.')
                return true;

            foreach (char c in name)
            {
                if (c >= 'A' && c <= 'Z')
                    return true;
            }

            return false;
        }

        private static DomainInfo Parse(string name)
        {
            DomainParser? parser = _parser.Value;
            if (parser == null)
                return DomainInfo.Empty;

            try
            {
                Nager.PublicSuffix.DomainInfo? info = parser.Parse(name);
                if (info == null)
                    return DomainInfo.Empty;

                return new DomainInfo(
                    tld: info.TopLevelDomain ?? string.Empty,
                    baseDomain: info.RegistrableDomain ?? string.Empty,
                    subdomain: info.Subdomain ?? string.Empty
                );
            }
            catch
            {
                // Parsing errors are intentionally ignored because PSL is optional.
                return DomainInfo.Empty;
            }
        }

        private static DomainParser? InitializeParser()
        {
            // ADR: The PSL download via SimpleHttpRuleProvider performs outbound HTTP.
            // Relying on external network connectivity at plugin startup is unsafe in
            // production DNS environments (offline appliances, firewalled networks,
            // corporate proxies). Initialization must never block or fail due to PSL
            // retrieval. We therefore treat PSL availability as optional:
            //   - If the download succeeds, domain parsing is enriched.
            //   - If it fails, we return null and logging continues without PSL data.
            try
            {
                SimpleHttpRuleProvider provider = new SimpleHttpRuleProvider();
                provider.BuildAsync().GetAwaiter().GetResult();
                return new DomainParser(provider);
            }
            catch
            {
                return null;
            }
        }

        private void AddToCache(string key, DomainInfo domain)
        {
            lock (_evictionLock)
            {
                if (_cache.ContainsKey(key))
                    return;

                while (_cache.Count >= MaxSize)
                    Evict();

                CacheNode newNode = new CacheNode(key, domain);
                InsertAtHead(newNode);
                _cache[key] = newNode;
            }
        }

        private void InsertAtHead(CacheNode node)
        {
            node.Next = _head;
            node.Prev = null;

            if (_head != null)
                _head.Prev = node;

            _head = node;

            _tail ??= node;

            _hand ??= node;
        }

        private void Evict()
        {
            _hand ??= _tail;

            while (_hand != null)
            {
                if (!_hand.Visited)
                {
                    CacheNode victim = _hand;
                    _hand = _hand.Prev ?? _tail;
                    RemoveNode(victim);
                    _cache.TryRemove(victim.Key, out _);
                    return;
                }

                _hand.Visited = false;
                _hand = _hand.Prev ?? _tail;
            }
        }

        private void RemoveNode(CacheNode node)
        {
            if (node.Prev != null)
                node.Prev.Next = node.Next;
            else
                _head = node.Next;

            if (node.Next != null)
                node.Next.Prev = node.Prev;
            else
                _tail = node.Prev;

            if (_hand == node)
                _hand = node.Prev ?? _tail;
        }

        private class CacheNode
        {
            public readonly string Key;
            public readonly DomainInfo Domain;
            public volatile bool Visited;
            public CacheNode? Next;
            public CacheNode? Prev;

            public CacheNode(string key, DomainInfo domain)
            {
                Key = key;
                Domain = domain;
            }
        }
    }

    /// <summary>
    /// Immutable data class representing parsed domain information.
    /// </summary>
    public sealed class DomainInfo
    {
        public static readonly DomainInfo Empty = new DomainInfo(string.Empty, string.Empty, string.Empty);

        public string TLD { get; }
        public string BaseDomain { get; }
        public string Subdomain { get; }

        public DomainInfo(string tld, string baseDomain, string subdomain)
        {
            TLD = tld;
            BaseDomain = baseDomain;
            Subdomain = subdomain;
        }
    }
}