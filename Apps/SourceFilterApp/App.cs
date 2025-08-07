﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using DnsServerCore.ApplicationCommon;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace SourceFilterApp;

public sealed class App : IDnsApplication, IDnsPostProcessor
{
    #region IDisposable

    public void Dispose() { }

    #endregion

    #region properties

    public string Description => "Filters answer records by client network according to include/exclude rules and optional splitNetworks.";

    #endregion

    #region private

    private Rule GetRule(string name)
    {
        Rule best = null;
        var bestScore = -1;

        foreach (var rule in this.rules)
        {
            var score = rule.Match(name);

            if (score <= bestScore)
                continue;
            bestScore = score;
            best = rule;
        }

        return best;
    }

    #endregion

    #region variables

    private bool enabled;
    private Rule[] rules;

    #endregion

    #region public

    public Task InitializeAsync(IDnsServer dnsServer, string config)
    {
        var list = new List<Rule>();

        if (string.IsNullOrEmpty(config))
        {
            this.enabled = false;

            return Task.CompletedTask;
        }

        using (var json = JsonDocument.Parse(config))
        {
            var root = json.RootElement;
            this.enabled = !root.TryGetProperty("enabled", out var jsonEnabled) || jsonEnabled.GetBoolean();

            if (root.TryGetProperty("rules", out var jsonRules) && jsonRules.ValueKind == JsonValueKind.Array)
                foreach (var jsonRule in jsonRules.EnumerateArray())
                    list.Add(new(jsonRule));
            else
                foreach (var prop in root.EnumerateObject().Where(prop => !prop.NameEquals("enabled")))
                    list.Add(new(prop.Name, prop.Value));
        }

        this.rules = list.Count == 0 ? [] : list.ToArray();

        return Task.CompletedTask;
    }

    public Task<DnsDatagram> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
    {
        if (!this.enabled)
            return Task.FromResult(response);

        if (response.Answer.Count == 0)
            return Task.FromResult(response);

        var clientIp = remoteEP.Address;
        var answer = new List<DnsResourceRecord>(response.Answer.Count);

        foreach (var record in response.Answer)
        {
            var rule = this.GetRule(record.Name);
            if (rule is null)
            {
                answer.Add(record);

                continue;
            }

            if (!rule.IsClientAllowed(clientIp))
                continue;

            if (rule.PassesSplit(clientIp, record))
                answer.Add(record);
        }

        if (answer.Count == response.Answer.Count)
            return Task.FromResult(response);

        if (answer.Count == 0)
            return Task.FromResult(response.Clone([]));

        return Task.FromResult(response.Clone(answer));
    }

    #endregion

    #region inner

    private sealed class Rule
    {
        private readonly NetworkSet exclude;
        private readonly NetworkSet include;
        private readonly string pattern;
        private readonly int specificity;
        private readonly SplitNetwork[] split;
        private readonly bool wildcard;

        public Rule(JsonElement json) : this(
            (json.TryGetProperty("pattern", out var jsonPattern)
                ? jsonPattern.ValueKind == JsonValueKind.String ? jsonPattern.GetString() : jsonPattern.ToString()
                : null)
            ?? "*",
            json) { }

        public Rule(string pattern, JsonElement jsonRule)
        {
            this.pattern = Normalize(pattern);
            this.wildcard = this.pattern == "*" || this.pattern.StartsWith("*.");
            this.specificity = this.wildcard ? this.pattern == "*" ? 0 : this.pattern.Length - 2 : this.pattern.Length;

            this.include = new(GetNetworks(jsonRule, true, "includeNetworks", "include"));
            this.exclude = new(GetNetworks(jsonRule, false, "excludeNetworks", "exclude"));
            this.split = GetSplitNetworks(jsonRule);
        }

        private static List<NetworkAddress> GetNetworks(JsonElement json, bool addDefault, params string[] names)
        {
            var list = new List<NetworkAddress>();

            foreach (var n in names)
            {
                if (!json.TryGetProperty(n, out var value) || value.ValueKind != JsonValueKind.Array)
                    continue;

                foreach (var str in value.EnumerateArray().Select(x => x.GetString()))
                    if (NetworkAddress.TryParse(str, out var addr))
                        list.Add(addr);
            }

            if (addDefault && list.Count == 0)
            {
                list.Add(NetworkAddress.Parse("0.0.0.0/0"));
                list.Add(NetworkAddress.Parse("::/0"));
            }

            return list;
        }

        public int Match(string name)
        {
            name = Normalize(name);

            if (this.pattern == "*")
                return 0;

            if (this.wildcard)
            {
                if (!name.EndsWith(this.pattern[1..], StringComparison.OrdinalIgnoreCase))
                    return -1;
                if (name.Length == this.specificity)
                    return -1;

                return this.specificity;
            }

            return name.Equals(this.pattern, StringComparison.OrdinalIgnoreCase)
                ? this.specificity
                : -1;
        }

        public bool IsClientAllowed(IPAddress clientIp)
        {
            if (!this.include.Contains(clientIp))
                return false;
            if (this.exclude.Contains(clientIp))
                return false;

            return true;
        }

        private static SplitNetwork[] GetSplitNetworks(JsonElement json)
        {
            if (!json.TryGetProperty("splitNetworks", out var value) || value.ValueKind != JsonValueKind.Array)
                return [];

            var list = new List<SplitNetwork>();

            foreach (var elem in value.EnumerateArray())
            {
                if (elem.ValueKind == JsonValueKind.String)
                {
                    if (NetworkAddress.TryParse(elem.GetString(), out var net))
                        list.Add(new SplitNetwork(net, null));
                }
                else if (elem.ValueKind == JsonValueKind.Object)
                {
                    if (!elem.TryGetProperty("network", out var netProp) || netProp.ValueKind != JsonValueKind.String)
                        continue;
                    if (!NetworkAddress.TryParse(netProp.GetString(), out var net))
                        continue;

                    int? samePrefix = null;
                    if (elem.TryGetProperty("samePrefix", out var prefProp) && prefProp.ValueKind == JsonValueKind.Number)
                        samePrefix = prefProp.GetInt32();

                    list.Add(new SplitNetwork(net, samePrefix));
                }
            }

            return list.Count == 0 ? [] : list.ToArray();
        }

        private static bool TryParseSplitNetwork(string str, out SplitNetwork split)
        {
            split = default;

            if (string.IsNullOrWhiteSpace(str))
                return false;

            var parts = str.Split('/');

            if (parts.Length == 3)
            {
                var networkPart = $"{parts[0]}/{parts[1]}";

                if (!NetworkAddress.TryParse(networkPart, out var net))
                    return false;
                if (!int.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var samePrefix))
                    return false;
                split = new SplitNetwork(net, samePrefix);

                return true;
            }

            if (NetworkAddress.TryParse(str, out var network))
            {
                split = new SplitNetwork(network, null);

                return true;
            }

            return false;
        }

        public bool PassesSplit(IPAddress clientIp, DnsResourceRecord record)
        {
            if (this.split.Length == 0)
                return true;

            var recordIp = record switch
            {
                { Type: DnsResourceRecordType.A, RDATA: DnsARecordData a } => a.Address,
                { Type: DnsResourceRecordType.AAAA, RDATA: DnsAAAARecordData aaaa } => aaaa.Address,
                _ => null
            };

            if (recordIp is null)
                return true;

            var clientInsideAny = false;
            var recordInsideAny = false;

            foreach (var sn in this.split)
            {
                var clientInside = sn.Network.Contains(clientIp);
                var recordInside = sn.Network.Contains(recordIp);

                if (clientInside && recordInside && sn.SamePrefix.HasValue && !IpPrefixEqual(clientIp, recordIp, sn.SamePrefix.Value))
                    return false;

                clientInsideAny |= clientInside;
                recordInsideAny |= recordInside;
            }

            return clientInsideAny == recordInsideAny;
        }

        private static bool IpPrefixEqual(IPAddress a, IPAddress b, int prefixBits)
        {
            var aBytes = a.GetAddressBytes();
            var bBytes = b.GetAddressBytes();

            if (aBytes.Length != bBytes.Length || prefixBits < 0)
                return false;

            var maxBits = aBytes.Length * 8;
            if (prefixBits > maxBits)
                prefixBits = maxBits;

            var bits = prefixBits;

            for (var i = 0; i < aBytes.Length && bits > 0; i++)
            {
                var take = bits >= 8 ? 8 : bits;
                var mask = (byte)(0xFF << (8 - take));

                if ((aBytes[i] & mask) != (bBytes[i] & mask))
                    return false;
                bits -= take;
            }

            return true;
        }

        private readonly struct SplitNetwork
        {
            public SplitNetwork(NetworkAddress network, int? samePrefix)
            {
                this.Network = network;
                this.SamePrefix = samePrefix;
            }

            public NetworkAddress Network { get; }
            public int? SamePrefix { get; }
        }
    }

    private sealed class NetworkSet
    {
        private readonly NetworkAddress[] nets;

        public NetworkSet(IReadOnlyList<NetworkAddress> nets) => this.nets = nets.Count == 0 ? [] : nets.ToArray();

        public bool IsEmpty => this.nets.Length == 0;

        public bool Contains(IPAddress ip)
        {
            foreach (var net in this.nets)
                if (net.Contains(ip))
                    return true;

            return false;
        }
    }

    private static readonly IdnMapping idn = new();

    private static string Normalize(string s)
    {
        s = s.TrimEnd('.');

        if (s == "*")
            return s.ToLowerInvariant();
        if (s.StartsWith("*."))
            return "*." + idn.GetAscii(s[2..]).ToLowerInvariant();

        return idn.GetAscii(s).ToLowerInvariant();
    }

    #endregion
}