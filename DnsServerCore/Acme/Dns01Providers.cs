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

using DnsServerCore.Dns;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Acme
{
    enum Dns01ProviderType : byte
    {
        LocalZone = 1,
        Rfc2136 = 2,
        Cloudflare = 3
    }

    //Publishes and removes the _acme-challenge TXT record for a dns-01 challenge.
    //To add a provider: implement this interface, add a Dns01ProviderType value, and create it in AcmeManager.CreateProvider().
    interface IDns01Provider
    {
        Task AddTxtRecordAsync(string recordName, string value, CancellationToken cancellationToken);

        Task RemoveTxtRecordAsync(string recordName, string value, CancellationToken cancellationToken);
    }

    //Zone hosted on this DNS server. Works when this server (or its secondaries) is publicly authoritative for the zone,
    //either for the domain itself or for a zone that _acme-challenge is CNAME-delegated to.
    sealed class LocalZoneDns01Provider : IDns01Provider
    {
        const uint TXT_TTL = 60;

        readonly DnsServer _dnsServer;

        public LocalZoneDns01Provider(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;
        }

        private AuthZoneInfo GetPrimaryZone(string recordName)
        {
            AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.FindAuthZoneInfo(recordName);

            if (zoneInfo is null)
                throw new AcmeException("No zone on this DNS server contains '" + recordName + "'. Create the zone, delegate _acme-challenge to a zone on this server with a CNAME, or use another DNS-01 provider.");

            if (zoneInfo.Type != AuthZoneType.Primary)
                throw new AcmeException("Zone '" + zoneInfo.DisplayName + "' on this DNS server is a " + zoneInfo.TypeName + " zone; the challenge record can only be added to a Primary zone. On a Cluster secondary node, use the RFC 2136 provider pointed at the Primary node.");

            if (zoneInfo.Disabled)
                throw new AcmeException("Zone '" + zoneInfo.DisplayName + "' on this DNS server is disabled.");

            return zoneInfo;
        }

        public Task AddTxtRecordAsync(string recordName, string value, CancellationToken cancellationToken)
        {
            AuthZoneInfo zoneInfo = GetPrimaryZone(recordName);

            _dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, new DnsResourceRecord(recordName, DnsResourceRecordType.TXT, DnsClass.IN, TXT_TTL, new DnsTXTRecordData(value)));
            _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            return Task.CompletedTask;
        }

        public Task RemoveTxtRecordAsync(string recordName, string value, CancellationToken cancellationToken)
        {
            AuthZoneInfo zoneInfo = GetPrimaryZone(recordName);

            if (_dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, recordName, DnsResourceRecordType.TXT, new DnsTXTRecordData(value)))
                _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            return Task.CompletedTask;
        }
    }

    //RFC 2136 dynamic update, optionally TSIG signed. Works with BIND, PowerDNS, Knot, Windows DNS, another
    //Technitium server (including a Cluster primary) and DNS hosting services that accept dynamic updates.
    sealed class Rfc2136Dns01Provider : IDns01Provider
    {
        const uint TXT_TTL = 60;

        readonly string _server;
        readonly TsigKey _tsigKey;

        public Rfc2136Dns01Provider(string server, TsigKey tsigKey)
        {
            if (string.IsNullOrWhiteSpace(server))
                throw new AcmeException("RFC 2136 provider requires the address of the DNS server that accepts dynamic updates.");

            _server = server.Trim();
            _tsigKey = tsigKey;
        }

        private async Task<DnsClient> GetClientAsync(CancellationToken cancellationToken)
        {
            string host = _server;
            int port = 53;

            //host, host:port, [ipv6]:port
            if (host.StartsWith('['))
            {
                int end = host.IndexOf(']');
                if ((end > 0) && (end + 2 < host.Length) && (host[end + 1] == ':'))
                    port = int.Parse(host.Substring(end + 2));

                host = host.Substring(1, end - 1);
            }
            else if ((host.Count(c => c == ':') == 1))
            {
                int i = host.IndexOf(':');
                port = int.Parse(host.Substring(i + 1));
                host = host.Substring(0, i);
            }

            if (!IPAddress.TryParse(host, out IPAddress address))
            {
                IPAddress[] addresses = await System.Net.Dns.GetHostAddressesAsync(host, cancellationToken);
                if (addresses.Length == 0)
                    throw new AcmeException("Cannot resolve RFC 2136 server: " + host);

                address = addresses[0];
            }

            DnsClient client = new DnsClient(new NameServerAddress(new IPEndPoint(address, port), DnsTransportProtocol.Tcp));
            client.Timeout = 5000;
            client.Retries = 2;

            return client;
        }

        //finds the zone apex by asking the update server for the SOA of the name and its parents
        private static async Task<string> FindZoneAsync(DnsClient client, string recordName, CancellationToken cancellationToken)
        {
            string name = recordName;

            while (true)
            {
                DnsDatagram response = await client.RawResolveAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.SOA, DnsClass.IN)]), cancellationToken);

                foreach (DnsResourceRecord record in response.Answer)
                {
                    if ((record.Type == DnsResourceRecordType.SOA) && record.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                        return record.Name;
                }

                foreach (DnsResourceRecord record in response.Authority)
                {
                    if (record.Type == DnsResourceRecordType.SOA)
                        return record.Name;
                }

                int i = name.IndexOf('.');
                if (i < 0)
                    throw new AcmeException("RFC 2136 server is not authoritative for any zone containing '" + recordName + "'.");

                name = name.Substring(i + 1);
            }
        }

        private async Task SendUpdateAsync(string recordName, DnsResourceRecord update, CancellationToken cancellationToken)
        {
            DnsClient client = await GetClientAsync(cancellationToken);
            string zone = await FindZoneAsync(client, recordName, cancellationToken);

            //zone section = question, prerequisite = answer (none), update = authority (RFC 2136 section 2)
            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.Update, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(zone, DnsResourceRecordType.SOA, DnsClass.IN)], null, [update]);

            DnsDatagram response = _tsigKey is null ? await client.RawResolveAsync(request, cancellationToken) : await client.TsigResolveAsync(request, _tsigKey, 300, cancellationToken);

            if (response.RCODE != DnsResponseCode.NoError)
                throw new AcmeException("RFC 2136 update for '" + recordName + "' in zone '" + zone + "' was rejected: " + response.RCODE.ToString() + (_tsigKey is null ? " (no TSIG key configured)" : ""));
        }

        public Task AddTxtRecordAsync(string recordName, string value, CancellationToken cancellationToken)
        {
            return SendUpdateAsync(recordName, new DnsResourceRecord(recordName, DnsResourceRecordType.TXT, DnsClass.IN, TXT_TTL, new DnsTXTRecordData(value)), cancellationToken);
        }

        public Task RemoveTxtRecordAsync(string recordName, string value, CancellationToken cancellationToken)
        {
            //class NONE + TTL 0 deletes this specific record (RFC 2136 section 2.5.4)
            return SendUpdateAsync(recordName, new DnsResourceRecord(recordName, DnsResourceRecordType.TXT, DnsClass.NONE, 0, new DnsTXTRecordData(value)), cancellationToken);
        }
    }

    //Cloudflare DNS API with a scoped API token (Zone:DNS:Edit).
    sealed class CloudflareDns01Provider : IDns01Provider
    {
        const string API_BASE = "https://api.cloudflare.com/client/v4/";

        readonly HttpMessageHandler _handler;
        readonly string _apiToken;

        public CloudflareDns01Provider(HttpMessageHandler handler, string apiToken)
        {
            if (string.IsNullOrWhiteSpace(apiToken))
                throw new AcmeException("Cloudflare provider requires an API token with Zone:DNS:Edit permission.");

            _handler = handler;
            _apiToken = apiToken.Trim();
        }

        private HttpClient CreateClient()
        {
            HttpClient http = new HttpClient(_handler, false);
            http.Timeout = TimeSpan.FromSeconds(30);
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _apiToken);

            return http;
        }

        private static async Task<JsonElement> SendAsync(HttpClient http, HttpMethod method, string path, string jsonBody, CancellationToken cancellationToken)
        {
            using (HttpRequestMessage request = new HttpRequestMessage(method, API_BASE + path))
            {
                if (jsonBody is not null)
                    request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

                using (HttpResponseMessage response = await http.SendAsync(request, cancellationToken))
                {
                    string body = await response.Content.ReadAsStringAsync(cancellationToken);
                    JsonElement json;

                    try
                    {
                        json = JsonDocument.Parse(body).RootElement.Clone();
                    }
                    catch (JsonException)
                    {
                        throw new AcmeException("Cloudflare API returned an invalid response (" + (int)response.StatusCode + ").");
                    }

                    if (!json.TryGetProperty("success", out JsonElement success) || !success.GetBoolean())
                    {
                        string errors = json.TryGetProperty("errors", out JsonElement errorsElement) ? errorsElement.ToString() : body;
                        throw new AcmeException("Cloudflare API request failed (" + (int)response.StatusCode + "): " + errors);
                    }

                    return json.GetProperty("result");
                }
            }
        }

        private static async Task<string> FindZoneIdAsync(HttpClient http, string recordName, CancellationToken cancellationToken)
        {
            string name = recordName;

            while (true)
            {
                int i = name.IndexOf('.');
                if (i < 0)
                    throw new AcmeException("No Cloudflare zone accessible with this API token contains '" + recordName + "'.");

                name = name.Substring(i + 1);

                JsonElement result = await SendAsync(http, HttpMethod.Get, "zones?name=" + Uri.EscapeDataString(name), null, cancellationToken);
                if (result.GetArrayLength() > 0)
                    return result[0].GetProperty("id").GetString();
            }
        }

        public async Task AddTxtRecordAsync(string recordName, string value, CancellationToken cancellationToken)
        {
            using (HttpClient http = CreateClient())
            {
                string zoneId = await FindZoneIdAsync(http, recordName, cancellationToken);
                string body = "{\"type\":\"TXT\",\"name\":" + JsonSerializer.Serialize(recordName) + ",\"content\":" + JsonSerializer.Serialize("\"" + value + "\"") + ",\"ttl\":60}";

                await SendAsync(http, HttpMethod.Post, "zones/" + zoneId + "/dns_records", body, cancellationToken);
            }
        }

        public async Task RemoveTxtRecordAsync(string recordName, string value, CancellationToken cancellationToken)
        {
            using (HttpClient http = CreateClient())
            {
                string zoneId = await FindZoneIdAsync(http, recordName, cancellationToken);
                JsonElement records = await SendAsync(http, HttpMethod.Get, "zones/" + zoneId + "/dns_records?type=TXT&name=" + Uri.EscapeDataString(recordName), null, cancellationToken);

                foreach (JsonElement record in records.EnumerateArray())
                {
                    string content = record.GetProperty("content").GetString().Trim('"');
                    if (content == value)
                        await SendAsync(http, HttpMethod.Delete, "zones/" + zoneId + "/dns_records/" + record.GetProperty("id").GetString(), null, cancellationToken);
                }
            }
        }
    }

    //Public DNS lookups for dns-01: CNAME delegation and propagation to the zone's authoritative name servers.
    //Uses public resolvers rather than this server, so a local (split-horizon) copy of the zone doesn't hide the public view.
    sealed class Dns01Resolver
    {
        readonly DnsClient _publicResolver;

        public Dns01Resolver(IReadOnlyList<IPAddress> publicResolvers)
        {
            _publicResolver = new DnsClient(publicResolvers.ToArray());
            _publicResolver.Timeout = 3000;
            _publicResolver.Retries = 2;
        }

        //follows _acme-challenge CNAMEs (e.g. delegation to a zone this server controls); returns the final name
        public async Task<string> ResolveChallengeNameAsync(string recordName, CancellationToken cancellationToken)
        {
            string name = recordName;

            for (int i = 0; i < 8; i++)
            {
                DnsDatagram response = await _publicResolver.ResolveAsync(name, DnsResourceRecordType.CNAME, cancellationToken);

                DnsResourceRecord cname = response.Answer.FirstOrDefault(r => (r.Type == DnsResourceRecordType.CNAME) && r.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (cname is null)
                    return name;

                name = (cname.RDATA as DnsCNAMERecordData).Domain;
            }

            throw new AcmeException("Too many CNAMEs while resolving " + recordName + ".");
        }

        private async Task<string> FindZoneAsync(string name, CancellationToken cancellationToken)
        {
            DnsDatagram response = await _publicResolver.ResolveAsync(name, DnsResourceRecordType.SOA, cancellationToken);

            foreach (DnsResourceRecord record in response.Answer.Concat(response.Authority))
            {
                if (record.Type == DnsResourceRecordType.SOA)
                    return record.Name;
            }

            int i = name.IndexOf('.');
            if (i < 0)
                throw new AcmeException("Cannot find the public zone for " + name + ".");

            return await FindZoneAsync(name.Substring(i + 1), cancellationToken);
        }

        private async Task<IReadOnlyList<IPAddress>> GetAuthoritativeServersAsync(string zone, CancellationToken cancellationToken)
        {
            DnsDatagram nsResponse = await _publicResolver.ResolveAsync(zone, DnsResourceRecordType.NS, cancellationToken);
            List<IPAddress> addresses = new List<IPAddress>();

            foreach (DnsResourceRecord ns in nsResponse.Answer.Where(r => r.Type == DnsResourceRecordType.NS))
            {
                string nsName = (ns.RDATA as DnsNSRecordData).NameServer;

                foreach (DnsResourceRecordType type in new[] { DnsResourceRecordType.A, DnsResourceRecordType.AAAA })
                {
                    try
                    {
                        DnsDatagram response = await _publicResolver.ResolveAsync(nsName, type, cancellationToken);

                        foreach (DnsResourceRecord record in response.Answer)
                        {
                            if (record.RDATA is DnsARecordData a)
                                addresses.Add(a.Address);
                            else if (record.RDATA is DnsAAAARecordData aaaa)
                                addresses.Add(aaaa.Address);
                        }
                    }
                    catch
                    {
                        //unresolvable name server is skipped
                    }
                }
            }

            if (addresses.Count == 0)
                throw new AcmeException("Cannot find the authoritative name servers for zone " + zone + ".");

            return addresses;
        }

        //null = server did not respond (e.g. no IPv6 connectivity), true/false = record present or not
        private static async Task<bool?> HasTxtAsync(IPAddress server, string recordName, string value, CancellationToken cancellationToken)
        {
            try
            {
                DnsClient client = new DnsClient(server);
                client.Timeout = 3000;
                client.Retries = 1;

                //non-recursive query straight to the authoritative server, like the CA's validator
                DnsDatagram response = await client.RawResolveAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(recordName, DnsResourceRecordType.TXT, DnsClass.IN)]), cancellationToken);

                return response.Answer.Any(r => (r.RDATA is DnsTXTRecordData txt) && (txt.GetText() == value));
            }
            catch
            {
                return null;
            }
        }

        //waits until every authoritative server that responds answers with the TXT value
        public async Task WaitForPropagationAsync(string recordName, string value, TimeSpan timeout, Action<string> log, CancellationToken cancellationToken)
        {
            string zone = await FindZoneAsync(recordName, cancellationToken);
            IReadOnlyList<IPAddress> servers = await GetAuthoritativeServersAsync(zone, cancellationToken);
            DateTime start = DateTime.UtcNow;
            DateTime deadline = start.Add(timeout);
            bool anyResponded = false;

            while (true)
            {
                bool?[] results = await Task.WhenAll(servers.Select(s => HasTxtAsync(s, recordName, value, cancellationToken)));
                int responded = results.Count(r => r.HasValue);
                int ready = results.Count(r => r == true);

                anyResponded |= responded > 0;

                //none of the zone's public servers can be reached from here, e.g. they are this network's own public IP
                //and the router has no NAT hairpin; the CA can still reach them, so don't block issuance on this check
                if (!anyResponded && (DateTime.UtcNow > start.AddSeconds(30)))
                {
                    log("None of the " + servers.Count + " authoritative server(s) of " + zone + " (" + string.Join(", ", servers) + ") responded from this server, so propagation can't be checked here. Continuing; the certificate authority will validate directly.");
                    return;
                }

                if ((responded > 0) && (ready == responded))
                {
                    log("TXT record " + recordName + " is visible on all " + responded + " responding authoritative server(s) of " + zone + (responded < servers.Count ? " (" + (servers.Count - responded) + " unreachable from here, e.g. IPv6)." : "."));
                    return;
                }

                if (DateTime.UtcNow > deadline)
                {
                    string missing = string.Join(", ", servers.Where((s, i) => results[i] == false).Select(s => s.ToString()));
                    throw new AcmeException("TXT record " + recordName + " is visible on only " + ready + " of " + responded + " responding authoritative server(s) of " + zone + " after " + (int)timeout.TotalSeconds + " seconds" + (missing.Length > 0 ? "; missing on: " + missing : "; no server responded") + ".");
                }

                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
            }
        }
    }
}
