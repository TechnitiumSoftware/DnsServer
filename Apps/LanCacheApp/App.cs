using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using DnsServerCore.ApplicationCommon;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace LanCache
{
    public class App: IDnsApplication, IDnsAuthoritativeRequestHandler
    {
        #region variables

        private const string LANCACHE_DOMAINS_DATA_URL =
            "https://github.com/uklans/cache-domains/archive/refs/heads/master.zip";

        private const string LANCACHE_DOMAINS_DEFAULT_ZIP_PREFIX = "cache-domains-master/";
        private const string DUMMY_LANCACHE_ADDRESS = "lancache.example.com";
        private DateTime DomainsLastUpdated;
        private Timer? DomainsUpdateTimer;
        private IDnsServer DnsServer = null!;
        private AppConfig Config = null!;
        private ReadOnlyDictionary<string, string> LanCacheDomains = new(new Dictionary<string, string>());
        private ReadOnlyDictionary<string, string> WildcardDomains = new(new Dictionary<string, string>());
        private DnsSOARecordData SoaRecord = null!;
        private DnsNSRecordData NsRecord = null!;
        private string CacheDomainsCacheFile = null!;
        private string WildcardDomainsCacheFile = null!;
        
        #endregion

        #region private

        private async Task LoadCachedDomainsData()
        {
            if (File.Exists(CacheDomainsCacheFile))
            {
                var cacheFile = File.OpenRead(CacheDomainsCacheFile);
                var parsed = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(cacheFile);
                if (parsed != null)
                {
                    LanCacheDomains = new ReadOnlyDictionary<string, string>(parsed);
                    DnsServer.WriteLog("Loaded cached direct domains.");
                }
            }

            if (File.Exists(WildcardDomainsCacheFile))
            {
                var cacheFile = File.OpenRead(WildcardDomainsCacheFile);
                var parsed = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(cacheFile);
                if (parsed != null)
                {
                    WildcardDomains = new ReadOnlyDictionary<string, string>(parsed);
                    DnsServer.WriteLog("Loaded cached wildcard domains.");
                }
            }
        }

        [SuppressMessage("ReSharper", "InvertIf")]
        private async Task UpdateLanCacheDomains()
        {
            if (DateTime.Now.Subtract(DomainsLastUpdated) < TimeSpan.FromHours(Config.DomainsUpdatePeriodHours))
            {
                DnsServer.WriteLog("Update of cache domains skipped due to set interval.");
                return;
            }
            
            DnsServer.WriteLog("Updating cache domains.");
            using var hc = new HttpClient();
            var domainsZipFile = Path.Combine(DnsServer.ApplicationFolder, "lancache-domains.zip");
            try
            {
                var respStream = await hc.GetStreamAsync(LANCACHE_DOMAINS_DATA_URL);
                await using var fileStream = new FileStream($"{domainsZipFile}.download", FileMode.Create);
                await respStream.CopyToAsync(fileStream);
                File.Move($"{domainsZipFile}.download", domainsZipFile, true);
            }
            catch (Exception ex)
            {
                DnsServer.WriteLog("Failed to download domains zip file. Reusing previous.");
                DnsServer.WriteLog(ex.ToString());
            }

            if (!File.Exists(domainsZipFile))
            {
                DnsServer.WriteLog("No existing domains zip file found. Attempting load of cached data.");
                await LoadCachedDomainsData();
                return;
            }
            
            
            using var archive = ZipFile.OpenRead(domainsZipFile);
            var domainsJsonEntry = archive.GetEntry($"{Config.DomainsDataPathPrefix}cache_domains.json");
            if (domainsJsonEntry == null)
            {
                DnsServer.WriteLog("cache_domains.json not found in domains zip file.");
                DnsServer.WriteLog("Entries in domains zip file:");
                foreach (var zipArchiveEntry in archive.Entries)
                {
                    DnsServer.WriteLog("- " + zipArchiveEntry.FullName);
                }

                await LoadCachedDomainsData();
                return;
            }

            await using var entryStream = domainsJsonEntry.Open();
            var cacheDomains = await JsonSerializer.DeserializeAsync<CacheDomainsIndex>(entryStream, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            if (cacheDomains == null)
            {
                DnsServer.WriteLog("Fail to parse cache_domains.json");
                await LoadCachedDomainsData();
                return;
            }

            var newCacheDomains = new Dictionary<string, string>();
            var wildcardDomains = new Dictionary<string, string>();
            foreach (var entry in cacheDomains.CacheDomains.Where(e => e.DomainFiles.Count > 0))
            {
                foreach (var zipEntry in entry.DomainFiles.Select(f => archive.GetEntry($"{Config.DomainsDataPathPrefix}{f}")).Where(s => s != null).Select(s => s!))
                {
                    await using var stream = zipEntry.Open();
                    using var reader = new StreamReader(stream);
                    while (!reader.EndOfStream)
                    {
                        var line = await reader.ReadLineAsync();
                        if ( line == null )
                            break;
                        if (line.StartsWith("*."))
                        {
                            wildcardDomains[line[2..]] = entry.Name;
                        }
                        else
                        {
                            newCacheDomains[line] = entry.Name;
                        }
                    }
                }
            }

            LanCacheDomains = new ReadOnlyDictionary<string, string>(newCacheDomains);
            WildcardDomains = new ReadOnlyDictionary<string, string>(wildcardDomains);
            DomainsLastUpdated = DateTime.Now;
            DnsServer.WriteLog("Updated cache domains.");

            await using var cacheDomainsFile =
                new FileStream(CacheDomainsCacheFile, FileMode.Create);
            await JsonSerializer.SerializeAsync(cacheDomainsFile, LanCacheDomains);
            await using var wildcardDomainsFile =
                new FileStream(WildcardDomainsCacheFile, FileMode.Create);
            await JsonSerializer.SerializeAsync(wildcardDomainsFile, WildcardDomains);
        }

        private static async Task<AppConfig> LoadOrInitializeConfig(IDnsServer dnsServer, string config)
        {
            try
            {
                return JsonSerializer.Deserialize<AppConfig>(config, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                }) ?? throw new InvalidOperationException();
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException)
            {
                dnsServer.WriteLog("Invalid config. Writing default config file.");
                dnsServer.WriteLog(ex.ToString());
                dnsServer.WriteLog($"Config: {config}");
                var appConfig = new AppConfig
                {
                    LanCacheEnabled = false,
                    DomainsDataUrl = LANCACHE_DOMAINS_DATA_URL,
                    DomainsDataPathPrefix = LANCACHE_DOMAINS_DEFAULT_ZIP_PREFIX,
                    DomainsUpdatePeriodHours = 24,
                    GlobalCacheAddresses = new List<string>
                    {
                        DUMMY_LANCACHE_ADDRESS
                    },
                    CacheAddresses = new Dictionary<string, List<string>>
                    {
                        {"steam", new List<string>{DUMMY_LANCACHE_ADDRESS}},
                        {"windowsupdates", new List<string>{DUMMY_LANCACHE_ADDRESS}}
                    }
                };
                var configFilePath = Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config");
                await using var configFileStream = new FileStream(configFilePath, FileMode.Create);
                await JsonSerializer.SerializeAsync(configFileStream, appConfig, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    WriteIndented = true
                });
                return appConfig;
            }
        }
        
        private async void DomainsUpdateTimerCallback(object? state)
        {
            await UpdateLanCacheDomains();
        }

        #endregion
        
        #region public

        public string Description { get; } = "DNS App that implements LanCache.NET DNS functionality.";

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            dnsServer.WriteLog("Initializing");
            DnsServer = dnsServer;
            CacheDomainsCacheFile = Path.Combine(DnsServer.ApplicationFolder, "cache_domains.json");
            WildcardDomainsCacheFile = Path.Combine(DnsServer.ApplicationFolder, "wildcard_domains.json");
            SoaRecord = new DnsSOARecordData(DnsServer.ServerDomain, "hostadmin@" + DnsServer.ServerDomain, 1, 14400, 3600, 604800, 60);
            NsRecord = new DnsNSRecordData(DnsServer.ServerDomain);
            Config = await LoadOrInitializeConfig(dnsServer, config);
            DomainsUpdateTimer = new Timer(DomainsUpdateTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
            DomainsUpdateTimer.Change(TimeSpan.FromHours(Config.DomainsUpdatePeriodHours),
                TimeSpan.FromHours(Config.DomainsUpdatePeriodHours));
            await UpdateLanCacheDomains();
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEp, DnsTransportProtocol protocol,
            bool isRecursionAllowed)
        {
            if (!Config.LanCacheEnabled)
            {
                return Task.FromResult<DnsDatagram>(null!);
            }
            
            var question = request.Question[0];
            var foundDirect = IsZoneFound(LanCacheDomains, question.Name, out var foundZone, out var cacheTarget);
            // Use short-circuiting to skip the wildcard search if it matches a direct domain.
            var foundWild = !foundDirect && IsZoneFound(WildcardDomains, question.Name, out foundZone, out cacheTarget);

            if ((!foundDirect && !foundWild) || cacheTarget == null)
            {
                return Task.FromResult<DnsDatagram>(null!);
            }

            List<string>? cacheTargets;
            var hasOverride = Config.CacheAddresses.TryGetValue(cacheTarget, out cacheTargets);
            if (!hasOverride || cacheTargets == null)
            {
                cacheTargets = Config.GlobalCacheAddresses;
            }

            var aRecords = new List<DnsResourceRecord>();
            var aaaaRecords = new List<DnsResourceRecord>();
            DnsResourceRecord? cnameRecord = null;
            
            foreach (var target in cacheTargets.Where(t => t != DUMMY_LANCACHE_ADDRESS))
            {
                var isIpAddress = IPAddress.TryParse(target, out var ipAddress);
                if (isIpAddress)
                {
                    switch (ipAddress?.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            aRecords.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A,
                                question.Class, 60, new DnsARecordData(ipAddress)));
                            break;
                        case AddressFamily.InterNetworkV6:
                            aaaaRecords.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA,
                                question.Class, 60, new DnsAAAARecordData(ipAddress)));
                            break;
                        default:
                            DnsServer.WriteLog("Found non v4/v6 IP address somehow: " + target);
                            break;
                    }
                }
                else
                {
                    try
                    {
                        // Use ANAME because it's probably the most transparent to the end client. Just in case.
                        cnameRecord = new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, question.Class,
                            60,
                            new DnsANAMERecordData(target));
                    }
                    catch (DnsClientException)
                    {
                        DnsServer.WriteLog("Invalid CNAME target: " + target);
                    }
                }
            }

            var answers = new List<DnsResourceRecord>();
            var authority = new List<DnsResourceRecord>();
            var domainZone = foundZone ?? question.Name;
            
            // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                    if (cnameRecord != null)
                        answers.Add(cnameRecord);
                    else
                        answers.AddRange(aRecords);
                    break;
                case DnsResourceRecordType.AAAA:
                    if (cnameRecord != null)
                        answers.Add(cnameRecord);
                    else
                        answers.AddRange(aaaaRecords);
                    break;
                case DnsResourceRecordType.NS:
                    if (question.Name.Equals(domainZone, StringComparison.OrdinalIgnoreCase))
                    {
                        answers.Add(new DnsResourceRecord(domainZone, DnsResourceRecordType.NS, question.Class, 60, NsRecord));
                    }
                    else
                    {
                        authority.Add(new DnsResourceRecord(domainZone, DnsResourceRecordType.SOA, question.Class, 60, SoaRecord));
                    }
                    break;
                case DnsResourceRecordType.SOA:
                    answers.Add(new DnsResourceRecord(domainZone, DnsResourceRecordType.SOA, question.Class, 60, SoaRecord));
                    break;
                default:
                    authority.Add(new DnsResourceRecord(domainZone, DnsResourceRecordType.SOA, question.Class, 60, SoaRecord));
                    break;
            }

            // No valid cache targets found, handle normally to not break the cached urls.
            if (answers.Count != 0)
            {
                return Task.FromResult(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false,
                    request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answers,
                    authority, null,
                    request.EDNS is null ? ushort.MinValue : DnsServer.UdpPayloadSize));
            }

            DnsServer.WriteLog("No valid targets found for cache: " + cacheTarget);
            return Task.FromResult<DnsDatagram>(null!);
        }
        
        private static string? GetParentZone(string domain)
        {
            var i = domain.IndexOf('.');
            //dont return root zone
            return i > -1 ? domain[(i + 1)..] : null;
        }

        private static bool IsZoneFound(IReadOnlyDictionary<string, string> domains, string domain, out string? foundZone, out string? cacheTarget)
        {
            var currentDomain = domain.ToLower();
            do
            {
                if (domains.TryGetValue(currentDomain, out var value))
                {
                    foundZone = currentDomain;
                    cacheTarget = value;
                    return true;
                }

                currentDomain = GetParentZone(currentDomain);
            }
            while (currentDomain is not null);

            foundZone = null;
            cacheTarget = null;
            return false;
        }
        
        public void Dispose()
        {
            DomainsUpdateTimer?.Dispose();
            GC.SuppressFinalize(this);
        }

        #endregion
    }
    
    internal class AppConfig
    {
        public required bool LanCacheEnabled { get; set; }
        public string DomainsDataUrl { get; set; } = "";
        public string DomainsDataPathPrefix { get; set; } = "";
        public int DomainsUpdatePeriodHours { get; set; }
        
        public List<string> GlobalCacheAddresses { get; set; } = new();
        public Dictionary<string, List<string>> CacheAddresses { get; set; } = new();
    }

    [SuppressMessage("ReSharper", "CollectionNeverUpdated.Global")]
    internal class CacheDomainsIndex
    {
        [JsonPropertyName("cache_domains")]
        public List<CacheDomainsEntry> CacheDomains { get; set; } = new();
    }
    
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "CollectionNeverUpdated.Global")]
    internal class CacheDomainsEntry
    {
        
        public required string Name { get; set; }
        public string? Description  { get; set; }
        [JsonPropertyName("domain_files")]
        public List<string> DomainFiles { get; set; } = new();
        public string? Notes  { get; set; }
        [JsonPropertyName("mixed_content")]
        public bool MixedContent  { get; set; }
    }
}