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

using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;

namespace AdvancedBlocking
{
    public sealed class App : IDnsApplication, IDnsRequestBlockingHandler, IDnsPostProcessor
    {
        #region variables

        readonly static JsonDocumentOptions _jsonParseOptions = new JsonDocumentOptions() { CommentHandling = JsonCommentHandling.Skip };

        IDnsServer? _dnsServer;

        DnsSOARecordData? _soaRecord;
        DnsNSRecordData? _nsRecord;

        bool _enableBlocking;
        uint _blockingAnswerTtl;
        int _blockListUrlUpdateIntervalHours;
        int _blockListUrlUpdateIntervalMinutes;

        Dictionary<EndPoint, string>? _localEndPointGroupMap;
        Dictionary<NetworkAddress, string>? _networkGroupMap;
        Dictionary<string, Group>? _groups;

        Dictionary<Uri, BlockList> _allAllowListZones = [];
        Dictionary<Uri, BlockList> _allBlockListZones = [];

        Dictionary<Uri, RegexList> _allRegexAllowListZones = [];
        Dictionary<Uri, RegexList> _allRegexBlockListZones = [];

        Dictionary<Uri, AdBlockList> _allAdBlockListZones = [];

        Timer? _blockListUrlUpdateTimer;
        DateTime _blockListUrlLastUpdatedOn;
        const int BLOCK_LIST_UPDATE_TIMER_INTERVAL = 60000;

        object? _coreAllowedZoneManager;
        MethodInfo? _coreIsAllowedMethod;
        HashSet<string> _coreAllowedZones = new(StringComparer.OrdinalIgnoreCase);
        DateTime _coreAllowedZonesLastRead = DateTime.MinValue;
        string? _coreAllowedConfigFilePath;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_blockListUrlUpdateTimer is not null)
            {
                _blockListUrlUpdateTimer.Dispose();
                _blockListUrlUpdateTimer = null;
            }
        }

        #endregion

        #region private

        private void RefreshCoreAllowedZones()
        {
            // 1. Try to refresh via live reflection if AllowedZoneManager is available
            if (_coreAllowedZoneManager is not null)
            {
                try
                {
                    MethodInfo? getAllZonesMethod = _coreAllowedZoneManager.GetType().GetMethod("GetAllZones");
                    if (getAllZonesMethod is not null)
                    {
                        object? res = getAllZonesMethod.Invoke(_coreAllowedZoneManager, null);
                        if (res is System.Collections.IEnumerable zoneList)
                        {
                            HashSet<string> zones = new(StringComparer.OrdinalIgnoreCase);
                            foreach (object zoneInfo in zoneList)
                            {
                                PropertyInfo? nameProp = zoneInfo.GetType().GetProperty("Name");
                                string? name = nameProp?.GetValue(zoneInfo) as string;
                                if (!string.IsNullOrEmpty(name))
                                    zones.Add(name.TrimEnd('.'));
                            }

                            if (zones.Count > 0)
                            {
                                _coreAllowedZones = zones;
                                _coreAllowedZonesLastRead = DateTime.UtcNow;
                                return;
                            }
                        }
                    }
                }
                catch
                {
                    // Fallback to binary file reading
                }
            }

            // 2. Binary file reading of allowed.config
            if (string.IsNullOrEmpty(_coreAllowedConfigFilePath) || !File.Exists(_coreAllowedConfigFilePath))
                return;

            try
            {
                FileInfo fi = new FileInfo(_coreAllowedConfigFilePath);
                if (fi.LastWriteTimeUtc <= _coreAllowedZonesLastRead && _coreAllowedZones.Count > 0)
                    return;

                HashSet<string> zones = new(StringComparer.OrdinalIgnoreCase);
                using (FileStream fileStream = new FileStream(_coreAllowedConfigFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] header = new byte[2];
                    if (fileStream.Read(header, 0, 2) == 2 && Encoding.ASCII.GetString(header) == "AZ")
                    {
                        BinaryReader binaryReader = new BinaryReader(fileStream);
                        byte version = binaryReader.ReadByte();
                        if (version == 1)
                        {
                            int count = binaryReader.ReadInt32();
                            for (int i = 0; i < count; i++)
                            {
                                string zone = fileStream.ReadShortString();
                                zones.Add(zone.TrimEnd('.'));
                            }
                        }
                    }
                }

                _coreAllowedZones = zones;
                _coreAllowedZonesLastRead = fi.LastWriteTimeUtc;
            }
            catch
            {
                // Fallback silently if reading file fails
            }
        }

        private bool IsCoreAllowedZone(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                return false;

            domain = domain.TrimEnd('.');

            // 1. Check direct AllowedZoneManager via reflection if available
            if (_coreAllowedZoneManager is not null && _coreIsAllowedMethod is not null)
            {
                try
                {
                    DnsDatagram query = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN)]);
                    object? res = _coreIsAllowedMethod.Invoke(_coreAllowedZoneManager, new object[] { query });
                    if (res is bool isAllowed && isAllowed)
                        return true;
                }
                catch
                {
                    // Fallback to file-based check
                }
            }

            // 2. Check cached file-based allowed zones from /etc/dns/allowed.config
            RefreshCoreAllowedZones();
            if (_coreAllowedZones.Count > 0)
            {
                if (_coreAllowedZones.Contains(domain))
                    return true;

                // Check parent domains (e.g. reddit.com allows www.reddit.com)
                int dotIndex = domain.IndexOf('.');
                while (dotIndex > 0)
                {
                    string parent = domain.Substring(dotIndex + 1);
                    if (_coreAllowedZones.Contains(parent))
                        return true;

                    dotIndex = domain.IndexOf('.', dotIndex + 1);
                }
            }

            return false;
        }

        private bool IsDomainAllowed(Group group, string domain, DnsResourceRecordType qType = DnsResourceRecordType.A, IPAddress? clientIp = null)
        {
            if (string.IsNullOrEmpty(domain))
                return false;

            domain = domain.TrimEnd('.');

            if (group.IsZoneAllowed(domain, qType, clientIp))
                return true;

            if (IsCoreAllowedZone(domain))
                return true;

            return false;
        }

        private async void BlockListUrlUpdateTimerCallbackAsync(object? state)
        {
            try
            {
                if (DateTime.UtcNow > _blockListUrlLastUpdatedOn.AddHours(_blockListUrlUpdateIntervalHours).AddMinutes(_blockListUrlUpdateIntervalMinutes))
                {
                    if (await UpdateAllListsAsync())
                    {
                        //block lists were updated
                        //save last updated on time
                        _blockListUrlLastUpdatedOn = DateTime.UtcNow;
                    }
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
        }

        private async Task<bool> UpdateAllListsAsync()
        {
            List<Task<bool>> updateTasks = new List<Task<bool>>();

            foreach (KeyValuePair<Uri, BlockList> allAllowListZone in _allAllowListZones)
                updateTasks.Add(allAllowListZone.Value.UpdateAsync());

            foreach (KeyValuePair<Uri, BlockList> allBlockListZone in _allBlockListZones)
                updateTasks.Add(allBlockListZone.Value.UpdateAsync());

            foreach (KeyValuePair<Uri, RegexList> allRegexAllowListZone in _allRegexAllowListZones)
                updateTasks.Add(allRegexAllowListZone.Value.UpdateAsync());

            foreach (KeyValuePair<Uri, RegexList> allRegexBlockListZone in _allRegexBlockListZones)
                updateTasks.Add(allRegexBlockListZone.Value.UpdateAsync());

            foreach (KeyValuePair<Uri, AdBlockList> allAdBlockListZone in _allAdBlockListZones)
                updateTasks.Add(allAdBlockListZone.Value.UpdateAsync());

            await Task.WhenAll(updateTasks);

            foreach (Task<bool> updateTask in updateTasks)
            {
                bool downloaded = await updateTask;
                if (downloaded)
                    return true;
            }

            return false;
        }

        private static string? GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

        private static bool IsZoneFound(HashSet<string> domains, string domain, out string? foundZone)
        {
            do
            {
                if (domains.Contains(domain))
                {
                    foundZone = domain;
                    return true;
                }

                domain = GetParentZone(domain)!;
            }
            while (domain is not null);

            foundZone = null;
            return false;
        }

        private static bool IsZoneFound(Dictionary<Uri, BlockList> listZones, string domain, out string? foundZone, out Uri? listUri)
        {
            foreach (KeyValuePair<Uri, BlockList> listZone in listZones)
            {
                if (listZone.Value.IsZoneFound(domain, out foundZone))
                {
                    listUri = listZone.Key;
                    return true;
                }
            }

            foundZone = null;
            listUri = null;
            return false;
        }

        private static bool IsZoneFound(Dictionary<Uri, ListZoneEntry<BlockList>> listZones, string domain, out string? foundZone, out UrlEntry? listUri)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<BlockList>> listZone in listZones)
            {
                if (listZone.Value.List.IsZoneFound(domain, out foundZone))
                {
                    listUri = listZone.Value.UrlEntry;
                    return true;
                }
            }

            foundZone = null;
            listUri = null;
            return false;
        }

        private static bool IsZoneAllowed(Dictionary<Uri, ListZoneEntry<AdBlockList>> listZones, string domain, DnsResourceRecordType qType, IPAddress? clientIp, out string? foundZone, out UrlEntry? listUri, HashSet<(bool isAllow, string key)>? groupCancelKeys = null)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<AdBlockList>> listZone in listZones)
            {
                if (listZone.Value.List.IsZoneAllowed(domain, qType, clientIp, out foundZone, out _, groupCancelKeys))
                {
                    listUri = listZone.Value.UrlEntry;
                    return true;
                }
            }

            foundZone = null;
            listUri = null;
            return false;
        }

        private static bool IsZoneBlocked(Dictionary<Uri, ListZoneEntry<AdBlockList>> listZones, string domain, DnsResourceRecordType qType, IPAddress? clientIp, out string? foundZone, out UrlEntry? listUri, out AdBlockRule? matchedRule, HashSet<(bool isAllow, string key)>? groupCancelKeys = null)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<AdBlockList>> listZone in listZones)
            {
                if (listZone.Value.List.IsZoneBlocked(domain, qType, clientIp, out foundZone, out matchedRule, groupCancelKeys))
                {
                    listUri = listZone.Value.UrlEntry;
                    return true;
                }
            }

            foundZone = null;
            listUri = null;
            matchedRule = null;
            return false;
        }

        private static bool IsImportantAllowed(Dictionary<Uri, ListZoneEntry<AdBlockList>> listZones, string domain, DnsResourceRecordType qType, IPAddress? clientIp, out string? foundZone, out UrlEntry? listUri, HashSet<(bool isAllow, string key)>? groupCancelKeys = null)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<AdBlockList>> listZone in listZones)
            {
                if (listZone.Value.List.IsImportantAllowed(domain, qType, clientIp, out AdBlockRule? matchedRule, groupCancelKeys))
                {
                    foundZone = matchedRule!.Domain ?? domain;
                    listUri = listZone.Value.UrlEntry;
                    return true;
                }
            }

            foundZone = null;
            listUri = null;
            return false;
        }

        private static bool IsImportantBlocked(Dictionary<Uri, ListZoneEntry<AdBlockList>> listZones, string domain, DnsResourceRecordType qType, IPAddress? clientIp, out string? foundZone, out UrlEntry? listUri, out AdBlockRule? matchedRule, HashSet<(bool isAllow, string key)>? groupCancelKeys = null)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<AdBlockList>> listZone in listZones)
            {
                if (listZone.Value.List.IsImportantBlocked(domain, qType, clientIp, out matchedRule, groupCancelKeys))
                {
                    foundZone = matchedRule!.Domain ?? domain;
                    listUri = listZone.Value.UrlEntry;
                    return true;
                }
            }

            foundZone = null;
            listUri = null;
            matchedRule = null;
            return false;
        }

        private static bool IsMatchFound(IReadOnlyList<Regex> regices, string domain, out string? matchingPattern)
        {
            foreach (Regex regex in regices)
            {
                if (regex.IsMatch(domain))
                {
                    //found pattern
                    matchingPattern = regex.ToString();
                    return true;
                }
            }

            matchingPattern = null;
            return false;
        }

        private static bool IsMatchFound(Dictionary<Uri, RegexList> regexListZones, string domain, out string? matchingPattern, out Uri? listUri)
        {
            foreach (KeyValuePair<Uri, RegexList> regexListZone in regexListZones)
            {
                if (regexListZone.Value.IsMatchFound(domain, out matchingPattern))
                {
                    listUri = regexListZone.Key;
                    return true;
                }
            }

            matchingPattern = null;
            listUri = null;
            return false;
        }

        private static bool IsMatchFound(Dictionary<Uri, ListZoneEntry<RegexList>> regexListZones, string domain, out string? matchingPattern, out UrlEntry? listUri)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<RegexList>> regexListZone in regexListZones)
            {
                if (regexListZone.Value.List.IsMatchFound(domain, out matchingPattern))
                {
                    listUri = regexListZone.Value.UrlEntry;
                    return true;
                }
            }

            matchingPattern = null;
            listUri = null;
            return false;
        }

        private string? GetGroupName(DnsDatagram request, IPEndPoint remoteEP)
        {
            if ((request.Metadata is not null) && (request.Metadata.NameServer is not null))
            {
                Uri requestLocalUriEP = request.Metadata.NameServer.DoHEndPoint;
                if (requestLocalUriEP is not null)
                {
                    foreach (KeyValuePair<EndPoint, string> entry in _localEndPointGroupMap!)
                    {
                        if (entry.Key is DomainEndPoint ep)
                        {
                            if (((ep.Port == 0) || (ep.Port == requestLocalUriEP.Port)) && ep.Address.Equals(requestLocalUriEP.Host, StringComparison.OrdinalIgnoreCase))
                                return entry.Value;
                        }
                    }
                }

                DomainEndPoint requestLocalDomainEP = request.Metadata.NameServer.DomainEndPoint;
                if (requestLocalDomainEP is not null)
                {
                    foreach (KeyValuePair<EndPoint, string> entry in _localEndPointGroupMap!)
                    {
                        if (entry.Key is DomainEndPoint ep)
                        {
                            if (((ep.Port == 0) || (ep.Port == requestLocalDomainEP.Port)) && ep.Address.Equals(requestLocalDomainEP.Address, StringComparison.OrdinalIgnoreCase))
                                return entry.Value;
                        }
                    }
                }

                IPEndPoint requestLocalEP = request.Metadata.NameServer.IPEndPoint;
                if (requestLocalEP is not null)
                {
                    foreach (KeyValuePair<EndPoint, string> entry in _localEndPointGroupMap!)
                    {
                        if (entry.Key is IPEndPoint ep)
                        {
                            if (((ep.Port == 0) || (ep.Port == requestLocalEP.Port)) && ep.Address.Equals(requestLocalEP.Address))
                                return entry.Value;
                        }
                    }
                }
            }

            string? groupName = null;
            IPAddress remoteIP = remoteEP.Address;
            NetworkAddress? network = null;

            foreach (KeyValuePair<NetworkAddress, string> entry in _networkGroupMap!)
            {
                if (entry.Key.Contains(remoteIP) && ((network is null) || (entry.Key.PrefixLength > network.PrefixLength)))
                {
                    network = entry.Key;
                    groupName = entry.Value;
                }
            }

            return groupName;
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string? config)
        {
            _dnsServer = dnsServer;

            if (config is null)
                throw new InvalidOperationException();

            Directory.CreateDirectory(Path.Combine(_dnsServer.ApplicationFolder, "blocklists"));
            using JsonDocument jsonDocument = JsonDocument.Parse(config, _jsonParseOptions);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _enableBlocking = jsonConfig.GetPropertyValue("enableBlocking", true);
            _blockingAnswerTtl = jsonConfig.GetPropertyValue("blockingAnswerTtl", 30u);
            _blockListUrlUpdateIntervalHours = jsonConfig.GetPropertyValue("blockListUrlUpdateIntervalHours", 24);
            _blockListUrlUpdateIntervalMinutes = jsonConfig.GetPropertyValue("blockListUrlUpdateIntervalMinutes", 0);

            _soaRecord = new DnsSOARecordData(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, _blockingAnswerTtl);
            _nsRecord = new DnsNSRecordData(_dnsServer.ServerDomain);

            if (jsonConfig.TryReadObjectAsMap("localEndPointGroupMap",
                delegate (string localEP, JsonElement jsonGroup)
                {
                    if (!EndPointExtensions.TryParse(localEP, out EndPoint ep))
                        throw new InvalidOperationException("Local end point group map contains an invalid end point: " + localEP);

                    return new Tuple<EndPoint, string>(ep, jsonGroup.GetString() ?? "");
                },
                out Dictionary<EndPoint, string>? localEndPointGroupMap))
            {
                _localEndPointGroupMap = localEndPointGroupMap;
            }

            _networkGroupMap = jsonConfig.ReadObjectAsMap("networkGroupMap", delegate (string network, JsonElement jsonGroup)
            {
                if (!NetworkAddress.TryParse(network, out NetworkAddress networkAddress))
                    throw new InvalidOperationException("Network group map contains an invalid network address: " + network);

                return new Tuple<NetworkAddress, string>(networkAddress, jsonGroup.GetString() ?? "");
            });

            {
                Dictionary<Uri, BlockList> allAllowListZones = new Dictionary<Uri, BlockList>(0);
                Dictionary<Uri, BlockList> allBlockListZones = new Dictionary<Uri, BlockList>(0);

                Dictionary<Uri, RegexList> allRegexAllowListZones = new Dictionary<Uri, RegexList>(0);
                Dictionary<Uri, RegexList> allRegexBlockListZones = new Dictionary<Uri, RegexList>(0);

                Dictionary<Uri, AdBlockList> allAdBlockListZones = new Dictionary<Uri, AdBlockList>(0);

                _groups = jsonConfig.ReadArrayAsMap("groups", delegate (JsonElement jsonGroup)
                {
                    Group group = new Group(this, jsonGroup);

                    foreach (Uri allowListUrl in group.AllowListUrls)
                    {
                        if (!allAllowListZones.ContainsKey(allowListUrl))
                        {
                            if (_allAllowListZones.TryGetValue(allowListUrl, out BlockList? allowList))
                                allAllowListZones.Add(allowListUrl, allowList);
                            else
                                allAllowListZones.Add(allowListUrl, new BlockList(_dnsServer, allowListUrl, true));
                        }
                    }

                    foreach (UrlEntry blockListUrl in group.BlockListUrls)
                    {
                        if (!allBlockListZones.ContainsKey(blockListUrl.Uri!))
                        {
                            if (_allBlockListZones.TryGetValue(blockListUrl.Uri!, out BlockList? blockList))
                                allBlockListZones.Add(blockListUrl.Uri!, blockList);
                            else
                                allBlockListZones.Add(blockListUrl.Uri!, new BlockList(_dnsServer, blockListUrl.Uri!, false));
                        }
                    }

                    foreach (Uri regexAllowListUrl in group.RegexAllowListUrls)
                    {
                        if (!allRegexAllowListZones.ContainsKey(regexAllowListUrl))
                        {
                            if (_allRegexAllowListZones.TryGetValue(regexAllowListUrl, out RegexList? regexAllowList))
                                allRegexAllowListZones.Add(regexAllowListUrl, regexAllowList);
                            else
                                allRegexAllowListZones.Add(regexAllowListUrl, new RegexList(_dnsServer, regexAllowListUrl, true));
                        }
                    }

                    foreach (UrlEntry regexBlockListUrl in group.RegexBlockListUrls)
                    {
                        if (!allRegexBlockListZones.ContainsKey(regexBlockListUrl.Uri!))
                        {
                            if (_allRegexBlockListZones.TryGetValue(regexBlockListUrl.Uri!, out RegexList? regexBlockList))
                                allRegexBlockListZones.Add(regexBlockListUrl.Uri!, regexBlockList);
                            else
                                allRegexBlockListZones.Add(regexBlockListUrl.Uri!, new RegexList(_dnsServer, regexBlockListUrl.Uri!, false));
                        }
                    }

                    foreach (UrlEntry adblockListUrl in group.AdblockListUrls)
                    {
                        if (!allAdBlockListZones.ContainsKey(adblockListUrl.Uri!))
                        {
                            if (_allAdBlockListZones.TryGetValue(adblockListUrl.Uri!, out AdBlockList? adBlockList))
                                allAdBlockListZones.Add(adblockListUrl.Uri!, adBlockList);
                            else
                                allAdBlockListZones.Add(adblockListUrl.Uri!, new AdBlockList(_dnsServer, adblockListUrl.Uri!));
                        }
                    }

                    return new Tuple<string, Group>(group.Name, group);
                }) ?? [];

                _allAllowListZones = allAllowListZones;
                _allBlockListZones = allBlockListZones;

                _allRegexAllowListZones = allRegexAllowListZones;
                _allRegexBlockListZones = allRegexBlockListZones;

                _allAdBlockListZones = allAdBlockListZones;
            }

            foreach (KeyValuePair<string, Group> group in _groups)
            {
                group.Value.LoadListZones();
                _dnsServer.WriteLog("Advanced Blocking app loaded all zones successfully for group: " + group.Key);
            }

            ThreadPool.QueueUserWorkItem(async delegate (object? state)
            {
                try
                {
                    List<Task> loadTasks = new List<Task>();

                    foreach (KeyValuePair<Uri, BlockList> allAllowListZone in _allAllowListZones)
                        loadTasks.Add(allAllowListZone.Value.LoadAsync());

                    foreach (KeyValuePair<Uri, BlockList> allBlockListZone in _allBlockListZones)
                        loadTasks.Add(allBlockListZone.Value.LoadAsync());

                    foreach (KeyValuePair<Uri, RegexList> allRegexAllowListZone in _allRegexAllowListZones)
                        loadTasks.Add(allRegexAllowListZone.Value.LoadAsync());

                    foreach (KeyValuePair<Uri, RegexList> allRegexBlockListZone in _allRegexBlockListZones)
                        loadTasks.Add(allRegexBlockListZone.Value.LoadAsync());

                    foreach (KeyValuePair<Uri, AdBlockList> allAdBlockListZone in _allAdBlockListZones)
                        loadTasks.Add(allAdBlockListZone.Value.LoadAsync());

                    await Task.WhenAll(loadTasks);

                    if (_blockListUrlUpdateTimer is null)
                    {
                        DateTime latest = DateTime.MinValue;

                        foreach (KeyValuePair<Uri, BlockList> allAllowListZone in _allAllowListZones)
                        {
                            if (allAllowListZone.Value.LastModified > latest)
                                latest = allAllowListZone.Value.LastModified;
                        }

                        foreach (KeyValuePair<Uri, BlockList> allBlockListZone in _allBlockListZones)
                        {
                            if (allBlockListZone.Value.LastModified > latest)
                                latest = allBlockListZone.Value.LastModified;
                        }

                        foreach (KeyValuePair<Uri, RegexList> allRegexAllowListZone in _allRegexAllowListZones)
                        {
                            if (allRegexAllowListZone.Value.LastModified > latest)
                                latest = allRegexAllowListZone.Value.LastModified;
                        }

                        foreach (KeyValuePair<Uri, RegexList> allRegexBlockListZone in _allRegexBlockListZones)
                        {
                            if (allRegexBlockListZone.Value.LastModified > latest)
                                latest = allRegexBlockListZone.Value.LastModified;
                        }

                        foreach (KeyValuePair<Uri, AdBlockList> allAdBlockListZone in _allAdBlockListZones)
                        {
                            if (allAdBlockListZone.Value.LastModified > latest)
                                latest = allAdBlockListZone.Value.LastModified;
                        }

                        _blockListUrlLastUpdatedOn = latest;

                        _blockListUrlUpdateTimer = new Timer(BlockListUrlUpdateTimerCallbackAsync, null, Timeout.Infinite, Timeout.Infinite);
                        _blockListUrlUpdateTimer.Change(BLOCK_LIST_UPDATE_TIMER_INTERVAL, BLOCK_LIST_UPDATE_TIMER_INTERVAL);
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(ex);
                }
            });

            if (!jsonConfig.TryGetProperty("localEndPointGroupMap", out _))
            {
                config = config.Replace("\"networkGroupMap\"", "\"localEndPointGroupMap\": {\r\n  },\r\n  \"networkGroupMap\"");

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }

            if (!jsonConfig.TryGetProperty("blockingAnswerTtl", out _))
            {
                config = config.Replace("\"blockListUrlUpdateIntervalHours\"", "\"blockingAnswerTtl\": 30,\r\n  \"blockListUrlUpdateIntervalHours\"");

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }

            if (!jsonConfig.TryGetProperty("blockListUrlUpdateIntervalMinutes", out _))
            {
                config = config.Replace("\"localEndPointGroupMap\"", "\"blockListUrlUpdateIntervalMinutes\": 0,\r\n  \"localEndPointGroupMap\"");

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }

            // Initialize Core Allowed Zone Manager via reflection or fallback file
            try
            {
                FieldInfo? internalServerField = _dnsServer.GetType().GetField("_dnsServer", BindingFlags.Instance | BindingFlags.NonPublic);
                object? coreServer = internalServerField?.GetValue(_dnsServer);
                if (coreServer is not null)
                {
                    PropertyInfo? azmProp = coreServer.GetType().GetProperty("AllowedZoneManager", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                    _coreAllowedZoneManager = azmProp?.GetValue(coreServer);
                    if (_coreAllowedZoneManager is not null)
                    {
                        _coreIsAllowedMethod = _coreAllowedZoneManager.GetType().GetMethod("IsAllowed", new Type[] { typeof(DnsDatagram) });
                    }
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog($"Advanced Blocking app Core AllowedZoneManager reflection init notice: {ex.Message}");
            }

            try
            {
                DirectoryInfo appDir = new DirectoryInfo(dnsServer.ApplicationFolder);
                string? dnsFolder = appDir.Parent?.Parent?.FullName;
                if (!string.IsNullOrEmpty(dnsFolder))
                {
                    string allowedConfigPath = Path.Combine(dnsFolder, "allowed.config");
                    if (File.Exists(allowedConfigPath))
                    {
                        _coreAllowedConfigFilePath = allowedConfigPath;
                    }
                }

                RefreshCoreAllowedZones();
            }
            catch
            {
                // Fallback
            }
        }

        public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return Task.FromResult(false);

            string? groupName = GetGroupName(request, remoteEP);
            if ((groupName is null) || !_groups!.TryGetValue(groupName, out Group? group) || !group.EnableBlocking)
                return Task.FromResult(false);

            DnsQuestionRecord question = request.Question[0];

            return Task.FromResult(IsDomainAllowed(group, question.Name, question.Type, remoteEP.Address));
        }

        public async Task<DnsDatagram?> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return null;

            string? groupName = GetGroupName(request, remoteEP);
            if ((groupName is null) || !_groups!.TryGetValue(groupName, out Group? group) || !group.EnableBlocking)
                return null;

            DnsQuestionRecord question = request.Question[0];

            if (IsDomainAllowed(group, question.Name, question.Type, remoteEP.Address))
                return null;

            if (!group.IsZoneBlocked(question.Name, question.Type, remoteEP.Address, out string? blockedDomain, out string? blockedRegex, out UrlEntry? blockListUrl, out AdBlockRule? matchedRule))
                return null;

            return await CreateBlockedResponseAsync(request, group, question, blockedDomain, blockedRegex, blockListUrl, matchedRule, false);
        }

        public async Task<DnsDatagram?> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (!_enableBlocking)
                return response;

            if ((response is null) || (response.Answer is null) || (response.Answer.Count == 0))
                return response;

            string? groupName = GetGroupName(request, remoteEP);
            if ((groupName is null) || !_groups!.TryGetValue(groupName, out Group? group) || !group.EnableBlocking)
                return response;

            DnsQuestionRecord question = request.Question[0];

            // If the original query was explicitly allowed (in Core or in App Group), bypass post-processing
            if (IsDomainAllowed(group, question.Name, question.Type, remoteEP.Address))
                return response;

            // Inspect each CNAME in answer for cloaked tracking
            for (int i = 0; i < response.Answer.Count; i++)
            {
                DnsResourceRecord rr = response.Answer[i];
                if ((rr.Type == DnsResourceRecordType.CNAME) && (rr.RDATA is DnsCNAMERecordData cnameData))
                {
                    string cnameDomain = cnameData.Domain.TrimEnd('.');

                    // If the CNAME target is explicitly allowed (in Core or in App Group), DO NOT BLOCK!
                    if (IsDomainAllowed(group, cnameDomain, question.Type, remoteEP.Address))
                        continue;

                    if (group.IsZoneBlocked(cnameDomain, question.Type, remoteEP.Address, out string? blockedDomain, out string? blockedRegex, out UrlEntry? blockListUrl, out AdBlockRule? matchedRule))
                    {
                        _dnsServer?.WriteLog($"Advanced Blocking app intercepted CNAME cloaking: query '{question.Name}' aliases to blocked domain '{cnameDomain}'");

                        // Native CNAME Pipeline Harmonization (DnsServer.cs L4817-4828):
                        // Preserve all preceding and current CNAME records so clients receive a valid delegation chain
                        List<DnsResourceRecord> answers = new List<DnsResourceRecord>(i + 2);
                        for (int j = 0; j <= i; j++)
                            answers.Add(response.Answer[j]);

                        // Generate blocked response for the cloaked target domain
                        DnsDatagram? blockedResp = await CreateBlockedResponseAsync(request, group, new DnsQuestionRecord(cnameDomain, question.Type, question.Class), blockedDomain ?? cnameDomain, blockedRegex, blockListUrl, matchedRule, true);

                        if ((blockedResp is not null) && (blockedResp.Answer is not null))
                        {
                            foreach (DnsResourceRecord bRR in blockedResp.Answer)
                            {
                                if (bRR.Type != DnsResourceRecordType.CNAME)
                                    answers.Add(bRR);
                            }
                        }

                        DnsResponseCode rcode = blockedResp?.RCODE ?? DnsResponseCode.NoError;
                        IReadOnlyList<DnsResourceRecord>? authority = blockedResp?.Authority;
                        IReadOnlyList<DnsResourceRecord>? additional = blockedResp?.Additional;

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, rcode, request.Question, answers, authority, additional);
                    }
                }
            }

            return response;
        }

        private async Task<DnsDatagram?> CreateBlockedResponseAsync(DnsDatagram request, Group group, DnsQuestionRecord question, string? blockedDomain, string? blockedRegex, UrlEntry? blockListUrl, AdBlockRule? matchedRule, bool isCnameCloaked)
        {
            //$dnsrewrite (adblock rule modifier) takes precedence over the group's default blocking response
            if ((matchedRule is not null) && (matchedRule.DnsRewrite is not null) && matchedRule.DnsRewrite.Recognized)
            {
                DnsRewriteAction rewrite = matchedRule.DnsRewrite;

                if (rewrite.ResponseCode.HasValue && (rewrite.ResponseCode.Value != DnsResponseCode.NoError))
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, rewrite.ResponseCode.Value, request.Question);

                // CNAME rewrite (alias / redirection)
                if (!string.IsNullOrEmpty(rewrite.CnameTarget))
                {
                    string cnameTarget = rewrite.CnameTarget;
                    List<DnsResourceRecord> answers = [new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, question.Class, _blockingAnswerTtl, new DnsCNAMERecordData(cnameTarget))];

                    // Firestack / mitmproxy Non-Blocking Async Pipeline:
                    // Return CNAME record directly without blocking worker threads via synchronous DirectQueryAsync
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answers);
                }

                // TXT rewrite
                if (rewrite.TxtData is not null)
                {
                    if (question.Type == DnsResourceRecordType.TXT)
                    {
                        DnsResourceRecord[] answer = [new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, _blockingAnswerTtl, new DnsTXTRecordData(rewrite.TxtData))];
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answer);
                    }

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question);
                }

                // PTR rewrite
                if (rewrite.PtrTarget is not null)
                {
                    if (question.Type == DnsResourceRecordType.PTR)
                    {
                        DnsResourceRecord[] answer = [new DnsResourceRecord(question.Name, DnsResourceRecordType.PTR, question.Class, _blockingAnswerTtl, new DnsPTRRecordData(rewrite.PtrTarget))];
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answer);
                    }

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question);
                }

                // MX rewrite
                if (rewrite.MxRecord.HasValue)
                {
                    if (question.Type == DnsResourceRecordType.MX)
                    {
                        DnsResourceRecord[] answer = [new DnsResourceRecord(question.Name, DnsResourceRecordType.MX, question.Class, _blockingAnswerTtl, new DnsMXRecordData(rewrite.MxRecord.Value.preference, rewrite.MxRecord.Value.exchange))];
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answer);
                    }

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question);
                }

                if ((rewrite.Addresses is not null) && (rewrite.Addresses.Count > 0))
                {
                    List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(rewrite.Addresses.Count);

                    foreach (IPAddress address in rewrite.Addresses)
                    {
                        switch (address.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                if (question.Type == DnsResourceRecordType.A)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, _blockingAnswerTtl, new DnsARecordData(address)));
                                break;

                            case AddressFamily.InterNetworkV6:
                                if (question.Type == DnsResourceRecordType.AAAA)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, _blockingAnswerTtl, new DnsAAAARecordData(address)));
                                break;
                        }
                    }

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, rrList.Count > 0 ? rrList : null);
                }

                // Empty NOERROR response ($empty or unmatched question type for address/rcode)
                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question);
            }

            string GetBlockingReport()
            {
                string blockingReport = "source=advanced-blocking-app; group=" + group.Name;

                if (isCnameCloaked)
                    blockingReport += "; cnameCloakingBlocked=" + blockedDomain;

                if (blockedRegex is null)
                {
                    if (blockListUrl?.Uri is not null)
                        blockingReport += "; blockListUrl=" + blockListUrl.Uri.AbsoluteUri + "; domain=" + blockedDomain;
                    else
                        blockingReport += "; domain=" + blockedDomain;
                }
                else
                {
                    if (blockListUrl?.Uri is not null)
                        blockingReport += "; regexBlockListUrl=" + blockListUrl.Uri.AbsoluteUri + "; regex=" + blockedRegex;
                    else
                        blockingReport += "; regex=" + blockedRegex;
                }

                return blockingReport;
            }

            if (group.AllowTxtBlockingReport && (question.Type == DnsResourceRecordType.TXT))
            {
                //return meta data
                string blockingReport = GetBlockingReport();

                DnsResourceRecord[] answer = [new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, _blockingAnswerTtl, new DnsTXTRecordData(blockingReport))];

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answer);
            }
            else
            {
                EDnsOption[]? options = null;

                if (group.AllowTxtBlockingReport && (request.EDNS is not null))
                {
                    string blockingReport = GetBlockingReport();

                    options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, blockingReport))];
                }

                DnsResponseCode rcode;
                IReadOnlyList<DnsResourceRecord>? answer = null;
                IReadOnlyList<DnsResourceRecord>? authority = null;

                bool blockAsNxDomain = blockListUrl is not null ? blockListUrl.BlockAsNxDomain : group.BlockAsNxDomain;

                if (blockAsNxDomain)
                {
                    rcode = DnsResponseCode.NxDomain;

                    if (blockedDomain is null)
                        blockedDomain = question.Name;

                    string? parentDomain = GetParentZone(blockedDomain);
                    if (parentDomain is null)
                        parentDomain = string.Empty;

                    authority = [new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, _blockingAnswerTtl, _soaRecord)];
                }
                else
                {
                    rcode = DnsResponseCode.NoError;

                    IReadOnlyList<DnsARecordData> aRecords = blockListUrl is not null ? blockListUrl.ARecords : group.ARecords;
                    IReadOnlyList<DnsAAAARecordData> aaaaRecords = blockListUrl is not null ? blockListUrl.AAAARecords : group.AAAARecords;

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.A:
                            {
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(aRecords.Count);

                                foreach (DnsARecordData record in aRecords)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, _blockingAnswerTtl, record));

                                answer = rrList;
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            {
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(aaaaRecords.Count);

                                foreach (DnsAAAARecordData record in aaaaRecords)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, _blockingAnswerTtl, record));

                                answer = rrList;
                            }
                            break;

                        case DnsResourceRecordType.NS:
                            if (blockedDomain is null)
                                blockedDomain = question.Name;

                            if (question.Name.Equals(blockedDomain, StringComparison.OrdinalIgnoreCase))
                                answer = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.NS, question.Class, _blockingAnswerTtl, _nsRecord)];
                            else
                                authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _blockingAnswerTtl, _soaRecord)];

                            break;

                        case DnsResourceRecordType.SOA:
                            if (blockedDomain is null)
                                blockedDomain = question.Name;

                            answer = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _blockingAnswerTtl, _soaRecord)];
                            break;

                        default:
                            if (blockedDomain is null)
                                blockedDomain = question.Name;

                            authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _blockingAnswerTtl, _soaRecord)];
                            break;
                    }
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, !group.AllowTxtBlockingReport, false, false, rcode, request.Question, answer, authority, null, request.EDNS is null ? ushort.MinValue : _dnsServer!.UdpPayloadSize, EDnsHeaderFlags.None, options);
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Blocks domain names using block lists and regex block lists. Supports creating groups based on client's IP address or subnet to enforce different block lists and regex block lists for each group."; } }

        #endregion

        class UrlEntry
        {
            #region variables

            readonly Uri? _uri;
            readonly bool _blockAsNxDomain;

            readonly List<DnsARecordData> _aRecords;
            readonly List<DnsAAAARecordData> _aaaaRecords;

            #endregion

            #region constructor

            public UrlEntry(Uri? uri, Group group)
            {
                _uri = uri;
                _blockAsNxDomain = group.BlockAsNxDomain;
                _aRecords = group.ARecords;
                _aaaaRecords = group.AAAARecords;
            }

            public UrlEntry(JsonElement jsonUrl, Group group)
            {
                switch (jsonUrl.ValueKind)
                {
                    case JsonValueKind.String:
                        _uri = new Uri(jsonUrl.GetString()!);

                        _blockAsNxDomain = group.BlockAsNxDomain;
                        _aRecords = group.ARecords;
                        _aaaaRecords = group.AAAARecords;
                        break;

                    case JsonValueKind.Object:
                        _uri = new Uri(jsonUrl.GetProperty("url").GetString()!);

                        if (jsonUrl.TryGetProperty("blockAsNxDomain", out JsonElement jsonBlockAsNxDomain))
                            _blockAsNxDomain = jsonBlockAsNxDomain.GetBoolean();
                        else
                            _blockAsNxDomain = group.BlockAsNxDomain;

                        if (jsonUrl.TryGetProperty("blockingAddresses", out JsonElement jsonBlockingAddresses))
                        {
                            List<DnsARecordData> aRecords = new List<DnsARecordData>();
                            List<DnsAAAARecordData> aaaaRecords = new List<DnsAAAARecordData>();

                            foreach (JsonElement jsonBlockingAddress in jsonBlockingAddresses.EnumerateArray())
                            {
                                string? strAddress = jsonBlockingAddress.GetString();

                                if (IPAddress.TryParse(strAddress, out IPAddress? address))
                                {
                                    switch (address.AddressFamily)
                                    {
                                        case AddressFamily.InterNetwork:
                                            aRecords.Add(new DnsARecordData(address));
                                            break;

                                        case AddressFamily.InterNetworkV6:
                                            aaaaRecords.Add(new DnsAAAARecordData(address));
                                            break;
                                    }
                                }
                            }

                            _aRecords = aRecords.Count > 0 ? aRecords : group.ARecords;
                            _aaaaRecords = aaaaRecords.Count > 0 ? aaaaRecords : group.AAAARecords;
                        }
                        else
                        {
                            _aRecords = group.ARecords;
                            _aaaaRecords = group.AAAARecords;
                        }

                        break;

                    default:
                        throw new InvalidDataException("Unexpected URL format: " + jsonUrl.ValueKind);
                }
            }

            #endregion

            #region properties

            public Uri? Uri
            { get { return _uri; } }

            public bool BlockAsNxDomain
            { get { return _blockAsNxDomain; } }

            public List<DnsARecordData> ARecords
            { get { return _aRecords; } }

            public List<DnsAAAARecordData> AAAARecords
            { get { return _aaaaRecords; } }

            #endregion
        }

        class ListZoneEntry<T> where T : ListBase
        {
            #region variables

            readonly UrlEntry _urlEntry;
            readonly T _list;

            #endregion

            #region constructor

            public ListZoneEntry(UrlEntry urlEntry, T list)
            {
                _urlEntry = urlEntry;
                _list = list;
            }

            #endregion

            #region public

            public UrlEntry UrlEntry
            { get { return _urlEntry; } }

            public T List
            { get { return _list; } }

            #endregion
        }

        class Group
        {
            #region variables

            readonly App _app;

            readonly string _name;
            readonly bool _enableBlocking;
            readonly bool _allowTxtBlockingReport;
            readonly bool _blockAsNxDomain;

            readonly List<DnsARecordData> _aRecords;
            readonly List<DnsAAAARecordData> _aaaaRecords;

            readonly HashSet<string> _allowed;
            readonly HashSet<string> _blocked;
            readonly Uri[] _allowListUrls;
            readonly UrlEntry[] _blockListUrls;

            readonly Regex[] _allowedRegex;
            readonly Regex[] _blockedRegex;
            readonly Uri[] _regexAllowListUrls;
            readonly UrlEntry[] _regexBlockListUrls;

            readonly UrlEntry[] _adblockListUrls;
            readonly string[] _adblockRules;

            Dictionary<Uri, BlockList> _allowListZones = [];
            Dictionary<Uri, ListZoneEntry<BlockList>> _blockListZones = [];

            Dictionary<Uri, RegexList> _regexAllowListZones = [];
            Dictionary<Uri, ListZoneEntry<RegexList>> _regexBlockListZones = [];

            Dictionary<Uri, ListZoneEntry<AdBlockList>> _adBlockListZones = [];
            AdBlockList? _inMemoryAdBlockList;
            HashSet<(bool isAllow, string key)> _groupCancelKeys = [];

            #endregion

            #region constructor

            public Group(App app, JsonElement jsonGroup)
            {
                _app = app;

                _name = jsonGroup.GetProperty("name").GetString()!;
                _enableBlocking = jsonGroup.GetPropertyValue("enableBlocking", true);
                _allowTxtBlockingReport = jsonGroup.GetPropertyValue("allowTxtBlockingReport", true);
                _blockAsNxDomain = jsonGroup.GetPropertyValue("blockAsNxDomain", false);

                if (jsonGroup.TryGetProperty("blockingAddresses", out JsonElement jsonBlockingAddresses))
                {
                    List<DnsARecordData> aRecords = new List<DnsARecordData>();
                    List<DnsAAAARecordData> aaaaRecords = new List<DnsAAAARecordData>();

                    foreach (JsonElement jsonBlockingAddress in jsonBlockingAddresses.EnumerateArray())
                    {
                        string? strAddress = jsonBlockingAddress.GetString();

                        if (IPAddress.TryParse(strAddress, out IPAddress? address))
                        {
                            switch (address.AddressFamily)
                            {
                                case AddressFamily.InterNetwork:
                                    aRecords.Add(new DnsARecordData(address));
                                    break;

                                case AddressFamily.InterNetworkV6:
                                    aaaaRecords.Add(new DnsAAAARecordData(address));
                                    break;
                            }
                        }
                    }

                    _aRecords = aRecords;
                    _aaaaRecords = aaaaRecords;
                }
                else
                {
                    _aRecords = [];
                    _aaaaRecords = [];
                }

                _allowed = jsonGroup.ReadArrayAsSet("allowed") ?? [];
                _blocked = jsonGroup.ReadArrayAsSet("blocked") ?? [];
                _allowListUrls = jsonGroup.ReadArray("allowListUrls", GetUriEntry) ?? [];
                _blockListUrls = jsonGroup.ReadArray("blockListUrls", GetUrlEntry) ?? [];

                _allowedRegex = jsonGroup.ReadArray("allowedRegex", GetRegexEntry) ?? [];
                _blockedRegex = jsonGroup.ReadArray("blockedRegex", GetRegexEntry) ?? [];
                _regexAllowListUrls = jsonGroup.ReadArray("regexAllowListUrls", GetUriEntry) ?? [];
                _regexBlockListUrls = jsonGroup.ReadArray("regexBlockListUrls", GetUrlEntry) ?? [];

                _adblockListUrls = jsonGroup.ReadArray("adblockListUrls", GetUrlEntry) ?? [];

                if (jsonGroup.TryGetProperty("adblockRules", out JsonElement jsonAdblockRules) && (jsonAdblockRules.ValueKind == JsonValueKind.Array))
                {
                    List<string> rules = new List<string>();
                    foreach (JsonElement elem in jsonAdblockRules.EnumerateArray())
                    {
                        string? ruleStr = elem.GetString();
                        if (!string.IsNullOrWhiteSpace(ruleStr))
                            rules.Add(ruleStr);
                    }
                    _adblockRules = rules.ToArray();
                }
                else
                {
                    _adblockRules = [];
                }
            }

            #endregion

            #region private

            private static Uri GetUriEntry(string uriString)
            {
                return new Uri(uriString);
            }

            private UrlEntry GetUrlEntry(JsonElement jsonUrl)
            {
                return new UrlEntry(jsonUrl, this);
            }

            private static Regex GetRegexEntry(string pattern)
            {
                return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
            }

            #endregion

            #region public

            public void LoadListZones()
            {
                {
                    Dictionary<Uri, BlockList> allowListZones = new Dictionary<Uri, BlockList>(_allowListUrls.Length);

                    foreach (Uri listUrl in _allowListUrls)
                    {
                        if (_app._allAllowListZones.TryGetValue(listUrl, out BlockList? allowListZone))
                            allowListZones.Add(listUrl, allowListZone);
                    }

                    _allowListZones = allowListZones;
                }

                {
                    Dictionary<Uri, ListZoneEntry<BlockList>> blockListZones = new Dictionary<Uri, ListZoneEntry<BlockList>>(_blockListUrls.Length);

                    foreach (UrlEntry listUrl in _blockListUrls)
                    {
                        if (_app._allBlockListZones.TryGetValue(listUrl.Uri!, out BlockList? blockListZone))
                            blockListZones.Add(listUrl.Uri!, new ListZoneEntry<BlockList>(listUrl, blockListZone));
                    }

                    _blockListZones = blockListZones;
                }

                {
                    Dictionary<Uri, RegexList> regexAllowListZones = new Dictionary<Uri, RegexList>(_regexAllowListUrls.Length);

                    foreach (Uri listUrl in _regexAllowListUrls)
                    {
                        if (_app._allRegexAllowListZones.TryGetValue(listUrl, out RegexList? regexAllowListZone))
                            regexAllowListZones.Add(listUrl, regexAllowListZone);
                    }

                    _regexAllowListZones = regexAllowListZones;
                }

                {
                    Dictionary<Uri, ListZoneEntry<RegexList>> regexBlockListZones = new Dictionary<Uri, ListZoneEntry<RegexList>>(_regexBlockListUrls.Length);

                    foreach (UrlEntry listUrl in _regexBlockListUrls)
                    {
                        if (_app._allRegexBlockListZones.TryGetValue(listUrl.Uri!, out RegexList? regexBlockListZone))
                            regexBlockListZones.Add(listUrl.Uri!, new ListZoneEntry<RegexList>(listUrl, regexBlockListZone));
                    }

                    _regexBlockListZones = regexBlockListZones;
                }

                {
                    int capacity = _adblockListUrls.Length + (_adblockRules.Length > 0 ? 1 : 0);
                    Dictionary<Uri, ListZoneEntry<AdBlockList>> adBlockListZones = new Dictionary<Uri, ListZoneEntry<AdBlockList>>(capacity);

                    if (_adblockRules.Length > 0)
                    {
                        _inMemoryAdBlockList = new AdBlockList(_app._dnsServer!, _adblockRules, _name);
                        _inMemoryAdBlockList.LoadListZone();
                        Uri inMemoryUri = new Uri("app://advanced-blocking/inline-rules/" + Uri.EscapeDataString(_name));
                        adBlockListZones.Add(inMemoryUri, new ListZoneEntry<AdBlockList>(new UrlEntry(null, this), _inMemoryAdBlockList));
                    }

                    foreach (UrlEntry listUrl in _adblockListUrls)
                    {
                        if (_app._allAdBlockListZones.TryGetValue(listUrl.Uri!, out AdBlockList? adBlockListZone))
                            adBlockListZones.Add(listUrl.Uri!, new ListZoneEntry<AdBlockList>(listUrl, adBlockListZone));
                    }

                    _adBlockListZones = adBlockListZones;

                    // Collect group-wide badfilter cancellation keys
                    HashSet<(bool isAllow, string key)> groupCancelKeys = new HashSet<(bool, string)>();
                    foreach (KeyValuePair<Uri, ListZoneEntry<AdBlockList>> entry in _adBlockListZones)
                    {
                        foreach (AdBlockRule rule in entry.Value.List.RawRules)
                        {
                            if (rule.BadFilter && (rule.MatchKey is not null))
                                groupCancelKeys.Add((rule.IsAllow, rule.MatchKey));
                        }
                    }

                    _groupCancelKeys = groupCancelKeys;
                }
            }

            public bool IsZoneAllowed(string domain, DnsResourceRecordType qType, IPAddress? clientIp)
            {
                domain = domain.ToLowerInvariant();

                //adblock $important block rule takes precedence over any allow rule
                if (App.IsImportantBlocked(_adBlockListZones, domain, qType, clientIp, out _, out _, out _, _groupCancelKeys))
                    return false;

                //adblock $important allow rule overrides normal block rules
                if (App.IsImportantAllowed(_adBlockListZones, domain, qType, clientIp, out _, out _, _groupCancelKeys))
                    return true;

                //allowed, allow list zone, allowedRegex, regex allow list zone, adblock list zone
                return IsZoneFound(_allowed, domain, out _) || IsZoneFound(_allowListZones, domain, out _, out _) || IsMatchFound(_allowedRegex, domain, out _) || IsMatchFound(_regexAllowListZones, domain, out _, out _) || App.IsZoneAllowed(_adBlockListZones, domain, qType, clientIp, out _, out _, _groupCancelKeys);
            }

            public bool IsZoneBlocked(string domain, DnsResourceRecordType qType, IPAddress? clientIp, out string? blockedDomain, out string? blockedRegex, out UrlEntry? listUrl, out AdBlockRule? matchedRule)
            {
                domain = domain.ToLowerInvariant();

                //adblock $important block rule - highest priority, overrides any allow rule
                if (App.IsImportantBlocked(_adBlockListZones, domain, qType, clientIp, out string? foundZoneImp, out UrlEntry? blockListUrlImp, out AdBlockRule? matchedRuleImp, _groupCancelKeys))
                {
                    blockedDomain = foundZoneImp;
                    blockedRegex = null;
                    listUrl = blockListUrlImp;
                    matchedRule = matchedRuleImp;
                    return true;
                }

                //adblock $important allow rule overrides normal block rules
                if (App.IsImportantAllowed(_adBlockListZones, domain, qType, clientIp, out _, out _, _groupCancelKeys))
                {
                    blockedDomain = null;
                    blockedRegex = null;
                    listUrl = null;
                    matchedRule = null;
                    return false;
                }

                //blocked
                if (IsZoneFound(_blocked, domain, out string? foundZone1))
                {
                    //found zone blocked
                    blockedDomain = foundZone1;
                    blockedRegex = null;
                    listUrl = new UrlEntry(null, this);
                    matchedRule = null;
                    return true;
                }

                //block list zone
                if (IsZoneFound(_blockListZones, domain, out string? foundZone2, out UrlEntry? blockListUrl1))
                {
                    //found zone blocked
                    blockedDomain = foundZone2;
                    blockedRegex = null;
                    listUrl = blockListUrl1;
                    matchedRule = null;
                    return true;
                }

                //blockedRegex
                if (IsMatchFound(_blockedRegex, domain, out string? blockedPattern1))
                {
                    //found pattern blocked
                    blockedDomain = null;
                    blockedRegex = blockedPattern1;
                    listUrl = new UrlEntry(null, this);
                    matchedRule = null;
                    return true;
                }

                //regex block list zone
                if (IsMatchFound(_regexBlockListZones, domain, out string? blockedPattern2, out UrlEntry? blockListUrl2))
                {
                    //found pattern blocked
                    blockedDomain = null;
                    blockedRegex = blockedPattern2;
                    listUrl = blockListUrl2;
                    matchedRule = null;
                    return true;
                }

                //adblock list zone
                if (App.IsZoneBlocked(_adBlockListZones, domain, qType, clientIp, out string? foundZone3, out UrlEntry? blockListUrl3, out AdBlockRule? matchedRule3, _groupCancelKeys))
                {
                    //found zone blocked
                    blockedDomain = foundZone3;
                    blockedRegex = null;
                    listUrl = blockListUrl3;
                    matchedRule = matchedRule3;
                    return true;
                }

                blockedDomain = null;
                blockedRegex = null;
                listUrl = null;
                matchedRule = null;
                return false;
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            public bool EnableBlocking
            { get { return _enableBlocking; } }

            public bool AllowTxtBlockingReport
            { get { return _allowTxtBlockingReport; } }

            public bool BlockAsNxDomain
            { get { return _blockAsNxDomain; } }

            public List<DnsARecordData> ARecords
            { get { return _aRecords; } }

            public List<DnsAAAARecordData> AAAARecords
            { get { return _aaaaRecords; } }

            public Uri[] AllowListUrls
            { get { return _allowListUrls; } }

            public UrlEntry[] BlockListUrls
            { get { return _blockListUrls; } }

            public UrlEntry[] RegexBlockListUrls
            { get { return _regexBlockListUrls; } }

            public Uri[] RegexAllowListUrls
            { get { return _regexAllowListUrls; } }

            public UrlEntry[] AdblockListUrls
            { get { return _adblockListUrls; } }

            public string[] AdblockRules
            { get { return _adblockRules; } }

            #endregion
        }

        abstract class ListBase
        {
            #region variables

            protected readonly IDnsServer _dnsServer;
            protected readonly Uri _listUrl;
            protected readonly bool _isAllowList;
            protected readonly bool _isRegexList;
            protected readonly bool _isAdblockList;

            protected readonly string _listFilePath;
            bool _listZoneLoaded;
            DateTime _lastModified;

            volatile bool _isLoading;

            #endregion

            #region constructor

            public ListBase(IDnsServer dnsServer, Uri listUrl, bool isAllowList, bool isRegexList, bool isAdblockList)
            {
                _dnsServer = dnsServer;
                _listUrl = listUrl;
                _isAllowList = isAllowList;
                _isRegexList = isRegexList;
                _isAdblockList = isAdblockList;

                _listFilePath = Path.Combine(Path.Combine(_dnsServer.ApplicationFolder, "blocklists"), Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(_listUrl.AbsoluteUri))).ToLowerInvariant());
            }

            #endregion

            #region private

            private async Task<bool> DownloadListFileAsync()
            {
                try
                {
                    _dnsServer.WriteLog("Advanced Blocking app is downloading " + (_isAdblockList ? "adblock" : (_isRegexList ? "regex " : "") + (_isAllowList ? "allow" : "block")) + " list: " + _listUrl.AbsoluteUri);

                    if (_listUrl.IsFile)
                    {
                        if (File.Exists(_listFilePath))
                        {
                            if (File.GetLastWriteTimeUtc(_listUrl.LocalPath) <= File.GetLastWriteTimeUtc(_listFilePath))
                            {
                                _dnsServer.WriteLog("Advanced Blocking app successfully checked for a new update of the " + (_isAdblockList ? "adblock" : (_isRegexList ? "regex " : "") + (_isAllowList ? "allow" : "block")) + " list: " + _listUrl.AbsoluteUri);
                                return false;
                            }
                        }

                        File.Copy(_listUrl.LocalPath, _listFilePath, true);
                        _lastModified = File.GetLastWriteTimeUtc(_listFilePath);

                        _dnsServer.WriteLog("Advanced Blocking app successfully downloaded " + (_isAdblockList ? "adblock" : (_isRegexList ? "regex " : "") + (_isAllowList ? "allow" : "block")) + " list (" + WebUtilities.GetFormattedSize(new FileInfo(_listFilePath).Length) + "): " + _listUrl.AbsoluteUri);
                        return true;
                    }
                    else
                    {
                        HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                        handler.Proxy = _dnsServer.Proxy;
                        handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode);
                        handler.DnsClient = _dnsServer;

                        using (HttpClient http = new HttpClient(handler))
                        {
                            if (File.Exists(_listFilePath))
                                http.DefaultRequestHeaders.IfModifiedSince = File.GetLastWriteTimeUtc(_listFilePath);

                            http.DefaultRequestHeaders.UserAgent.TryParseAdd("Technitium DNS Server");

                            HttpResponseMessage httpResponse = await http.GetAsync(_listUrl, HttpCompletionOption.ResponseHeadersRead);
                            switch (httpResponse.StatusCode)
                            {
                                case HttpStatusCode.OK:
                                    string listDownloadFilePath = _listFilePath + ".downloading";

                                    await using (FileStream fS = new FileStream(listDownloadFilePath, FileMode.Create, FileAccess.Write))
                                    {
                                        await using (Stream httpStream = await httpResponse.Content.ReadAsStreamAsync())
                                        {
                                            //copy stream with idle timeout
                                            await httpStream.CopyToAsync(fS, TimeSpan.FromSeconds(60));
                                        }
                                    }

                                    File.Move(listDownloadFilePath, _listFilePath, true);

                                    if (httpResponse.Content.Headers.LastModified is null)
                                    {
                                        _lastModified = DateTime.UtcNow;
                                    }
                                    else
                                    {
                                        _lastModified = httpResponse.Content.Headers.LastModified.Value.UtcDateTime;
                                        File.SetLastWriteTimeUtc(_listFilePath, _lastModified);
                                    }

                                    _dnsServer.WriteLog("Advanced Blocking app successfully downloaded " + (_isAdblockList ? "adblock" : (_isRegexList ? "regex " : "") + (_isAllowList ? "allow" : "block")) + " list (" + WebUtilities.GetFormattedSize(new FileInfo(_listFilePath).Length) + "): " + _listUrl.AbsoluteUri);
                                    return true;

                                case HttpStatusCode.NotModified:
                                    _dnsServer.WriteLog("Advanced Blocking app successfully checked for a new update of the " + (_isAdblockList ? "adblock" : (_isRegexList ? "regex " : "") + (_isAllowList ? "allow" : "block")) + " list: " + _listUrl.AbsoluteUri);
                                    return false;

                                default:
                                    throw new HttpRequestException((int)httpResponse.StatusCode + " " + httpResponse.ReasonPhrase);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("Advanced Blocking app failed to download " + (_isAdblockList ? "adblock" : (_isRegexList ? "regex " : "") + (_isAllowList ? "allow" : "block")) + " list and will use previously downloaded file (if available): " + _listUrl.AbsoluteUri, ex);
                    return false;
                }
            }

            #endregion

            #region internal

            internal abstract void LoadListZone();

            #endregion

            #region public

            public async Task LoadAsync()
            {
                if (_listUrl.Scheme.Equals("app", StringComparison.OrdinalIgnoreCase))
                {
                    if (!_listZoneLoaded)
                    {
                        LoadListZone();
                        _listZoneLoaded = true;
                    }
                    return;
                }

                if (_isLoading)
                    return;

                _isLoading = true;

                try
                {
                    if (File.Exists(_listFilePath))
                    {
                        _lastModified = File.GetLastWriteTimeUtc(_listFilePath);

                        if (_listUrl.IsFile && (File.GetLastWriteTimeUtc(_listUrl.LocalPath) > _lastModified))
                        {
                            File.Copy(_listUrl.LocalPath, _listFilePath, true);
                            _lastModified = File.GetLastWriteTimeUtc(_listFilePath);

                            _dnsServer.WriteLog("Advanced Blocking app successfully downloaded " + (_isAdblockList ? "adblock" : (_isRegexList ? "regex " : "") + (_isAllowList ? "allow" : "block")) + " list (" + WebUtilities.GetFormattedSize(new FileInfo(_listFilePath).Length) + "): " + _listUrl.AbsoluteUri);

                            LoadListZone();
                            _listZoneLoaded = true;
                        }
                        else if (!_listZoneLoaded)
                        {
                            LoadListZone();
                            _listZoneLoaded = true;
                        }
                    }
                    else
                    {
                        if (await DownloadListFileAsync())
                        {
                            LoadListZone();
                            _listZoneLoaded = true;
                        }
                    }
                }
                finally
                {
                    _isLoading = false;
                }
            }

            public async Task<bool> UpdateAsync()
            {
                if (_listUrl.Scheme.Equals("app", StringComparison.OrdinalIgnoreCase))
                    return false;

                if (await DownloadListFileAsync())
                {
                    LoadListZone();
                    return true;
                }

                return false;
            }

            #endregion

            #region properties

            public DateTime LastModified
            { get { return _lastModified; } }

            #endregion
        }

        class BlockList : ListBase
        {
            #region variables

            readonly static char[] _popWordSeperator = new char[] { ' ', '\t' };

            HashSet<string> _listZone = [];

            #endregion

            #region constructor

            public BlockList(IDnsServer dnsServer, Uri listUrl, bool isAllowList)
                : base(dnsServer, listUrl, isAllowList, false, false)
            { }

            #endregion

            #region private

            private static string PopWord(ref string line)
            {
                if (line.Length == 0)
                    return line;

                line = line.TrimStart(_popWordSeperator);

                int i = line.IndexOfAny(_popWordSeperator);
                string word;

                if (i < 0)
                {
                    word = line;
                    line = "";
                }
                else
                {
                    word = line.Substring(0, i);
                    line = line.Substring(i + 1);
                }

                return word;
            }

            private Queue<string> ReadListFile()
            {
                Queue<string> domains = new Queue<string>();

                try
                {
                    _dnsServer.WriteLog("Advanced Blocking app is reading " + (_isAllowList ? "allow" : "block") + " list from: " + _listUrl.AbsoluteUri);

                    using (FileStream fS = new FileStream(_listFilePath, FileMode.Open, FileAccess.Read))
                    {
                        //parse hosts file and populate block zone
                        StreamReader sR = new StreamReader(fS, true);
                        char[] trimSeperator = new char[] { ' ', '\t', '*', '.' };
                        string? line;
                        string firstWord;
                        string secondWord;
                        string hostname;

                        while (true)
                        {
                            line = sR.ReadLine();
                            if (line is null)
                                break; //eof

                            line = line.TrimStart(trimSeperator);

                            if (line.Length == 0)
                                continue; //skip empty line

                            if (line.StartsWith('#'))
                                continue; //skip comment line

                            firstWord = PopWord(ref line);

                            if (line.Length == 0)
                            {
                                hostname = firstWord;
                            }
                            else
                            {
                                secondWord = PopWord(ref line);

                                if ((secondWord.Length == 0) || secondWord.StartsWith('#'))
                                {
                                    hostname = firstWord;
                                }
                                else
                                {
                                    if (!IPAddress.TryParse(firstWord, out _))
                                        continue; //first word must be an IP address for using second word as hostname as per hosts file format

                                    hostname = secondWord;
                                }
                            }

                            hostname = hostname.Trim('.').ToLowerInvariant();

                            switch (hostname)
                            {
                                case "":
                                case "localhost":
                                case "localhost.localdomain":
                                case "local":
                                case "broadcasthost":
                                case "ip6-localhost":
                                case "ip6-loopback":
                                case "ip6-localnet":
                                case "ip6-mcastprefix":
                                case "ip6-allnodes":
                                case "ip6-allrouters":
                                case "ip6-allhosts":
                                    continue; //skip these hostnames
                            }

                            if (!DnsClient.IsDomainNameValid(hostname))
                                continue;

                            if (IPAddress.TryParse(hostname, out _))
                                continue; //skip line when hostname is IP address

                            domains.Enqueue(hostname);
                        }
                    }

                    _dnsServer.WriteLog("Advanced Blocking app read " + (_isAllowList ? "allow" : "block") + " list file (" + domains.Count + " domains) from: " + _listUrl.AbsoluteUri);
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("Advanced Blocking app failed to read " + (_isAllowList ? "allow" : "block") + " list from: " + _listUrl.AbsoluteUri, ex);
                }

                return domains;
            }

            #endregion

            #region protected

            internal override void LoadListZone()
            {
                Queue<string> listQueue = ReadListFile();
                HashSet<string> listZone = new HashSet<string>(listQueue.Count);

                while (listQueue.Count > 0)
                    listZone.Add(listQueue.Dequeue());

                _listZone = listZone;
            }

            #endregion

            #region public

            public bool IsZoneFound(string domain, out string? foundZone)
            {
                return App.IsZoneFound(_listZone, domain, out foundZone);
            }

            #endregion
        }

        class RegexList : ListBase
        {
            #region variables

            IReadOnlyList<Regex> _regexListZone = [];

            #endregion

            #region constructor

            public RegexList(IDnsServer dnsServer, Uri listUrl, bool isAllowList)
                : base(dnsServer, listUrl, isAllowList, true, false)
            { }

            #endregion

            #region private

            private Queue<string> ReadRegexListFile()
            {
                Queue<string> regices = new Queue<string>();

                try
                {
                    _dnsServer.WriteLog("Advanced Blocking app is reading regex " + (_isAllowList ? "allow" : "block") + " list from: " + _listUrl.AbsoluteUri);

                    using (FileStream fS = new FileStream(_listFilePath, FileMode.Open, FileAccess.Read))
                    {
                        //parse hosts file and populate block zone
                        StreamReader sR = new StreamReader(fS, true);
                        char[] trimSeperator = new char[] { ' ', '\t' };
                        string? line;

                        while (true)
                        {
                            line = sR.ReadLine();
                            if (line is null)
                                break; //eof

                            line = line.TrimStart(trimSeperator);

                            if (line.Length == 0)
                                continue; //skip empty line

                            if (line.StartsWith('#'))
                                continue; //skip comment line

                            regices.Enqueue(line);
                        }
                    }

                    _dnsServer.WriteLog("Advanced Blocking app read regex " + (_isAllowList ? "allow" : "block") + " list file (" + regices.Count + " regex patterns) from: " + _listUrl.AbsoluteUri);
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("Advanced Blocking app failed to read regex " + (_isAllowList ? "allow" : "block") + " list from: " + _listUrl.AbsoluteUri, ex);
                }

                return regices;
            }

            #endregion

            #region protected

            internal override void LoadListZone()
            {
                Queue<string> regexPatterns = ReadRegexListFile();
                string[] patterns = regexPatterns.ToArray();
                System.Collections.Concurrent.ConcurrentBag<Regex> compiledList = new();

                Parallel.ForEach(patterns, pattern =>
                {
                    try
                    {
                        compiledList.Add(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled));
                    }
                    catch (RegexParseException ex)
                    {
                        _dnsServer.WriteLog(ex);
                    }
                });

                _regexListZone = compiledList.ToArray();
            }

            #endregion

            #region public

            public bool IsMatchFound(string domain, out string? matchingPattern)
            {
                return App.IsMatchFound(_regexListZone, domain, out matchingPattern);
            }

            #endregion
        }

        //parses and represents the "$dnsrewrite=" adblock modifier value. Supports IP addresses (bare or "A;IP"/"AAAA;IP"),
        //response-code override keywords ("NOERROR", "NXDOMAIN", "REFUSED", "SERVFAIL"), CNAME aliases ("$dnsrewrite=cname.target"
        //or "CNAME;target"), TXT records ("TXT;payload"), PTR records ("PTR;target"), MX records ("MX;pref;exchange"), and $empty.
        class DnsRewriteAction
        {
            #region variables

            bool _recognized;
            DnsResponseCode? _responseCode;
            List<IPAddress>? _addresses;
            string? _cnameTarget;
            string? _txtData;
            string? _ptrTarget;
            (ushort preference, string exchange)? _mxRecord;

            #endregion

            #region constructor

            private DnsRewriteAction()
            { }

            #endregion

            #region static

            public static DnsRewriteAction Empty
            {
                get
                {
                    return new DnsRewriteAction()
                    {
                        _recognized = true,
                        _responseCode = DnsResponseCode.NoError
                    };
                }
            }

            public static DnsRewriteAction Parse(string rawValue)
            {
                DnsRewriteAction action = new DnsRewriteAction();

                string value = rawValue.Trim().Trim(';');
                if (value.Length == 0)
                    return action; //not recognized

                int i = value.IndexOf(';');
                string keyword = i < 0 ? value : value.Substring(0, i);
                string? payload = i < 0 ? null : value.Substring(i + 1);

                switch (keyword.ToUpperInvariant())
                {
                    case "$EMPTY":
                    case "EMPTY":
                    case "NOERROR":
                        action._recognized = true;
                        action._responseCode = DnsResponseCode.NoError;
                        break;

                    case "NXDOMAIN":
                        action._recognized = true;
                        action._responseCode = DnsResponseCode.NxDomain;
                        break;

                    case "REFUSED":
                        action._recognized = true;
                        action._responseCode = DnsResponseCode.Refused;
                        break;

                    case "SERVFAIL":
                        action._recognized = true;
                        action._responseCode = DnsResponseCode.ServerFailure;
                        break;

                    case "A":
                    case "AAAA":
                        if ((payload is not null) && IPAddress.TryParse(payload, out IPAddress? typedAddress))
                        {
                            action._recognized = true;
                            action._addresses = new List<IPAddress>(1) { typedAddress };
                        }
                        break;

                    case "CNAME":
                        if ((payload is not null) && DnsClient.IsDomainNameValid(payload.Trim()))
                        {
                            action._recognized = true;
                            action._cnameTarget = payload.Trim().Trim('.').ToLowerInvariant();
                        }
                        break;

                    case "TXT":
                        if (payload is not null)
                        {
                            action._recognized = true;
                            action._txtData = payload;
                        }
                        break;

                    case "PTR":
                        if ((payload is not null) && DnsClient.IsDomainNameValid(payload.Trim()))
                        {
                            action._recognized = true;
                            action._ptrTarget = payload.Trim().Trim('.').ToLowerInvariant();
                        }
                        break;

                    case "MX":
                        if (payload is not null)
                        {
                            string[] mxParts = payload.Split(';', StringSplitOptions.RemoveEmptyEntries);
                            if ((mxParts.Length >= 2) && ushort.TryParse(mxParts[0].Trim(), out ushort pref) && DnsClient.IsDomainNameValid(mxParts[1].Trim()))
                            {
                                action._recognized = true;
                                action._mxRecord = (pref, mxParts[1].Trim().Trim('.').ToLowerInvariant());
                            }
                            else if ((mxParts.Length == 1) && DnsClient.IsDomainNameValid(mxParts[0].Trim()))
                            {
                                action._recognized = true;
                                action._mxRecord = (10, mxParts[0].Trim().Trim('.').ToLowerInvariant());
                            }
                        }
                        break;

                    default:
                        if ((i < 0) && IPAddress.TryParse(value, out IPAddress? bareAddress))
                        {
                            //bare IP address shorthand, e.g. $dnsrewrite=1.2.3.4 or $dnsrewrite=::1
                            action._recognized = true;
                            action._addresses = new List<IPAddress>(1) { bareAddress };
                        }
                        else if ((i < 0) && DnsClient.IsDomainNameValid(value))
                        {
                            //bare CNAME alias shorthand, e.g. $dnsrewrite=forcesafesearch.google.com
                            action._recognized = true;
                            action._cnameTarget = value.Trim().Trim('.').ToLowerInvariant();
                        }
                        break;
                }

                return action;
            }

            #endregion

            #region properties

            public bool Recognized
            { get { return _recognized; } }

            public DnsResponseCode? ResponseCode
            { get { return _responseCode; } }

            public List<IPAddress>? Addresses
            { get { return _addresses; } }

            public string? CnameTarget
            { get { return _cnameTarget; } }

            public string? TxtData
            { get { return _txtData; } }

            public string? PtrTarget
            { get { return _ptrTarget; } }

            public (ushort preference, string exchange)? MxRecord
            { get { return _mxRecord; } }

            public bool IsEmpty
            { get { return _recognized && (_responseCode == DnsResponseCode.NoError) && (_addresses is null) && (_cnameTarget is null) && (_txtData is null) && (_ptrTarget is null) && (!_mxRecord.HasValue); } }

            #endregion
        }

        //unified rule model produced by the adblock parser. Simple, unmodified "||domain^"/bare-domain/"@@" rules
        //never reach this object at match time (they are folded into the fast HashSet zone-walk instead); this
        //type only carries rules that need per-rule evaluation: wildcards, "/regex/" rules, exact-match rules, and rules carrying
        //$important, $dnstype=, $denyallow=, $dnsrewrite= or $client= modifiers.
        class AdBlockRule
        {
            #region variables

            readonly bool _isAllow;
            readonly bool _isRegex;
            readonly bool _hasWildcard;
            readonly bool _exactMatch;
            readonly string? _domain;
            readonly string? _baseDomain;
            readonly Regex? _regex;
            readonly bool _important;
            readonly bool _badFilter;
            readonly HashSet<DnsResourceRecordType>? _dnsTypes;
            readonly HashSet<DnsResourceRecordType>? _excludedDnsTypes;
            readonly HashSet<string>? _denyAllowDomains;
            readonly DnsRewriteAction? _dnsRewrite;
            readonly List<IPAddress>? _clientIps;
            readonly List<NetworkAddress>? _clientNetworks;
            readonly List<IPAddress>? _excludedClientIps;
            readonly List<NetworkAddress>? _excludedClientNetworks;

            #endregion

            #region constructor

            public AdBlockRule(bool isAllow, bool isRegex, bool hasWildcard, bool exactMatch, string? domain, Regex? regex, bool important, bool badFilter, HashSet<DnsResourceRecordType>? dnsTypes, HashSet<DnsResourceRecordType>? excludedDnsTypes, HashSet<string>? denyAllowDomains, DnsRewriteAction? dnsRewrite, List<IPAddress>? clientIps, List<NetworkAddress>? clientNetworks, List<IPAddress>? excludedClientIps, List<NetworkAddress>? excludedClientNetworks)
            {
                _isAllow = isAllow;
                _isRegex = isRegex;
                _hasWildcard = hasWildcard;
                _exactMatch = exactMatch;
                _domain = domain;
                _regex = regex;
                _important = important;
                _badFilter = badFilter;
                _dnsTypes = dnsTypes;
                _excludedDnsTypes = excludedDnsTypes;
                _denyAllowDomains = denyAllowDomains;
                _dnsRewrite = dnsRewrite;
                _clientIps = clientIps;
                _clientNetworks = clientNetworks;
                _excludedClientIps = excludedClientIps;
                _excludedClientNetworks = excludedClientNetworks;

                // Compute base domain for partitioned indexing
                if (_domain is not null)
                {
                    if (_hasWildcard)
                    {
                        int lastStar = _domain.LastIndexOf('*');
                        if ((lastStar >= 0) && (lastStar < _domain.Length - 1))
                        {
                            string suffix = _domain.Substring(lastStar + 1);
                            if (suffix.StartsWith('.') && (suffix.Length > 1))
                            {
                                string candidate = suffix.Substring(1);
                                if (DnsClient.IsDomainNameValid(candidate))
                                    _baseDomain = candidate.ToLowerInvariant();
                            }
                        }
                    }
                    else
                    {
                        _baseDomain = _domain.ToLowerInvariant();
                    }
                }
            }

            #endregion

            #region public

            public bool IsMatch(string domain, DnsResourceRecordType qType, IPAddress? clientIp)
            {
                if ((_dnsTypes is not null) && !_dnsTypes.Contains(qType))
                    return false;

                if ((_excludedDnsTypes is not null) && _excludedDnsTypes.Contains(qType))
                    return false;

                if (clientIp is not null)
                {
                    if ((_excludedClientIps is not null) && _excludedClientIps.Contains(clientIp))
                        return false;

                    if (_excludedClientNetworks is not null)
                    {
                        foreach (NetworkAddress net in _excludedClientNetworks)
                        {
                            if (net.Contains(clientIp))
                                return false;
                        }
                    }

                    if ((_clientIps is not null) || (_clientNetworks is not null))
                    {
                        bool clientMatched = false;
                        if ((_clientIps is not null) && _clientIps.Contains(clientIp))
                        {
                            clientMatched = true;
                        }
                        else if (_clientNetworks is not null)
                        {
                            foreach (NetworkAddress net in _clientNetworks)
                            {
                                if (net.Contains(clientIp))
                                {
                                    clientMatched = true;
                                    break;
                                }
                            }
                        }

                        if (!clientMatched)
                            return false;
                    }
                }

                bool isMatch;

                if (_isRegex || _hasWildcard)
                    isMatch = (_regex is not null) && _regex.IsMatch(domain);
                else if (_exactMatch)
                    isMatch = (_domain is not null) && domain.Equals(_domain, StringComparison.OrdinalIgnoreCase);
                else
                    isMatch = (_domain is not null) && (domain.Equals(_domain, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + _domain, StringComparison.OrdinalIgnoreCase));

                if (!isMatch)
                    return false;

                if ((_denyAllowDomains is not null) && IsZoneFound(_denyAllowDomains, domain, out _))
                    return false; //excluded via $denyallow=

                return true;
            }

            #endregion

            #region properties

            public bool IsAllow
            { get { return _isAllow; } }

            public bool IsRegex
            { get { return _isRegex; } }

            public bool HasWildcard
            { get { return _hasWildcard; } }

            public bool ExactMatch
            { get { return _exactMatch; } }

            public string? Domain
            { get { return _domain; } }

            public string? BaseDomain
            { get { return _baseDomain; } }

            public bool Important
            { get { return _important; } }

            public bool BadFilter
            { get { return _badFilter; } }

            public HashSet<DnsResourceRecordType>? DnsTypes
            { get { return _dnsTypes; } }

            public HashSet<DnsResourceRecordType>? ExcludedDnsTypes
            { get { return _excludedDnsTypes; } }

            public DnsRewriteAction? DnsRewrite
            { get { return _dnsRewrite; } }

            public List<IPAddress>? ClientIps
            { get { return _clientIps; } }

            public List<NetworkAddress>? ClientNetworks
            { get { return _clientNetworks; } }

            public List<IPAddress>? ExcludedClientIps
            { get { return _excludedClientIps; } }

            public List<NetworkAddress>? ExcludedClientNetworks
            { get { return _excludedClientNetworks; } }

            public HashSet<string>? DenyAllowDomains
            { get { return _denyAllowDomains; } }

            public string? MatchKey
            { get { return _isRegex || _hasWildcard ? _regex?.ToString() : _domain; } }

            #endregion
        }

        class AdBlockList : ListBase
        {
            #region variables

            static readonly Regex _wildcardDomainCharsetRegex = new Regex(@"^[a-zA-Z0-9*._-]+$", RegexOptions.Compiled);

            readonly string[]? _inMemoryRules;
            List<AdBlockRule> _rawRules = [];

            HashSet<string> _allowedListZone = [];
            HashSet<string> _blockedListZone = [];

            Dictionary<string, List<AdBlockRule>> _specialAllowByDomain = new(StringComparer.OrdinalIgnoreCase);
            List<AdBlockRule> _specialAllowUnconstrained = [];

            Dictionary<string, List<AdBlockRule>> _specialBlockByDomain = new(StringComparer.OrdinalIgnoreCase);
            List<AdBlockRule> _specialBlockUnconstrained = [];

            Dictionary<string, List<AdBlockRule>> _importantAllowByDomain = new(StringComparer.OrdinalIgnoreCase);
            List<AdBlockRule> _importantAllowUnconstrained = [];

            Dictionary<string, List<AdBlockRule>> _importantBlockByDomain = new(StringComparer.OrdinalIgnoreCase);
            List<AdBlockRule> _importantBlockUnconstrained = [];

            #endregion

            #region constructor

            public AdBlockList(IDnsServer dnsServer, Uri listUrl)
                : base(dnsServer, listUrl, false, false, true)
            {
                _inMemoryRules = null;
            }

            public AdBlockList(IDnsServer dnsServer, string[] inMemoryRules, string groupName)
                : base(dnsServer, new Uri("app://advanced-blocking/inline-rules/" + Uri.EscapeDataString(groupName)), false, false, true)
            {
                _inMemoryRules = inMemoryRules;
            }

            #endregion

            #region private

            private static bool IsCosmeticRule(string line)
            {
                //element-hiding / HTML-filtering rules are out of scope for DNS-only blocking
                return line.Contains("##") || line.Contains("#@#") || line.Contains("#$#") || line.Contains("#%#") || line.Contains("#?#") || line.Contains("$$");
            }

            private static void ParseModifiers(string modifiersStr, out bool important, out bool badFilter, out HashSet<DnsResourceRecordType>? dnsTypes, out HashSet<DnsResourceRecordType>? excludedDnsTypes, out HashSet<string>? denyAllowDomains, out DnsRewriteAction? dnsRewrite, out List<IPAddress>? clientIps, out List<NetworkAddress>? clientNetworks, out List<IPAddress>? excludedClientIps, out List<NetworkAddress>? excludedClientNetworks)
            {
                important = false;
                badFilter = false;
                dnsTypes = null;
                excludedDnsTypes = null;
                denyAllowDomains = null;
                dnsRewrite = null;
                clientIps = null;
                clientNetworks = null;
                excludedClientIps = null;
                excludedClientNetworks = null;

                if (string.IsNullOrEmpty(modifiersStr))
                    return;

                foreach (string rawToken in modifiersStr.Split(','))
                {
                    string token = rawToken.Trim();
                    if (token.Length == 0)
                        continue;

                    if (token.Equals("important", StringComparison.OrdinalIgnoreCase))
                    {
                        important = true;
                    }
                    else if (token.Equals("badfilter", StringComparison.OrdinalIgnoreCase))
                    {
                        badFilter = true;
                    }
                    else if (token.Equals("empty", StringComparison.OrdinalIgnoreCase))
                    {
                        dnsRewrite = DnsRewriteAction.Empty;
                    }
                    else if (token.StartsWith("dnstype=", StringComparison.OrdinalIgnoreCase))
                    {
                        HashSet<DnsResourceRecordType> posTypes = new HashSet<DnsResourceRecordType>();
                        HashSet<DnsResourceRecordType> negTypes = new HashSet<DnsResourceRecordType>();

                        foreach (string typeToken in token.Substring(8).Split('|'))
                        {
                            string t = typeToken.Trim();
                            bool isNegated = t.StartsWith('~');
                            if (isNegated)
                                t = t.Substring(1).Trim();

                            if ((t.Length > 0) && Enum.TryParse(t, true, out DnsResourceRecordType parsedType))
                            {
                                if (isNegated)
                                    negTypes.Add(parsedType);
                                else
                                    posTypes.Add(parsedType);
                            }
                        }

                        if (posTypes.Count > 0)
                            dnsTypes = posTypes;

                        if (negTypes.Count > 0)
                            excludedDnsTypes = negTypes;
                    }
                    else if (token.StartsWith("denyallow=", StringComparison.OrdinalIgnoreCase))
                    {
                        HashSet<string> domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                        foreach (string domainToken in token.Substring(10).Split('|'))
                        {
                            string d = domainToken.Trim().Trim('.').ToLowerInvariant();

                            if ((d.Length > 0) && DnsClient.IsDomainNameValid(d))
                                domains.Add(d);
                        }

                        if (domains.Count > 0)
                            denyAllowDomains = domains;
                    }
                    else if (token.StartsWith("dnsrewrite=", StringComparison.OrdinalIgnoreCase))
                    {
                        dnsRewrite = DnsRewriteAction.Parse(token.Substring(11));
                    }
                    else if (token.StartsWith("client=", StringComparison.OrdinalIgnoreCase) || token.StartsWith("~client=", StringComparison.OrdinalIgnoreCase) || token.StartsWith("~$client=", StringComparison.OrdinalIgnoreCase))
                    {
                        bool tokenNegated = token.StartsWith('~');
                        int eqIdx = token.IndexOf('=');
                        string clientVal = token.Substring(eqIdx + 1);

                        foreach (string rawClientEntry in clientVal.Split('|'))
                        {
                            string entry = rawClientEntry.Trim();
                            bool entryNegated = tokenNegated || entry.StartsWith('~');
                            if (entry.StartsWith('~'))
                                entry = entry.Substring(1).Trim();

                            if (entry.Length == 0)
                                continue;

                            if (IPAddress.TryParse(entry, out IPAddress? parsedIp))
                            {
                                if (entryNegated)
                                {
                                    excludedClientIps ??= new List<IPAddress>(1);
                                    excludedClientIps.Add(parsedIp);
                                }
                                else
                                {
                                    clientIps ??= new List<IPAddress>(1);
                                    clientIps.Add(parsedIp);
                                }
                            }
                            else if (NetworkAddress.TryParse(entry, out NetworkAddress? parsedNet))
                            {
                                if (entryNegated)
                                {
                                    excludedClientNetworks ??= new List<NetworkAddress>(1);
                                    excludedClientNetworks.Add(parsedNet);
                                }
                                else
                                {
                                    clientNetworks ??= new List<NetworkAddress>(1);
                                    clientNetworks.Add(parsedNet);
                                }
                            }
                        }
                    }

                    //all other modifiers (third-party, domain=, doc, all, match-case, ctag=, app=,
                    //popup, etc.) are intentionally ignored rather than invalidating the rule
                }
            }

            private static string BuildWildcardRegexPattern(string domainPart)
            {
                StringBuilder sb = new StringBuilder();
                sb.Append("^(?:.*\\.)?");

                string[] segments = domainPart.Split('*');
                for (int i = 0; i < segments.Length; i++)
                {
                    if (i > 0)
                        sb.Append(".*");

                    sb.Append(Regex.Escape(segments[i]));
                }

                sb.Append('$');

                return sb.ToString();
            }

            private static AdBlockRule? BuildDomainRule(bool isAllow, string domainPart, string? modifiersStr, bool exactMatch = false)
            {
                domainPart = domainPart.Trim();
                if (domainPart.Length == 0)
                    return null;

                if (!_wildcardDomainCharsetRegex.IsMatch(domainPart))
                    return null; //contains characters outside the hostname/wildcard charset (e.g. a URL path) - out of scope

                ParseModifiers(modifiersStr ?? string.Empty, out bool important, out bool badFilter, out HashSet<DnsResourceRecordType>? dnsTypes, out HashSet<DnsResourceRecordType>? excludedDnsTypes, out HashSet<string>? denyAllowDomains, out DnsRewriteAction? dnsRewrite, out List<IPAddress>? clientIps, out List<NetworkAddress>? clientNetworks, out List<IPAddress>? excludedClientIps, out List<NetworkAddress>? excludedClientNetworks);

                bool hasWildcard = domainPart.Contains('*');

                if (hasWildcard && domainPart.StartsWith("*.") && (domainPart.IndexOf('*', 2) < 0) && !exactMatch)
                {
                    //a leading "*." with no other wildcard is functionally identical to a plain "||domain^"
                    //rule (which already matches the domain and all of its subdomains) - normalize it so it
                    //can use the cheap suffix-match path instead of compiling a regex
                    domainPart = domainPart.Substring(2);
                    hasWildcard = false;
                }

                Regex? regex = null;

                if (hasWildcard)
                {
                    regex = new Regex(BuildWildcardRegexPattern(domainPart), RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
                }
                else
                {
                    if (!DnsClient.IsDomainNameValid(domainPart))
                        return null;
                }

                return new AdBlockRule(isAllow, false, hasWildcard, exactMatch, domainPart.ToLowerInvariant(), regex, important, badFilter, dnsTypes, excludedDnsTypes, denyAllowDomains, dnsRewrite, clientIps, clientNetworks, excludedClientIps, excludedClientNetworks);
            }

            private static AdBlockRule? BuildRegexRule(bool isAllow, string pattern, string? modifiersStr)
            {
                Regex regex;

                try
                {
                    regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
                }
                catch (RegexParseException)
                {
                    return null;
                }

                ParseModifiers(modifiersStr ?? string.Empty, out bool important, out bool badFilter, out HashSet<DnsResourceRecordType>? dnsTypes, out HashSet<DnsResourceRecordType>? excludedDnsTypes, out HashSet<string>? denyAllowDomains, out DnsRewriteAction? dnsRewrite, out List<IPAddress>? clientIps, out List<NetworkAddress>? clientNetworks, out List<IPAddress>? excludedClientIps, out List<NetworkAddress>? excludedClientNetworks);

                return new AdBlockRule(isAllow, true, false, false, null, regex, important, badFilter, dnsTypes, excludedDnsTypes, denyAllowDomains, dnsRewrite, clientIps, clientNetworks, excludedClientIps, excludedClientNetworks);
            }

            private static AdBlockRule? ParseLine(string line, out bool wasCosmetic, out bool wasUnsupported)
            {
                wasCosmetic = false;
                wasUnsupported = false;

                if (IsCosmeticRule(line))
                {
                    wasCosmetic = true;
                    return null;
                }

                bool isAllow = line.StartsWith("@@");
                string rule = isAllow ? line.Substring(2) : line;

                if (rule.Length == 0)
                    return null;

                //"/regex/" or "/regex/$modifiers"
                if (rule[0] == '/')
                {
                    int end = rule.LastIndexOf('/');
                    if (end > 0)
                    {
                        string pattern = rule.Substring(1, end - 1);
                        string remainder = rule.Substring(end + 1);
                        string? modifiers = remainder.StartsWith('$') ? remainder.Substring(1) : null;

                        AdBlockRule? regexRule = BuildRegexRule(isAllow, pattern, modifiers);
                        if (regexRule is null)
                            wasUnsupported = true;

                        return regexRule;
                    }

                    wasUnsupported = true;
                    return null;
                }

                //"||domain^[$modifiers]" or "||domain" (no anchor char)
                if (rule.StartsWith("||"))
                {
                    string body = rule.Substring(2);
                    int i = body.IndexOf('^');

                    string domainPart;
                    string? modifiers;

                    if (i > -1)
                    {
                        domainPart = body.Substring(0, i);
                        string options = body.Substring(i + 1);

                        if (options.Length == 0)
                        {
                            modifiers = null;
                        }
                        else if (options[0] == '$')
                        {
                            modifiers = options.Substring(1);
                        }
                        else
                        {
                            //content after the domain anchor that isn't a $modifier list is a URL/path
                            //qualifier (e.g. "||example.com^/path") - out of scope for DNS-only blocking
                            wasUnsupported = true;
                            return null;
                        }
                    }
                    else
                    {
                        domainPart = body;
                        modifiers = null;
                    }

                    if (domainPart.Contains('/') || domainPart.Contains('$'))
                    {
                        wasUnsupported = true;
                        return null;
                    }

                    AdBlockRule? domainRule = BuildDomainRule(isAllow, domainPart, modifiers, exactMatch: false);
                    if (domainRule is null)
                        wasUnsupported = true;

                    return domainRule;
                }

                //exact-domain matching ("|domain|" or "|domain^")
                if (rule.StartsWith('|') && !rule.StartsWith("||"))
                {
                    string body = rule.Substring(1);

                    //single-pipe URL-anchor rules ("|https://..." or "|http://...") are out of scope for DNS-only blocking
                    if (body.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || body.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || body.Contains('/'))
                    {
                        wasUnsupported = true;
                        return null;
                    }

                    int endAnchor = body.IndexOfAny(['|', '^']);
                    string domainPart;
                    string? modifiers = null;

                    if (endAnchor > -1)
                    {
                        domainPart = body.Substring(0, endAnchor);
                        string remainder = body.Substring(endAnchor + 1);

                        if (remainder.StartsWith('$'))
                        {
                            modifiers = remainder.Substring(1);
                        }
                        else if (remainder.Length > 0 && remainder != "|")
                        {
                            wasUnsupported = true;
                            return null;
                        }
                    }
                    else
                    {
                        domainPart = body;
                    }

                    if (domainPart.Length == 0 || !DnsClient.IsDomainNameValid(domainPart))
                    {
                        wasUnsupported = true;
                        return null;
                    }

                    AdBlockRule? exactRule = BuildDomainRule(isAllow, domainPart, modifiers, exactMatch: true);
                    if (exactRule is null)
                        wasUnsupported = true;

                    return exactRule;
                }

                //bare-domain fallback (hosts-file-style single domain per line, with optional wildcard and
                //optional trailing "$modifiers"), e.g. "example.com" or "*.ads.example.com$important"
                {
                    int dollar = rule.IndexOf('$');
                    string domainPart = dollar < 0 ? rule : rule.Substring(0, dollar);
                    string? modifiers = dollar < 0 ? null : rule.Substring(dollar + 1);

                    if (domainPart.Contains('/'))
                    {
                        wasUnsupported = true;
                        return null;
                    }

                    AdBlockRule? domainRule = BuildDomainRule(isAllow, domainPart, modifiers, exactMatch: false);
                    if (domainRule is null)
                        wasUnsupported = true;

                    return domainRule;
                }
            }

            private List<AdBlockRule> ReadAdblockRulesFromMemory(string[] lines)
            {
                List<AdBlockRule> rules = new List<AdBlockRule>(lines.Length);
                char[] trimSeparator = [' ', '\t'];

                foreach (string rawLine in lines)
                {
                    string line = rawLine.TrimStart(trimSeparator).TrimEnd();
                    if (line.Length == 0 || line.StartsWith('!'))
                        continue;

                    AdBlockRule? parsedRule = ParseLine(line, out _, out _);
                    if (parsedRule is not null)
                        rules.Add(parsedRule);
                }

                return rules;
            }

            private List<AdBlockRule> ReadAdblockListFile()
            {
                List<AdBlockRule> rules = new List<AdBlockRule>();
                int cosmeticSkipped = 0;
                int unsupportedSkipped = 0;

                try
                {
                    _dnsServer.WriteLog("Advanced Blocking app is reading adblock list from: " + _listUrl.AbsoluteUri);

                    using (FileStream fS = new FileStream(_listFilePath, FileMode.Open, FileAccess.Read))
                    {
                        StreamReader sR = new StreamReader(fS, true);
                        char[] trimSeperator = new char[] { ' ', '\t' };
                        string? line;

                        while (true)
                        {
                            line = sR.ReadLine();
                            if (line is null)
                                break; //eof

                            line = line.TrimStart(trimSeperator).TrimEnd();

                            if (line.Length == 0)
                                continue; //skip empty line

                            if (line.StartsWith('!'))
                                continue; //skip comment line

                            AdBlockRule? parsedRule = ParseLine(line, out bool wasCosmetic, out bool wasUnsupported);

                            if (wasCosmetic)
                                cosmeticSkipped++;
                            else if (wasUnsupported)
                                unsupportedSkipped++;

                            if (parsedRule is not null)
                                rules.Add(parsedRule);
                        }
                    }

                    _dnsServer.WriteLog("Advanced Blocking app read adblock list file (" + rules.Count + " rules; skipped " + cosmeticSkipped + " cosmetic, " + unsupportedSkipped + " unsupported) from: " + _listUrl.AbsoluteUri);
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("Advanced Blocking app failed to read adblock list from: " + _listUrl.AbsoluteUri, ex);
                }

                return rules;
            }

            private static void AddPartitionedRule(Dictionary<string, List<AdBlockRule>> dict, List<AdBlockRule> unconstrained, AdBlockRule rule)
            {
                if (rule.BaseDomain is not null)
                {
                    if (!dict.TryGetValue(rule.BaseDomain, out List<AdBlockRule>? list))
                    {
                        list = new List<AdBlockRule>(1);
                        dict.Add(rule.BaseDomain, list);
                    }
                    list.Add(rule);
                }
                else
                {
                    unconstrained.Add(rule);
                }
            }

            private static IEnumerable<string> GetDomainSuffixes(string domain)
            {
                yield return domain;

                int dotIndex = 0;
                while ((dotIndex = domain.IndexOf('.', dotIndex)) >= 0)
                {
                    dotIndex++;
                    if (dotIndex < domain.Length)
                        yield return domain.Substring(dotIndex);
                }
            }

            #endregion

            #region protected

            internal override void LoadListZone()
            {
                List<AdBlockRule> allRules = _inMemoryRules is not null ? ReadAdblockRulesFromMemory(_inMemoryRules) : ReadAdblockListFile();
                _rawRules = allRules;

                // $badfilter cancellation: identify and track rule signatures matching identical allow/block
                // polarity to cancel matching filter entries within this list
                HashSet<(bool isAllow, string key)> cancelKeys = new HashSet<(bool, string)>();

                foreach (AdBlockRule rule in allRules)
                {
                    if (rule.BadFilter && (rule.MatchKey is not null))
                        cancelKeys.Add((rule.IsAllow, rule.MatchKey!));
                }

                HashSet<string> allowedListZone = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                HashSet<string> blockedListZone = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                Dictionary<string, List<AdBlockRule>> specialAllowByDomain = new(StringComparer.OrdinalIgnoreCase);
                List<AdBlockRule> specialAllowUnconstrained = [];

                Dictionary<string, List<AdBlockRule>> specialBlockByDomain = new(StringComparer.OrdinalIgnoreCase);
                List<AdBlockRule> specialBlockUnconstrained = [];

                Dictionary<string, List<AdBlockRule>> importantAllowByDomain = new(StringComparer.OrdinalIgnoreCase);
                List<AdBlockRule> importantAllowUnconstrained = [];

                Dictionary<string, List<AdBlockRule>> importantBlockByDomain = new(StringComparer.OrdinalIgnoreCase);
                List<AdBlockRule> importantBlockUnconstrained = [];

                foreach (AdBlockRule rule in allRules)
                {
                    if (rule.BadFilter)
                        continue; //$badfilter rules only cancel other rules; they never match a query themselves

                    if ((rule.MatchKey is not null) && cancelKeys.Contains((rule.IsAllow, rule.MatchKey!)))
                        continue; //cancelled by a $badfilter rule

                    if (rule.Important)
                    {
                        if (rule.IsAllow)
                            AddPartitionedRule(importantAllowByDomain, importantAllowUnconstrained, rule);
                        else
                            AddPartitionedRule(importantBlockByDomain, importantBlockUnconstrained, rule);

                        continue;
                    }

                    bool isSimple = !rule.IsRegex && !rule.HasWildcard && !rule.ExactMatch && (rule.DnsTypes is null) && (rule.ExcludedDnsTypes is null) && (rule.DnsRewrite is null) && (rule.DenyAllowDomains is null) && (rule.ClientIps is null) && (rule.ClientNetworks is null) && (rule.ExcludedClientIps is null) && (rule.ExcludedClientNetworks is null) && (rule.Domain is not null);

                    if (isSimple)
                    {
                        if (rule.IsAllow)
                            allowedListZone.Add(rule.Domain!);
                        else
                            blockedListZone.Add(rule.Domain!);
                    }
                    else
                    {
                        if (rule.IsAllow)
                            AddPartitionedRule(specialAllowByDomain, specialAllowUnconstrained, rule);
                        else
                            AddPartitionedRule(specialBlockByDomain, specialBlockUnconstrained, rule);
                    }
                }

                _allowedListZone = allowedListZone;
                _blockedListZone = blockedListZone;

                _specialAllowByDomain = specialAllowByDomain;
                _specialAllowUnconstrained = specialAllowUnconstrained;

                _specialBlockByDomain = specialBlockByDomain;
                _specialBlockUnconstrained = specialBlockUnconstrained;

                _importantAllowByDomain = importantAllowByDomain;
                _importantAllowUnconstrained = importantAllowUnconstrained;

                _importantBlockByDomain = importantBlockByDomain;
                _importantBlockUnconstrained = importantBlockUnconstrained;
            }

            #endregion

            #region public

            public IReadOnlyList<AdBlockRule> RawRules
            { get { return _rawRules; } }

            public bool IsZoneAllowed(string domain, DnsResourceRecordType qType, IPAddress? clientIp, out string? foundZone, out AdBlockRule? matchedRule, HashSet<(bool isAllow, string key)>? groupCancelKeys = null)
            {
                domain = domain.ToLowerInvariant();

                if (IsZoneFound(_allowedListZone, domain, out foundZone))
                {
                    if ((foundZone is not null) && (groupCancelKeys is null || !groupCancelKeys.Contains((true, foundZone))))
                    {
                        matchedRule = null;
                        return true;
                    }
                }

                foreach (AdBlockRule rule in _specialAllowUnconstrained)
                {
                    if ((rule.MatchKey is not null) && (groupCancelKeys is not null) && groupCancelKeys.Contains((true, rule.MatchKey)))
                        continue;

                    if (rule.IsMatch(domain, qType, clientIp))
                    {
                        foundZone = rule.Domain ?? domain;
                        matchedRule = rule;
                        return true;
                    }
                }

                foreach (string suffix in GetDomainSuffixes(domain))
                {
                    if (_specialAllowByDomain.TryGetValue(suffix, out List<AdBlockRule>? rules))
                    {
                        foreach (AdBlockRule rule in rules)
                        {
                            if ((rule.MatchKey is not null) && (groupCancelKeys is not null) && groupCancelKeys.Contains((true, rule.MatchKey)))
                                continue;

                            if (rule.IsMatch(domain, qType, clientIp))
                            {
                                foundZone = rule.Domain ?? domain;
                                matchedRule = rule;
                                return true;
                            }
                        }
                    }
                }

                foundZone = null;
                matchedRule = null;
                return false;
            }

            public bool IsZoneBlocked(string domain, DnsResourceRecordType qType, IPAddress? clientIp, out string? foundZone, out AdBlockRule? matchedRule, HashSet<(bool isAllow, string key)>? groupCancelKeys = null)
            {
                domain = domain.ToLowerInvariant();

                if (IsZoneFound(_blockedListZone, domain, out foundZone))
                {
                    if ((foundZone is not null) && (groupCancelKeys is null || !groupCancelKeys.Contains((false, foundZone))))
                    {
                        matchedRule = null;
                        return true;
                    }
                }

                foreach (AdBlockRule rule in _specialBlockUnconstrained)
                {
                    if ((rule.MatchKey is not null) && (groupCancelKeys is not null) && groupCancelKeys.Contains((false, rule.MatchKey)))
                        continue;

                    if (rule.IsMatch(domain, qType, clientIp))
                    {
                        foundZone = rule.Domain ?? domain;
                        matchedRule = rule;
                        return true;
                    }
                }

                foreach (string suffix in GetDomainSuffixes(domain))
                {
                    if (_specialBlockByDomain.TryGetValue(suffix, out List<AdBlockRule>? rules))
                    {
                        foreach (AdBlockRule rule in rules)
                        {
                            if ((rule.MatchKey is not null) && (groupCancelKeys is not null) && groupCancelKeys.Contains((false, rule.MatchKey)))
                                continue;

                            if (rule.IsMatch(domain, qType, clientIp))
                            {
                                foundZone = rule.Domain ?? domain;
                                matchedRule = rule;
                                return true;
                            }
                        }
                    }
                }

                foundZone = null;
                matchedRule = null;
                return false;
            }

            public bool IsImportantAllowed(string domain, DnsResourceRecordType qType, IPAddress? clientIp, out AdBlockRule? matchedRule, HashSet<(bool isAllow, string key)>? groupCancelKeys = null)
            {
                domain = domain.ToLowerInvariant();

                foreach (AdBlockRule rule in _importantAllowUnconstrained)
                {
                    if ((rule.MatchKey is not null) && (groupCancelKeys is not null) && groupCancelKeys.Contains((true, rule.MatchKey)))
                        continue;

                    if (rule.IsMatch(domain, qType, clientIp))
                    {
                        matchedRule = rule;
                        return true;
                    }
                }

                foreach (string suffix in GetDomainSuffixes(domain))
                {
                    if (_importantAllowByDomain.TryGetValue(suffix, out List<AdBlockRule>? rules))
                    {
                        foreach (AdBlockRule rule in rules)
                        {
                            if ((rule.MatchKey is not null) && (groupCancelKeys is not null) && groupCancelKeys.Contains((true, rule.MatchKey)))
                                continue;

                            if (rule.IsMatch(domain, qType, clientIp))
                            {
                                matchedRule = rule;
                                return true;
                            }
                        }
                    }
                }

                matchedRule = null;
                return false;
            }

            public bool IsImportantBlocked(string domain, DnsResourceRecordType qType, IPAddress? clientIp, out AdBlockRule? matchedRule, HashSet<(bool isAllow, string key)>? groupCancelKeys = null)
            {
                domain = domain.ToLowerInvariant();

                foreach (AdBlockRule rule in _importantBlockUnconstrained)
                {
                    if ((rule.MatchKey is not null) && (groupCancelKeys is not null) && groupCancelKeys.Contains((false, rule.MatchKey)))
                        continue;

                    if (rule.IsMatch(domain, qType, clientIp))
                    {
                        matchedRule = rule;
                        return true;
                    }
                }

                foreach (string suffix in GetDomainSuffixes(domain))
                {
                    if (_importantBlockByDomain.TryGetValue(suffix, out List<AdBlockRule>? rules))
                    {
                        foreach (AdBlockRule rule in rules)
                        {
                            if ((rule.MatchKey is not null) && (groupCancelKeys is not null) && groupCancelKeys.Contains((false, rule.MatchKey)))
                                continue;

                            if (rule.IsMatch(domain, qType, clientIp))
                            {
                                matchedRule = rule;
                                return true;
                            }
                        }
                    }
                }

                matchedRule = null;
                return false;
            }

            #endregion
        }
    }
}
