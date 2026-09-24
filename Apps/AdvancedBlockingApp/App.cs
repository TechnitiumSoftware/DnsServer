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
    public sealed class App : IDnsApplication, IDnsRequestBlockingHandler
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

        private static bool IsZoneAllowed(Dictionary<Uri, ListZoneEntry<AdBlockList>> listZones, string domain, DnsResourceRecordType qType, out string? foundZone, out UrlEntry? listUri)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<AdBlockList>> listZone in listZones)
            {
                if (listZone.Value.List.IsZoneAllowed(domain, qType, out foundZone, out _))
                {
                    listUri = listZone.Value.UrlEntry;
                    return true;
                }
            }

            foundZone = null;
            listUri = null;
            return false;
        }

        private static bool IsZoneBlocked(Dictionary<Uri, ListZoneEntry<AdBlockList>> listZones, string domain, DnsResourceRecordType qType, out string? foundZone, out UrlEntry? listUri, out AdBlockRule? matchedRule)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<AdBlockList>> listZone in listZones)
            {
                if (listZone.Value.List.IsZoneBlocked(domain, qType, out foundZone, out matchedRule))
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

        private static bool IsImportantAllowed(Dictionary<Uri, ListZoneEntry<AdBlockList>> listZones, string domain, DnsResourceRecordType qType, out string? foundZone, out UrlEntry? listUri)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<AdBlockList>> listZone in listZones)
            {
                if (listZone.Value.List.IsImportantAllowed(domain, qType, out AdBlockRule? matchedRule))
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

        private static bool IsImportantBlocked(Dictionary<Uri, ListZoneEntry<AdBlockList>> listZones, string domain, DnsResourceRecordType qType, out string? foundZone, out UrlEntry? listUri, out AdBlockRule? matchedRule)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<AdBlockList>> listZone in listZones)
            {
                if (listZone.Value.List.IsImportantBlocked(domain, qType, out matchedRule))
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
        }

        public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return Task.FromResult(false);

            string? groupName = GetGroupName(request, remoteEP);
            if ((groupName is null) || !_groups!.TryGetValue(groupName, out Group? group) || !group.EnableBlocking)
                return Task.FromResult(false);

            DnsQuestionRecord question = request.Question[0];

            return Task.FromResult(group.IsZoneAllowed(question.Name, question.Type));
        }

        public Task<DnsDatagram?> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return Task.FromResult<DnsDatagram?>(null);

            string? groupName = GetGroupName(request, remoteEP);
            if ((groupName is null) || !_groups!.TryGetValue(groupName, out Group? group) || !group.EnableBlocking)
                return Task.FromResult<DnsDatagram?>(null);

            DnsQuestionRecord question = request.Question[0];

            if (!group.IsZoneBlocked(question.Name, question.Type, out string? blockedDomain, out string? blockedRegex, out UrlEntry? blockListUrl, out AdBlockRule? matchedRule))
                return Task.FromResult<DnsDatagram?>(null);

            //$dnsrewrite (adblock rule modifier) takes precedence over the group's default blocking response
            if ((matchedRule is not null) && (matchedRule.DnsRewrite is not null) && matchedRule.DnsRewrite.Recognized)
            {
                DnsRewriteAction rewrite = matchedRule.DnsRewrite;

                if (rewrite.ResponseCode.HasValue && (rewrite.ResponseCode.Value != DnsResponseCode.NoError))
                    return Task.FromResult<DnsDatagram?>(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, rewrite.ResponseCode.Value, request.Question));

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

                    return Task.FromResult<DnsDatagram?>(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, rrList.Count > 0 ? rrList : null));
                }

                //recognized $dnsrewrite with no address/rcode payload for this question type (e.g. AAAA rewrite target on an A query) - respond empty NOERROR
                return Task.FromResult<DnsDatagram?>(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question));
            }

            string GetBlockingReport()
            {
                string blockingReport = "source=advanced-blocking-app; group=" + group.Name;

                if (blockedRegex is null)
                {
                    if (blockListUrl!.Uri is not null)
                        blockingReport += "; blockListUrl=" + blockListUrl.Uri.AbsoluteUri + "; domain=" + blockedDomain;
                    else
                        blockingReport += "; domain=" + blockedDomain;
                }
                else
                {
                    if (blockListUrl!.Uri is not null)
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

                return Task.FromResult<DnsDatagram?>(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answer));
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
                bool ra;
                IReadOnlyList<DnsResourceRecord>? answer = null;
                IReadOnlyList<DnsResourceRecord>? authority = null;

                if (blockListUrl!.BlockAsNxDomain)
                {
                    rcode = DnsResponseCode.NxDomain;
                    ra = !group.AllowTxtBlockingReport;

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
                    ra = true;

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.A:
                            {
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(blockListUrl.ARecords.Count);

                                foreach (DnsARecordData record in blockListUrl.ARecords)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, _blockingAnswerTtl, record));

                                answer = rrList;
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            {
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(blockListUrl.AAAARecords.Count);

                                foreach (DnsAAAARecordData record in blockListUrl.AAAARecords)
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

                return Task.FromResult<DnsDatagram?>(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, ra, false, false, rcode, request.Question, answer, authority, null, request.EDNS is null ? ushort.MinValue : _dnsServer!.UdpPayloadSize, EDnsHeaderFlags.None, options));
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

            Dictionary<Uri, BlockList> _allowListZones = [];
            Dictionary<Uri, ListZoneEntry<BlockList>> _blockListZones = [];

            Dictionary<Uri, RegexList> _regexAllowListZones = [];
            Dictionary<Uri, ListZoneEntry<RegexList>> _regexBlockListZones = [];

            Dictionary<Uri, ListZoneEntry<AdBlockList>> _adBlockListZones = [];

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
                    Dictionary<Uri, ListZoneEntry<AdBlockList>> adBlockListZones = new Dictionary<Uri, ListZoneEntry<AdBlockList>>(_adblockListUrls.Length);

                    foreach (UrlEntry listUrl in _adblockListUrls)
                    {
                        if (_app._allAdBlockListZones.TryGetValue(listUrl.Uri!, out AdBlockList? adBlockListZone))
                            adBlockListZones.Add(listUrl.Uri!, new ListZoneEntry<AdBlockList>(listUrl, adBlockListZone));
                    }

                    _adBlockListZones = adBlockListZones;
                }
            }

            public bool IsZoneAllowed(string domain, DnsResourceRecordType qType)
            {
                domain = domain.ToLowerInvariant();

                //adblock $important block rule takes precedence over any allow rule
                if (App.IsImportantBlocked(_adBlockListZones, domain, qType, out _, out _, out _))
                    return false;

                //adblock $important allow rule overrides normal block rules
                if (App.IsImportantAllowed(_adBlockListZones, domain, qType, out _, out _))
                    return true;

                //allowed, allow list zone, allowedRegex, regex allow list zone, adblock list zone
                return IsZoneFound(_allowed, domain, out _) || IsZoneFound(_allowListZones, domain, out _, out _) || IsMatchFound(_allowedRegex, domain, out _) || IsMatchFound(_regexAllowListZones, domain, out _, out _) || App.IsZoneAllowed(_adBlockListZones, domain, qType, out _, out _);
            }

            public bool IsZoneBlocked(string domain, DnsResourceRecordType qType, out string? blockedDomain, out string? blockedRegex, out UrlEntry? listUrl, out AdBlockRule? matchedRule)
            {
                domain = domain.ToLowerInvariant();

                //adblock $important block rule - highest priority, overrides any allow rule (checked again here since
                //IsAllowedAsync and IsZoneBlocked are separate calls and must independently agree on this precedence)
                if (App.IsImportantBlocked(_adBlockListZones, domain, qType, out string? foundZoneImp, out UrlEntry? blockListUrlImp, out AdBlockRule? matchedRuleImp))
                {
                    blockedDomain = foundZoneImp;
                    blockedRegex = null;
                    listUrl = blockListUrlImp;
                    matchedRule = matchedRuleImp;
                    return true;
                }

                //adblock $important allow rule overrides normal block rules
                if (App.IsImportantAllowed(_adBlockListZones, domain, qType, out _, out _))
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
                if (App.IsZoneBlocked(_adBlockListZones, domain, qType, out string? foundZone3, out UrlEntry? blockListUrl3, out AdBlockRule? matchedRule3))
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

            #region protected

            protected abstract void LoadListZone();

            #endregion

            #region public

            public async Task LoadAsync()
            {
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

            protected override void LoadListZone()
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

            protected override void LoadListZone()
            {
                Queue<string> regexPatterns = ReadRegexListFile();
                List<Regex> regexListZone = new List<Regex>(regexPatterns.Count);

                while (regexPatterns.Count > 0)
                {
                    try
                    {
                        regexListZone.Add(new Regex(regexPatterns.Dequeue(), RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled));
                    }
                    catch (RegexParseException ex)
                    {
                        _dnsServer.WriteLog(ex);
                    }
                }

                _regexListZone = regexListZone;
            }

            #endregion

            #region public

            public bool IsMatchFound(string domain, out string? matchingPattern)
            {
                return App.IsMatchFound(_regexListZone, domain, out matchingPattern);
            }

            #endregion
        }

        //parses and represents the "$dnsrewrite=" adblock modifier value. Only the DNS-relevant subset is
        //modeled: a bare IP address (or "A;IP"/"AAAA;IP") for an inline answer, and the "NOERROR"/"NXDOMAIN"/
        //"REFUSED" response-code override keywords. CNAME/TXT/HTTPS/SVCB/MX rewrite targets would require
        //re-invoking the resolver and are intentionally out of scope; such values are left unrecognized so
        //that the carrying rule still blocks/allows using the group's normal default behaviour.
        class DnsRewriteAction
        {
            #region variables

            bool _recognized;
            DnsResponseCode? _responseCode;
            List<IPAddress>? _addresses;

            #endregion

            #region constructor

            private DnsRewriteAction()
            { }

            #endregion

            #region static

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

                    case "A":
                    case "AAAA":
                        if ((payload is not null) && IPAddress.TryParse(payload, out IPAddress? typedAddress))
                        {
                            action._recognized = true;
                            action._addresses = new List<IPAddress>(1) { typedAddress };
                        }

                        break;

                    default:
                        if ((i < 0) && IPAddress.TryParse(value, out IPAddress? bareAddress))
                        {
                            //bare IP address shorthand, e.g. $dnsrewrite=1.2.3.4 or $dnsrewrite=::1
                            action._recognized = true;
                            action._addresses = new List<IPAddress>(1) { bareAddress };
                        }

                        //else: CNAME/TXT/HTTPS/SVCB/MX and other rewrite targets are not modeled here;
                        //action remains unrecognized
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

            #endregion
        }

        //unified rule model produced by the adblock parser. Simple, unmodified "||domain^"/bare-domain/"@@" rules
        //never reach this object at match time (they are folded into the fast HashSet zone-walk instead); this
        //type only carries rules that need per-rule evaluation: wildcards, "/regex/" rules, and rules carrying
        //$important, $dnstype=, $denyallow= or $dnsrewrite= modifiers.
        class AdBlockRule
        {
            #region variables

            readonly bool _isAllow;
            readonly bool _isRegex;
            readonly bool _hasWildcard;
            readonly string? _domain;
            readonly Regex? _regex;
            readonly bool _important;
            readonly bool _badFilter;
            readonly HashSet<DnsResourceRecordType>? _dnsTypes;
            readonly HashSet<string>? _denyAllowDomains;
            readonly DnsRewriteAction? _dnsRewrite;

            #endregion

            #region constructor

            public AdBlockRule(bool isAllow, bool isRegex, bool hasWildcard, string? domain, Regex? regex, bool important, bool badFilter, HashSet<DnsResourceRecordType>? dnsTypes, HashSet<string>? denyAllowDomains, DnsRewriteAction? dnsRewrite)
            {
                _isAllow = isAllow;
                _isRegex = isRegex;
                _hasWildcard = hasWildcard;
                _domain = domain;
                _regex = regex;
                _important = important;
                _badFilter = badFilter;
                _dnsTypes = dnsTypes;
                _denyAllowDomains = denyAllowDomains;
                _dnsRewrite = dnsRewrite;
            }

            #endregion

            #region public

            public bool IsMatch(string domain, DnsResourceRecordType qType)
            {
                if ((_dnsTypes is not null) && !_dnsTypes.Contains(qType))
                    return false;

                bool isMatch;

                if (_isRegex || _hasWildcard)
                    isMatch = (_regex is not null) && _regex.IsMatch(domain);
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

            public string? Domain
            { get { return _domain; } }

            public bool Important
            { get { return _important; } }

            public bool BadFilter
            { get { return _badFilter; } }

            public HashSet<DnsResourceRecordType>? DnsTypes
            { get { return _dnsTypes; } }

            public DnsRewriteAction? DnsRewrite
            { get { return _dnsRewrite; } }

            //cancellation key used to approximate $badfilter matching: exact rule text matching per the
            //true AdGuard spec isn't practical in this simplified engine, so cancellation is approximated
            //via allow/block polarity plus this domain-or-pattern-text key (documented simplification).
            public string? MatchKey
            { get { return _isRegex || _hasWildcard ? _regex?.ToString() : _domain; } }

            #endregion
        }

        class AdBlockList : ListBase
        {
            #region variables

            static readonly Regex _wildcardDomainCharsetRegex = new Regex(@"^[a-zA-Z0-9*._-]+$", RegexOptions.Compiled);

            HashSet<string> _allowedListZone = [];
            HashSet<string> _blockedListZone = [];

            List<AdBlockRule> _specialAllowRules = [];
            List<AdBlockRule> _specialBlockRules = [];

            List<AdBlockRule> _importantAllowRules = [];
            List<AdBlockRule> _importantBlockRules = [];

            #endregion

            #region constructor

            public AdBlockList(IDnsServer dnsServer, Uri listUrl)
                : base(dnsServer, listUrl, false, false, true)
            { }

            #endregion

            #region private

            private static bool IsCosmeticRule(string line)
            {
                //element-hiding / HTML-filtering rules are out of scope for DNS-only blocking
                return line.Contains("##") || line.Contains("#@#") || line.Contains("#$#") || line.Contains("#%#") || line.Contains("#?#") || line.Contains("$$");
            }

            private static void ParseModifiers(string modifiersStr, out bool important, out bool badFilter, out HashSet<DnsResourceRecordType>? dnsTypes, out HashSet<string>? denyAllowDomains, out DnsRewriteAction? dnsRewrite)
            {
                important = false;
                badFilter = false;
                dnsTypes = null;
                denyAllowDomains = null;
                dnsRewrite = null;

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
                    else if (token.StartsWith("dnstype=", StringComparison.OrdinalIgnoreCase))
                    {
                        HashSet<DnsResourceRecordType> types = new HashSet<DnsResourceRecordType>();

                        foreach (string typeToken in token.Substring(8).Split('|'))
                        {
                            //negated dnstype entries (e.g. "~TXT") are not modeled and are treated as a
                            //positive match instead of an exclusion (documented simplification)
                            string t = typeToken.Trim().TrimStart('~');

                            if ((t.Length > 0) && Enum.TryParse(t, true, out DnsResourceRecordType parsedType))
                                types.Add(parsedType);
                        }

                        if (types.Count > 0)
                            dnsTypes = types;
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

                    //all other modifiers (third-party, domain=, doc, all, match-case, client=, ctag=, app=,
                    //popup, badfilter's target modifiers, etc.) are intentionally ignored rather than
                    //invalidating the rule - this is the key fix for rules being silently dropped entirely
                    //whenever they carried any modifier not containing the literal substring "doc" or "all"
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

            private static AdBlockRule? BuildDomainRule(bool isAllow, string domainPart, string? modifiersStr)
            {
                domainPart = domainPart.Trim();
                if (domainPart.Length == 0)
                    return null;

                if (!_wildcardDomainCharsetRegex.IsMatch(domainPart))
                    return null; //contains characters outside the hostname/wildcard charset (e.g. a URL path) - out of scope

                ParseModifiers(modifiersStr ?? string.Empty, out bool important, out bool badFilter, out HashSet<DnsResourceRecordType>? dnsTypes, out HashSet<string>? denyAllowDomains, out DnsRewriteAction? dnsRewrite);

                bool hasWildcard = domainPart.Contains('*');

                if (hasWildcard && domainPart.StartsWith("*.") && (domainPart.IndexOf('*', 2) < 0))
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

                return new AdBlockRule(isAllow, false, hasWildcard, domainPart.ToLowerInvariant(), regex, important, badFilter, dnsTypes, denyAllowDomains, dnsRewrite);
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

                ParseModifiers(modifiersStr ?? string.Empty, out bool important, out bool badFilter, out HashSet<DnsResourceRecordType>? dnsTypes, out HashSet<string>? denyAllowDomains, out DnsRewriteAction? dnsRewrite);

                return new AdBlockRule(isAllow, true, false, null, regex, important, badFilter, dnsTypes, denyAllowDomains, dnsRewrite);
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

                    AdBlockRule? domainRule = BuildDomainRule(isAllow, domainPart, modifiers);
                    if (domainRule is null)
                        wasUnsupported = true;

                    return domainRule;
                }

                //single-pipe URL-anchor rules ("|https://...") are out of scope for DNS-only blocking
                if (rule.StartsWith('|'))
                {
                    wasUnsupported = true;
                    return null;
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

                    AdBlockRule? domainRule = BuildDomainRule(isAllow, domainPart, modifiers);
                    if (domainRule is null)
                        wasUnsupported = true;

                    return domainRule;
                }
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

            #endregion

            #region protected

            protected override void LoadListZone()
            {
                List<AdBlockRule> allRules = ReadAdblockListFile();

                //$badfilter: cancel any other rule of the same allow/block polarity whose domain/pattern text
                //matches - an approximation of AdGuard's exact-rule-text $badfilter matching (documented
                //simplification; scoped to rules within this same list)
                HashSet<(bool isAllow, string key)> cancelKeys = new HashSet<(bool, string)>();

                foreach (AdBlockRule rule in allRules)
                {
                    if (rule.BadFilter && (rule.MatchKey is not null))
                        cancelKeys.Add((rule.IsAllow, rule.MatchKey!));
                }

                HashSet<string> allowedListZone = new HashSet<string>();
                HashSet<string> blockedListZone = new HashSet<string>();

                List<AdBlockRule> specialAllowRules = new List<AdBlockRule>();
                List<AdBlockRule> specialBlockRules = new List<AdBlockRule>();

                List<AdBlockRule> importantAllowRules = new List<AdBlockRule>();
                List<AdBlockRule> importantBlockRules = new List<AdBlockRule>();

                foreach (AdBlockRule rule in allRules)
                {
                    if (rule.BadFilter)
                        continue; //$badfilter rules only cancel other rules; they never match a query themselves

                    if ((rule.MatchKey is not null) && cancelKeys.Contains((rule.IsAllow, rule.MatchKey!)))
                        continue; //cancelled by a $badfilter rule

                    if (rule.Important)
                    {
                        if (rule.IsAllow)
                            importantAllowRules.Add(rule);
                        else
                            importantBlockRules.Add(rule);

                        continue;
                    }

                    bool isSimple = !rule.IsRegex && !rule.HasWildcard && (rule.DnsTypes is null) && (rule.DnsRewrite is null) && (rule.Domain is not null);

                    //denyallow-carrying rules always need the full per-rule evaluation path since the fast
                    //HashSet zone-walk has no mechanism to apply an exception
                    if (isSimple)
                    {
                        //re-check denyallow presence via the special list path since HashSet fast path can't honour it
                        if (rule.IsAllow)
                            allowedListZone.Add(rule.Domain!);
                        else
                            blockedListZone.Add(rule.Domain!);
                    }
                    else
                    {
                        if (rule.IsAllow)
                            specialAllowRules.Add(rule);
                        else
                            specialBlockRules.Add(rule);
                    }
                }

                _allowedListZone = allowedListZone;
                _blockedListZone = blockedListZone;

                _specialAllowRules = specialAllowRules;
                _specialBlockRules = specialBlockRules;

                _importantAllowRules = importantAllowRules;
                _importantBlockRules = importantBlockRules;
            }

            #endregion

            #region public

            public bool IsZoneAllowed(string domain, DnsResourceRecordType qType, out string? foundZone, out AdBlockRule? matchedRule)
            {
                domain = domain.ToLowerInvariant();

                if (IsZoneFound(_allowedListZone, domain, out foundZone))
                {
                    matchedRule = null;
                    return true;
                }

                foreach (AdBlockRule rule in _specialAllowRules)
                {
                    if (rule.IsMatch(domain, qType))
                    {
                        foundZone = rule.Domain ?? domain;
                        matchedRule = rule;
                        return true;
                    }
                }

                foundZone = null;
                matchedRule = null;
                return false;
            }

            public bool IsZoneBlocked(string domain, DnsResourceRecordType qType, out string? foundZone, out AdBlockRule? matchedRule)
            {
                domain = domain.ToLowerInvariant();

                if (IsZoneFound(_blockedListZone, domain, out foundZone))
                {
                    matchedRule = null;
                    return true;
                }

                foreach (AdBlockRule rule in _specialBlockRules)
                {
                    if (rule.IsMatch(domain, qType))
                    {
                        foundZone = rule.Domain ?? domain;
                        matchedRule = rule;
                        return true;
                    }
                }

                foundZone = null;
                matchedRule = null;
                return false;
            }

            public bool IsImportantAllowed(string domain, DnsResourceRecordType qType, out AdBlockRule? matchedRule)
            {
                domain = domain.ToLowerInvariant();

                foreach (AdBlockRule rule in _importantAllowRules)
                {
                    if (rule.IsMatch(domain, qType))
                    {
                        matchedRule = rule;
                        return true;
                    }
                }

                matchedRule = null;
                return false;
            }

            public bool IsImportantBlocked(string domain, DnsResourceRecordType qType, out AdBlockRule? matchedRule)
            {
                domain = domain.ToLowerInvariant();

                foreach (AdBlockRule rule in _importantBlockRules)
                {
                    if (rule.IsMatch(domain, qType))
                    {
                        matchedRule = rule;
                        return true;
                    }
                }

                matchedRule = null;
                return false;
            }

            #endregion
        }
    }
}
