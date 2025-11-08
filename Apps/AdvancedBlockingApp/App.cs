/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

        IDnsServer _dnsServer;

        DnsSOARecordData _soaRecord;
        DnsNSRecordData _nsRecord;

        bool _enableBlocking;
        int _blockListUrlUpdateIntervalHours;

        Dictionary<EndPoint, string> _localEndPointGroupMap;
        Dictionary<NetworkAddress, string> _networkGroupMap;
        Dictionary<string, Group> _groups;

        Dictionary<Uri, BlockList> _allAllowListZones = new Dictionary<Uri, BlockList>(0);
        Dictionary<Uri, BlockList> _allBlockListZones = new Dictionary<Uri, BlockList>(0);

        Dictionary<Uri, RegexList> _allRegexAllowListZones = new Dictionary<Uri, RegexList>(0);
        Dictionary<Uri, RegexList> _allRegexBlockListZones = new Dictionary<Uri, RegexList>(0);

        Dictionary<Uri, AdBlockList> _allAdBlockListZones = new Dictionary<Uri, AdBlockList>(0);

        Timer _blockListUrlUpdateTimer;
        DateTime _blockListUrlLastUpdatedOn;
        const int BLOCK_LIST_UPDATE_TIMER_INTERVAL = 900000;

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

        private async void BlockListUrlUpdateTimerCallbackAsync(object state)
        {
            try
            {
                if (DateTime.UtcNow > _blockListUrlLastUpdatedOn.AddHours(_blockListUrlUpdateIntervalHours))
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
                _dnsServer.WriteLog(ex);
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

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

        private static bool IsZoneFound(Dictionary<string, object> domains, string domain, out string foundZone)
        {
            do
            {
                if (domains.TryGetValue(domain, out _))
                {
                    foundZone = domain;
                    return true;
                }

                domain = GetParentZone(domain);
            }
            while (domain is not null);

            foundZone = null;
            return false;
        }

        private static bool IsZoneFound(Dictionary<Uri, BlockList> listZones, string domain, out string foundZone, out Uri listUri)
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

        private static bool IsZoneFound(Dictionary<Uri, ListZoneEntry<BlockList>> listZones, string domain, out string foundZone, out UrlEntry listUri)
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

        private static bool IsZoneAllowed(Dictionary<Uri, ListZoneEntry<AdBlockList>> listZones, string domain, out string foundZone, out UrlEntry listUri)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<AdBlockList>> listZone in listZones)
            {
                if (listZone.Value.List.IsZoneAllowed(domain, out foundZone))
                {
                    listUri = listZone.Value.UrlEntry;
                    return true;
                }
            }

            foundZone = null;
            listUri = null;
            return false;
        }

        private static bool IsZoneBlocked(Dictionary<Uri, ListZoneEntry<AdBlockList>> listZones, string domain, out string foundZone, out UrlEntry listUri)
        {
            foreach (KeyValuePair<Uri, ListZoneEntry<AdBlockList>> listZone in listZones)
            {
                if (listZone.Value.List.IsZoneBlocked(domain, out foundZone))
                {
                    listUri = listZone.Value.UrlEntry;
                    return true;
                }
            }

            foundZone = null;
            listUri = null;
            return false;
        }

        private static bool IsMatchFound(Regex[] regices, string domain, out string matchingPattern)
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

        private static bool IsMatchFound(Dictionary<Uri, RegexList> regexListZones, string domain, out string matchingPattern, out Uri listUri)
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

        private static bool IsMatchFound(Dictionary<Uri, ListZoneEntry<RegexList>> regexListZones, string domain, out string matchingPattern, out UrlEntry listUri)
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

        private string GetGroupName(DnsDatagram request, IPEndPoint remoteEP)
        {
            if ((request.Metadata is not null) && (request.Metadata.NameServer is not null))
            {
                Uri requestLocalUriEP = request.Metadata.NameServer.DoHEndPoint;
                if (requestLocalUriEP is not null)
                {
                    foreach (KeyValuePair<EndPoint, string> entry in _localEndPointGroupMap)
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
                    foreach (KeyValuePair<EndPoint, string> entry in _localEndPointGroupMap)
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
                    foreach (KeyValuePair<EndPoint, string> entry in _localEndPointGroupMap)
                    {
                        if (entry.Key is IPEndPoint ep)
                        {
                            if (((ep.Port == 0) || (ep.Port == requestLocalEP.Port)) && ep.Address.Equals(requestLocalEP.Address))
                                return entry.Value;
                        }
                    }
                }
            }

            string groupName = null;
            IPAddress remoteIP = remoteEP.Address;
            NetworkAddress network = null;

            foreach (KeyValuePair<NetworkAddress, string> entry in _networkGroupMap)
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

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            Directory.CreateDirectory(Path.Combine(_dnsServer.ApplicationFolder, "blocklists"));

            _soaRecord = new DnsSOARecordData(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, 60);
            _nsRecord = new DnsNSRecordData(_dnsServer.ServerDomain);

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _enableBlocking = jsonConfig.GetProperty("enableBlocking").GetBoolean();
            _blockListUrlUpdateIntervalHours = jsonConfig.GetProperty("blockListUrlUpdateIntervalHours").GetInt32();

            if (jsonConfig.TryReadObjectAsMap("localEndPointGroupMap",
                delegate (string localEP, JsonElement jsonGroup)
                {
                    if (!EndPointExtensions.TryParse(localEP, out EndPoint ep))
                        throw new InvalidOperationException("Local end point group map contains an invalid end point: " + localEP);

                    return new Tuple<EndPoint, string>(ep, jsonGroup.GetString());
                },
                out Dictionary<EndPoint, string> localEndPointGroupMap))
            {
                _localEndPointGroupMap = localEndPointGroupMap;
            }

            _networkGroupMap = jsonConfig.ReadObjectAsMap("networkGroupMap", delegate (string network, JsonElement jsonGroup)
            {
                if (!NetworkAddress.TryParse(network, out NetworkAddress networkAddress))
                    throw new InvalidOperationException("Network group map contains an invalid network address: " + network);

                return new Tuple<NetworkAddress, string>(networkAddress, jsonGroup.GetString());
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
                            if (_allAllowListZones.TryGetValue(allowListUrl, out BlockList allowList))
                                allAllowListZones.Add(allowListUrl, allowList);
                            else
                                allAllowListZones.Add(allowListUrl, new BlockList(_dnsServer, allowListUrl, true));
                        }
                    }

                    foreach (UrlEntry blockListUrl in group.BlockListUrls)
                    {
                        if (!allBlockListZones.ContainsKey(blockListUrl.Uri))
                        {
                            if (_allBlockListZones.TryGetValue(blockListUrl.Uri, out BlockList blockList))
                                allBlockListZones.Add(blockListUrl.Uri, blockList);
                            else
                                allBlockListZones.Add(blockListUrl.Uri, new BlockList(_dnsServer, blockListUrl.Uri, false));
                        }
                    }

                    foreach (Uri regexAllowListUrl in group.RegexAllowListUrls)
                    {
                        if (!allRegexAllowListZones.ContainsKey(regexAllowListUrl))
                        {
                            if (_allRegexAllowListZones.TryGetValue(regexAllowListUrl, out RegexList regexAllowList))
                                allRegexAllowListZones.Add(regexAllowListUrl, regexAllowList);
                            else
                                allRegexAllowListZones.Add(regexAllowListUrl, new RegexList(_dnsServer, regexAllowListUrl, true));
                        }
                    }

                    foreach (UrlEntry regexBlockListUrl in group.RegexBlockListUrls)
                    {
                        if (!allRegexBlockListZones.ContainsKey(regexBlockListUrl.Uri))
                        {
                            if (_allRegexBlockListZones.TryGetValue(regexBlockListUrl.Uri, out RegexList regexBlockList))
                                allRegexBlockListZones.Add(regexBlockListUrl.Uri, regexBlockList);
                            else
                                allRegexBlockListZones.Add(regexBlockListUrl.Uri, new RegexList(_dnsServer, regexBlockListUrl.Uri, false));
                        }
                    }

                    foreach (UrlEntry adblockListUrl in group.AdblockListUrls)
                    {
                        if (!allAdBlockListZones.ContainsKey(adblockListUrl.Uri))
                        {
                            if (_allAdBlockListZones.TryGetValue(adblockListUrl.Uri, out AdBlockList adBlockList))
                                allAdBlockListZones.Add(adblockListUrl.Uri, adBlockList);
                            else
                                allAdBlockListZones.Add(adblockListUrl.Uri, new AdBlockList(_dnsServer, adblockListUrl.Uri));
                        }
                    }

                    return new Tuple<string, Group>(group.Name, group);
                });

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

            ThreadPool.QueueUserWorkItem(async delegate (object state)
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
        }

        public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return Task.FromResult(false);

            string groupName = GetGroupName(request, remoteEP);
            if ((groupName is null) || !_groups.TryGetValue(groupName, out Group group) || !group.EnableBlocking)
                return Task.FromResult(false);

            DnsQuestionRecord question = request.Question[0];

            return Task.FromResult(group.IsZoneAllowed(question.Name));
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return Task.FromResult<DnsDatagram>(null);

            string groupName = GetGroupName(request, remoteEP);
            if ((groupName is null) || !_groups.TryGetValue(groupName, out Group group) || !group.EnableBlocking)
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];

            if (!group.IsZoneBlocked(question.Name, out string blockedDomain, out string blockedRegex, out UrlEntry blockListUrl))
                return Task.FromResult<DnsDatagram>(null);

            string GetBlockingReport()
            {
                string blockingReport = "source=advanced-blocking-app; group=" + group.Name;

                if (blockedRegex is null)
                {
                    if (blockListUrl.Uri is not null)
                        blockingReport += "; blockListUrl=" + blockListUrl.Uri.AbsoluteUri + "; domain=" + blockedDomain;
                    else
                        blockingReport += "; domain=" + blockedDomain;
                }
                else
                {
                    if (blockListUrl.Uri is not null)
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

                DnsResourceRecord[] answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecordData(blockingReport)) };

                return Task.FromResult(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answer));
            }
            else
            {
                EDnsOption[] options = null;

                if (group.AllowTxtBlockingReport && (request.EDNS is not null))
                {
                    string blockingReport = GetBlockingReport();

                    options = new EDnsOption[] { new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, blockingReport)) };
                }

                DnsResponseCode rcode;
                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;

                if (blockListUrl.BlockAsNxDomain)
                {
                    rcode = DnsResponseCode.NxDomain;

                    if (blockedDomain is null)
                        blockedDomain = question.Name;

                    string parentDomain = GetParentZone(blockedDomain);
                    if (parentDomain is null)
                        parentDomain = string.Empty;

                    authority = new DnsResourceRecord[] { new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) };
                }
                else
                {
                    rcode = DnsResponseCode.NoError;

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.A:
                            {
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(blockListUrl.ARecords.Count);

                                foreach (DnsARecordData record in blockListUrl.ARecords)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, 60, record));

                                answer = rrList;
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            {
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(blockListUrl.AAAARecords.Count);

                                foreach (DnsAAAARecordData record in blockListUrl.AAAARecords)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, 60, record));

                                answer = rrList;
                            }
                            break;

                        case DnsResourceRecordType.NS:
                            if (blockedDomain is null)
                                blockedDomain = question.Name;

                            if (question.Name.Equals(blockedDomain, StringComparison.OrdinalIgnoreCase))
                                answer = new DnsResourceRecord[] { new DnsResourceRecord(blockedDomain, DnsResourceRecordType.NS, question.Class, 60, _nsRecord) };
                            else
                                authority = new DnsResourceRecord[] { new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) };

                            break;

                        case DnsResourceRecordType.SOA:
                            if (blockedDomain is null)
                                blockedDomain = question.Name;

                            answer = new DnsResourceRecord[] { new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) };
                            break;

                        default:
                            if (blockedDomain is null)
                                blockedDomain = question.Name;

                            authority = new DnsResourceRecord[] { new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) };
                            break;
                    }
                }

                return Task.FromResult(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, rcode, request.Question, answer, authority, null, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options));
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

            readonly Uri _uri;
            readonly bool _blockAsNxDomain;

            readonly List<DnsARecordData> _aRecords;
            readonly List<DnsAAAARecordData> _aaaaRecords;

            #endregion

            #region constructor

            public UrlEntry(Uri uri, Group group)
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
                        _uri = new Uri(jsonUrl.GetString());

                        _blockAsNxDomain = group.BlockAsNxDomain;
                        _aRecords = group.ARecords;
                        _aaaaRecords = group.AAAARecords;
                        break;

                    case JsonValueKind.Object:
                        _uri = new Uri(jsonUrl.GetProperty("url").GetString());

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
                                string strAddress = jsonBlockingAddress.GetString();

                                if (IPAddress.TryParse(strAddress, out IPAddress address))
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

            public Uri Uri
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

            readonly Dictionary<string, object> _allowed;
            readonly Dictionary<string, object> _blocked;
            readonly Uri[] _allowListUrls;
            readonly UrlEntry[] _blockListUrls;

            readonly Regex[] _allowedRegex;
            readonly Regex[] _blockedRegex;
            readonly Uri[] _regexAllowListUrls;
            readonly UrlEntry[] _regexBlockListUrls;

            readonly UrlEntry[] _adblockListUrls;

            Dictionary<Uri, BlockList> _allowListZones = new Dictionary<Uri, BlockList>(0);
            Dictionary<Uri, ListZoneEntry<BlockList>> _blockListZones = new Dictionary<Uri, ListZoneEntry<BlockList>>(0);

            Dictionary<Uri, RegexList> _regexAllowListZones = new Dictionary<Uri, RegexList>(0);
            Dictionary<Uri, ListZoneEntry<RegexList>> _regexBlockListZones = new Dictionary<Uri, ListZoneEntry<RegexList>>(0);

            Dictionary<Uri, ListZoneEntry<AdBlockList>> _adBlockListZones = new Dictionary<Uri, ListZoneEntry<AdBlockList>>(0);

            #endregion

            #region constructor

            public Group(App app, JsonElement jsonGroup)
            {
                _app = app;

                _name = jsonGroup.GetProperty("name").GetString();
                _enableBlocking = jsonGroup.GetProperty("enableBlocking").GetBoolean();
                _allowTxtBlockingReport = jsonGroup.GetProperty("allowTxtBlockingReport").GetBoolean();
                _blockAsNxDomain = jsonGroup.GetPropertyValue("blockAsNxDomain", false);

                if (jsonGroup.TryGetProperty("blockingAddresses", out JsonElement jsonBlockingAddresses))
                {
                    List<DnsARecordData> aRecords = new List<DnsARecordData>();
                    List<DnsAAAARecordData> aaaaRecords = new List<DnsAAAARecordData>();

                    foreach (JsonElement jsonBlockingAddress in jsonBlockingAddresses.EnumerateArray())
                    {
                        string strAddress = jsonBlockingAddress.GetString();

                        if (IPAddress.TryParse(strAddress, out IPAddress address))
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

                _allowed = jsonGroup.ReadArrayAsMap("allowed", GetMapEntry);
                _blocked = jsonGroup.ReadArrayAsMap("blocked", GetMapEntry);
                _allowListUrls = jsonGroup.ReadArray("allowListUrls", GetUriEntry);
                _blockListUrls = jsonGroup.ReadArray("blockListUrls", GetUrlEntry);

                _allowedRegex = jsonGroup.ReadArray("allowedRegex", GetRegexEntry);
                _blockedRegex = jsonGroup.ReadArray("blockedRegex", GetRegexEntry);
                _regexAllowListUrls = jsonGroup.ReadArray("regexAllowListUrls", GetUriEntry);
                _regexBlockListUrls = jsonGroup.ReadArray("regexBlockListUrls", GetUrlEntry);

                _adblockListUrls = jsonGroup.ReadArray("adblockListUrls", GetUrlEntry);
            }

            #endregion

            #region private

            private static Tuple<string, object> GetMapEntry(JsonElement jsonElement)
            {
                return new Tuple<string, object>(jsonElement.GetString(), null);
            }

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
                        if (_app._allAllowListZones.TryGetValue(listUrl, out BlockList allowListZone))
                            allowListZones.Add(listUrl, allowListZone);
                    }

                    _allowListZones = allowListZones;
                }

                {
                    Dictionary<Uri, ListZoneEntry<BlockList>> blockListZones = new Dictionary<Uri, ListZoneEntry<BlockList>>(_blockListUrls.Length);

                    foreach (UrlEntry listUrl in _blockListUrls)
                    {
                        if (_app._allBlockListZones.TryGetValue(listUrl.Uri, out BlockList blockListZone))
                            blockListZones.Add(listUrl.Uri, new ListZoneEntry<BlockList>(listUrl, blockListZone));
                    }

                    _blockListZones = blockListZones;
                }

                {
                    Dictionary<Uri, RegexList> regexAllowListZones = new Dictionary<Uri, RegexList>(_regexAllowListUrls.Length);

                    foreach (Uri listUrl in _regexAllowListUrls)
                    {
                        if (_app._allRegexAllowListZones.TryGetValue(listUrl, out RegexList regexAllowListZone))
                            regexAllowListZones.Add(listUrl, regexAllowListZone);
                    }

                    _regexAllowListZones = regexAllowListZones;
                }

                {
                    Dictionary<Uri, ListZoneEntry<RegexList>> regexBlockListZones = new Dictionary<Uri, ListZoneEntry<RegexList>>(_regexBlockListUrls.Length);

                    foreach (UrlEntry listUrl in _regexBlockListUrls)
                    {
                        if (_app._allRegexBlockListZones.TryGetValue(listUrl.Uri, out RegexList regexBlockListZone))
                            regexBlockListZones.Add(listUrl.Uri, new ListZoneEntry<RegexList>(listUrl, regexBlockListZone));
                    }

                    _regexBlockListZones = regexBlockListZones;
                }

                {
                    Dictionary<Uri, ListZoneEntry<AdBlockList>> adBlockListZones = new Dictionary<Uri, ListZoneEntry<AdBlockList>>(_adblockListUrls.Length);

                    foreach (UrlEntry listUrl in _adblockListUrls)
                    {
                        if (_app._allAdBlockListZones.TryGetValue(listUrl.Uri, out AdBlockList adBlockListZone))
                            adBlockListZones.Add(listUrl.Uri, new ListZoneEntry<AdBlockList>(listUrl, adBlockListZone));
                    }

                    _adBlockListZones = adBlockListZones;
                }
            }

            public bool IsZoneAllowed(string domain)
            {
                domain = domain.ToLowerInvariant();

                //allowed, allow list zone, allowedRegex, regex allow list zone, adblock list zone
                return IsZoneFound(_allowed, domain, out _) || IsZoneFound(_allowListZones, domain, out _, out _) || IsMatchFound(_allowedRegex, domain, out _) || IsMatchFound(_regexAllowListZones, domain, out _, out _) || App.IsZoneAllowed(_adBlockListZones, domain, out _, out _);
            }

            public bool IsZoneBlocked(string domain, out string blockedDomain, out string blockedRegex, out UrlEntry listUrl)
            {
                domain = domain.ToLowerInvariant();

                //blocked
                if (IsZoneFound(_blocked, domain, out string foundZone1))
                {
                    //found zone blocked
                    blockedDomain = foundZone1;
                    blockedRegex = null;
                    listUrl = new UrlEntry(null, this);
                    return true;
                }

                //block list zone
                if (IsZoneFound(_blockListZones, domain, out string foundZone2, out UrlEntry blockListUrl1))
                {
                    //found zone blocked
                    blockedDomain = foundZone2;
                    blockedRegex = null;
                    listUrl = blockListUrl1;
                    return true;
                }

                //blockedRegex
                if (IsMatchFound(_blockedRegex, domain, out string blockedPattern1))
                {
                    //found pattern blocked
                    blockedDomain = null;
                    blockedRegex = blockedPattern1;
                    listUrl = new UrlEntry(null, this);
                    return true;
                }

                //regex block list zone
                if (IsMatchFound(_regexBlockListZones, domain, out string blockedPattern2, out UrlEntry blockListUrl2))
                {
                    //found pattern blocked
                    blockedDomain = null;
                    blockedRegex = blockedPattern2;
                    listUrl = blockListUrl2;
                    return true;
                }

                //adblock list zone
                if (App.IsZoneBlocked(_adBlockListZones, domain, out string foundZone3, out UrlEntry blockListUrl3))
                {
                    //found zone blocked
                    blockedDomain = foundZone3;
                    blockedRegex = null;
                    listUrl = blockListUrl3;
                    return true;
                }

                blockedDomain = null;
                blockedRegex = null;
                listUrl = null;
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
                        handler.NetworkType = _dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
                        handler.DnsClient = _dnsServer;

                        using (HttpClient http = new HttpClient(handler))
                        {
                            if (File.Exists(_listFilePath))
                                http.DefaultRequestHeaders.IfModifiedSince = File.GetLastWriteTimeUtc(_listFilePath);

                            HttpResponseMessage httpResponse = await http.GetAsync(_listUrl);
                            switch (httpResponse.StatusCode)
                            {
                                case HttpStatusCode.OK:
                                    string listDownloadFilePath = _listFilePath + ".downloading";

                                    using (FileStream fS = new FileStream(listDownloadFilePath, FileMode.Create, FileAccess.Write))
                                    {
                                        using (Stream httpStream = await httpResponse.Content.ReadAsStreamAsync())
                                        {
                                            await httpStream.CopyToAsync(fS);
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
                    _dnsServer.WriteLog("Advanced Blocking app failed to download " + (_isAdblockList ? "adblock" : (_isRegexList ? "regex " : "") + (_isAllowList ? "allow" : "block")) + " list and will use previously downloaded file (if available): " + _listUrl.AbsoluteUri + "\r\n" + ex.ToString());
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

            Dictionary<string, object> _listZone = new Dictionary<string, object>(0);

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
                        string line;
                        string firstWord;
                        string secondWord;
                        string hostname;

                        while (true)
                        {
                            line = sR.ReadLine();
                            if (line == null)
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
                                    hostname = firstWord;
                                else
                                    hostname = secondWord;
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
                    _dnsServer.WriteLog("Advanced Blocking app failed to read " + (_isAllowList ? "allow" : "block") + " list from: " + _listUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }

                return domains;
            }

            #endregion

            #region protected

            protected override void LoadListZone()
            {
                Queue<string> listQueue = ReadListFile();
                Dictionary<string, object> listZone = new Dictionary<string, object>(listQueue.Count);

                while (listQueue.Count > 0)
                    listZone.TryAdd(listQueue.Dequeue(), null);

                _listZone = listZone;
            }

            #endregion

            #region public

            public bool IsZoneFound(string domain, out string foundZone)
            {
                return App.IsZoneFound(_listZone, domain, out foundZone);
            }

            #endregion
        }

        class RegexList : ListBase
        {
            #region variables

            Regex[] _regexListZone = Array.Empty<Regex>();

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
                        string line;

                        while (true)
                        {
                            line = sR.ReadLine();
                            if (line == null)
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
                    _dnsServer.WriteLog("Advanced Blocking app failed to read regex " + (_isAllowList ? "allow" : "block") + " list from: " + _listUrl.AbsoluteUri + "\r\n" + ex.ToString());
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

                _regexListZone = regexListZone.ToArray();
            }

            #endregion

            #region public

            public bool IsMatchFound(string domain, out string matchingPattern)
            {
                return App.IsMatchFound(_regexListZone, domain, out matchingPattern);
            }

            #endregion
        }

        class AdBlockList : ListBase
        {
            #region variables

            Dictionary<string, object> _allowedListZone = new Dictionary<string, object>(0);
            Dictionary<string, object> _blockedListZone = new Dictionary<string, object>(0);

            #endregion

            #region constructor

            public AdBlockList(IDnsServer dnsServer, Uri listUrl)
                : base(dnsServer, listUrl, false, false, true)
            { }

            #endregion

            #region private

            private void ReadAdblockListFile(out Queue<string> allowedDomains, out Queue<string> blockedDomains)
            {
                allowedDomains = new Queue<string>();
                blockedDomains = new Queue<string>();

                try
                {
                    _dnsServer.WriteLog("Advanced Blocking app is reading adblock list from: " + _listUrl.AbsoluteUri);

                    using (FileStream fS = new FileStream(_listFilePath, FileMode.Open, FileAccess.Read))
                    {
                        //parse hosts file and populate block zone
                        StreamReader sR = new StreamReader(fS, true);
                        char[] trimSeperator = new char[] { ' ', '\t' };
                        string line;

                        while (true)
                        {
                            line = sR.ReadLine();
                            if (line == null)
                                break; //eof

                            line = line.TrimStart(trimSeperator);

                            if (line.Length == 0)
                                continue; //skip empty line

                            if (line.StartsWith('!'))
                                continue; //skip comment line

                            if (line.StartsWith("||"))
                            {
                                int i = line.IndexOf('^');
                                if (i > -1)
                                {
                                    string domain = line.Substring(2, i - 2);
                                    string options = line.Substring(i + 1);

                                    if (((options.Length == 0) || (options.StartsWith('$') && (options.Contains("doc") || options.Contains("all")))) && DnsClient.IsDomainNameValid(domain))
                                        blockedDomains.Enqueue(domain);
                                }
                                else
                                {
                                    string domain = line.Substring(2);

                                    if (DnsClient.IsDomainNameValid(domain))
                                        blockedDomains.Enqueue(domain);
                                }
                            }
                            else if (line.StartsWith("@@||"))
                            {
                                int i = line.IndexOf('^');
                                if (i > -1)
                                {
                                    string domain = line.Substring(4, i - 4);
                                    string options = line.Substring(i + 1);

                                    if (((options.Length == 0) || (options.StartsWith('$') && (options.Contains("doc") || options.Contains("all")))) && DnsClient.IsDomainNameValid(domain))
                                        allowedDomains.Enqueue(domain);
                                }
                                else
                                {
                                    string domain = line.Substring(4);

                                    if (DnsClient.IsDomainNameValid(domain))
                                        allowedDomains.Enqueue(domain);
                                }
                            }
                        }
                    }

                    _dnsServer.WriteLog("Advanced Blocking app read adblock list file (" + (allowedDomains.Count + blockedDomains.Count) + " domains) from: " + _listUrl.AbsoluteUri);
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("Advanced Blocking app failed to read adblock list from: " + _listUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            #endregion

            #region protected

            protected override void LoadListZone()
            {
                ReadAdblockListFile(out Queue<string> allowedDomains, out Queue<string> blockedDomains);

                Dictionary<string, object> allowedListZone = new Dictionary<string, object>(allowedDomains.Count);
                Dictionary<string, object> blockedListZone = new Dictionary<string, object>(blockedDomains.Count);

                while (allowedDomains.Count > 0)
                    allowedListZone.TryAdd(allowedDomains.Dequeue(), null);

                while (blockedDomains.Count > 0)
                    blockedListZone.TryAdd(blockedDomains.Dequeue(), null);

                _allowedListZone = allowedListZone;
                _blockedListZone = blockedListZone;
            }

            #endregion

            #region public

            public bool IsZoneAllowed(string domain, out string foundZone)
            {
                return IsZoneFound(_allowedListZone, domain, out foundZone);
            }

            public bool IsZoneBlocked(string domain, out string foundZone)
            {
                return IsZoneFound(_blockedListZone, domain, out foundZone);
            }

            #endregion
        }
    }
}
