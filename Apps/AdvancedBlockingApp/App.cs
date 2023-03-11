/*
Technitium DNS Server
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
    public sealed class App : IDnsApplication, IDnsAuthoritativeRequestHandler
    {
        #region variables

        IDnsServer _dnsServer;

        DnsSOARecordData _soaRecord;
        DnsNSRecordData _nsRecord;

        bool _enableBlocking;
        int _blockListUrlUpdateIntervalHours;

        IReadOnlyDictionary<NetworkAddress, string> _networkGroupMap;
        IReadOnlyDictionary<string, Group> _groups;

        IReadOnlyDictionary<Uri, BlockList> _allAllowListZones = new Dictionary<Uri, BlockList>(0);
        IReadOnlyDictionary<Uri, BlockList> _allBlockListZones = new Dictionary<Uri, BlockList>(0);

        IReadOnlyDictionary<Uri, RegexList> _allRegexAllowListZones = new Dictionary<Uri, RegexList>(0);
        IReadOnlyDictionary<Uri, RegexList> _allRegexBlockListZones = new Dictionary<Uri, RegexList>(0);

        IReadOnlyDictionary<Uri, AdBlockList> _allAdBlockListZones = new Dictionary<Uri, AdBlockList>(0);

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

        private static bool IsZoneFound(IReadOnlyDictionary<string, object> domains, string domain, out string foundZone)
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

        private static bool IsZoneFound(IReadOnlyDictionary<Uri, BlockList> listZones, string domain, out string foundZone, out Uri listUri)
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

        private static bool IsZoneAllowed(IReadOnlyDictionary<Uri, AdBlockList> listZones, string domain, out string foundZone, out Uri listUri)
        {
            foreach (KeyValuePair<Uri, AdBlockList> listZone in listZones)
            {
                if (listZone.Value.IsZoneAllowed(domain, out foundZone))
                {
                    listUri = listZone.Key;
                    return true;
                }
            }

            foundZone = null;
            listUri = null;
            return false;
        }

        private static bool IsZoneBlocked(IReadOnlyDictionary<Uri, AdBlockList> listZones, string domain, out string foundZone, out Uri listUri)
        {
            foreach (KeyValuePair<Uri, AdBlockList> listZone in listZones)
            {
                if (listZone.Value.IsZoneBlocked(domain, out foundZone))
                {
                    listUri = listZone.Key;
                    return true;
                }
            }

            foundZone = null;
            listUri = null;
            return false;
        }

        private static bool IsMatchFound(IReadOnlyList<Regex> regices, string domain, out string matchingPattern)
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

        private static bool IsMatchFound(IReadOnlyDictionary<Uri, RegexList> regexListZones, string domain, out string matchingPattern, out Uri listUri)
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

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            Directory.CreateDirectory(Path.Combine(_dnsServer.ApplicationFolder, "blocklists"));

            _soaRecord = new DnsSOARecordData(_dnsServer.ServerDomain, "hostadmin@" + _dnsServer.ServerDomain, 1, 14400, 3600, 604800, 60);
            _nsRecord = new DnsNSRecordData(_dnsServer.ServerDomain);

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _enableBlocking = jsonConfig.GetProperty("enableBlocking").GetBoolean();
            _blockListUrlUpdateIntervalHours = jsonConfig.GetProperty("blockListUrlUpdateIntervalHours").GetInt32();

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

                    foreach (Uri blockListUrl in group.BlockListUrls)
                    {
                        if (!allBlockListZones.ContainsKey(blockListUrl))
                        {
                            if (_allBlockListZones.TryGetValue(blockListUrl, out BlockList blockList))
                                allBlockListZones.Add(blockListUrl, blockList);
                            else
                                allBlockListZones.Add(blockListUrl, new BlockList(_dnsServer, blockListUrl, false));
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

                    foreach (Uri regexBlockListUrl in group.RegexBlockListUrls)
                    {
                        if (!allRegexBlockListZones.ContainsKey(regexBlockListUrl))
                        {
                            if (_allRegexBlockListZones.TryGetValue(regexBlockListUrl, out RegexList regexBlockList))
                                allRegexBlockListZones.Add(regexBlockListUrl, regexBlockList);
                            else
                                allRegexBlockListZones.Add(regexBlockListUrl, new RegexList(_dnsServer, regexBlockListUrl, false));
                        }
                    }

                    foreach (Uri adblockListUrl in group.AdblockListUrls)
                    {
                        if (!allAdBlockListZones.ContainsKey(adblockListUrl))
                        {
                            if (_allAdBlockListZones.TryGetValue(adblockListUrl, out AdBlockList adBlockList))
                                allAdBlockListZones.Add(adblockListUrl, adBlockList);
                            else
                                allAdBlockListZones.Add(adblockListUrl, new AdBlockList(_dnsServer, adblockListUrl));
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

            Task.Run(async delegate ()
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
            });

            return Task.CompletedTask;
        }

        public async Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (!_enableBlocking)
                return null;

            IPAddress remoteIP = remoteEP.Address;
            NetworkAddress network = null;
            string groupName = null;

            foreach (KeyValuePair<NetworkAddress, string> entry in _networkGroupMap)
            {
                if (entry.Key.Contains(remoteIP) && ((network is null) || (entry.Key.PrefixLength > network.PrefixLength)))
                {
                    network = entry.Key;
                    groupName = entry.Value;
                }
            }

            if ((groupName is null) || !_groups.TryGetValue(groupName, out Group group) || !group.EnableBlocking)
                return null;

            DnsQuestionRecord question = request.Question[0];

            if (!group.IsZoneBlocked(question.Name, out bool allowed, out string blockedDomain, out string blockedRegex, out Uri blockListUrl))
            {
                if (allowed)
                {
                    try
                    {
                        DnsDatagram internalResponse = await _dnsServer.DirectQueryAsync(request);
                        if (internalResponse.Tag is null)
                            internalResponse.Tag = DnsServerResponseType.Recursive;

                        return internalResponse;
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog("Failed to resolve the request for allowed domain name with QNAME: " + question.Name + "; QTYPE: " + question.Type + "; QCLASS: " + question.Class + "\r\n" + ex.ToString());
                    }
                }

                return null;
            }

            string GetBlockingReport()
            {
                string blockingReport = "source=advanced-blocking-app; group=" + group.Name;

                if (blockedRegex is null)
                {
                    if (blockListUrl is not null)
                        blockingReport += "; blockListUrl=" + blockListUrl.AbsoluteUri + "; domain=" + blockedDomain;
                    else
                        blockingReport += "; domain=" + blockedDomain;
                }
                else
                {
                    if (blockListUrl is not null)
                        blockingReport += "; regexBlockListUrl=" + blockListUrl.AbsoluteUri + "; regex=" + blockedRegex;
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

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answer) { Tag = DnsServerResponseType.Blocked };
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

                if (group.BlockAsNxDomain)
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
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(group.ARecords.Count);

                                foreach (DnsARecordData record in group.ARecords)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, 60, record));

                                answer = rrList;
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            {
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(group.AAAARecords.Count);

                                foreach (DnsAAAARecordData record in group.AAAARecords)
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

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, rcode, request.Question, answer, authority, null, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options) { Tag = DnsServerResponseType.Blocked };
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Blocks domain names using block lists and regex block lists. Supports creating groups based on client's IP address or subnet to enforce different block lists and regex block lists for each group."; } }

        #endregion

        class Group
        {
            #region variables

            readonly App _app;

            readonly string _name;
            readonly bool _enableBlocking;
            readonly bool _allowTxtBlockingReport;
            readonly bool _blockAsNxDomain;

            readonly IReadOnlyCollection<DnsARecordData> _aRecords;
            readonly IReadOnlyCollection<DnsAAAARecordData> _aaaaRecords;

            readonly IReadOnlyDictionary<string, object> _allowed;
            readonly IReadOnlyDictionary<string, object> _blocked;
            readonly IReadOnlyList<Uri> _allowListUrls;
            readonly IReadOnlyList<Uri> _blockListUrls;

            readonly IReadOnlyList<Regex> _allowedRegex;
            readonly IReadOnlyList<Regex> _blockedRegex;
            readonly IReadOnlyList<Uri> _regexAllowListUrls;
            readonly IReadOnlyList<Uri> _regexBlockListUrls;

            readonly IReadOnlyList<Uri> _adblockListUrls;

            IReadOnlyDictionary<Uri, BlockList> _allowListZones = new Dictionary<Uri, BlockList>(0);
            IReadOnlyDictionary<Uri, BlockList> _blockListZones = new Dictionary<Uri, BlockList>(0);

            IReadOnlyDictionary<Uri, RegexList> _regexAllowListZones = new Dictionary<Uri, RegexList>(0);
            IReadOnlyDictionary<Uri, RegexList> _regexBlockListZones = new Dictionary<Uri, RegexList>(0);

            IReadOnlyDictionary<Uri, AdBlockList> _adBlockListZones = new Dictionary<Uri, AdBlockList>(0);

            #endregion

            #region constructor

            public Group(App app, JsonElement jsonGroup)
            {
                _app = app;

                _name = jsonGroup.GetProperty("name").GetString();
                _enableBlocking = jsonGroup.GetProperty("enableBlocking").GetBoolean();
                _allowTxtBlockingReport = jsonGroup.GetProperty("allowTxtBlockingReport").GetBoolean();
                _blockAsNxDomain = jsonGroup.GetProperty("blockAsNxDomain").GetBoolean();

                {
                    JsonElement jsonBlockingAddresses = jsonGroup.GetProperty("blockingAddresses");
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
                _blockListUrls = jsonGroup.ReadArray("blockListUrls", GetUriEntry);

                _allowedRegex = jsonGroup.ReadArray("allowedRegex", GetRegexEntry);
                _blockedRegex = jsonGroup.ReadArray("blockedRegex", GetRegexEntry);
                _regexAllowListUrls = jsonGroup.ReadArray("regexAllowListUrls", GetUriEntry);
                _regexBlockListUrls = jsonGroup.ReadArray("regexBlockListUrls", GetUriEntry);

                _adblockListUrls = jsonGroup.ReadArray("adblockListUrls", GetUriEntry);
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

            private static Regex GetRegexEntry(string pattern)
            {
                return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
            }

            #endregion

            #region public

            public void LoadListZones()
            {
                {
                    Dictionary<Uri, BlockList> allowListZones = new Dictionary<Uri, BlockList>(_allowListUrls.Count);

                    foreach (Uri listUrl in _allowListUrls)
                    {
                        if (_app._allAllowListZones.TryGetValue(listUrl, out BlockList allowListZone))
                            allowListZones.Add(listUrl, allowListZone);
                    }

                    _allowListZones = allowListZones;
                }

                {
                    Dictionary<Uri, BlockList> blockListZones = new Dictionary<Uri, BlockList>(_blockListUrls.Count);

                    foreach (Uri listUrl in _blockListUrls)
                    {
                        if (_app._allBlockListZones.TryGetValue(listUrl, out BlockList blockListZone))
                            blockListZones.Add(listUrl, blockListZone);
                    }

                    _blockListZones = blockListZones;
                }

                {
                    Dictionary<Uri, RegexList> regexAllowListZones = new Dictionary<Uri, RegexList>(_regexAllowListUrls.Count);

                    foreach (Uri listUrl in _regexAllowListUrls)
                    {
                        if (_app._allRegexAllowListZones.TryGetValue(listUrl, out RegexList regexAllowListZone))
                            regexAllowListZones.Add(listUrl, regexAllowListZone);
                    }

                    _regexAllowListZones = regexAllowListZones;
                }

                {
                    Dictionary<Uri, RegexList> regexBlockListZones = new Dictionary<Uri, RegexList>(_regexBlockListUrls.Count);

                    foreach (Uri listUrl in _regexBlockListUrls)
                    {
                        if (_app._allRegexBlockListZones.TryGetValue(listUrl, out RegexList regexBlockListZone))
                            regexBlockListZones.Add(listUrl, regexBlockListZone);
                    }

                    _regexBlockListZones = regexBlockListZones;
                }

                {
                    Dictionary<Uri, AdBlockList> adBlockListZones = new Dictionary<Uri, AdBlockList>(_adblockListUrls.Count);

                    foreach (Uri listUrl in _adblockListUrls)
                    {
                        if (_app._allAdBlockListZones.TryGetValue(listUrl, out AdBlockList adBlockListZone))
                            adBlockListZones.Add(listUrl, adBlockListZone);
                    }

                    _adBlockListZones = adBlockListZones;
                }
            }

            public bool IsZoneBlocked(string domain, out bool allowed, out string blockedDomain, out string blockedRegex, out Uri listUrl)
            {
                domain = domain.ToLower();

                //allowed, allow list zone, allowedRegex, regex allow list zone, adblock list zone
                if (IsZoneFound(_allowed, domain, out _) || IsZoneFound(_allowListZones, domain, out _, out _) || IsMatchFound(_allowedRegex, domain, out _) || IsMatchFound(_regexAllowListZones, domain, out _, out _) || IsZoneAllowed(_adBlockListZones, domain, out _, out _))
                {
                    //found zone allowed
                    allowed = true;
                    blockedDomain = null;
                    blockedRegex = null;
                    listUrl = null;
                    return false;
                }

                //blocked
                if (IsZoneFound(_blocked, domain, out string foundZone1))
                {
                    //found zone blocked
                    allowed = false;
                    blockedDomain = foundZone1;
                    blockedRegex = null;
                    listUrl = null;
                    return true;
                }

                //block list zone
                if (IsZoneFound(_blockListZones, domain, out string foundZone2, out Uri blockListUrl1))
                {
                    //found zone blocked
                    allowed = false;
                    blockedDomain = foundZone2;
                    blockedRegex = null;
                    listUrl = blockListUrl1;
                    return true;
                }

                //blockedRegex
                if (IsMatchFound(_blockedRegex, domain, out string blockedPattern1))
                {
                    //found pattern blocked
                    allowed = false;
                    blockedDomain = null;
                    blockedRegex = blockedPattern1;
                    listUrl = null;
                    return true;
                }

                //regex block list zone
                if (IsMatchFound(_regexBlockListZones, domain, out string blockedPattern2, out Uri blockListUrl2))
                {
                    //found pattern blocked
                    allowed = false;
                    blockedDomain = null;
                    blockedRegex = blockedPattern2;
                    listUrl = blockListUrl2;
                    return true;
                }

                //adblock list zone
                if (App.IsZoneBlocked(_adBlockListZones, domain, out string foundZone3, out Uri blockListUrl3))
                {
                    //found zone blocked
                    allowed = false;
                    blockedDomain = foundZone3;
                    blockedRegex = null;
                    listUrl = blockListUrl3;
                    return true;
                }

                allowed = false;
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

            public IReadOnlyCollection<DnsARecordData> ARecords
            { get { return _aRecords; } }

            public IReadOnlyCollection<DnsAAAARecordData> AAAARecords
            { get { return _aaaaRecords; } }

            public IReadOnlyList<Uri> AllowListUrls
            { get { return _allowListUrls; } }

            public IReadOnlyList<Uri> BlockListUrls
            { get { return _blockListUrls; } }

            public IReadOnlyList<Uri> RegexBlockListUrls
            { get { return _regexBlockListUrls; } }

            public IReadOnlyList<Uri> RegexAllowListUrls
            { get { return _regexAllowListUrls; } }

            public IReadOnlyList<Uri> AdblockListUrls
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

                using (HashAlgorithm hash = SHA256.Create())
                {
                    _listFilePath = Path.Combine(Path.Combine(_dnsServer.ApplicationFolder, "blocklists"), Convert.ToHexString(hash.ComputeHash(Encoding.UTF8.GetBytes(_listUrl.AbsoluteUri))).ToLower());
                }
            }

            #endregion

            #region private

            private async Task<bool> DownloadListFileAsync()
            {
                try
                {
                    _dnsServer.WriteLog("Advanced Blocking app is downloading " + (_isAdblockList ? "adblock" : (_isRegexList ? "regex " : "") + (_isAllowList ? "allow" : "block")) + " list: " + _listUrl.AbsoluteUri);

                    SocketsHttpHandler handler = new SocketsHttpHandler();
                    handler.Proxy = _dnsServer.Proxy;
                    handler.UseProxy = _dnsServer.Proxy is not null;
                    handler.AutomaticDecompression = DecompressionMethods.All;

                    using (HttpClient http = new HttpClient(new HttpClientRetryHandler(handler)))
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
                        if (!_listZoneLoaded)
                        {
                            _lastModified = File.GetLastWriteTimeUtc(_listFilePath);
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

            IReadOnlyDictionary<string, object> _listZone = new Dictionary<string, object>(0);

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

                            hostname = hostname.Trim('.').ToLower();

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

            IReadOnlyList<Regex> _regexListZone = new List<Regex>();

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

                _regexListZone = regexListZone;
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

            IReadOnlyDictionary<string, object> _allowedListZone = new Dictionary<string, object>(0);
            IReadOnlyDictionary<string, object> _blockedListZone = new Dictionary<string, object>(0);

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
