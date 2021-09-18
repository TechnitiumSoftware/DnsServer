/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace AdvanceBlocking
{
    public sealed class App : IDnsAuthoritativeRequestHandler
    {
        #region variables

        IDnsServer _dnsServer;
        string _localCacheFolder;

        bool _enableBlocking;
        bool _blockAsNxDomain;
        int _blockListUrlUpdateIntervalHours;

        IReadOnlyCollection<DnsARecord> _aRecords;
        IReadOnlyCollection<DnsAAAARecord> _aaaaRecords;
        DnsSOARecord _soaRecord;
        DnsNSRecord _nsRecord;

        IReadOnlyDictionary<NetworkAddress, string> _networkGroupMap;
        IReadOnlyDictionary<string, Group> _groups;

        Timer _blockListUrlUpdateTimer;
        DateTime _blockListUrlLastUpdatedOn;
        const int BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL = 5000;
        const int BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL = 900000;

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
                    if (await UpdateBlockListsAsync())
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

        private string GetBlockListFilePath(Uri blockListUrl)
        {
            using (HashAlgorithm hash = SHA256.Create())
            {
                return Path.Combine(_localCacheFolder, BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(blockListUrl.AbsoluteUri))).Replace("-", "").ToLower());
            }
        }

        private async Task<bool> UpdateBlockListsAsync()
        {
            List<Uri> downloadedAllowListUrls = new List<Uri>();
            List<Uri> downloadedBlockListUrls = new List<Uri>();
            List<Uri> downloadedRegexAllowListUrls = new List<Uri>();
            List<Uri> downloadedRegexBlockListUrls = new List<Uri>();
            bool notModified = false;

            async Task DownloadListUrlAsync(Uri listUrl, bool isAllowList, bool isRegexList)
            {
                string listFilePath = GetBlockListFilePath(listUrl);
                string listDownloadFilePath = listFilePath + ".downloading";

                try
                {
                    if (File.Exists(listDownloadFilePath))
                        File.Delete(listDownloadFilePath);

                    SocketsHttpHandler handler = new SocketsHttpHandler();
                    handler.Proxy = _dnsServer.Proxy;
                    handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        if (File.Exists(listFilePath))
                            http.DefaultRequestHeaders.IfModifiedSince = File.GetLastWriteTimeUtc(listFilePath);

                        HttpResponseMessage httpResponse = await http.GetAsync(listUrl);
                        switch (httpResponse.StatusCode)
                        {
                            case HttpStatusCode.OK:
                                {
                                    using (FileStream fS = new FileStream(listDownloadFilePath, FileMode.Create, FileAccess.Write))
                                    {
                                        using (Stream httpStream = await httpResponse.Content.ReadAsStreamAsync())
                                        {
                                            await httpStream.CopyToAsync(fS);
                                        }
                                    }

                                    if (File.Exists(listFilePath))
                                        File.Delete(listFilePath);

                                    File.Move(listDownloadFilePath, listFilePath);

                                    if (httpResponse.Content.Headers.LastModified != null)
                                        File.SetLastWriteTimeUtc(listFilePath, httpResponse.Content.Headers.LastModified.Value.UtcDateTime);

                                    if (isAllowList)
                                    {
                                        if (isRegexList)
                                        {
                                            lock (downloadedRegexAllowListUrls)
                                            {
                                                downloadedRegexAllowListUrls.Add(listUrl);
                                            }
                                        }
                                        else
                                        {
                                            lock (downloadedAllowListUrls)
                                            {
                                                downloadedAllowListUrls.Add(listUrl);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        if (isRegexList)
                                        {
                                            lock (downloadedRegexBlockListUrls)
                                            {
                                                downloadedRegexBlockListUrls.Add(listUrl);
                                            }
                                        }
                                        else
                                        {
                                            lock (downloadedBlockListUrls)
                                            {
                                                downloadedBlockListUrls.Add(listUrl);
                                            }
                                        }
                                    }

                                    _dnsServer.WriteLog("Advance Blocking app successfully downloaded " + (isRegexList ? "regex " : "") + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);
                                }
                                break;

                            case HttpStatusCode.NotModified:
                                {
                                    notModified = true;

                                    _dnsServer.WriteLog("Advance Blocking app successfully checked for a new update of the " + (isRegexList ? "regex " : "") + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);
                                }
                                break;

                            default:
                                throw new HttpRequestException((int)httpResponse.StatusCode + " " + httpResponse.ReasonPhrase);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("Advance Blocking app failed to download " + (isRegexList ? "regex " : "") + (isAllowList ? "allow" : "block") + " list and will use previously downloaded file (if available): " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            List<Task> tasks = new List<Task>();
            IReadOnlyList<Uri> uniqueAllowListUrls = GetUniqueAllowListUrls();
            IReadOnlyList<Uri> uniqueBlockListUrls = GetUniqueBlockListUrls();
            IReadOnlyList<Uri> uniqueRegexAllowListUrls = GetUniqueRegexAllowListUrls();
            IReadOnlyList<Uri> uniqueRegexBlockListUrls = GetUniqueRegexBlockListUrls();

            foreach (Uri allowListUrl in uniqueAllowListUrls)
                tasks.Add(DownloadListUrlAsync(allowListUrl, true, false));

            foreach (Uri blockListUrl in uniqueBlockListUrls)
                tasks.Add(DownloadListUrlAsync(blockListUrl, false, false));

            foreach (Uri regexAllowListUrl in uniqueRegexAllowListUrls)
                tasks.Add(DownloadListUrlAsync(regexAllowListUrl, true, true));

            foreach (Uri regexBlockListUrl in uniqueRegexBlockListUrls)
                tasks.Add(DownloadListUrlAsync(regexBlockListUrl, false, true));

            await Task.WhenAll(tasks);

            if ((downloadedAllowListUrls.Count > 0) || (downloadedBlockListUrls.Count > 0))
                LoadBlockListZones(downloadedAllowListUrls, downloadedBlockListUrls);

            if ((downloadedRegexAllowListUrls.Count > 0) || (downloadedRegexBlockListUrls.Count > 0))
                LoadRegexBlockListZones(downloadedRegexAllowListUrls, downloadedRegexBlockListUrls);

            return (downloadedAllowListUrls.Count > 0) || (downloadedBlockListUrls.Count > 0) || (downloadedRegexAllowListUrls.Count > 0) || (downloadedRegexBlockListUrls.Count > 0) || notModified;
        }

        private static string PopWord(ref string line)
        {
            if (line.Length == 0)
                return line;

            line = line.TrimStart(' ', '\t');

            int i = line.IndexOfAny(new char[] { ' ', '\t' });
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

        private Queue<string> ReadListFile(Uri listUrl, bool isAllowList)
        {
            Queue<string> domains = new Queue<string>();

            try
            {
                _dnsServer.WriteLog("Advance Blocking app is reading " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri);

                using (FileStream fS = new FileStream(GetBlockListFilePath(listUrl), FileMode.Open, FileAccess.Read))
                {
                    //parse hosts file and populate block zone
                    StreamReader sR = new StreamReader(fS, true);
                    string line;
                    string firstWord;
                    string secondWord;
                    string hostname;

                    while (true)
                    {
                        line = sR.ReadLine();
                        if (line == null)
                            break; //eof

                        line = line.TrimStart(' ', '\t');

                        if (line.Length == 0)
                            continue; //skip empty line

                        if (line.StartsWith("#"))
                            continue; //skip comment line

                        firstWord = PopWord(ref line);

                        if (line.Length == 0)
                        {
                            hostname = firstWord;
                        }
                        else
                        {
                            secondWord = PopWord(ref line);

                            if (secondWord.Length == 0)
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

                _dnsServer.WriteLog("Advance Blocking app read " + (isAllowList ? "allow" : "block") + " list file (" + domains.Count + " domains) from: " + listUrl.AbsoluteUri);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog("Advance Blocking app failed to read " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
            }

            return domains;
        }

        private Queue<string> ReadRegexListFile(Uri listUrl, bool isAllowList)
        {
            Queue<string> regices = new Queue<string>();

            try
            {
                _dnsServer.WriteLog("Advance Blocking app is reading regex " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri);

                using (FileStream fS = new FileStream(GetBlockListFilePath(listUrl), FileMode.Open, FileAccess.Read))
                {
                    //parse hosts file and populate block zone
                    StreamReader sR = new StreamReader(fS, true);
                    string line;

                    while (true)
                    {
                        line = sR.ReadLine();
                        if (line == null)
                            break; //eof

                        line = line.TrimStart(' ', '\t');

                        if (line.Length == 0)
                            continue; //skip empty line

                        if (line.StartsWith("#"))
                            continue; //skip comment line

                        regices.Enqueue(line);
                    }
                }

                _dnsServer.WriteLog("Advance Blocking app read regex " + (isAllowList ? "allow" : "block") + " list file (" + regices.Count + " regex patterns) from: " + listUrl.AbsoluteUri);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog("Advance Blocking app failed to read regex " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
            }

            return regices;
        }

        private IReadOnlyList<Uri> GetUniqueAllowListUrls()
        {
            List<Uri> allowListUrls = new List<Uri>();

            foreach (KeyValuePair<string, Group> group in _groups)
            {
                foreach (Uri allowListUrl in group.Value.AllowListUrls)
                {
                    if (!allowListUrls.Contains(allowListUrl))
                        allowListUrls.Add(allowListUrl);
                }
            }

            return allowListUrls;
        }

        private IReadOnlyList<Uri> GetUniqueBlockListUrls()
        {
            List<Uri> blockListUrls = new List<Uri>();

            foreach (KeyValuePair<string, Group> group in _groups)
            {
                foreach (Uri blockListUrl in group.Value.BlockListUrls)
                {
                    if (!blockListUrls.Contains(blockListUrl))
                        blockListUrls.Add(blockListUrl);
                }
            }

            return blockListUrls;
        }

        private IReadOnlyList<Uri> GetUniqueRegexAllowListUrls()
        {
            List<Uri> regexAllowListUrls = new List<Uri>();

            foreach (KeyValuePair<string, Group> group in _groups)
            {
                foreach (Uri regexAllowListUrl in group.Value.RegexAllowListUrls)
                {
                    if (!regexAllowListUrls.Contains(regexAllowListUrl))
                        regexAllowListUrls.Add(regexAllowListUrl);
                }
            }

            return regexAllowListUrls;
        }

        private IReadOnlyList<Uri> GetUniqueRegexBlockListUrls()
        {
            List<Uri> regexBlockListUrls = new List<Uri>();

            foreach (KeyValuePair<string, Group> group in _groups)
            {
                foreach (Uri regexBlockListUrl in group.Value.RegexBlockListUrls)
                {
                    if (!regexBlockListUrls.Contains(regexBlockListUrl))
                        regexBlockListUrls.Add(regexBlockListUrl);
                }
            }

            return regexBlockListUrls;
        }

        private static IReadOnlyList<Uri> GetUniqueAllowListUrls(IReadOnlyList<Group> groups)
        {
            List<Uri> allowListUrls = new List<Uri>();

            foreach (Group group in groups)
            {
                foreach (Uri blockListUrl in group.AllowListUrls)
                {
                    if (!allowListUrls.Contains(blockListUrl))
                        allowListUrls.Add(blockListUrl);
                }
            }

            return allowListUrls;
        }

        private static IReadOnlyList<Uri> GetUniqueBlockListUrls(IReadOnlyList<Group> groups)
        {
            List<Uri> blockListUrls = new List<Uri>();

            foreach (Group group in groups)
            {
                foreach (Uri blockListUrl in group.BlockListUrls)
                {
                    if (!blockListUrls.Contains(blockListUrl))
                        blockListUrls.Add(blockListUrl);
                }
            }

            return blockListUrls;
        }

        private static IReadOnlyList<Uri> GetUniqueRegexAllowListUrls(IReadOnlyList<Group> groups)
        {
            List<Uri> regexAllowListUrls = new List<Uri>();

            foreach (Group group in groups)
            {
                foreach (Uri regexAllowListUrl in group.RegexAllowListUrls)
                {
                    if (!regexAllowListUrls.Contains(regexAllowListUrl))
                        regexAllowListUrls.Add(regexAllowListUrl);
                }
            }

            return regexAllowListUrls;
        }

        private static IReadOnlyList<Uri> GetUniqueRegexBlockListUrls(IReadOnlyList<Group> groups)
        {
            List<Uri> regexBlockListUrls = new List<Uri>();

            foreach (Group group in groups)
            {
                foreach (Uri regexBlockListUrl in group.RegexBlockListUrls)
                {
                    if (!regexBlockListUrls.Contains(regexBlockListUrl))
                        regexBlockListUrls.Add(regexBlockListUrl);
                }
            }

            return regexBlockListUrls;
        }

        private IReadOnlyList<Group> GetUpdatedGroups(List<Uri> updatedAllowListUrls, List<Uri> updatedBlockListUrls)
        {
            List<Group> updatedGroups = new List<Group>();

            foreach (KeyValuePair<string, Group> group in _groups)
            {
                bool found = false;

                foreach (Uri allowListUrl in group.Value.AllowListUrls)
                {
                    if (updatedAllowListUrls.Contains(allowListUrl))
                    {
                        updatedGroups.Add(group.Value);
                        found = true;
                        break;
                    }
                }

                if (found)
                    continue;

                foreach (Uri blockListUrl in group.Value.BlockListUrls)
                {
                    if (updatedBlockListUrls.Contains(blockListUrl))
                    {
                        updatedGroups.Add(group.Value);
                        break;
                    }
                }
            }

            return updatedGroups;
        }

        private IReadOnlyList<Group> GetRegexUpdatedGroups(List<Uri> updatedRegexAllowListUrls, List<Uri> updatedRegexBlockListUrls)
        {
            List<Group> updatedGroups = new List<Group>();

            foreach (KeyValuePair<string, Group> group in _groups)
            {
                bool found = false;

                foreach (Uri regexAllowListUrl in group.Value.RegexAllowListUrls)
                {
                    if (updatedRegexAllowListUrls.Contains(regexAllowListUrl))
                    {
                        updatedGroups.Add(group.Value);
                        found = true;
                        break;
                    }
                }

                if (found)
                    continue;

                foreach (Uri regexBlockListUrl in group.Value.RegexBlockListUrls)
                {
                    if (updatedRegexBlockListUrls.Contains(regexBlockListUrl))
                    {
                        updatedGroups.Add(group.Value);
                        break;
                    }
                }
            }

            return updatedGroups;
        }

        private void LoadBlockListZones(List<Uri> updatedAllowListUrls, List<Uri> updatedBlockListUrls)
        {
            LoadBlockListZones(GetUpdatedGroups(updatedAllowListUrls, updatedBlockListUrls));
        }

        private void LoadRegexBlockListZones(List<Uri> updatedRegexAllowListUrls, List<Uri> updatedRegexBlockListUrls)
        {
            LoadRegexBlockListZones(GetRegexUpdatedGroups(updatedRegexAllowListUrls, updatedRegexBlockListUrls));
        }

        private void LoadBlockListZones(IReadOnlyList<Group> updatedGroups)
        {
            //read all allow lists in a queue
            IReadOnlyList<Uri> uniqueAllowListUrls = GetUniqueAllowListUrls(updatedGroups);
            Dictionary<Uri, Queue<string>> allAllowListQueues = new Dictionary<Uri, Queue<string>>(uniqueAllowListUrls.Count);

            foreach (Uri allowListUrl in uniqueAllowListUrls)
            {
                if (!allAllowListQueues.ContainsKey(allowListUrl))
                {
                    Queue<string> allowListQueue = ReadListFile(allowListUrl, true);
                    allAllowListQueues.Add(allowListUrl, allowListQueue);
                }
            }

            //read all block lists in a queue
            IReadOnlyList<Uri> uniqueBlockListUrls = GetUniqueBlockListUrls(updatedGroups);
            Dictionary<Uri, Queue<string>> allBlockListQueues = new Dictionary<Uri, Queue<string>>(uniqueBlockListUrls.Count);

            foreach (Uri blockListUrl in uniqueBlockListUrls)
            {
                if (!allBlockListQueues.ContainsKey(blockListUrl))
                {
                    Queue<string> blockListQueue = ReadListFile(blockListUrl, false);
                    allBlockListQueues.Add(blockListUrl, blockListQueue);
                }
            }

            //load block list zone per group
            foreach (Group group in updatedGroups)
                group.LoadBlockListZone(allAllowListQueues, allBlockListQueues);

            _dnsServer.WriteLog("Advance Blocking app loaded all block list zones successfully.");

            //force GC collection to remove old zone data from memory quickly
            GC.Collect();
        }

        private void LoadRegexBlockListZones(IReadOnlyList<Group> updatedGroups)
        {
            //read all allow lists in a queue
            IReadOnlyList<Uri> uniqueRegexAllowListUrls = GetUniqueRegexAllowListUrls(updatedGroups);
            Dictionary<Uri, Queue<string>> allRegexAllowListQueues = new Dictionary<Uri, Queue<string>>(uniqueRegexAllowListUrls.Count);

            foreach (Uri regexAllowListUrl in uniqueRegexAllowListUrls)
            {
                if (!allRegexAllowListQueues.ContainsKey(regexAllowListUrl))
                {
                    Queue<string> regexAllowListQueue = ReadRegexListFile(regexAllowListUrl, true);
                    allRegexAllowListQueues.Add(regexAllowListUrl, regexAllowListQueue);
                }
            }

            //read all regex block lists in a queue
            IReadOnlyList<Uri> uniqueRegexBlockListUrls = GetUniqueRegexBlockListUrls(updatedGroups);
            Dictionary<Uri, Queue<string>> allRegexBlockListQueues = new Dictionary<Uri, Queue<string>>(uniqueRegexBlockListUrls.Count);

            foreach (Uri regexBlockListUrl in uniqueRegexBlockListUrls)
            {
                if (!allRegexBlockListQueues.ContainsKey(regexBlockListUrl))
                {
                    Queue<string> regexBlockListQueue = ReadRegexListFile(regexBlockListUrl, false);
                    allRegexBlockListQueues.Add(regexBlockListUrl, regexBlockListQueue);
                }
            }

            //load regex block list zone per group
            foreach (Group group in updatedGroups)
                group.LoadRegexBlockListZone(allRegexAllowListQueues, allRegexBlockListQueues);

            _dnsServer.WriteLog("Advance Blocking app loaded all regex block list zones successfully.");

            //force GC collection to remove old zone data from memory quickly
            GC.Collect();
        }

        private static bool ListsEquals<T>(IReadOnlyList<T> list1, IReadOnlyList<T> list2)
        {
            if (list1.Count != list2.Count)
                return false;

            foreach (T item in list1)
            {
                if (!list2.Contains(item))
                    return false;
            }

            return true;
        }

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            _localCacheFolder = Path.Combine(_dnsServer.ApplicationFolder, "blocklists");

            Directory.CreateDirectory(_localCacheFolder);

            dynamic jsonConfig = JsonConvert.DeserializeObject(config);

            _enableBlocking = jsonConfig.enableBlocking.Value;
            _blockAsNxDomain = jsonConfig.blockAsNxDomain.Value;
            _blockListUrlUpdateIntervalHours = Convert.ToInt32(jsonConfig.blockListUrlUpdateIntervalHours.Value);

            {
                List<DnsARecord> aRecords = new List<DnsARecord>();
                List<DnsAAAARecord> aaaaRecords = new List<DnsAAAARecord>();

                foreach (dynamic jsonBlockingAddress in jsonConfig.blockingAddresses)
                {
                    string strAddress = jsonBlockingAddress.Value;

                    if (IPAddress.TryParse(strAddress, out IPAddress address))
                    {
                        switch (address.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                aRecords.Add(new DnsARecord(address));
                                break;

                            case AddressFamily.InterNetworkV6:
                                aaaaRecords.Add(new DnsAAAARecord(address));
                                break;
                        }
                    }
                }

                _aRecords = aRecords;
                _aaaaRecords = aaaaRecords;
                _soaRecord = new DnsSOARecord(dnsServer.ServerDomain, "hostadmin." + dnsServer.ServerDomain, 1, 14400, 3600, 604800, 60);
                _nsRecord = new DnsNSRecord(dnsServer.ServerDomain);
            }

            {
                Dictionary<NetworkAddress, string> networkGroupMap = new Dictionary<NetworkAddress, string>();

                foreach (dynamic jsonProperty in jsonConfig.networkGroupMap)
                {
                    string network = jsonProperty.Name;
                    string group = jsonProperty.Value;

                    if (NetworkAddress.TryParse(network, out NetworkAddress networkAddress))
                        networkGroupMap.Add(networkAddress, group);
                }

                _networkGroupMap = networkGroupMap;
            }

            {
                List<Group> updatedGroups = new List<Group>();
                List<Group> updatedRegexGroups = new List<Group>();
                Dictionary<string, Group> groups = new Dictionary<string, Group>();

                foreach (dynamic jsonGroup in jsonConfig.groups)
                {
                    Group group = new Group(jsonGroup);

                    if ((_groups is not null) && _groups.TryGetValue(group.Name, out Group existingGroup))
                    {
                        if (!ListsEquals(group.AllowListUrls, existingGroup.AllowListUrls) || !ListsEquals(group.BlockListUrls, existingGroup.BlockListUrls))
                            updatedGroups.Add(existingGroup);

                        if (!ListsEquals(group.RegexAllowListUrls, existingGroup.RegexAllowListUrls) || !ListsEquals(group.RegexBlockListUrls, existingGroup.RegexBlockListUrls))
                            updatedRegexGroups.Add(existingGroup);

                        existingGroup.Enabled = group.Enabled;

                        existingGroup.Allowed = group.Allowed;
                        existingGroup.Blocked = group.Blocked;
                        existingGroup.AllowListUrls = group.AllowListUrls;
                        existingGroup.BlockListUrls = group.BlockListUrls;

                        existingGroup.AllowedRegex = group.AllowedRegex;
                        existingGroup.BlockedRegex = group.BlockedRegex;
                        existingGroup.RegexAllowListUrls = group.RegexAllowListUrls;
                        existingGroup.RegexBlockListUrls = group.RegexBlockListUrls;

                        groups.TryAdd(existingGroup.Name, existingGroup);
                    }
                    else
                    {
                        updatedGroups.Add(group);
                        updatedRegexGroups.Add(group);
                        groups.TryAdd(group.Name, group);
                    }
                }

                _groups = groups;

                if (updatedGroups.Count > 0)
                {
                    Task.Run(delegate ()
                    {
                        LoadBlockListZones(updatedGroups);
                    });
                }

                if (updatedRegexGroups.Count > 0)
                {
                    Task.Run(delegate ()
                    {
                        LoadRegexBlockListZones(updatedRegexGroups);
                    });
                }
            }

            if (_blockListUrlUpdateTimer is null)
            {
                _blockListUrlUpdateTimer = new Timer(BlockListUrlUpdateTimerCallbackAsync, null, Timeout.Infinite, Timeout.Infinite);
                _blockListUrlUpdateTimer.Change(BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL);
            }

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (!_enableBlocking)
                return Task.FromResult<DnsDatagram>(null);

            IPAddress remoteIP = remoteEP.Address;
            string groupName = null;

            foreach (KeyValuePair<NetworkAddress, string> entry in _networkGroupMap)
            {
                if (entry.Key.Contains(remoteIP))
                {
                    groupName = entry.Value;
                    break;
                }
            }

            if ((groupName is null) || !_groups.TryGetValue(groupName, out Group group) || !group.Enabled)
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];

            IReadOnlyList<Uri> blockListUrls = group.IsZoneBlocked(question.Name, out string blockedDomain, out string blockedRegex);
            if (blockListUrls is null)
                return Task.FromResult<DnsDatagram>(null);

            if (question.Type == DnsResourceRecordType.TXT)
            {
                //return meta data
                DnsResourceRecord[] answer;

                if (blockedRegex is null)
                {
                    if (blockListUrls.Count > 0)
                    {
                        answer = new DnsResourceRecord[blockListUrls.Count];

                        for (int i = 0; i < answer.Length; i++)
                            answer[i] = new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("source=advance-blocking-app; group=" + group.Name + "; blockListUrl=" + blockListUrls[i].AbsoluteUri + "; domain=" + blockedDomain));
                    }
                    else
                    {
                        answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("source=advance-blocking-app; group=" + group.Name + "; domain=" + blockedDomain)) };
                    }
                }
                else
                {
                    if (blockListUrls.Count > 0)
                    {
                        answer = new DnsResourceRecord[blockListUrls.Count];

                        for (int i = 0; i < answer.Length; i++)
                            answer[i] = new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("source=advance-blocking-app; group=" + group.Name + "; regexBlockListUrl=" + blockListUrls[i].AbsoluteUri + "; regex=" + blockedRegex));
                    }
                    else
                    {
                        answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("source=advance-blocking-app; group=" + group.Name + "; regex=" + blockedRegex)) };
                    }
                }

                return Task.FromResult(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answer) { Tag = DnsServerResponseType.Blocked });
            }
            else
            {
                DnsResponseCode rcode;
                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;

                if (_blockAsNxDomain)
                {
                    rcode = DnsResponseCode.NxDomain;

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
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(_aRecords.Count);

                                foreach (DnsARecord record in _aRecords)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, 60, record));

                                answer = rrList;
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            {
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(_aaaaRecords.Count);

                                foreach (DnsAAAARecord record in _aaaaRecords)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, 60, record));

                                answer = rrList;
                            }
                            break;

                        case DnsResourceRecordType.NS:
                            if (question.Name.Equals(blockedDomain, StringComparison.OrdinalIgnoreCase))
                                answer = new DnsResourceRecord[] { new DnsResourceRecord(blockedDomain, DnsResourceRecordType.NS, question.Class, 60, _nsRecord) };
                            else
                                authority = new DnsResourceRecord[] { new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) };

                            break;

                        default:
                            authority = new DnsResourceRecord[] { new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) };
                            break;
                    }
                }

                return Task.FromResult(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, rcode, request.Question, answer, authority) { Tag = DnsServerResponseType.Blocked });
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

            readonly string _name;
            bool _enabled;

            IReadOnlyDictionary<string, object> _allowed;
            IReadOnlyDictionary<string, object> _blocked;
            IReadOnlyList<Uri> _allowListUrls;
            IReadOnlyList<Uri> _blockListUrls;

            IReadOnlyList<Regex> _allowedRegex;
            IReadOnlyList<Regex> _blockedRegex;
            IReadOnlyList<Uri> _regexAllowListUrls;
            IReadOnlyList<Uri> _regexBlockListUrls;

            IReadOnlyDictionary<string, List<Uri>> _blockListZone = new Dictionary<string, List<Uri>>(0);

            IReadOnlyList<RegexItem> _regexAllowListZone = Array.Empty<RegexItem>();
            IReadOnlyList<RegexItem> _regexBlockListZone = Array.Empty<RegexItem>();

            #endregion

            #region constructor

            public Group(dynamic jsonGroup)
            {
                _name = jsonGroup.name.Value;
                _enabled = jsonGroup.enabled.Value;

                {
                    Dictionary<string, object> allowed = new Dictionary<string, object>(1);

                    foreach (dynamic jsonDomain in jsonGroup.allowed)
                        allowed.TryAdd(jsonDomain.Value, null);

                    _allowed = allowed;
                }

                {
                    Dictionary<string, object> blocked = new Dictionary<string, object>(1);

                    foreach (dynamic jsonDomain in jsonGroup.blocked)
                        blocked.TryAdd(jsonDomain.Value, null);

                    _blocked = blocked;
                }

                {
                    List<Uri> allowListUrls = new List<Uri>(2);

                    foreach (dynamic jsonUrl in jsonGroup.allowListUrls)
                    {
                        Uri url = new Uri(jsonUrl.Value);

                        if (!allowListUrls.Contains(url))
                            allowListUrls.Add(url);
                    }

                    _allowListUrls = allowListUrls;
                }

                {
                    List<Uri> blockListUrls = new List<Uri>(2);

                    foreach (dynamic jsonUrl in jsonGroup.blockListUrls)
                    {
                        Uri url = new Uri(jsonUrl.Value);

                        if (!blockListUrls.Contains(url))
                            blockListUrls.Add(url);
                    }

                    _blockListUrls = blockListUrls;
                }

                {
                    List<Regex> allowedRegex = new List<Regex>();

                    foreach (dynamic jsonRegex in jsonGroup.allowedRegex)
                    {
                        string regexPattern = jsonRegex.Value;

                        allowedRegex.Add(new Regex(regexPattern, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled));
                    }

                    _allowedRegex = allowedRegex;
                }

                {
                    List<Regex> blockedRegex = new List<Regex>();

                    foreach (dynamic jsonRegex in jsonGroup.blockedRegex)
                    {
                        string regexPattern = jsonRegex.Value;

                        blockedRegex.Add(new Regex(regexPattern, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled));
                    }

                    _blockedRegex = blockedRegex;
                }

                {
                    List<Uri> regexAllowListUrls = new List<Uri>();

                    foreach (dynamic jsonUrl in jsonGroup.regexAllowListUrls)
                    {
                        string strUrl = jsonUrl.Value;

                        regexAllowListUrls.Add(new Uri(strUrl));
                    }

                    _regexAllowListUrls = regexAllowListUrls;
                }

                {
                    List<Uri> regexBlockListUrls = new List<Uri>();

                    foreach (dynamic jsonUrl in jsonGroup.regexBlockListUrls)
                    {
                        string strUrl = jsonUrl.Value;

                        regexBlockListUrls.Add(new Uri(strUrl));
                    }

                    _regexBlockListUrls = regexBlockListUrls;
                }
            }

            #endregion

            #region private

            private static bool IsZoneAllowed(IReadOnlyDictionary<string, object> allowedDomains, string domain)
            {
                do
                {
                    if (allowedDomains.TryGetValue(domain, out _))
                        return true;

                    domain = GetParentZone(domain);
                }
                while (domain is not null);

                return false;
            }

            #endregion

            #region public

            public void LoadBlockListZone(Dictionary<Uri, Queue<string>> allAllowListQueues, Dictionary<Uri, Queue<string>> allBlockListQueues)
            {
                //read all allowed domains in dictionary
                Dictionary<string, object> allowedDomains = new Dictionary<string, object>();

                foreach (Uri allowListUrl in _allowListUrls)
                {
                    if (allAllowListQueues.TryGetValue(allowListUrl, out Queue<string> queue))
                    {
                        while (queue.Count > 0)
                        {
                            string domain = queue.Dequeue();

                            allowedDomains.TryAdd(domain, null);
                        }
                    }
                }

                //select block lists
                Dictionary<Uri, Queue<string>> blockListQueues = new Dictionary<Uri, Queue<string>>(_blockListUrls.Count);
                int totalDomains = 0;

                foreach (Uri blockListUrl in _blockListUrls)
                {
                    if (allBlockListQueues.TryGetValue(blockListUrl, out Queue<string> blockListQueue))
                    {
                        totalDomains += blockListQueue.Count;
                        blockListQueues.Add(blockListUrl, blockListQueue);
                    }
                }

                //load block list zone
                Dictionary<string, List<Uri>> blockListZone = new Dictionary<string, List<Uri>>(totalDomains);

                foreach (KeyValuePair<Uri, Queue<string>> blockListQueue in blockListQueues)
                {
                    Queue<string> queue = blockListQueue.Value;

                    while (queue.Count > 0)
                    {
                        string domain = queue.Dequeue();

                        if (IsZoneAllowed(allowedDomains, domain))
                            continue; //domain is in allowed list so skip adding it to block list zone

                        if (!blockListZone.TryGetValue(domain, out List<Uri> blockListUrls))
                        {
                            blockListUrls = new List<Uri>(2);
                            blockListZone.Add(domain, blockListUrls);
                        }

                        blockListUrls.Add(blockListQueue.Key);
                    }
                }

                _blockListZone = blockListZone;
            }

            public void LoadRegexBlockListZone(Dictionary<Uri, Queue<string>> allRegexAllowListQueues, Dictionary<Uri, Queue<string>> allRegexBlockListQueues)
            {
                {
                    //select regex allow lists
                    Dictionary<Uri, Queue<string>> regexAllowListQueues = new Dictionary<Uri, Queue<string>>(_regexAllowListUrls.Count);
                    int totalRegexPatterns = 0;

                    foreach (Uri regexAllowListUrl in _regexAllowListUrls)
                    {
                        if (allRegexAllowListQueues.TryGetValue(regexAllowListUrl, out Queue<string> regexAllowListQueue))
                        {
                            totalRegexPatterns += regexAllowListQueue.Count;
                            regexAllowListQueues.Add(regexAllowListUrl, regexAllowListQueue);
                        }
                    }

                    //load regex allow list patterns from queue
                    Dictionary<string, object> allRegexPatterns = new Dictionary<string, object>(totalRegexPatterns);

                    foreach (KeyValuePair<Uri, Queue<string>> regexAllowListQueue in regexAllowListQueues)
                    {
                        Queue<string> queue = regexAllowListQueue.Value;

                        while (queue.Count > 0)
                        {
                            string regex = queue.Dequeue();

                            if (!allRegexPatterns.TryGetValue(regex, out _))
                                allRegexPatterns.Add(regex, null);
                        }
                    }

                    //load regex allow list zone
                    List<RegexItem> regexAllowListZone = new List<RegexItem>(totalRegexPatterns);

                    foreach (KeyValuePair<string, object> regexPattern in allRegexPatterns)
                    {
                        Regex regex = new Regex(regexPattern.Key, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

                        regexAllowListZone.Add(new RegexItem(regex, null));
                    }

                    _regexAllowListZone = regexAllowListZone;
                }

                {
                    //select regex block lists
                    Dictionary<Uri, Queue<string>> regexBlockListQueues = new Dictionary<Uri, Queue<string>>(_regexBlockListUrls.Count);
                    int totalRegexPatterns = 0;

                    foreach (Uri regexBlockListUrl in _regexBlockListUrls)
                    {
                        if (allRegexBlockListQueues.TryGetValue(regexBlockListUrl, out Queue<string> regexBlockListQueue))
                        {
                            totalRegexPatterns += regexBlockListQueue.Count;
                            regexBlockListQueues.Add(regexBlockListUrl, regexBlockListQueue);
                        }
                    }

                    //load regex block list patterns from queue
                    Dictionary<string, List<Uri>> allRegexPatterns = new Dictionary<string, List<Uri>>(totalRegexPatterns);

                    foreach (KeyValuePair<Uri, Queue<string>> regexBlockListQueue in regexBlockListQueues)
                    {
                        Queue<string> queue = regexBlockListQueue.Value;

                        while (queue.Count > 0)
                        {
                            string regexPattern = queue.Dequeue();

                            if (!allRegexPatterns.TryGetValue(regexPattern, out List<Uri> regexBlockLists))
                            {
                                regexBlockLists = new List<Uri>(2);
                                allRegexPatterns.Add(regexPattern, regexBlockLists);
                            }

                            regexBlockLists.Add(regexBlockListQueue.Key);
                        }
                    }

                    //load regex block list zone
                    List<RegexItem> regexBlockListZone = new List<RegexItem>(totalRegexPatterns);

                    foreach (KeyValuePair<string, List<Uri>> regexPattern in allRegexPatterns)
                    {
                        Regex regex = new Regex(regexPattern.Key, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

                        regexBlockListZone.Add(new RegexItem(regex, regexPattern.Value));
                    }

                    _regexBlockListZone = regexBlockListZone;
                }
            }

            public IReadOnlyList<Uri> IsZoneBlocked(string domain, out string blockedDomain, out string blockedRegex)
            {
                domain = domain.ToLower();

                //allowed
                string domain1 = domain;
                do
                {
                    if (_allowed.TryGetValue(domain1, out _))
                    {
                        //found zone allowed
                        blockedDomain = null;
                        blockedRegex = null;
                        return null;
                    }

                    domain1 = GetParentZone(domain1);
                }
                while (domain1 is not null);

                //allowedRegex
                foreach (Regex regex in _allowedRegex)
                {
                    if (regex.IsMatch(domain))
                    {
                        //found pattern allowed
                        blockedDomain = null;
                        blockedRegex = null;
                        return null;
                    }
                }

                //regex allow list zone
                foreach (RegexItem regexItem in _regexAllowListZone)
                {
                    if (regexItem.Regex.IsMatch(domain))
                    {
                        //found pattern allowed
                        blockedDomain = null;
                        blockedRegex = null;
                        return null;
                    }
                }

                //blocked
                string domain2 = domain;
                do
                {
                    if (_blocked.TryGetValue(domain2, out _))
                    {
                        //found zone blocked
                        blockedDomain = domain2;
                        blockedRegex = null;
                        return Array.Empty<Uri>();
                    }

                    domain2 = GetParentZone(domain2);
                }
                while (domain2 is not null);

                //block list zone
                string domain3 = domain;
                do
                {
                    if (_blockListZone.TryGetValue(domain3, out List<Uri> blockListUrls))
                    {
                        //found zone blocked
                        blockedDomain = domain3;
                        blockedRegex = null;
                        return blockListUrls;
                    }

                    domain3 = GetParentZone(domain3);
                }
                while (domain3 is not null);

                //blockedRegex
                foreach (Regex regex in _blockedRegex)
                {
                    if (regex.IsMatch(domain))
                    {
                        //found pattern blocked
                        blockedDomain = null;
                        blockedRegex = regex.ToString();
                        return Array.Empty<Uri>();
                    }
                }

                //regex block list zone
                foreach (RegexItem regexItem in _regexBlockListZone)
                {
                    if (regexItem.Regex.IsMatch(domain))
                    {
                        //found pattern blocked
                        blockedDomain = null;
                        blockedRegex = regexItem.Regex.ToString();
                        return regexItem.BlockListUrls;
                    }
                }

                blockedDomain = null;
                blockedRegex = null;
                return null;
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            public bool Enabled
            {
                get { return _enabled; }
                set { _enabled = value; }
            }

            public IReadOnlyDictionary<string, object> Allowed
            {
                get { return _allowed; }
                set { _allowed = value; }
            }

            public IReadOnlyDictionary<string, object> Blocked
            {
                get { return _blocked; }
                set { _blocked = value; }
            }

            public IReadOnlyList<Uri> AllowListUrls
            {
                get { return _allowListUrls; }
                set { _allowListUrls = value; }
            }

            public IReadOnlyList<Uri> BlockListUrls
            {
                get { return _blockListUrls; }
                set { _blockListUrls = value; }
            }

            public IReadOnlyList<Regex> AllowedRegex
            {
                get { return _allowedRegex; }
                set { _allowedRegex = value; }
            }

            public IReadOnlyList<Regex> BlockedRegex
            {
                get { return _blockedRegex; }
                set { _blockedRegex = value; }
            }

            public IReadOnlyList<Uri> RegexBlockListUrls
            {
                get { return _regexBlockListUrls; }
                set { _regexBlockListUrls = value; }
            }

            public IReadOnlyList<Uri> RegexAllowListUrls
            {
                get { return _regexAllowListUrls; }
                set { _regexAllowListUrls = value; }
            }

            #endregion
        }

        class RegexItem
        {
            #region variables

            readonly Regex _regex;
            readonly IReadOnlyList<Uri> _blockListUrls;

            #endregion

            #region constructor

            public RegexItem(Regex regex, IReadOnlyList<Uri> blockListUrls)
            {
                _regex = regex;
                _blockListUrls = blockListUrls;
            }

            #endregion

            #region properties

            public Regex Regex
            { get { return _regex; } }

            public IReadOnlyList<Uri> BlockListUrls
            { get { return _blockListUrls; } }

            #endregion
        }
    }
}
