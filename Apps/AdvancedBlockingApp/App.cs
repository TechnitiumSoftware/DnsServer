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

namespace AdvancedBlocking
{
    public sealed class App : IDnsApplication, IDnsAuthoritativeRequestHandler
    {
        #region variables

        IDnsServer _dnsServer;
        string _localCacheFolder;

        DnsSOARecord _soaRecord;
        DnsNSRecord _nsRecord;

        bool _enableBlocking;
        int _blockListUrlUpdateIntervalHours;

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

        private void FindAndSetBlockListUrlLastUpdatedOn()
        {
            try
            {
                string[] files = Directory.GetFiles(_localCacheFolder);
                DateTime latest = DateTime.MinValue;

                foreach (string file in files)
                {
                    DateTime lastModified = File.GetLastWriteTimeUtc(file);

                    if (lastModified > latest)
                        latest = lastModified;
                }

                _blockListUrlLastUpdatedOn = latest;
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog(ex);
            }
        }

        private string GetListFilePath(Uri listUrl)
        {
            using (HashAlgorithm hash = SHA256.Create())
            {
                return Path.Combine(_localCacheFolder, BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(listUrl.AbsoluteUri))).Replace("-", "").ToLower());
            }
        }

        private async Task<bool> UpdateAllListsAsync()
        {
            List<Uri> downloadedAllowListUrls = new List<Uri>();
            List<Uri> downloadedBlockListUrls = new List<Uri>();
            List<Uri> downloadedRegexAllowListUrls = new List<Uri>();
            List<Uri> downloadedRegexBlockListUrls = new List<Uri>();
            List<Uri> downloadedAdblockListUrls = new List<Uri>();
            bool notModified = false;

            async Task DownloadListUrlAsync(Uri listUrl, bool isAllowList, bool isRegexList, bool isAdblockList)
            {
                string listFilePath = GetListFilePath(listUrl);
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

                                    if (isAdblockList)
                                    {
                                        lock (downloadedAdblockListUrls)
                                        {
                                            downloadedAdblockListUrls.Add(listUrl);
                                        }
                                    }
                                    else
                                    {
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
                                    }

                                    _dnsServer.WriteLog("Advanced Blocking app successfully downloaded " + (isAdblockList ? "adblock" : (isRegexList ? "regex " : "") + (isAllowList ? "allow" : "block")) + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);
                                }
                                break;

                            case HttpStatusCode.NotModified:
                                {
                                    notModified = true;

                                    _dnsServer.WriteLog("Advanced Blocking app successfully checked for a new update of the " + (isAdblockList ? "adblock" : (isRegexList ? "regex " : "") + (isAllowList ? "allow" : "block")) + " list: " + listUrl.AbsoluteUri);
                                }
                                break;

                            default:
                                throw new HttpRequestException((int)httpResponse.StatusCode + " " + httpResponse.ReasonPhrase);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("Advanced Blocking app failed to download " + (isAdblockList ? "adblock" : (isRegexList ? "regex " : "") + (isAllowList ? "allow" : "block")) + " list and will use previously downloaded file (if available): " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            List<Task> tasks = new List<Task>();
            IReadOnlyList<Uri> uniqueAllowListUrls = GetUniqueAllowListUrls();
            IReadOnlyList<Uri> uniqueBlockListUrls = GetUniqueBlockListUrls();
            IReadOnlyList<Uri> uniqueRegexAllowListUrls = GetUniqueRegexAllowListUrls();
            IReadOnlyList<Uri> uniqueRegexBlockListUrls = GetUniqueRegexBlockListUrls();
            IReadOnlyList<Uri> uniqueAdblockListUrls = GetUniqueAdblockListUrls();

            foreach (Uri allowListUrl in uniqueAllowListUrls)
                tasks.Add(DownloadListUrlAsync(allowListUrl, true, false, false));

            foreach (Uri blockListUrl in uniqueBlockListUrls)
                tasks.Add(DownloadListUrlAsync(blockListUrl, false, false, false));

            foreach (Uri regexAllowListUrl in uniqueRegexAllowListUrls)
                tasks.Add(DownloadListUrlAsync(regexAllowListUrl, true, true, false));

            foreach (Uri regexBlockListUrl in uniqueRegexBlockListUrls)
                tasks.Add(DownloadListUrlAsync(regexBlockListUrl, false, true, false));

            foreach (Uri adblockListUrl in uniqueAdblockListUrls)
                tasks.Add(DownloadListUrlAsync(adblockListUrl, false, false, true));

            await Task.WhenAll(tasks);

            bool downloaded = (downloadedAllowListUrls.Count > 0) || (downloadedBlockListUrls.Count > 0) || (downloadedRegexAllowListUrls.Count > 0) || (downloadedRegexBlockListUrls.Count > 0) || (downloadedAdblockListUrls.Count > 0);
            if (downloaded)
                LoadZones(downloadedAllowListUrls, downloadedBlockListUrls, downloadedRegexAllowListUrls, downloadedRegexBlockListUrls, downloadedAdblockListUrls);

            return downloaded || notModified;
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
                _dnsServer.WriteLog("Advanced Blocking app is reading " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri);

                using (FileStream fS = new FileStream(GetListFilePath(listUrl), FileMode.Open, FileAccess.Read))
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

                _dnsServer.WriteLog("Advanced Blocking app read " + (isAllowList ? "allow" : "block") + " list file (" + domains.Count + " domains) from: " + listUrl.AbsoluteUri);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog("Advanced Blocking app failed to read " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
            }

            return domains;
        }

        private Queue<string> ReadRegexListFile(Uri listUrl, bool isAllowList)
        {
            Queue<string> regices = new Queue<string>();

            try
            {
                _dnsServer.WriteLog("Advanced Blocking app is reading regex " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri);

                using (FileStream fS = new FileStream(GetListFilePath(listUrl), FileMode.Open, FileAccess.Read))
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

                _dnsServer.WriteLog("Advanced Blocking app read regex " + (isAllowList ? "allow" : "block") + " list file (" + regices.Count + " regex patterns) from: " + listUrl.AbsoluteUri);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog("Advanced Blocking app failed to read regex " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
            }

            return regices;
        }

        private void ReadAdblockListFile(Uri listUrl, out Queue<string> allowedDomains, out Queue<string> blockedDomains)
        {
            allowedDomains = new Queue<string>();
            blockedDomains = new Queue<string>();

            try
            {
                _dnsServer.WriteLog("Advanced Blocking app is reading adblock list from: " + listUrl.AbsoluteUri);

                using (FileStream fS = new FileStream(GetListFilePath(listUrl), FileMode.Open, FileAccess.Read))
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

                        if (line.StartsWith("!"))
                            continue; //skip comment line

                        if (line.StartsWith("||"))
                        {
                            int i = line.IndexOf('^');
                            if (i > -1)
                            {
                                string domain = line.Substring(2, i - 2);
                                string options = line.Substring(i + 1);

                                if (((options.Length == 0) || (options.StartsWith("$") && (options.Contains("doc") || options.Contains("all")))) && DnsClient.IsDomainNameValid(domain))
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

                                if (((options.Length == 0) || (options.StartsWith("$") && (options.Contains("doc") || options.Contains("all")))) && DnsClient.IsDomainNameValid(domain))
                                    blockedDomains.Enqueue(domain);
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

                _dnsServer.WriteLog("Advanced Blocking app read adblock list file (" + (allowedDomains.Count + blockedDomains.Count) + " domains) from: " + listUrl.AbsoluteUri);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog("Advanced Blocking app failed to read adblock list from: " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
            }
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

        private IReadOnlyList<Uri> GetUniqueAdblockListUrls()
        {
            List<Uri> adblockListUrls = new List<Uri>();

            foreach (KeyValuePair<string, Group> group in _groups)
            {
                foreach (Uri adblockListUrl in group.Value.AdblockListUrls)
                {
                    if (!adblockListUrls.Contains(adblockListUrl))
                        adblockListUrls.Add(adblockListUrl);
                }
            }

            return adblockListUrls;
        }

        private static IReadOnlyList<Uri> GetAllUniqueListUrls(IReadOnlyDictionary<Group, int> groups)
        {
            List<Uri> listUrls = new List<Uri>();

            foreach (KeyValuePair<Group, int> group in groups)
            {
                foreach (Uri allowListUrl in group.Key.AllowListUrls)
                {
                    if (!listUrls.Contains(allowListUrl))
                        listUrls.Add(allowListUrl);
                }

                foreach (Uri blockListUrl in group.Key.BlockListUrls)
                {
                    if (!listUrls.Contains(blockListUrl))
                        listUrls.Add(blockListUrl);
                }

                foreach (Uri regexAllowListUrl in group.Key.RegexAllowListUrls)
                {
                    if (!listUrls.Contains(regexAllowListUrl))
                        listUrls.Add(regexAllowListUrl);
                }

                foreach (Uri regexBlockListUrl in group.Key.RegexBlockListUrls)
                {
                    if (!listUrls.Contains(regexBlockListUrl))
                        listUrls.Add(regexBlockListUrl);
                }

                foreach (Uri adblockListUrl in group.Key.AdblockListUrls)
                {
                    if (!listUrls.Contains(adblockListUrl))
                        listUrls.Add(adblockListUrl);
                }
            }

            return listUrls;
        }

        private void LoadZones(List<Uri> updatedAllowListUrls, List<Uri> updatedBlockListUrls, List<Uri> updatedRegexAllowListUrls, List<Uri> updatedRegexBlockListUrls, List<Uri> updatedAdblockListUrls)
        {
            Dictionary<Uri, Queue<string>> allowCache = new Dictionary<Uri, Queue<string>>();
            Dictionary<Uri, Queue<string>> blockCache = new Dictionary<Uri, Queue<string>>();

            foreach (KeyValuePair<string, Group> group in _groups)
            {
                bool loadAllowList = ListContainsAnyItem(group.Value.AllowListUrls, updatedAllowListUrls);
                bool loadBlockList = ListContainsAnyItem(group.Value.BlockListUrls, updatedBlockListUrls);
                bool loadRegexAllowList = ListContainsAnyItem(group.Value.RegexAllowListUrls, updatedRegexAllowListUrls);
                bool loadRegexBlockList = ListContainsAnyItem(group.Value.RegexBlockListUrls, updatedRegexBlockListUrls);
                bool loadAdblockList = ListContainsAnyItem(group.Value.AdblockListUrls, updatedAdblockListUrls);

                LoadListZones(allowCache, blockCache, group.Value, loadAllowList, loadBlockList, loadRegexAllowList, loadRegexBlockList, loadAdblockList);
            }
        }

        private void LoadListZones(Dictionary<Uri, Queue<string>> allowCache, Dictionary<Uri, Queue<string>> blockCache, Group group, bool loadAllowList, bool loadBlockList, bool loadRegexAllowList, bool loadRegexBlockList, bool loadAdblockList)
        {
            if (loadAdblockList)
            {
                loadAllowList = true;
                loadBlockList = true;
            }

            Dictionary<Uri, Queue<string>> allAllowListQueues = new Dictionary<Uri, Queue<string>>();
            Dictionary<Uri, Queue<string>> allBlockListQueues = new Dictionary<Uri, Queue<string>>();
            Dictionary<Uri, Queue<string>> allRegexAllowListQueues = new Dictionary<Uri, Queue<string>>();
            Dictionary<Uri, Queue<string>> allRegexBlockListQueues = new Dictionary<Uri, Queue<string>>();

            if (loadAllowList)
            {
                //read all allow lists in a queue
                foreach (Uri allowListUrl in group.AllowListUrls)
                {
                    if (allAllowListQueues.ContainsKey(allowListUrl))
                        continue;

                    if (!allowCache.TryGetValue(allowListUrl, out Queue<string> allowListQueue))
                    {
                        allowListQueue = ReadListFile(allowListUrl, true);
                        allowCache.Add(allowListUrl, allowListQueue);
                    }

                    allAllowListQueues.Add(allowListUrl, allowListQueue);
                }
            }

            if (loadBlockList)
            {
                //read all block lists in a queue
                foreach (Uri blockListUrl in group.BlockListUrls)
                {
                    if (allBlockListQueues.ContainsKey(blockListUrl))
                        continue;

                    if (!blockCache.TryGetValue(blockListUrl, out Queue<string> blockListQueue))
                    {
                        blockListQueue = ReadListFile(blockListUrl, false);
                        blockCache.Add(blockListUrl, blockListQueue);
                    }

                    allBlockListQueues.Add(blockListUrl, blockListQueue);
                }
            }

            if (loadAdblockList)
            {
                //read all adblock lists in queue
                foreach (Uri adblockListUrl in group.AdblockListUrls)
                {
                    if (!allowCache.TryGetValue(adblockListUrl, out Queue<string> allowListQueue) & !blockCache.TryGetValue(adblockListUrl, out Queue<string> blockListQueue))
                    {
                        ReadAdblockListFile(adblockListUrl, out allowListQueue, out blockListQueue);

                        allowCache.Add(adblockListUrl, allowListQueue);
                        blockCache.Add(adblockListUrl, blockListQueue);
                    }

                    allAllowListQueues.Add(adblockListUrl, allowListQueue);
                    allBlockListQueues.Add(adblockListUrl, blockListQueue);
                }
            }

            if (loadRegexAllowList)
            {
                //read all allow lists in a queue
                foreach (Uri regexAllowListUrl in group.RegexAllowListUrls)
                {
                    if (allRegexAllowListQueues.ContainsKey(regexAllowListUrl))
                        continue;

                    if (!allowCache.TryGetValue(regexAllowListUrl, out Queue<string> regexAllowListQueue))
                    {
                        regexAllowListQueue = ReadRegexListFile(regexAllowListUrl, true);
                        allowCache.Add(regexAllowListUrl, regexAllowListQueue);
                    }

                    allRegexAllowListQueues.Add(regexAllowListUrl, regexAllowListQueue);
                }
            }

            if (loadRegexBlockList)
            {
                //read all regex block lists in a queue
                foreach (Uri regexBlockListUrl in group.RegexBlockListUrls)
                {
                    if (allRegexBlockListQueues.ContainsKey(regexBlockListUrl))
                        continue;

                    if (!blockCache.TryGetValue(regexBlockListUrl, out Queue<string> regexBlockListQueue))
                    {
                        regexBlockListQueue = ReadRegexListFile(regexBlockListUrl, false);
                        blockCache.Add(regexBlockListUrl, regexBlockListQueue);
                    }

                    allRegexBlockListQueues.Add(regexBlockListUrl, regexBlockListQueue);
                }
            }

            //load block list zone
            if (loadAllowList)
                group.LoadAllowListZone(allAllowListQueues);

            if (loadBlockList)
                group.LoadBlockListZone(allBlockListQueues);

            //load regex block list zone
            if (loadRegexAllowList)
                group.LoadRegexAllowListZone(allRegexAllowListQueues);

            if (loadRegexBlockList)
                group.LoadRegexBlockListZone(allRegexBlockListQueues);

            _dnsServer.WriteLog("Advanced Blocking app loaded all zones successfully for group: " + group.Name);
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

        private static bool ListContainsAnyItem<T>(IReadOnlyList<T> list, IReadOnlyList<T> items)
        {
            foreach (T item in list)
            {
                if (items.Contains(item))
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

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            _localCacheFolder = Path.Combine(_dnsServer.ApplicationFolder, "blocklists");

            Directory.CreateDirectory(_localCacheFolder);

            _soaRecord = new DnsSOARecord(_dnsServer.ServerDomain, "hostadmin." + _dnsServer.ServerDomain, 1, 14400, 3600, 604800, 60);
            _nsRecord = new DnsNSRecord(_dnsServer.ServerDomain);

            dynamic jsonConfig = JsonConvert.DeserializeObject(config);

            _enableBlocking = jsonConfig.enableBlocking.Value;
            _blockListUrlUpdateIntervalHours = Convert.ToInt32(jsonConfig.blockListUrlUpdateIntervalHours.Value);

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

            bool cachedListFileMissing = false;

            {
                const int LOAD_ALLOW_LIST_ZONE = 1;
                const int LOAD_BLOCK_LIST_ZONE = 2;
                const int LOAD_REGEX_ALLOW_LIST_ZONE = 4;
                const int LOAD_REGEX_BLOCK_LIST_ZONE = 8;
                const int LOAD_ADBLOCK_LIST_ZONE = 16;

                Dictionary<Group, int> updatedGroups = new Dictionary<Group, int>();
                Dictionary<string, Group> groups = new Dictionary<string, Group>();

                foreach (dynamic jsonGroup in jsonConfig.groups)
                {
                    Group group = new Group(this, jsonGroup);

                    if ((_groups is not null) && _groups.TryGetValue(group.Name, out Group existingGroup))
                    {
                        int loadFlags = 0;

                        if (!ListsEquals(group.AllowListUrls, existingGroup.AllowListUrls))
                            loadFlags |= LOAD_ALLOW_LIST_ZONE;

                        if (!ListsEquals(group.BlockListUrls, existingGroup.BlockListUrls))
                            loadFlags |= LOAD_BLOCK_LIST_ZONE;

                        if (!ListsEquals(group.RegexAllowListUrls, existingGroup.RegexAllowListUrls))
                            loadFlags |= LOAD_REGEX_ALLOW_LIST_ZONE;

                        if (!ListsEquals(group.RegexBlockListUrls, existingGroup.RegexBlockListUrls))
                            loadFlags |= LOAD_REGEX_BLOCK_LIST_ZONE;

                        if (!ListsEquals(group.AdblockListUrls, existingGroup.AdblockListUrls))
                            loadFlags |= LOAD_ADBLOCK_LIST_ZONE;

                        if (loadFlags > 0)
                            updatedGroups.Add(existingGroup, loadFlags);

                        existingGroup.EnableBlocking = group.EnableBlocking;
                        existingGroup.AllowTxtBlockingReport = group.AllowTxtBlockingReport;
                        existingGroup.BlockAsNxDomain = group.BlockAsNxDomain;
                        existingGroup.ARecords = group.ARecords;
                        existingGroup.AAAARecords = group.AAAARecords;

                        existingGroup.Allowed = group.Allowed;
                        existingGroup.Blocked = group.Blocked;
                        existingGroup.AllowListUrls = group.AllowListUrls;
                        existingGroup.BlockListUrls = group.BlockListUrls;

                        existingGroup.AllowedRegex = group.AllowedRegex;
                        existingGroup.BlockedRegex = group.BlockedRegex;
                        existingGroup.RegexAllowListUrls = group.RegexAllowListUrls;
                        existingGroup.RegexBlockListUrls = group.RegexBlockListUrls;

                        existingGroup.AdblockListUrls = group.AdblockListUrls;

                        groups.TryAdd(existingGroup.Name, existingGroup);
                    }
                    else
                    {
                        updatedGroups.Add(group, LOAD_ALLOW_LIST_ZONE | LOAD_BLOCK_LIST_ZONE | LOAD_REGEX_ALLOW_LIST_ZONE | LOAD_REGEX_BLOCK_LIST_ZONE | LOAD_ADBLOCK_LIST_ZONE);
                        groups.TryAdd(group.Name, group);
                    }
                }

                _groups = groups;

                if (updatedGroups.Count > 0)
                {
                    foreach (Uri listUrl in GetAllUniqueListUrls(updatedGroups))
                    {
                        if (!File.Exists(GetListFilePath(listUrl)))
                        {
                            cachedListFileMissing = true;
                            break;
                        }
                    }

                    if (!cachedListFileMissing)
                    {
                        Task.Run(delegate ()
                        {
                            Dictionary<Uri, Queue<string>> allowCache = new Dictionary<Uri, Queue<string>>();
                            Dictionary<Uri, Queue<string>> blockCache = new Dictionary<Uri, Queue<string>>();

                            foreach (KeyValuePair<Group, int> group in updatedGroups)
                            {
                                bool loadAllowList = (group.Value & LOAD_ALLOW_LIST_ZONE) > 0;
                                bool loadBlockList = (group.Value & LOAD_ALLOW_LIST_ZONE) > 0;
                                bool loadRegexAllowList = (group.Value & LOAD_REGEX_ALLOW_LIST_ZONE) > 0;
                                bool loadRegexBlockList = (group.Value & LOAD_REGEX_ALLOW_LIST_ZONE) > 0;
                                bool loadAdblockList = (group.Value & LOAD_ADBLOCK_LIST_ZONE) > 0;

                                LoadListZones(allowCache, blockCache, group.Key, loadAllowList, loadBlockList, loadRegexAllowList, loadRegexBlockList, loadAdblockList);
                            }
                        });
                    }
                }
            }

            if (_blockListUrlUpdateTimer is null)
            {
                if (!cachedListFileMissing)
                    FindAndSetBlockListUrlLastUpdatedOn();

                _blockListUrlUpdateTimer = new Timer(BlockListUrlUpdateTimerCallbackAsync, null, Timeout.Infinite, Timeout.Infinite);
                _blockListUrlUpdateTimer.Change(BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL);
            }
            else
            {
                if (cachedListFileMissing)
                {
                    //force update
                    _blockListUrlLastUpdatedOn = DateTime.MinValue;
                    _blockListUrlUpdateTimer.Change(BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL);
                }
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

            if ((groupName is null) || !_groups.TryGetValue(groupName, out Group group) || !group.EnableBlocking)
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];

            IReadOnlyList<Uri> blockListUrls = group.IsZoneBlocked(question.Name, out string blockedDomain, out string blockedRegex);
            if (blockListUrls is null)
                return Task.FromResult<DnsDatagram>(null);

            if (group.AllowTxtBlockingReport && (question.Type == DnsResourceRecordType.TXT))
            {
                //return meta data
                DnsResourceRecord[] answer;

                if (blockedRegex is null)
                {
                    if (blockListUrls.Count > 0)
                    {
                        answer = new DnsResourceRecord[blockListUrls.Count];

                        for (int i = 0; i < answer.Length; i++)
                            answer[i] = new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("source=advanced-blocking-app; group=" + group.Name + "; blockListUrl=" + blockListUrls[i].AbsoluteUri + "; domain=" + blockedDomain));
                    }
                    else
                    {
                        answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("source=advanced-blocking-app; group=" + group.Name + "; domain=" + blockedDomain)) };
                    }
                }
                else
                {
                    if (blockListUrls.Count > 0)
                    {
                        answer = new DnsResourceRecord[blockListUrls.Count];

                        for (int i = 0; i < answer.Length; i++)
                            answer[i] = new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("source=advanced-blocking-app; group=" + group.Name + "; regexBlockListUrl=" + blockListUrls[i].AbsoluteUri + "; regex=" + blockedRegex));
                    }
                    else
                    {
                        answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("source=advanced-blocking-app; group=" + group.Name + "; regex=" + blockedRegex)) };
                    }
                }

                return Task.FromResult(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answer) { Tag = DnsServerResponseType.Blocked });
            }
            else
            {
                DnsResponseCode rcode;
                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;

                if (group.BlockAsNxDomain)
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
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(group.ARecords.Count);

                                foreach (DnsARecord record in group.ARecords)
                                    rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, 60, record));

                                answer = rrList;
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            {
                                List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(group.AAAARecords.Count);

                                foreach (DnsAAAARecord record in group.AAAARecords)
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

            readonly App _app;

            readonly string _name;
            bool _enableBlocking;
            bool _allowTxtBlockingReport;
            bool _blockAsNxDomain;

            IReadOnlyCollection<DnsARecord> _aRecords;
            IReadOnlyCollection<DnsAAAARecord> _aaaaRecords;

            IReadOnlyDictionary<string, object> _allowed;
            IReadOnlyDictionary<string, object> _blocked;
            IReadOnlyList<Uri> _allowListUrls;
            IReadOnlyList<Uri> _blockListUrls;

            IReadOnlyList<Regex> _allowedRegex;
            IReadOnlyList<Regex> _blockedRegex;
            IReadOnlyList<Uri> _regexAllowListUrls;
            IReadOnlyList<Uri> _regexBlockListUrls;

            IReadOnlyList<Uri> _adblockListUrls;

            IReadOnlyDictionary<string, List<Uri>> _allowListZone = new Dictionary<string, List<Uri>>(0);
            IReadOnlyDictionary<string, List<Uri>> _blockListZone = new Dictionary<string, List<Uri>>(0);

            IReadOnlyList<RegexItem> _regexAllowListZone = Array.Empty<RegexItem>();
            IReadOnlyList<RegexItem> _regexBlockListZone = Array.Empty<RegexItem>();

            #endregion

            #region constructor

            public Group(App app, dynamic jsonGroup)
            {
                _app = app;

                _name = jsonGroup.name.Value;
                _enableBlocking = jsonGroup.enableBlocking.Value;
                _allowTxtBlockingReport = jsonGroup.allowTxtBlockingReport.Value;
                _blockAsNxDomain = jsonGroup.blockAsNxDomain.Value;

                {
                    List<DnsARecord> aRecords = new List<DnsARecord>();
                    List<DnsAAAARecord> aaaaRecords = new List<DnsAAAARecord>();

                    foreach (dynamic jsonBlockingAddress in jsonGroup.blockingAddresses)
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
                }

                _allowed = ReadJsonDomainArray(jsonGroup.allowed);
                _blocked = ReadJsonDomainArray(jsonGroup.blocked);
                _allowListUrls = ReadJsonUrlArray(jsonGroup.allowListUrls);
                _blockListUrls = ReadJsonUrlArray(jsonGroup.blockListUrls);

                _allowedRegex = ReadJsonRegexArray(jsonGroup.allowedRegex);
                _blockedRegex = ReadJsonRegexArray(jsonGroup.blockedRegex);
                _regexAllowListUrls = ReadJsonUrlArray(jsonGroup.regexAllowListUrls);
                _regexBlockListUrls = ReadJsonUrlArray(jsonGroup.regexBlockListUrls);

                _adblockListUrls = ReadJsonUrlArray(jsonGroup.adblockListUrls);
            }

            #endregion

            #region private

            private static IReadOnlyDictionary<string, object> ReadJsonDomainArray(dynamic jsonDomainArray)
            {
                Dictionary<string, object> domains = new Dictionary<string, object>(jsonDomainArray.Count);

                foreach (dynamic jsonDomain in jsonDomainArray)
                    domains.TryAdd(jsonDomain.Value, null);

                return domains;
            }

            private static IReadOnlyList<Regex> ReadJsonRegexArray(dynamic jsonRegexArray)
            {
                List<Regex> regices = new List<Regex>(jsonRegexArray.Count);

                foreach (dynamic jsonRegex in jsonRegexArray)
                {
                    string regexPattern = jsonRegex.Value;

                    regices.Add(new Regex(regexPattern, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled));
                }

                return regices;
            }

            private static IReadOnlyList<Uri> ReadJsonUrlArray(dynamic jsonUrlArray)
            {
                List<Uri> urls = new List<Uri>(jsonUrlArray.Count);

                foreach (dynamic jsonUrl in jsonUrlArray)
                {
                    string strUrl = jsonUrl.Value;

                    urls.Add(new Uri(strUrl));
                }

                return urls;
            }

            private static bool IsZoneFound<T>(IReadOnlyDictionary<string, T> domains, string domain, out string foundZone, out T foundValue) where T : class
            {
                do
                {
                    if (domains.TryGetValue(domain, out T value))
                    {
                        foundZone = domain;
                        foundValue = value;
                        return true;
                    }

                    domain = GetParentZone(domain);
                }
                while (domain is not null);

                foundZone = null;
                foundValue = null;
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

            private static bool IsMatchFound(IReadOnlyList<RegexItem> regices, string domain, out string matchingPattern, out IReadOnlyList<Uri> blockListUrls)
            {
                foreach (RegexItem regex in regices)
                {
                    if (regex.Regex.IsMatch(domain))
                    {
                        //found pattern
                        matchingPattern = regex.Regex.ToString();
                        blockListUrls = regex.BlockListUrls;
                        return true;
                    }
                }

                matchingPattern = null;
                blockListUrls = null;
                return false;
            }

            private static IReadOnlyDictionary<string, List<Uri>> LoadListZone(IReadOnlyList<Uri> listUrls, Dictionary<Uri, Queue<string>> allListQueues)
            {
                //select lists
                Dictionary<Uri, Queue<string>> listQueues = new Dictionary<Uri, Queue<string>>(listUrls.Count);
                int totalDomains = 0;

                foreach (Uri listUrl in listUrls)
                {
                    if (allListQueues.TryGetValue(listUrl, out Queue<string> listQueue))
                    {
                        totalDomains += listQueue.Count;
                        listQueues.Add(listUrl, listQueue);
                    }
                }

                //load list zone
                Dictionary<string, List<Uri>> listZone = new Dictionary<string, List<Uri>>(totalDomains);

                foreach (KeyValuePair<Uri, Queue<string>> listQueue in listQueues)
                {
                    Queue<string> queue = listQueue.Value;

                    while (queue.Count > 0)
                    {
                        string domain = queue.Dequeue();

                        if (!listZone.TryGetValue(domain, out List<Uri> sourceListUrls))
                        {
                            sourceListUrls = new List<Uri>(2);
                            listZone.Add(domain, sourceListUrls);
                        }

                        sourceListUrls.Add(listQueue.Key);
                    }
                }

                return listZone;
            }

            private IReadOnlyList<RegexItem> LoadRegexListZone(IReadOnlyList<Uri> regexListUrls, Dictionary<Uri, Queue<string>> allRegexListQueues)
            {
                //select regex lists
                Dictionary<Uri, Queue<string>> regexListQueues = new Dictionary<Uri, Queue<string>>(regexListUrls.Count);
                int totalRegexPatterns = 0;

                foreach (Uri regexListUrl in regexListUrls)
                {
                    if (allRegexListQueues.TryGetValue(regexListUrl, out Queue<string> regexListQueue))
                    {
                        totalRegexPatterns += regexListQueue.Count;
                        regexListQueues.Add(regexListUrl, regexListQueue);
                    }
                }

                //load regex list patterns from queue
                Dictionary<string, List<Uri>> allRegexPatterns = new Dictionary<string, List<Uri>>(totalRegexPatterns);

                foreach (KeyValuePair<Uri, Queue<string>> regexListQueue in regexListQueues)
                {
                    Queue<string> queue = regexListQueue.Value;

                    while (queue.Count > 0)
                    {
                        string regex = queue.Dequeue();

                        if (!allRegexPatterns.TryGetValue(regex, out List<Uri> sourceListUrls))
                        {
                            sourceListUrls = new List<Uri>(2);
                            allRegexPatterns.Add(regex, sourceListUrls);
                        }

                        sourceListUrls.Add(regexListQueue.Key);
                    }
                }

                //load regex list zone
                List<RegexItem> regexListZone = new List<RegexItem>(totalRegexPatterns);

                foreach (KeyValuePair<string, List<Uri>> regexPattern in allRegexPatterns)
                {
                    try
                    {
                        Regex regex = new Regex(regexPattern.Key, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

                        regexListZone.Add(new RegexItem(regex, regexPattern.Value));
                    }
                    catch (RegexParseException ex)
                    {
                        _app._dnsServer.WriteLog(ex);
                    }
                }

                return regexListZone;
            }

            #endregion

            #region public

            public void LoadAllowListZone(Dictionary<Uri, Queue<string>> allAllowListQueues)
            {
                List<Uri> listUrls = new List<Uri>();

                listUrls.AddRange(_allowListUrls);
                listUrls.AddRange(_adblockListUrls);

                _allowListZone = LoadListZone(listUrls, allAllowListQueues);
            }

            public void LoadBlockListZone(Dictionary<Uri, Queue<string>> allBlockListQueues)
            {
                List<Uri> listUrls = new List<Uri>();

                listUrls.AddRange(_blockListUrls);
                listUrls.AddRange(_adblockListUrls);

                _blockListZone = LoadListZone(listUrls, allBlockListQueues);
            }

            public void LoadRegexAllowListZone(Dictionary<Uri, Queue<string>> allRegexAllowListQueues)
            {
                _regexAllowListZone = LoadRegexListZone(_regexAllowListUrls, allRegexAllowListQueues);
            }

            public void LoadRegexBlockListZone(Dictionary<Uri, Queue<string>> allRegexBlockListQueues)
            {
                _regexBlockListZone = LoadRegexListZone(_regexBlockListUrls, allRegexBlockListQueues);
            }

            public IReadOnlyList<Uri> IsZoneBlocked(string domain, out string blockedDomain, out string blockedRegex)
            {
                domain = domain.ToLower();

                //allowed, allow list zone, allowedRegex, regex allow list zone
                if (IsZoneFound(_allowed, domain, out _, out _) || IsZoneFound(_allowListZone, domain, out _, out _) || IsMatchFound(_allowedRegex, domain, out _) || IsMatchFound(_regexAllowListZone, domain, out _, out _))
                {
                    //found zone allowed
                    blockedDomain = null;
                    blockedRegex = null;
                    return null;
                }

                //blocked
                if (IsZoneFound(_blocked, domain, out string foundZone1, out _))
                {
                    //found zone blocked
                    blockedDomain = foundZone1;
                    blockedRegex = null;
                    return Array.Empty<Uri>();
                }

                //block list zone
                if (IsZoneFound(_blockListZone, domain, out string foundZone2, out List<Uri> blockListUrls1))
                {
                    //found zone blocked
                    blockedDomain = foundZone2;
                    blockedRegex = null;
                    return blockListUrls1;
                }

                //blockedRegex
                if (IsMatchFound(_blockedRegex, domain, out string blockedPattern1))
                {
                    //found pattern blocked
                    blockedDomain = null;
                    blockedRegex = blockedPattern1;
                    return Array.Empty<Uri>();
                }

                //regex block list zone
                if (IsMatchFound(_regexBlockListZone, domain, out string blockedPattern2, out IReadOnlyList<Uri> blockListUrls2))
                {
                    //found pattern blocked
                    blockedDomain = null;
                    blockedRegex = blockedPattern2;
                    return blockListUrls2;
                }

                blockedDomain = null;
                blockedRegex = null;
                return null;
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            public bool EnableBlocking
            {
                get { return _enableBlocking; }
                set { _enableBlocking = value; }
            }

            public bool AllowTxtBlockingReport
            {
                get { return _allowTxtBlockingReport; }
                set { _allowTxtBlockingReport = value; }
            }

            public bool BlockAsNxDomain
            {
                get { return _blockAsNxDomain; }
                set { _blockAsNxDomain = value; }
            }

            public IReadOnlyCollection<DnsARecord> ARecords
            {
                get { return _aRecords; }
                set { _aRecords = value; }
            }

            public IReadOnlyCollection<DnsAAAARecord> AAAARecords
            {
                get { return _aaaaRecords; }
                set { _aaaaRecords = value; }
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

            public IReadOnlyList<Uri> AdblockListUrls
            {
                get { return _adblockListUrls; }
                set { _adblockListUrls = value; }
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
