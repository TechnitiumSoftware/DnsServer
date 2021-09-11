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

using DnsApplicationCommon;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace BlockListGroups
{
    public class App : IDnsAuthoritativeRequestHandler
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

        IReadOnlyDictionary<string, IReadOnlyList<Uri>> _blockListUrlGroups;
        IReadOnlyDictionary<NetworkAddress, string> _networkGroupMap;

        IReadOnlyDictionary<string, IReadOnlyDictionary<string, List<Uri>>> _blockListZones;

        Timer _blockListUrlUpdateTimer;
        DateTime _blockListUrlLastUpdatedOn;
        const int BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL = 5000;
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
            bool downloaded = false;
            bool notModified = false;

            async Task DownloadListUrlAsync(Uri listUrl, bool isAllowList)
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

                                    downloaded = true;

                                    _dnsServer.WriteLog("Block List Groups app successfully downloaded " + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);
                                }
                                break;

                            case HttpStatusCode.NotModified:
                                {
                                    notModified = true;

                                    _dnsServer.WriteLog("Block List Groups app successfully checked for a new update of the " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);
                                }
                                break;

                            default:
                                throw new HttpRequestException((int)httpResponse.StatusCode + " " + httpResponse.ReasonPhrase);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("Block List Groups app failed to download " + (isAllowList ? "allow" : "block") + " list and will use previously downloaded file (if available): " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            List<Task> tasks = new List<Task>();
            IReadOnlyList<Uri> uniqueBlockListUrls = GetUniqueBlockListUrls();

            foreach (Uri blockListUrl in uniqueBlockListUrls)
                tasks.Add(DownloadListUrlAsync(blockListUrl, false));

            await Task.WhenAll(tasks);

            if (downloaded)
                LoadBlockListUrls();

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

        private Queue<string> ReadListFile(Uri listUrl, bool isAllow)
        {
            Queue<string> domains = new Queue<string>();

            try
            {
                _dnsServer.WriteLog("Block List Groups app is reading " + (isAllow ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri);

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

                _dnsServer.WriteLog("Block List Groups app " + (isAllow ? "allow" : "block") + " list file was read (" + domains.Count + " domains) from: " + listUrl.AbsoluteUri);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog("Block List Groups app failed to read " + (isAllow ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
            }

            return domains;
        }

        private IReadOnlyList<Uri> GetUniqueBlockListUrls()
        {
            List<Uri> blockListUrls = new List<Uri>();

            foreach (KeyValuePair<string, IReadOnlyList<Uri>> blockListUrlGroup in _blockListUrlGroups)
            {
                foreach (Uri blockListUrl in blockListUrlGroup.Value)
                {
                    if (!blockListUrls.Contains(blockListUrl))
                        blockListUrls.Add(blockListUrl);
                }
            }

            return blockListUrls;
        }

        private void LoadBlockListUrls()
        {
            IReadOnlyList<Uri> uniqueBlockListUrls = GetUniqueBlockListUrls();

            //read all block lists in a queue
            Dictionary<Uri, Queue<string>> uniqueBlockListQueues = new Dictionary<Uri, Queue<string>>(uniqueBlockListUrls.Count);

            foreach (Uri blockListUrl in uniqueBlockListUrls)
            {
                if (!uniqueBlockListQueues.ContainsKey(blockListUrl))
                {
                    Queue<string> blockListQueue = ReadListFile(blockListUrl, false);
                    uniqueBlockListQueues.Add(blockListUrl, blockListQueue);
                }
            }

            //load block list zone per group
            Dictionary<string, IReadOnlyDictionary<string, List<Uri>>> blockListZones = new Dictionary<string, IReadOnlyDictionary<string, List<Uri>>>();

            foreach (KeyValuePair<string, IReadOnlyList<Uri>> blockListUrlGroup in _blockListUrlGroups)
            {
                string group = blockListUrlGroup.Key;
                IReadOnlyList<Uri> blockListUrls = blockListUrlGroup.Value;

                //prepare group wise block list queue
                Dictionary<Uri, Queue<string>> blockListQueues = new Dictionary<Uri, Queue<string>>(uniqueBlockListUrls.Count);
                int totalDomains = 0;

                foreach (Uri blockListUrl in blockListUrls)
                {
                    if (uniqueBlockListQueues.TryGetValue(blockListUrl, out Queue<string> blockListQueue))
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

                        if (!blockListZone.TryGetValue(domain, out List<Uri> blockLists))
                        {
                            blockLists = new List<Uri>(2);
                            blockListZone.Add(domain, blockLists);
                        }

                        blockLists.Add(blockListQueue.Key);
                    }
                }

                blockListZones.Add(group, blockListZone);
            }

            //set new blocked zone
            _blockListZones = blockListZones;

            _dnsServer.WriteLog("Block List Groups app loaded all block list zones successfully.");

            //force GC collection to remove old zone data from memory quickly
            GC.Collect();
        }

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

        private IReadOnlyList<Uri> IsZoneBlocked(string group, string domain, out string blockedDomain)
        {
            if (!_blockListZones.TryGetValue(group, out IReadOnlyDictionary<string, List<Uri>> blockListZone))
            {
                blockedDomain = null;
                return null;
            }

            domain = domain.ToLower();

            do
            {
                if (blockListZone.TryGetValue(domain, out List<Uri> blockLists))
                {
                    //found zone blocked
                    blockedDomain = domain;
                    return blockLists;
                }

                domain = GetParentZone(domain);
            }
            while (domain is not null);

            blockedDomain = null;
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
                Dictionary<string, IReadOnlyList<Uri>> blockListUrlGroups = new Dictionary<string, IReadOnlyList<Uri>>();

                foreach (dynamic jsonProperty in jsonConfig.blockListUrlGroups)
                {
                    string group = jsonProperty.Name;

                    List<Uri> blockListUrls = new List<Uri>();

                    foreach (dynamic jsonUrl in jsonProperty.Value)
                        blockListUrls.Add(new Uri(jsonUrl.Value));

                    blockListUrlGroups.Add(group, blockListUrls);
                }

                _blockListUrlGroups = blockListUrlGroups;
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

            if (_blockListUrlUpdateTimer is null)
            {
                _blockListUrlUpdateTimer = new Timer(BlockListUrlUpdateTimerCallbackAsync, null, Timeout.Infinite, Timeout.Infinite);
                _blockListUrlUpdateTimer.Change(BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, BLOCK_LIST_UPDATE_TIMER_INTERVAL);
            }

            Task.Run(delegate ()
            {
                LoadBlockListUrls();
            });

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (!_enableBlocking)
                return Task.FromResult<DnsDatagram>(null);

            IPAddress remoteIP = remoteEP.Address;
            string group = null;

            foreach (KeyValuePair<NetworkAddress, string> entry in _networkGroupMap)
            {
                if (entry.Key.Contains(remoteIP))
                {
                    group = entry.Value;
                    break;
                }
            }

            if (group is null)
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];

            IReadOnlyList<Uri> blockLists = IsZoneBlocked(group, question.Name, out string blockedDomain);
            if (blockLists is null)
                return Task.FromResult<DnsDatagram>(null);

            if (question.Type == DnsResourceRecordType.TXT)
            {
                //return meta data
                DnsResourceRecord[] answer = new DnsResourceRecord[blockLists.Count];

                for (int i = 0; i < answer.Length; i++)
                    answer[i] = new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("blockList=block-list-groups-app; blockListUrl=" + blockLists[i].AbsoluteUri + "; domain=" + blockedDomain));

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
        { get { return "Blocks domain names using client's IP address or subnet specific block list URLs."; } }

        #endregion
    }
}
