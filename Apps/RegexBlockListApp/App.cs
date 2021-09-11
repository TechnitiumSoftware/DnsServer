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
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RegexBlockList
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

        IReadOnlyList<Regex> _regexAllowListPatterns;
        IReadOnlyList<Regex> _regexBlockListPatterns;
        IReadOnlyList<RegexItem> _regexBlockListUrlPatterns = Array.Empty<RegexItem>();

        IReadOnlyList<Uri> _regexBlockListUrls;

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

                                    _dnsServer.WriteLog("Regex Block List app successfully downloaded " + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);
                                }
                                break;

                            case HttpStatusCode.NotModified:
                                {
                                    notModified = true;

                                    _dnsServer.WriteLog("Regex Block List app successfully checked for a new update of the " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);
                                }
                                break;

                            default:
                                throw new HttpRequestException((int)httpResponse.StatusCode + " " + httpResponse.ReasonPhrase);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("Regex Block List app failed to download " + (isAllowList ? "allow" : "block") + " list and will use previously downloaded file (if available): " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            List<Task> tasks = new List<Task>();

            foreach (Uri blockListUrl in _regexBlockListUrls)
                tasks.Add(DownloadListUrlAsync(blockListUrl, false));

            await Task.WhenAll(tasks);

            if (downloaded)
                LoadBlockListUrls();

            return downloaded || notModified;
        }

        private Queue<string> ReadListFile(Uri listUrl, bool isAllow)
        {
            Queue<string> regexPatterns = new Queue<string>();

            try
            {
                _dnsServer.WriteLog("Regex Block List app is reading " + (isAllow ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri);

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

                        regexPatterns.Enqueue(line);
                    }
                }

                _dnsServer.WriteLog("Regex Block List app " + (isAllow ? "allow" : "block") + " list file was read (" + regexPatterns.Count + " regex patterns) from: " + listUrl.AbsoluteUri);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog("Regex Block List app failed to read " + (isAllow ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
            }

            return regexPatterns;
        }

        private void LoadBlockListUrls()
        {
            //read all block lists in a queue
            Dictionary<Uri, Queue<string>> blockListQueues = new Dictionary<Uri, Queue<string>>(_regexBlockListUrls.Count);
            int totalPatterns = 0;

            foreach (Uri blockListUrl in _regexBlockListUrls)
            {
                if (!blockListQueues.ContainsKey(blockListUrl))
                {
                    Queue<string> regexPatterns = ReadListFile(blockListUrl, false);
                    totalPatterns += regexPatterns.Count;
                    blockListQueues.Add(blockListUrl, regexPatterns);
                }
            }

            //load block list patterns from queue
            Dictionary<string, List<Uri>> blockListPatterns = new Dictionary<string, List<Uri>>(totalPatterns);

            foreach (KeyValuePair<Uri, Queue<string>> blockListQueue in blockListQueues)
            {
                Queue<string> queue = blockListQueue.Value;

                while (queue.Count > 0)
                {
                    string regexPattern = queue.Dequeue();

                    if (!blockListPatterns.TryGetValue(regexPattern, out List<Uri> blockLists))
                    {
                        blockLists = new List<Uri>(2);
                        blockListPatterns.Add(regexPattern, blockLists);
                    }

                    blockLists.Add(blockListQueue.Key);
                }
            }

            //load block list patterns into regex list
            List<RegexItem> regexBlockListUrlPatterns = new List<RegexItem>();

            foreach (KeyValuePair<string, List<Uri>> item in blockListPatterns)
            {
                Regex regex = new Regex(item.Key, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

                regexBlockListUrlPatterns.Add(new RegexItem(regex, item.Value));
            }

            _regexBlockListUrlPatterns = regexBlockListUrlPatterns;

            _dnsServer.WriteLog("Regex Block List app block list URL regex patterns were loaded successfully.");
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
                List<Regex> regexAllowListPatterns = new List<Regex>();

                foreach (dynamic jsonRegex in jsonConfig.regexAllowList)
                {
                    string regexPattern = jsonRegex.Value;

                    regexAllowListPatterns.Add(new Regex(regexPattern, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled));
                }

                _regexAllowListPatterns = regexAllowListPatterns;
            }

            {
                List<Regex> regexBlockListPatterns = new List<Regex>();

                foreach (dynamic jsonRegex in jsonConfig.regexBlockList)
                {
                    string regexPattern = jsonRegex.Value;

                    regexBlockListPatterns.Add(new Regex(regexPattern, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled));
                }

                _regexBlockListPatterns = regexBlockListPatterns;
            }

            {
                List<Uri> regexBlockListUrls = new List<Uri>();

                foreach (dynamic jsonUrl in jsonConfig.regexBlockListUrls)
                {
                    string strUrl = jsonUrl.Value;

                    regexBlockListUrls.Add(new Uri(strUrl));
                }

                _regexBlockListUrls = regexBlockListUrls;
            }

            if (_blockListUrlUpdateTimer is null)
            {
                _blockListUrlUpdateTimer = new Timer(BlockListUrlUpdateTimerCallbackAsync, null, Timeout.Infinite, Timeout.Infinite);
                _blockListUrlUpdateTimer.Change(BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, BLOCK_LIST_UPDATE_TIMER_INTERVAL);
            }

            LoadBlockListUrls();

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (!_enableBlocking)
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];
            string domain = question.Name;

            foreach (Regex regex in _regexAllowListPatterns)
            {
                if (regex.IsMatch(domain))
                    return Task.FromResult<DnsDatagram>(null);
            }

            bool isBlocked = false;
            Regex matchedRegex = null;
            RegexItem matchedRegexItem = null;

            foreach (Regex regex in _regexBlockListPatterns)
            {
                if (regex.IsMatch(domain))
                {
                    isBlocked = true;
                    matchedRegex = regex;
                    break;
                }
            }

            if (!isBlocked)
            {
                foreach (RegexItem regexItem in _regexBlockListUrlPatterns)
                {
                    if (regexItem.Regex.IsMatch(domain))
                    {
                        isBlocked = true;
                        matchedRegexItem = regexItem;
                        break;
                    }
                }
            }

            if (!isBlocked)
                return Task.FromResult<DnsDatagram>(null);

            if (question.Type == DnsResourceRecordType.TXT)
            {
                //return meta data
                DnsResourceRecord[] answer;

                if (matchedRegexItem is null)
                {
                    answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("blockList=regex-block-list-app; pattern=" + matchedRegex.ToString())) };
                }
                else
                {
                    answer = new DnsResourceRecord[matchedRegexItem.BlockListUrls.Count];

                    for (int i = 0; i < answer.Length; i++)
                        answer[i] = new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("blockList=regex-block-list-app; regexBlockListUrl=" + matchedRegexItem.BlockListUrls[i].AbsoluteUri + "; pattern=" + matchedRegexItem.Regex.ToString()));
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

                    string parentDomain = GetParentZone(question.Name);
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
                            answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.NS, question.Class, 60, _nsRecord) };
                            break;

                        default:
                            authority = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) };
                            break;
                    }
                }

                return Task.FromResult(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, rcode, request.Question, answer, authority) { Tag = DnsServerResponseType.Blocked });
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Blocks domain names that match the regex defined in the config and from regex based block list URLs."; } }

        #endregion

        class RegexItem
        {
            public readonly Regex Regex;
            public readonly IReadOnlyList<Uri> BlockListUrls;

            public RegexItem(Regex regex, IReadOnlyList<Uri> blockListUrls)
            {
                Regex = regex;
                BlockListUrls = blockListUrls;
            }
        }
    }
}
