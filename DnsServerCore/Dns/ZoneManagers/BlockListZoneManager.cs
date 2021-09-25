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

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class BlockListZoneManager
    {
        #region variables

        readonly DnsServer _dnsServer;
        readonly string _localCacheFolder;

        readonly List<Uri> _allowListUrls = new List<Uri>();
        readonly List<Uri> _blockListUrls = new List<Uri>();
        IReadOnlyDictionary<string, List<Uri>> _blockListZone = new Dictionary<string, List<Uri>>();

        DnsSOARecord _soaRecord;
        DnsNSRecord _nsRecord;

        readonly IReadOnlyCollection<DnsARecord> _aRecords = new DnsARecord[] { new DnsARecord(IPAddress.Any) };
        readonly IReadOnlyCollection<DnsAAAARecord> _aaaaRecords = new DnsAAAARecord[] { new DnsAAAARecord(IPAddress.IPv6Any) };

        #endregion

        #region constructor

        public BlockListZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _localCacheFolder = Path.Combine(_dnsServer.ConfigFolder, "blocklists");

            if (!Directory.Exists(_localCacheFolder))
                Directory.CreateDirectory(_localCacheFolder);

            UpdateServerDomain(_dnsServer.ServerDomain);
        }

        #endregion

        #region private

        private void UpdateServerDomain(string serverDomain)
        {
            _soaRecord = new DnsSOARecord(serverDomain, "hostadmin." + serverDomain, 1, 14400, 3600, 604800, 60);
            _nsRecord = new DnsNSRecord(serverDomain);
        }

        private string GetBlockListFilePath(Uri blockListUrl)
        {
            using (HashAlgorithm hash = SHA256.Create())
            {
                return Path.Combine(_localCacheFolder, BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(blockListUrl.AbsoluteUri))).Replace("-", "").ToLower());
            }
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
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write("DNS Server is reading " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri);

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

                if (log != null)
                    log.Write("DNS Server read " + (isAllowList ? "allow" : "block") + " list file (" + domains.Count + " domains) from: " + listUrl.AbsoluteUri);
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write("DNS Server failed to read " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
            }

            return domains;
        }

        internal static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

        private List<Uri> IsZoneBlocked(string domain, out string blockedDomain)
        {
            domain = domain.ToLower();

            do
            {
                if (_blockListZone.TryGetValue(domain, out List<Uri> blockLists))
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

        private static bool IsZoneAllowed(Dictionary<string, object> allowedDomains, string domain)
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

        public void LoadBlockLists()
        {
            //read all allowed domains in dictionary
            Dictionary<string, object> allowedDomains = new Dictionary<string, object>();

            foreach (Uri allowListUrl in _allowListUrls)
            {
                Queue<string> queue = ReadListFile(allowListUrl, true);

                while (queue.Count > 0)
                {
                    string domain = queue.Dequeue();

                    allowedDomains.TryAdd(domain, null);
                }
            }

            //read all block lists in a queue
            Dictionary<Uri, Queue<string>> blockListQueues = new Dictionary<Uri, Queue<string>>(_blockListUrls.Count);
            int totalDomains = 0;

            foreach (Uri blockListUrl in _blockListUrls)
            {
                if (!blockListQueues.ContainsKey(blockListUrl))
                {
                    Queue<string> blockListQueue = ReadListFile(blockListUrl, false);
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

                    if (!blockListZone.TryGetValue(domain, out List<Uri> blockLists))
                    {
                        blockLists = new List<Uri>(2);
                        blockListZone.Add(domain, blockLists);
                    }

                    blockLists.Add(blockListQueue.Key);
                }
            }

            //set new blocked zone
            _blockListZone = blockListZone;

            LogManager log = _dnsServer.LogManager;
            if (log != null)
                log.Write("DNS Server block list zone was loaded successfully.");
        }

        public void Flush()
        {
            _blockListZone = new Dictionary<string, List<Uri>>();
        }

        public async Task<bool> UpdateBlockListsAsync()
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

                                    LogManager log = _dnsServer.LogManager;
                                    if (log != null)
                                        log.Write("DNS Server successfully downloaded " + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);
                                }
                                break;

                            case HttpStatusCode.NotModified:
                                {
                                    notModified = true;

                                    LogManager log = _dnsServer.LogManager;
                                    if (log != null)
                                        log.Write("DNS Server successfully checked for a new update of the " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);
                                }
                                break;

                            default:
                                throw new HttpRequestException((int)httpResponse.StatusCode + " " + httpResponse.ReasonPhrase);
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogManager log = _dnsServer.LogManager;
                    if (log != null)
                        log.Write("DNS Server failed to download " + (isAllowList ? "allow" : "block") + " list and will use previously downloaded file (if available): " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            List<Task> tasks = new List<Task>();

            foreach (Uri allowListUrl in _allowListUrls)
                tasks.Add(DownloadListUrlAsync(allowListUrl, true));

            foreach (Uri blockListUrl in _blockListUrls)
                tasks.Add(DownloadListUrlAsync(blockListUrl, false));

            await Task.WhenAll(tasks);

            if (downloaded)
            {
                LoadBlockLists();

                //force GC collection to remove old zone data from memory quickly
                GC.Collect();
            }

            return downloaded || notModified;
        }

        public DnsDatagram Query(DnsDatagram request)
        {
            DnsQuestionRecord question = request.Question[0];

            List<Uri> blockLists = IsZoneBlocked(question.Name, out string blockedDomain);
            if (blockLists is null)
                return null; //zone not blocked

            //zone is blocked
            if (_dnsServer.AllowTxtBlockingReport && (question.Type == DnsResourceRecordType.TXT))
            {
                //return meta data
                DnsResourceRecord[] answer = new DnsResourceRecord[blockLists.Count];

                for (int i = 0; i < answer.Length; i++)
                    answer[i] = new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("source=block-list-zone; blockListUrl=" + blockLists[i].AbsoluteUri + "; domain=" + blockedDomain));

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answer);
            }
            else
            {
                IReadOnlyCollection<DnsARecord> aRecords;
                IReadOnlyCollection<DnsAAAARecord> aaaaRecords;

                switch (_dnsServer.BlockingType)
                {
                    case DnsServerBlockingType.AnyAddress:
                        aRecords = _aRecords;
                        aaaaRecords = _aaaaRecords;
                        break;

                    case DnsServerBlockingType.CustomAddress:
                        aRecords = _dnsServer.CustomBlockingARecords;
                        aaaaRecords = _dnsServer.CustomBlockingAAAARecords;
                        break;

                    case DnsServerBlockingType.NxDomain:
                        string parentDomain = GetParentZone(blockedDomain);
                        if (parentDomain is null)
                            parentDomain = string.Empty;

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NxDomain, request.Question, null, new DnsResourceRecord[] { new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) });

                    default:
                        throw new InvalidOperationException();
                }

                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;

                switch (question.Type)
                {
                    case DnsResourceRecordType.A:
                        {
                            List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(aRecords.Count);

                            foreach (DnsARecord record in aRecords)
                                rrList.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, 60, record));

                            answer = rrList;
                        }
                        break;

                    case DnsResourceRecordType.AAAA:
                        {
                            List<DnsResourceRecord> rrList = new List<DnsResourceRecord>(aaaaRecords.Count);

                            foreach (DnsAAAARecord record in aaaaRecords)
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

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answer, authority);
            }
        }

        #endregion

        #region properties

        public string ServerDomain
        {
            get { return _soaRecord.PrimaryNameServer; }
            set { UpdateServerDomain(value); }
        }

        public List<Uri> AllowListUrls
        { get { return _allowListUrls; } }

        public List<Uri> BlockListUrls
        { get { return _blockListUrls; } }

        public int TotalZonesBlocked
        { get { return _blockListZone.Count; } }

        #endregion
    }
}
