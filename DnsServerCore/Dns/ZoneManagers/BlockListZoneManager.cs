/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class BlockListZoneManager
    {
        #region variables

        readonly static char[] _popWordSeperator = new char[] { ' ', '\t' };

        readonly DnsServer _dnsServer;
        readonly string _localCacheFolder;

        readonly List<Uri> _allowListUrls = new List<Uri>();
        readonly List<Uri> _blockListUrls = new List<Uri>();

        Dictionary<string, object> _allowListZone = new Dictionary<string, object>();
        Dictionary<string, List<Uri>> _blockListZone = new Dictionary<string, List<Uri>>();

        DnsSOARecordData _soaRecord;
        DnsNSRecordData _nsRecord;

        readonly IReadOnlyCollection<DnsARecordData> _aRecords = new DnsARecordData[] { new DnsARecordData(IPAddress.Any) };
        readonly IReadOnlyCollection<DnsAAAARecordData> _aaaaRecords = new DnsAAAARecordData[] { new DnsAAAARecordData(IPAddress.IPv6Any) };

        #endregion

        #region constructor

        public BlockListZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _localCacheFolder = Path.Combine(_dnsServer.ConfigFolder, "blocklists");

            if (!Directory.Exists(_localCacheFolder))
                Directory.CreateDirectory(_localCacheFolder);

            UpdateServerDomain();
        }

        #endregion

        #region private

        internal void UpdateServerDomain()
        {
            _soaRecord = new DnsSOARecordData(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, _dnsServer.BlockingAnswerTtl);
            _nsRecord = new DnsNSRecordData(_dnsServer.ServerDomain);
        }

        private string GetBlockListFilePath(Uri blockListUrl)
        {
            return Path.Combine(_localCacheFolder, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(blockListUrl.AbsoluteUri))).ToLowerInvariant());
        }

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

        private Queue<string> ReadListFile(Uri listUrl, bool isAllowList, out Queue<string> exceptionDomains)
        {
            Queue<string> domains = new Queue<string>();
            exceptionDomains = new Queue<string>();

            try
            {
                _dnsServer.LogManager?.Write("DNS Server is reading " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri);

                string listFilePath = GetBlockListFilePath(listUrl);

                if (listUrl.IsFile)
                {
                    if (!File.Exists(listFilePath) || (File.GetLastWriteTimeUtc(listUrl.LocalPath) > File.GetLastWriteTimeUtc(listFilePath)))
                    {
                        File.Copy(listUrl.LocalPath, listFilePath, true);

                        _dnsServer.LogManager?.Write("DNS Server successfully downloaded " + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);
                    }
                }

                using (FileStream fS = new FileStream(listFilePath, FileMode.Open, FileAccess.Read))
                {
                    //parse hosts file and populate block zone
                    StreamReader sR = new StreamReader(fS, true);
                    char[] trimSeperator = new char[] { ' ', '\t', '*', '.' };
                    string line;
                    string firstWord;
                    string secondWord;
                    string hostname;
                    string domain;
                    string options;
                    int i;

                    while (true)
                    {
                        line = sR.ReadLine();
                        if (line is null)
                            break; //eof

                        line = line.TrimStart(trimSeperator);

                        if (line.Length == 0)
                            continue; //skip empty line

                        if (line.StartsWith('#') || line.StartsWith('!'))
                            continue; //skip comment line

                        if (line.StartsWith("||"))
                        {
                            //adblock format
                            i = line.IndexOf('^');
                            if (i > -1)
                            {
                                domain = line.Substring(2, i - 2);
                                options = line.Substring(i + 1);

                                if (((options.Length == 0) || (options.StartsWith('$') && (options.Contains("doc") || options.Contains("all")))) && DnsClient.IsDomainNameValid(domain))
                                    domains.Enqueue(domain.ToLowerInvariant());
                            }
                            else
                            {
                                domain = line.Substring(2);

                                if (DnsClient.IsDomainNameValid(domain))
                                    domains.Enqueue(domain.ToLowerInvariant());
                            }
                        }
                        else if (line.StartsWith("@@||"))
                        {
                            //adblock format - exception syntax
                            i = line.IndexOf('^');
                            if (i > -1)
                            {
                                domain = line.Substring(4, i - 4);
                                options = line.Substring(i + 1);

                                if (((options.Length == 0) || (options.StartsWith('$') && (options.Contains("doc") || options.Contains("all")))) && DnsClient.IsDomainNameValid(domain))
                                    exceptionDomains.Enqueue(domain.ToLowerInvariant());
                            }
                            else
                            {
                                domain = line.Substring(4);

                                if (DnsClient.IsDomainNameValid(domain))
                                    exceptionDomains.Enqueue(domain.ToLowerInvariant());
                            }
                        }
                        else
                        {
                            //hosts file format
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
                }

                _dnsServer.LogManager?.Write("DNS Server read " + (isAllowList ? "allow" : "block") + " list file (" + domains.Count + " domains) from: " + listUrl.AbsoluteUri);
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager?.Write("DNS Server failed to read " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
            }

            return domains;
        }

        private List<Uri> IsZoneBlocked(string domain, out string blockedDomain)
        {
            domain = domain.ToLowerInvariant();

            do
            {
                if (_blockListZone.TryGetValue(domain, out List<Uri> blockLists))
                {
                    //found zone blocked
                    blockedDomain = domain;
                    return blockLists;
                }

                domain = AuthZoneManager.GetParentZone(domain);
            }
            while (domain is not null);

            blockedDomain = null;
            return null;
        }

        private bool IsZoneAllowed(string domain)
        {
            domain = domain.ToLowerInvariant();

            do
            {
                if (_allowListZone.TryGetValue(domain, out _))
                    return true;

                domain = AuthZoneManager.GetParentZone(domain);
            }
            while (domain is not null);

            return false;
        }

        #endregion

        #region public

        public void LoadBlockLists()
        {
            Dictionary<Uri, Queue<string>> allowListQueues = new Dictionary<Uri, Queue<string>>(_allowListUrls.Count);
            Dictionary<Uri, Queue<string>> blockListQueues = new Dictionary<Uri, Queue<string>>(_blockListUrls.Count);
            int totalAllowedDomains = 0;
            int totalBlockedDomains = 0;

            //read all allow lists in a queue
            foreach (Uri allowListUrl in _allowListUrls)
            {
                if (!allowListQueues.ContainsKey(allowListUrl))
                {
                    Queue<string> allowListQueue = ReadListFile(allowListUrl, true, out Queue<string> blockListQueue);

                    totalAllowedDomains += allowListQueue.Count;
                    allowListQueues.Add(allowListUrl, allowListQueue);

                    totalBlockedDomains += blockListQueue.Count;
                    blockListQueues.Add(allowListUrl, blockListQueue);
                }
            }

            //read all block lists in a queue
            foreach (Uri blockListUrl in _blockListUrls)
            {
                if (!blockListQueues.ContainsKey(blockListUrl))
                {
                    Queue<string> blockListQueue = ReadListFile(blockListUrl, false, out Queue<string> allowListQueue);

                    totalBlockedDomains += blockListQueue.Count;
                    blockListQueues.Add(blockListUrl, blockListQueue);

                    totalAllowedDomains += allowListQueue.Count;
                    allowListQueues.Add(blockListUrl, allowListQueue);
                }
            }

            //load block list zone
            Dictionary<string, object> allowListZone = new Dictionary<string, object>(totalAllowedDomains);

            foreach (KeyValuePair<Uri, Queue<string>> allowListQueue in allowListQueues)
            {
                Queue<string> queue = allowListQueue.Value;

                while (queue.Count > 0)
                {
                    string domain = queue.Dequeue();

                    allowListZone.TryAdd(domain, null);
                }
            }

            Dictionary<string, List<Uri>> blockListZone = new Dictionary<string, List<Uri>>(totalBlockedDomains);

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

            //set new allowed and blocked zones
            _allowListZone = allowListZone;
            _blockListZone = blockListZone;

            _dnsServer.LogManager?.Write("DNS Server block list zone was loaded successfully.");
        }

        public void Flush()
        {
            _allowListZone = new Dictionary<string, object>();
            _blockListZone = new Dictionary<string, List<Uri>>();
        }

        public async Task<bool> UpdateBlockListsAsync(bool forceReload)
        {
            bool downloaded = false;
            bool notModified = false;

            async Task DownloadListUrlAsync(Uri listUrl, bool isAllowList)
            {
                try
                {
                    _dnsServer.LogManager?.Write("DNS Server is downloading " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);

                    string listFilePath = GetBlockListFilePath(listUrl);

                    if (listUrl.IsFile)
                    {
                        if (File.Exists(listFilePath))
                        {
                            if (File.GetLastWriteTimeUtc(listUrl.LocalPath) <= File.GetLastWriteTimeUtc(listFilePath))
                            {
                                notModified = true;
                                _dnsServer.LogManager?.Write("DNS Server successfully checked for a new update of the " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);
                                return;
                            }
                        }

                        File.Copy(listUrl.LocalPath, listFilePath, true);

                        downloaded = true;
                        _dnsServer.LogManager?.Write("DNS Server successfully downloaded " + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);
                    }
                    else
                    {
                        SocketsHttpHandler handler = new SocketsHttpHandler();
                        handler.Proxy = _dnsServer.Proxy;
                        handler.UseProxy = _dnsServer.Proxy is not null;
                        handler.AutomaticDecompression = DecompressionMethods.All;

                        using (HttpClient http = new HttpClient(new HttpClientNetworkHandler(handler, _dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default, _dnsServer)))
                        {
                            if (File.Exists(listFilePath))
                                http.DefaultRequestHeaders.IfModifiedSince = File.GetLastWriteTimeUtc(listFilePath);

                            HttpResponseMessage httpResponse = await http.GetAsync(listUrl);
                            switch (httpResponse.StatusCode)
                            {
                                case HttpStatusCode.OK:
                                    {
                                        string listDownloadFilePath = listFilePath + ".downloading";

                                        using (FileStream fS = new FileStream(listDownloadFilePath, FileMode.Create, FileAccess.Write))
                                        {
                                            using (Stream httpStream = await httpResponse.Content.ReadAsStreamAsync())
                                            {
                                                await httpStream.CopyToAsync(fS);
                                            }
                                        }

                                        File.Move(listDownloadFilePath, listFilePath, true);

                                        if (httpResponse.Content.Headers.LastModified != null)
                                            File.SetLastWriteTimeUtc(listFilePath, httpResponse.Content.Headers.LastModified.Value.UtcDateTime);

                                        downloaded = true;
                                        _dnsServer.LogManager?.Write("DNS Server successfully downloaded " + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);
                                    }
                                    break;

                                case HttpStatusCode.NotModified:
                                    {
                                        notModified = true;
                                        _dnsServer.LogManager?.Write("DNS Server successfully checked for a new update of the " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);
                                    }
                                    break;

                                default:
                                    throw new HttpRequestException((int)httpResponse.StatusCode + " " + httpResponse.ReasonPhrase);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager?.Write("DNS Server failed to download " + (isAllowList ? "allow" : "block") + " list and will use previously downloaded file (if available): " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            List<Task> tasks = new List<Task>();

            foreach (Uri allowListUrl in _allowListUrls)
                tasks.Add(DownloadListUrlAsync(allowListUrl, true));

            foreach (Uri blockListUrl in _blockListUrls)
                tasks.Add(DownloadListUrlAsync(blockListUrl, false));

            await Task.WhenAll(tasks);

            if (downloaded || forceReload)
            {
                LoadBlockLists();

                //force GC collection to remove old zone data from memory quickly
                GC.Collect();
            }

            return downloaded || notModified;
        }

        public bool IsAllowed(DnsDatagram request)
        {
            if (_allowListZone.Count < 1)
                return false;

            return IsZoneAllowed(request.Question[0].Name);
        }

        public DnsDatagram Query(DnsDatagram request)
        {
            if (_blockListZone.Count < 1)
                return null;

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
                    answer[i] = new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, _dnsServer.BlockingAnswerTtl, new DnsTXTRecordData("source=block-list-zone; blockListUrl=" + blockLists[i].AbsoluteUri + "; domain=" + blockedDomain));

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answer);
            }
            else
            {
                EDnsOption[] options = null;

                if (_dnsServer.AllowTxtBlockingReport && (request.EDNS is not null))
                {
                    options = new EDnsOption[blockLists.Count];

                    for (int i = 0; i < options.Length; i++)
                        options[i] = new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, "source=block-list-zone; blockListUrl=" + blockLists[i].AbsoluteUri + "; domain=" + blockedDomain));
                }

                IReadOnlyCollection<DnsARecordData> aRecords;
                IReadOnlyCollection<DnsAAAARecordData> aaaaRecords;

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
                        string parentDomain = AuthZoneManager.GetParentZone(blockedDomain);
                        if (parentDomain is null)
                            parentDomain = string.Empty;

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NxDomain, request.Question, null, [new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)], null, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options);

                    default:
                        throw new InvalidOperationException();
                }

                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;

                switch (question.Type)
                {
                    case DnsResourceRecordType.A:
                        {
                            if (aRecords.Count > 0)
                            {
                                DnsResourceRecord[] rrList = new DnsResourceRecord[aRecords.Count];
                                int i = 0;

                                foreach (DnsARecordData record in aRecords)
                                    rrList[i++] = new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, _dnsServer.BlockingAnswerTtl, record);

                                answer = rrList;
                            }
                            else
                            {
                                authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)];
                            }
                        }
                        break;

                    case DnsResourceRecordType.AAAA:
                        {
                            if (aaaaRecords.Count > 0)
                            {
                                DnsResourceRecord[] rrList = new DnsResourceRecord[aaaaRecords.Count];
                                int i = 0;

                                foreach (DnsAAAARecordData record in aaaaRecords)
                                    rrList[i++] = new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, _dnsServer.BlockingAnswerTtl, record);

                                answer = rrList;
                            }
                            else
                            {
                                authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)];
                            }
                        }
                        break;

                    case DnsResourceRecordType.NS:
                        if (question.Name.Equals(blockedDomain, StringComparison.OrdinalIgnoreCase))
                            answer = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.NS, question.Class, _dnsServer.BlockingAnswerTtl, _nsRecord)];
                        else
                            authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)];

                        break;

                    case DnsResourceRecordType.SOA:
                        answer = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)];
                        break;

                    default:
                        authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingAnswerTtl, _soaRecord)];
                        break;
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answer, authority, null, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options);
            }
        }

        #endregion

        #region properties

        public List<Uri> AllowListUrls
        { get { return _allowListUrls; } }

        public List<Uri> BlockListUrls
        { get { return _blockListUrls; } }

        public int TotalZonesAllowed
        { get { return _allowListZone.Count; } }

        public int TotalZonesBlocked
        { get { return _blockListZone.Count; } }

        #endregion
    }
}
