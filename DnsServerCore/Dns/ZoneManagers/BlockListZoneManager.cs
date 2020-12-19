/*
Technitium DNS Server
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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

        readonly List<Uri> _blockListUrls = new List<Uri>();
        IReadOnlyDictionary<string, List<Uri>> _blockListZone = new Dictionary<string, List<Uri>>();

        DnsSOARecord _soaRecord;
        DnsNSRecord _nsRecord;

        readonly DnsARecord _aRecord = new DnsARecord(IPAddress.Any);
        readonly DnsAAAARecord _aaaaRecord = new DnsAAAARecord(IPAddress.IPv6Any);

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
            _soaRecord = new DnsSOARecord(serverDomain, "hostadmin." + serverDomain, 1, 14400, 3600, 604800, 900);
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

        private Queue<string> ReadBlockListFile(Uri blockListUrl)
        {
            Queue<string> domains = new Queue<string>();

            try
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write("DNS Server is reading block list from: " + blockListUrl.AbsoluteUri);

                using (FileStream fS = new FileStream(GetBlockListFilePath(blockListUrl), FileMode.Open, FileAccess.Read))
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
                    log.Write("DNS Server block list file was read (" + domains.Count + " domains) from: " + blockListUrl.AbsoluteUri);
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write("DNS Server failed to read block list from: " + blockListUrl.AbsoluteUri + "\r\n" + ex.ToString());
            }

            return domains;
        }

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            return null;
        }

        private List<Uri> IsZoneBlocked(string domain)
        {
            while (domain != null)
            {
                if (_blockListZone.TryGetValue(domain, out List<Uri> blockLists))
                    return blockLists; //found zone blocked

                domain = GetParentZone(domain);
            }

            return null;
        }

        #endregion

        #region public

        public void LoadBlockLists()
        {
            //read all block lists in a queue
            Dictionary<Uri, Queue<string>> blockListQueues = new Dictionary<Uri, Queue<string>>(_blockListUrls.Count);
            int totalDomains = 0;

            foreach (Uri blockListUrl in _blockListUrls)
            {
                if (!blockListQueues.ContainsKey(blockListUrl))
                {
                    Queue<string> blockListQueue = ReadBlockListFile(blockListUrl);
                    totalDomains += blockListQueue.Count;
                    blockListQueues.Add(blockListUrl, blockListQueue);
                }
            }

            //load custom blocked zone into new block zone
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
            bool notmodified = false;

            foreach (Uri blockListUrl in _blockListUrls)
            {
                string blockListFilePath = GetBlockListFilePath(blockListUrl);
                string blockListDownloadFilePath = blockListFilePath + ".downloading";

                try
                {
                    if (File.Exists(blockListDownloadFilePath))
                        File.Delete(blockListDownloadFilePath);

                    HttpClientHandler handler = new HttpClientHandler();
                    handler.Proxy = _dnsServer.Proxy;
                    handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        if (File.Exists(blockListFilePath))
                            http.DefaultRequestHeaders.IfModifiedSince = File.GetLastWriteTimeUtc(blockListFilePath);

                        HttpResponseMessage httpResponse = await http.GetAsync(blockListUrl);
                        switch (httpResponse.StatusCode)
                        {
                            case HttpStatusCode.OK:
                                {
                                    using (FileStream fS = new FileStream(blockListDownloadFilePath, FileMode.Create, FileAccess.Write))
                                    {
                                        Stream httpStream = await httpResponse.Content.ReadAsStreamAsync();
                                        await httpStream.CopyToAsync(fS);
                                    }

                                    if (File.Exists(blockListFilePath))
                                        File.Delete(blockListFilePath);

                                    File.Move(blockListDownloadFilePath, blockListFilePath);

                                    if (httpResponse.Content.Headers.LastModified != null)
                                        File.SetLastWriteTimeUtc(blockListFilePath, httpResponse.Content.Headers.LastModified.Value.UtcDateTime);

                                    downloaded = true;

                                    LogManager log = _dnsServer.LogManager;
                                    if (log != null)
                                        log.Write("DNS Server successfully downloaded block list (" + WebUtilities.GetFormattedSize(new FileInfo(blockListFilePath).Length) + "): " + blockListUrl.AbsoluteUri);
                                }
                                break;

                            case HttpStatusCode.NotModified:
                                {
                                    notmodified = true;

                                    LogManager log = _dnsServer.LogManager;
                                    if (log != null)
                                        log.Write("DNS Server successfully checked for a new update of the block list: " + blockListUrl.AbsoluteUri);
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
                        log.Write("DNS Server failed to download block list and will use previously downloaded file (if available): " + blockListUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            if (downloaded)
            {
                LoadBlockLists();

                //force GC collection to remove old zone data from memory quickly
                GC.Collect();
            }

            return downloaded || notmodified;
        }

        public DnsDatagram Query(DnsDatagram request)
        {
            List<Uri> blockLists = IsZoneBlocked(request.Question[0].Name.ToLower());

            if (blockLists == null)
            {
                //zone not blocked
                return null;
            }

            //zone is blocked
            DnsResourceRecord[] answers = null;
            DnsResourceRecord[] authority = null;

            switch (request.Question[0].Type)
            {
                case DnsResourceRecordType.A:
                    answers = new DnsResourceRecord[] { new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.A, request.Question[0].Class, 60, _aRecord) };
                    break;

                case DnsResourceRecordType.AAAA:
                    answers = new DnsResourceRecord[] { new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.AAAA, request.Question[0].Class, 60, _aaaaRecord) };
                    break;

                case DnsResourceRecordType.NS:
                    answers = new DnsResourceRecord[] { new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.NS, request.Question[0].Class, 60, _nsRecord) };
                    break;

                case DnsResourceRecordType.TXT:
                    answers = new DnsResourceRecord[blockLists.Count];

                    for (int i = 0; i < answers.Length; i++)
                        answers[i] = new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.TXT, request.Question[0].Class, 60, new DnsTXTRecord("blockList=" + blockLists[i].AbsoluteUri + "; domain=" + request.Question[0].Name));

                    break;

                default:
                    authority = new DnsResourceRecord[] { new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.SOA, request.Question[0].Class, 60, _soaRecord) };
                    break;
            }

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answers, authority);
        }

        #endregion

        #region properties

        public string ServerDomain
        {
            get { return _soaRecord.PrimaryNameServer; }
            set { UpdateServerDomain(value); }
        }

        public List<Uri> BlockListUrls
        { get { return _blockListUrls; } }

        public int TotalZonesBlocked
        { get { return _blockListZone.Count; } }

        #endregion
    }
}
