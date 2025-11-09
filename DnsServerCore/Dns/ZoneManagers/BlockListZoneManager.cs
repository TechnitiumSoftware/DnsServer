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

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class BlockListZoneManager : IDisposable
    {
        #region variables

        readonly static char[] _popWordSeperator = new char[] { ' ', '\t' };
        readonly static char[] _trimSeperator = new char[] { ' ', '\t', '*', '.' };

        readonly DnsServer _dnsServer;
        readonly string _localCacheFolder;

        IReadOnlyList<string> _blockListUrls = [];

        Dictionary<string, object> _allowListZone = new Dictionary<string, object>();
        Dictionary<string, List<Uri>> _blockListZone = new Dictionary<string, List<Uri>>();

        DnsSOARecordData _soaRecord;
        DnsNSRecordData _nsRecord;

        readonly IReadOnlyCollection<DnsARecordData> _aRecords = [new DnsARecordData(IPAddress.Any)];
        readonly IReadOnlyCollection<DnsAAAARecordData> _aaaaRecords = [new DnsAAAARecordData(IPAddress.IPv6Any)];

        Timer _blockListUpdateTimer;
        DateTime _blockListLastUpdatedOn;
        int _blockListUpdateIntervalHours = 24;
        const int BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL = 5000;
        const int BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL = 900000;

        Timer _temporaryDisableBlockingTimer;
        DateTime _temporaryDisableBlockingTill;

        readonly object _saveLock = new object();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        public BlockListZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _localCacheFolder = Path.Combine(_dnsServer.ConfigFolder, "blocklists");

            if (!Directory.Exists(_localCacheFolder))
                Directory.CreateDirectory(_localCacheFolder);

            UpdateServerDomain();

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveConfigFileInternal();
                            _pendingSave = false;
                        }
                        catch (Exception ex)
                        {
                            _dnsServer.LogManager.Write(ex);

                            //set timer to retry again
                            _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                        }
                    }
                }
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _blockListUpdateTimer?.Dispose();
            _temporaryDisableBlockingTimer?.Dispose();

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave)
                {
                    try
                    {
                        SaveConfigFileInternal();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            _disposed = true;
        }

        #endregion

        #region config

        public void LoadConfigFile()
        {
            string blockListConfigFile = Path.Combine(_dnsServer.ConfigFolder, "blocklist.config");

            try
            {
                using (FileStream fS = new FileStream(blockListConfigFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS, false);
                }

                _dnsServer.LogManager.Write("DNS Server block list config file was loaded: " + blockListConfigFile);
            }
            catch (FileNotFoundException)
            {
                SaveConfigFileInternal();
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server encountered an error while loading block list config file: " + blockListConfigFile + "\r\n" + ex.ToString());
            }
        }

        public void LoadConfig(Stream s, bool isConfigTransfer)
        {
            lock (_saveLock)
            {
                ReadConfigFrom(s, isConfigTransfer);

                SaveConfigFileInternal();

                if (_pendingSave)
                {
                    _pendingSave = false;
                    _saveTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
        }

        private void SaveConfigFileInternal()
        {
            string blockListConfigFile = Path.Combine(_dnsServer.ConfigFolder, "blocklist.config");

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize config
                WriteConfigTo(mS);

                //write config
                mS.Position = 0;

                using (FileStream fS = new FileStream(blockListConfigFile, FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _dnsServer.LogManager.Write("DNS Server block list config file was saved: " + blockListConfigFile);
        }

        public void SaveConfigFile()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void ReadConfigFrom(Stream s, bool isConfigTransfer)
        {
            BinaryReader bR = new BinaryReader(s);

            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "BL") //format
                throw new InvalidDataException("DnsServer block list zone file format is invalid.");

            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    int count = bR.ReadByte();
                    string[] blockListUrls = new string[count];

                    for (int i = 0; i < count; i++)
                        blockListUrls[i] = bR.ReadShortString();

                    _blockListUpdateIntervalHours = bR.ReadInt32();

                    DateTime blockListLastUpdatedOn = bR.ReadDateTime();
                    if (!isConfigTransfer)
                        _blockListLastUpdatedOn = blockListLastUpdatedOn;

                    if (blockListUrls.Length > 0)
                    {
                        //load block list URLs async
                        ThreadPool.QueueUserWorkItem(delegate (object state)
                        {
                            try
                            {
                                LoadBlockLists();
                            }
                            catch (Exception ex)
                            {
                                _dnsServer.LogManager.Write(ex);
                            }
                        });
                    }

                    ApplyBlockListUrls(blockListUrls);
                    ApplyBlockListUpdateInterval();
                    break;

                default:
                    throw new InvalidDataException("DnsServer block list zone file version not supported.");
            }
        }

        private void WriteConfigTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("BL")); //format
            bW.Write((byte)1); //version

            bW.Write(Convert.ToByte(_blockListUrls.Count));

            foreach (string blockListUrl in _blockListUrls)
                bW.WriteShortString(blockListUrl);

            bW.Write(_blockListUpdateIntervalHours);
            bW.Write(_blockListLastUpdatedOn);
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
                _dnsServer.LogManager.Write("DNS Server is reading " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri);

                string listFilePath = GetBlockListFilePath(listUrl);

                if (listUrl.IsFile)
                {
                    if (!File.Exists(listFilePath) || (File.GetLastWriteTimeUtc(listUrl.LocalPath) > File.GetLastWriteTimeUtc(listFilePath)))
                    {
                        File.Copy(listUrl.LocalPath, listFilePath, true);

                        _dnsServer.LogManager.Write("DNS Server successfully downloaded " + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);
                    }
                }

                using (FileStream fS = new FileStream(listFilePath, FileMode.Open, FileAccess.Read))
                {
                    //parse hosts file and populate block zone
                    StreamReader sR = new StreamReader(fS, true);

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

                        line = line.TrimStart(_trimSeperator);

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

                _dnsServer.LogManager.Write("DNS Server read " + (isAllowList ? "allow" : "block") + " list file (" + domains.Count + " domain(s) blocked" + (exceptionDomains.Count > 0 ? ", " + exceptionDomains.Count + " domain(s) allowed" : "") + ") from: " + listUrl.AbsoluteUri);
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server failed to read " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
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

        private void ApplyBlockListUrls(IReadOnlyList<string> blockListUrls)
        {
            bool blockListUrlsUpdated = !blockListUrls.HasSameItems(_blockListUrls);

            _blockListUrls = blockListUrls;

            if ((_blockListUpdateIntervalHours > 0) && (_blockListUrls.Count > 0))
            {
                if (_blockListUpdateTimer is null)
                    StartBlockListUpdateTimer(blockListUrlsUpdated);
                else if (blockListUrlsUpdated)
                    ForceUpdateBlockLists(true);
            }
            else
            {
                StopBlockListUpdateTimer();
            }

            if (_blockListUrls.Count < 1)
                Flush();
        }

        private void ApplyBlockListUpdateInterval()
        {
            if ((_blockListUpdateIntervalHours > 0) && (_blockListUrls.Count > 0))
            {
                if (_blockListUpdateTimer is null)
                    StartBlockListUpdateTimer(false);
            }
            else
            {
                StopBlockListUpdateTimer();
            }
        }

        private void Flush()
        {
            _allowListZone = new Dictionary<string, object>();
            _blockListZone = new Dictionary<string, List<Uri>>();
        }

        private async Task<bool> UpdateBlockListsAsync(bool forceReload)
        {
            bool downloaded = false;
            bool notModified = false;

            async Task DownloadListUrlAsync(Uri listUrl, bool isAllowList)
            {
                try
                {
                    _dnsServer.LogManager.Write("DNS Server is downloading " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);

                    string listFilePath = GetBlockListFilePath(listUrl);

                    if (listUrl.IsFile)
                    {
                        if (File.Exists(listFilePath))
                        {
                            if (File.GetLastWriteTimeUtc(listUrl.LocalPath) <= File.GetLastWriteTimeUtc(listFilePath))
                            {
                                notModified = true;
                                _dnsServer.LogManager.Write("DNS Server successfully checked for a new update of the " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);
                                return;
                            }
                        }

                        File.Copy(listUrl.LocalPath, listFilePath, true);

                        downloaded = true;
                        _dnsServer.LogManager.Write("DNS Server successfully downloaded " + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);
                    }
                    else
                    {
                        HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                        handler.Proxy = _dnsServer.Proxy;
                        handler.NetworkType = _dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
                        handler.DnsClient = _dnsServer;

                        using (HttpClient http = new HttpClient(handler))
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
                                        _dnsServer.LogManager.Write("DNS Server successfully downloaded " + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);
                                    }
                                    break;

                                case HttpStatusCode.NotModified:
                                    {
                                        notModified = true;
                                        _dnsServer.LogManager.Write("DNS Server successfully checked for a new update of the " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);
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
                    _dnsServer.LogManager.Write("DNS Server failed to download " + (isAllowList ? "allow" : "block") + " list and will use previously downloaded file (if available): " + listUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            List<Task> tasks = new List<Task>();

            foreach (string blockListUrl in _blockListUrls)
            {
                if (blockListUrl.StartsWith('!'))
                    tasks.Add(DownloadListUrlAsync(new Uri(blockListUrl.Substring(1)), true));
                else
                    tasks.Add(DownloadListUrlAsync(new Uri(blockListUrl), false));
            }

            await Task.WhenAll(tasks);

            if (downloaded || forceReload)
            {
                LoadBlockLists();

                //force GC collection to remove old zone data from memory quickly
                GC.Collect();
            }

            return downloaded || notModified;
        }

        private void ForceUpdateBlockLists(bool forceReload)
        {
            ThreadPool.QueueUserWorkItem(async delegate (object state)
            {
                try
                {
                    if (await UpdateBlockListsAsync(forceReload))
                    {
                        //block lists were updated
                        //save last updated on time
                        _blockListLastUpdatedOn = DateTime.UtcNow;
                        SaveConfigFile();
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            });
        }

        private void StartBlockListUpdateTimer(bool forceUpdateAndReload)
        {
            if (_blockListUpdateTimer is null)
            {
                if (forceUpdateAndReload)
                    _blockListLastUpdatedOn = default;

                _blockListUpdateTimer = new Timer(async delegate (object state)
                {
                    try
                    {
                        if (DateTime.UtcNow > _blockListLastUpdatedOn.AddHours(_blockListUpdateIntervalHours))
                        {
                            if (await UpdateBlockListsAsync(_blockListLastUpdatedOn == default))
                            {
                                //block lists were updated
                                //save last updated on time
                                _blockListLastUpdatedOn = DateTime.UtcNow;
                                SaveConfigFile();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write("DNS Server encountered an error while updating block lists.\r\n" + ex.ToString());
                    }
                    finally
                    {
                        try
                        {
                            _blockListUpdateTimer.Change(BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL, Timeout.Infinite);
                        }
                        catch (ObjectDisposedException)
                        { }
                    }
                }, null, BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void StopBlockListUpdateTimer()
        {
            if (_blockListUpdateTimer is not null)
            {
                _blockListUpdateTimer.Dispose();
                _blockListUpdateTimer = null;
            }
        }

        private void LoadBlockLists()
        {
            _dnsServer.LogManager.Write("DNS Server is loading block list zone...");

            List<Uri> allowListUrls = new List<Uri>();
            List<Uri> blockListUrls = new List<Uri>();

            foreach (string listUri in this._blockListUrls)
            {
                if (listUri.StartsWith('!'))
                    allowListUrls.Add(new Uri(listUri.Substring(1)));
                else
                    blockListUrls.Add(new Uri(listUri));
            }

            Dictionary<Uri, Queue<string>> allowListQueues = new Dictionary<Uri, Queue<string>>(allowListUrls.Count);
            Dictionary<Uri, Queue<string>> blockListQueues = new Dictionary<Uri, Queue<string>>(blockListUrls.Count);
            int totalAllowedDomains = 0;
            int totalBlockedDomains = 0;

            //read all allow lists in a queue
            foreach (Uri allowListUrl in allowListUrls)
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
            foreach (Uri blockListUrl in blockListUrls)
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

            _dnsServer.LogManager.Write("DNS Server block list zone was loaded successfully.");
        }

        #endregion

        #region public

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

        public void ForceUpdateBlockLists()
        {
            ForceUpdateBlockLists(false);
        }

        public void TemporaryDisableBlocking(int minutes, IPEndPoint userEP, string username)
        {
            Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
            if (temporaryDisableBlockingTimer is not null)
                temporaryDisableBlockingTimer.Dispose();

            Timer newTemporaryDisableBlockingTimer = new Timer(delegate (object state)
            {
                try
                {
                    _dnsServer.EnableBlocking = true;
                    _dnsServer.LogManager.Write(userEP, "[" + username + "] Blocking was enabled after " + minutes + " minute(s) being temporarily disabled.");
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            });

            Timer originalTimer = Interlocked.CompareExchange(ref _temporaryDisableBlockingTimer, newTemporaryDisableBlockingTimer, temporaryDisableBlockingTimer);
            if (ReferenceEquals(originalTimer, temporaryDisableBlockingTimer))
            {
                newTemporaryDisableBlockingTimer.Change(minutes * 60 * 1000, Timeout.Infinite);
                _dnsServer.EnableBlocking = false;
                _temporaryDisableBlockingTill = DateTime.UtcNow.AddMinutes(minutes);

                _dnsServer.LogManager.Write(userEP, "[" + username + "] Blocking was temporarily disabled for " + minutes + " minute(s).");
            }
            else
            {
                newTemporaryDisableBlockingTimer.Dispose();
            }
        }

        public void StopTemporaryDisableBlockingTimer()
        {
            Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
            if (temporaryDisableBlockingTimer is not null)
                temporaryDisableBlockingTimer.Dispose();
        }

        #endregion

        #region properties

        public IReadOnlyList<string> BlockListUrls
        {
            get { return _blockListUrls; }
            set
            {
                if (value is null)
                {
                    value = [];
                }
                else if (value.Count > 255)
                {
                    throw new ArgumentException("Cannot configure more than 255 block list URLs.", nameof(BlockListUrls));
                }
                else
                {
                    List<string> uniqueList = new List<string>(value.Count);

                    foreach (string url in value)
                    {
                        if (url.Length > 255)
                            throw new ArgumentException("Block list URL length cannot exceed 255 characters.", nameof(BlockListUrls));

                        if (!uniqueList.Contains(url))
                            uniqueList.Add(url);
                    }

                    value = uniqueList;
                }

                ApplyBlockListUrls(value);
            }
        }

        public int BlockListUpdateIntervalHours
        {
            get { return _blockListUpdateIntervalHours; }
            set
            {
                if ((value < 0) || (value > 168))
                    throw new ArgumentOutOfRangeException(nameof(BlockListUpdateIntervalHours), "Value must be between 1 hour and 168 hours (7 days) or 0 to disable automatic update.");

                _blockListUpdateIntervalHours = value;

                ApplyBlockListUpdateInterval();
            }
        }

        public bool BlockListUpdateEnabled
        { get { return _blockListUpdateTimer is not null; } }

        public DateTime BlockListLastUpdatedOn
        {
            get { return _blockListLastUpdatedOn; }
            internal set
            {
                _blockListLastUpdatedOn = value;
            }
        }

        public DateTime TemporaryDisableBlockingTill
        { get { return _temporaryDisableBlockingTill; } }

        public int TotalZonesAllowed
        { get { return _allowListZone.Count; } }

        public int TotalZonesBlocked
        { get { return _blockListZone.Count; } }

        #endregion
    }
}
