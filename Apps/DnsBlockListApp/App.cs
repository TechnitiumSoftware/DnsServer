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

using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsBlockList
{
    //DNS Blacklists and Whitelists
    //https://www.rfc-editor.org/rfc/rfc5782

    public sealed class App : IDnsApplication, IDnsAppRecordRequestHandler
    {
        #region variables

        IDnsServer _dnsServer;

        Dictionary<string, BlockList> _dnsBlockLists;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_dnsBlockLists is not null)
            {
                foreach (KeyValuePair<string, BlockList> dnsBlockList in _dnsBlockLists)
                    dnsBlockList.Value.Dispose();

                _dnsBlockLists = null;
            }
        }

        #endregion

        #region private

        private static bool TryParseDnsblDomain(string qName, string appRecordName, out IPAddress address, out string domain)
        {
            qName = qName.Substring(0, qName.Length - appRecordName.Length - 1);

            string[] parts = qName.Split('.');
            string lastPart = parts[parts.Length - 1];

            if (byte.TryParse(lastPart, out _) || byte.TryParse(lastPart, NumberStyles.HexNumber, null, out _))
            {
                switch (parts.Length)
                {
                    case 4:
                        {
                            Span<byte> buffer = stackalloc byte[4];

                            for (int i = 0, j = parts.Length - 1; (i < 4) && (j > -1); i++, j--)
                                buffer[i] = byte.Parse(parts[j]);

                            address = new IPAddress(buffer);
                            domain = null;
                            return true;
                        }

                    case 32:
                        {
                            Span<byte> buffer = stackalloc byte[16];

                            for (int i = 0, j = parts.Length - 1; (i < 16) && (j > 0); i++, j -= 2)
                                buffer[i] = (byte)(byte.Parse(parts[j], NumberStyles.HexNumber) << 4 | byte.Parse(parts[j - 1], NumberStyles.HexNumber));

                            address = new IPAddress(buffer);
                            domain = null;
                            return true;
                        }

                    default:
                        address = null;
                        domain = null;
                        return false;
                }
            }
            else
            {
                address = null;
                domain = lastPart;

                for (int i = parts.Length - 2; i > -1; i--)
                    domain = parts[i] + "." + domain;

                return true;
            }
        }

        private Tuple<string, BlockList> ReadBlockList(JsonElement jsonBlockList)
        {
            BlockList blockList;
            string name = jsonBlockList.GetProperty("name").GetString();
            BlockListType type = jsonBlockList.GetPropertyEnumValue("type", BlockListType.Ip);

            if ((_dnsBlockLists is not null) && _dnsBlockLists.TryGetValue(name, out BlockList existingBlockList) && (existingBlockList.Type == type))
            {
                existingBlockList.ReloadConfig(jsonBlockList);
                blockList = existingBlockList;
            }
            else
            {
                switch (type)
                {
                    case BlockListType.Ip:
                        blockList = new IpBlockList(_dnsServer, jsonBlockList);
                        break;

                    case BlockListType.Domain:
                        blockList = new DomainBlockList(_dnsServer, jsonBlockList);
                        break;

                    default:
                        throw new NotSupportedException("DNSBL block list type is not supported: " + type.ToString());
                }
            }

            return new Tuple<string, BlockList>(blockList.Name, blockList);
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            if (jsonConfig.TryReadArrayAsMap("dnsBlockLists", ReadBlockList, out Dictionary<string, BlockList> dnsBlockLists))
            {
                if (_dnsBlockLists is not null)
                {
                    foreach (KeyValuePair<string, BlockList> dnsBlockList in _dnsBlockLists)
                    {
                        if (!dnsBlockLists.ContainsKey(dnsBlockList.Key))
                            dnsBlockList.Value.Dispose();
                    }
                }

                _dnsBlockLists = dnsBlockLists;
            }
            else
            {
                if (_dnsBlockLists is not null)
                {
                    foreach (KeyValuePair<string, BlockList> dnsBlockList in _dnsBlockLists)
                        dnsBlockList.Value.Dispose();
                }

                _dnsBlockLists = null;
            }

            return Task.CompletedTask;
        }

        public async Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];
            string qname = question.Name;

            if (qname.Length == appRecordName.Length)
                return null;

            if ((_dnsBlockLists is null) || !TryParseDnsblDomain(qname, appRecordName, out IPAddress address, out string domain))
                return null;

            using JsonDocument jsonDocument = JsonDocument.Parse(appRecordData);
            JsonElement jsonAppRecordData = jsonDocument.RootElement;

            if (jsonAppRecordData.TryReadArray("dnsBlockLists", out string[] dnsBlockLists))
            {
                bool isBlocked = false;
                IPAddress responseA = null;
                string responseTXT = null;

                if (address is not null)
                {
                    foreach (string dnsBlockList in dnsBlockLists)
                    {
                        if (_dnsBlockLists.TryGetValue(dnsBlockList, out BlockList blockList) && blockList.Enabled && (blockList.Type == BlockListType.Ip) && blockList.IsBlocked(address, out responseA, out responseTXT))
                        {
                            isBlocked = true;

                            if (!string.IsNullOrEmpty(responseTXT))
                                responseTXT = responseTXT.Replace("{ip}", address.ToString());

                            break;
                        }
                    }
                }
                else if (domain is not null)
                {
                    foreach (string dnsBlockList in dnsBlockLists)
                    {
                        if (_dnsBlockLists.TryGetValue(dnsBlockList, out BlockList blockList) && blockList.Enabled && (blockList.Type == BlockListType.Domain) && blockList.IsBlocked(domain, out string foundDomain, out responseA, out responseTXT))
                        {
                            isBlocked = true;

                            if (!string.IsNullOrEmpty(responseTXT))
                                responseTXT = responseTXT.Replace("{domain}", foundDomain);

                            break;
                        }
                    }
                }

                if (isBlocked)
                {
                    switch (question.Type)
                    {
                        case DnsResourceRecordType.A:
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, new DnsResourceRecord[] { new DnsResourceRecord(qname, DnsResourceRecordType.A, question.Class, appRecordTtl, new DnsARecordData(responseA)) });

                        case DnsResourceRecordType.TXT:
                            if (!string.IsNullOrEmpty(responseTXT))
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, new DnsResourceRecord[] { new DnsResourceRecord(qname, DnsResourceRecordType.TXT, question.Class, appRecordTtl, new DnsTXTRecordData(responseTXT)) });

                            break;
                    }

                    //NODATA response
                    DnsDatagram soaResponse = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(zoneName, DnsResourceRecordType.SOA, DnsClass.IN));

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, null, soaResponse.Answer);
                }
            }

            return null;
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns A or TXT records based on the DNS Block Lists (DNSBL) configured in the APP record data. Returns NXDOMAIN response when an IP address or domain name is not blocked in any of the configured blocklists."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""dnsBlockLists"": [
    ""ipblocklist1"",
    ""domainblocklist1""
  ]
}";
            }
        }

        #endregion

        enum BlockListType
        {
            Ip = 1,
            Domain = 2
        }

        abstract class BlockList : IDisposable
        {
            #region variables

            protected static readonly char[] _popWordSeperator = new char[] { ' ', '\t', '|' };

            protected readonly IDnsServer _dnsServer;
            readonly BlockListType _type;

            readonly string _name;
            bool _enabled;
            protected IPAddress _responseA;
            protected string _responseTXT;
            protected string _blockListFile;

            protected DateTime _blockListFileLastModified;

            Timer _autoReloadTimer;
            const int AUTO_RELOAD_TIMER_INTERVAL = 60000;

            #endregion

            #region constructor

            protected BlockList(IDnsServer dnsServer, BlockListType type, JsonElement jsonBlockList)
            {
                _dnsServer = dnsServer;
                _type = type;

                _name = jsonBlockList.GetProperty("name").GetString();

                _autoReloadTimer = new Timer(delegate (object state)
                {
                    try
                    {
                        DateTime blockListFileLastModified = File.GetLastWriteTimeUtc(_blockListFile);
                        if (blockListFileLastModified > _blockListFileLastModified)
                            ReloadBlockListFile();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog(ex);
                    }
                    finally
                    {
                        _autoReloadTimer?.Change(AUTO_RELOAD_TIMER_INTERVAL, Timeout.Infinite);
                    }
                });

                ReloadConfig(jsonBlockList);
            }

            #endregion

            #region IDisposable

            public void Dispose()
            {
                if (_autoReloadTimer is not null)
                {
                    _autoReloadTimer.Dispose();
                    _autoReloadTimer = null;
                }
            }

            #endregion

            #region protected

            protected abstract void ReloadBlockListFile();

            protected static string PopWord(ref string line)
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

            #endregion

            #region public

            public void ReloadConfig(JsonElement jsonBlockList)
            {
                _enabled = jsonBlockList.GetPropertyValue("enabled", true);
                _responseA = IPAddress.Parse(jsonBlockList.GetPropertyValue("responseA", "127.0.0.2"));

                if (jsonBlockList.TryGetProperty("responseTXT", out JsonElement jsonResponseTXT))
                    _responseTXT = jsonResponseTXT.GetString();
                else
                    _responseTXT = null;

                string blockListFile = jsonBlockList.GetProperty("blockListFile").GetString();

                if (!Path.IsPathRooted(blockListFile))
                    blockListFile = Path.Combine(_dnsServer.ApplicationFolder, blockListFile);

                if (!blockListFile.Equals(_blockListFile))
                {
                    _blockListFile = blockListFile;
                    _blockListFileLastModified = default;
                }

                _autoReloadTimer.Change(0, Timeout.Infinite);
            }

            public virtual bool IsBlocked(IPAddress address, out IPAddress responseA, out string responseTXT)
            {
                throw new InvalidOperationException();
            }

            public virtual bool IsBlocked(string domain, out string foundDomain, out IPAddress responseA, out string responseTXT)
            {
                throw new InvalidOperationException();
            }

            #endregion

            #region properties

            public BlockListType Type
            { get { return _type; } }

            public string Name
            { get { return _name; } }

            public bool Enabled
            { get { return _enabled; } }

            public IPAddress ResponseA
            { get { return _responseA; } }

            public string ResponseTXT
            { get { return _responseTXT; } }

            public string BlockListFile
            { get { return _blockListFile; } }

            #endregion
        }

        class BlockEntry<T>
        {
            #region variables

            readonly T _key;
            readonly IPAddress _responseA;
            readonly string _responseTXT;

            #endregion

            #region constructor

            public BlockEntry(T key, string responseA, string responseTXT)
            {
                _key = key;

                if (IPAddress.TryParse(responseA, out IPAddress addr))
                    _responseA = addr;

                if (!string.IsNullOrEmpty(responseTXT))
                    _responseTXT = responseTXT;
            }

            #endregion

            #region properties

            public T Key
            { get { return _key; } }

            public IPAddress ResponseA
            { get { return _responseA; } }

            public string ResponseTXT
            { get { return _responseTXT; } }

            #endregion
        }

        class IpBlockList : BlockList
        {
            #region variables

            Dictionary<IPAddress, BlockEntry<IPAddress>> _ipv4Map;
            Dictionary<IPAddress, BlockEntry<IPAddress>> _ipv6Map;
            NetworkMap<BlockEntry<NetworkAddress>> _ipv4NetworkMap;
            NetworkMap<BlockEntry<NetworkAddress>> _ipv6NetworkMap;

            #endregion

            #region constructor

            public IpBlockList(IDnsServer dnsServer, JsonElement jsonBlockList)
                : base(dnsServer, BlockListType.Ip, jsonBlockList)
            { }

            #endregion

            #region protected

            protected override void ReloadBlockListFile()
            {
                try
                {
                    _dnsServer.WriteLog("The app is reading IP block list file: " + _blockListFile);

                    //parse ip block list file
                    Queue<BlockEntry<IPAddress>> ipv4Addresses = new Queue<BlockEntry<IPAddress>>();
                    Queue<BlockEntry<IPAddress>> ipv6Addresses = new Queue<BlockEntry<IPAddress>>();
                    Queue<BlockEntry<NetworkAddress>> ipv4Networks = new Queue<BlockEntry<NetworkAddress>>();
                    Queue<BlockEntry<NetworkAddress>> ipv6Networks = new Queue<BlockEntry<NetworkAddress>>();

                    ipv4Addresses.Enqueue(new BlockEntry<IPAddress>(IPAddress.Parse("127.0.0.2"), "127.0.0.2", "rfc5782 test entry"));
                    ipv6Addresses.Enqueue(new BlockEntry<IPAddress>(IPAddress.Parse("::FFFF:7F00:2"), "127.0.0.2", "rfc5782 test entry"));

                    using (FileStream fS = new FileStream(_blockListFile, FileMode.Open, FileAccess.Read))
                    {
                        StreamReader sR = new StreamReader(fS, true);
                        string line;
                        string network;
                        string responseA;
                        string responseTXT;

                        while (true)
                        {
                            line = sR.ReadLine();
                            if (line is null)
                                break; //eof

                            line = line.TrimStart(_popWordSeperator);

                            if (line.Length == 0)
                                continue; //skip empty line

                            if (line.StartsWith('#'))
                                continue; //skip comment line

                            network = PopWord(ref line);
                            responseA = PopWord(ref line);
                            responseTXT = line;

                            if (NetworkAddress.TryParse(network, out NetworkAddress networkAddress))
                            {
                                switch (networkAddress.AddressFamily)
                                {
                                    case AddressFamily.InterNetwork:
                                        if (networkAddress.PrefixLength == 32)
                                            ipv4Addresses.Enqueue(new BlockEntry<IPAddress>(networkAddress.Address, responseA, responseTXT));
                                        else
                                            ipv4Networks.Enqueue(new BlockEntry<NetworkAddress>(networkAddress, responseA, responseTXT));

                                        break;

                                    case AddressFamily.InterNetworkV6:
                                        if (networkAddress.PrefixLength == 128)
                                            ipv6Addresses.Enqueue(new BlockEntry<IPAddress>(networkAddress.Address, responseA, responseTXT));
                                        else
                                            ipv6Networks.Enqueue(new BlockEntry<NetworkAddress>(networkAddress, responseA, responseTXT));

                                        break;
                                }
                            }
                        }

                        _blockListFileLastModified = File.GetLastWriteTimeUtc(fS.SafeFileHandle);
                    }

                    //load ip lookup list
                    Dictionary<IPAddress, BlockEntry<IPAddress>> ipv4AddressMap = new Dictionary<IPAddress, BlockEntry<IPAddress>>(ipv4Addresses.Count);

                    while (ipv4Addresses.Count > 0)
                    {
                        BlockEntry<IPAddress> entry = ipv4Addresses.Dequeue();
                        ipv4AddressMap.TryAdd(entry.Key, entry);
                    }

                    Dictionary<IPAddress, BlockEntry<IPAddress>> ipv6AddressMap = new Dictionary<IPAddress, BlockEntry<IPAddress>>(ipv6Addresses.Count);

                    while (ipv6Addresses.Count > 0)
                    {
                        BlockEntry<IPAddress> entry = ipv6Addresses.Dequeue();
                        ipv6AddressMap.TryAdd(entry.Key, entry);
                    }

                    NetworkMap<BlockEntry<NetworkAddress>> ipv4NetworkMap = new NetworkMap<BlockEntry<NetworkAddress>>(ipv4Networks.Count);

                    while (ipv4Networks.Count > 0)
                    {
                        BlockEntry<NetworkAddress> entry = ipv4Networks.Dequeue();
                        ipv4NetworkMap.Add(entry.Key, entry);
                    }

                    NetworkMap<BlockEntry<NetworkAddress>> ipv6NetworkMap = new NetworkMap<BlockEntry<NetworkAddress>>(ipv6Networks.Count);

                    while (ipv6Networks.Count > 0)
                    {
                        BlockEntry<NetworkAddress> entry = ipv6Networks.Dequeue();
                        ipv6NetworkMap.Add(entry.Key, entry);
                    }

                    //update
                    _ipv4Map = ipv4AddressMap;
                    _ipv6Map = ipv6AddressMap;
                    _ipv4NetworkMap = ipv4NetworkMap;
                    _ipv6NetworkMap = ipv6NetworkMap;

                    _dnsServer.WriteLog("The app has successfully loaded IP block list file: " + _blockListFile);
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("The app failed to read IP block list file: " + _blockListFile + "\r\n" + ex.ToString());
                }
            }

            #endregion

            #region public

            public override bool IsBlocked(IPAddress address, out IPAddress responseA, out string responseTXT)
            {
                switch (address.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        {
                            if (_ipv4Map.TryGetValue(address, out BlockEntry<IPAddress> ipEntry))
                            {
                                responseA = ipEntry.ResponseA is null ? _responseA : ipEntry.ResponseA;
                                responseTXT = ipEntry.ResponseTXT is null ? _responseTXT : ipEntry.ResponseTXT;
                                return true;
                            }

                            if (_ipv4NetworkMap.TryGetValue(address, out BlockEntry<NetworkAddress> networkEntry))
                            {
                                responseA = networkEntry.ResponseA is null ? _responseA : networkEntry.ResponseA;
                                responseTXT = networkEntry.ResponseTXT is null ? _responseTXT : networkEntry.ResponseTXT;
                                return true;
                            }
                        }
                        break;

                    case AddressFamily.InterNetworkV6:
                        {
                            if (_ipv6Map.TryGetValue(address, out BlockEntry<IPAddress> ipEntry))
                            {
                                responseA = ipEntry.ResponseA is null ? _responseA : ipEntry.ResponseA;
                                responseTXT = ipEntry.ResponseTXT is null ? _responseTXT : ipEntry.ResponseTXT;
                                return true;
                            }

                            if (_ipv6NetworkMap.TryGetValue(address, out BlockEntry<NetworkAddress> networkEntry))
                            {
                                responseA = networkEntry.ResponseA is null ? _responseA : networkEntry.ResponseA;
                                responseTXT = networkEntry.ResponseTXT is null ? _responseTXT : networkEntry.ResponseTXT;
                                return true;
                            }
                        }
                        break;
                }

                responseA = null;
                responseTXT = null;
                return false;
            }

            #endregion
        }

        class DomainBlockList : BlockList
        {
            #region variables

            Dictionary<string, BlockEntry<string>> _domainMap;

            #endregion

            #region constructor

            public DomainBlockList(IDnsServer dnsServer, JsonElement jsonIpBlockList)
                : base(dnsServer, BlockListType.Domain, jsonIpBlockList)
            { }

            #endregion

            #region protected

            protected override void ReloadBlockListFile()
            {
                try
                {
                    _dnsServer.WriteLog("The app is reading domain block list file: " + _blockListFile);

                    //parse ip block list file
                    Queue<BlockEntry<string>> domains = new Queue<BlockEntry<string>>();

                    domains.Enqueue(new BlockEntry<string>("test", "127.0.0.2", "rfc5782 test entry"));

                    using (FileStream fS = new FileStream(_blockListFile, FileMode.Open, FileAccess.Read))
                    {
                        StreamReader sR = new StreamReader(fS, true);
                        char[] trimSeperator = new char[] { ' ', '\t', ':', '|', ',' };
                        string line;
                        string domain;
                        string responseA;
                        string responseTXT;

                        while (true)
                        {
                            line = sR.ReadLine();
                            if (line is null)
                                break; //eof

                            line = line.TrimStart(trimSeperator);

                            if (line.Length == 0)
                                continue; //skip empty line

                            if (line.StartsWith('#'))
                                continue; //skip comment line

                            domain = PopWord(ref line);
                            responseA = PopWord(ref line);
                            responseTXT = line;

                            if (DnsClient.IsDomainNameValid(domain))
                                domains.Enqueue(new BlockEntry<string>(domain.ToLowerInvariant(), responseA, responseTXT));
                        }

                        _blockListFileLastModified = File.GetLastWriteTimeUtc(fS.SafeFileHandle);
                    }

                    //load ip lookup list
                    Dictionary<string, BlockEntry<string>> domainMap = new Dictionary<string, BlockEntry<string>>(domains.Count);

                    while (domains.Count > 0)
                    {
                        BlockEntry<string> entry = domains.Dequeue();
                        domainMap.TryAdd(entry.Key, entry);
                    }

                    //update
                    _domainMap = domainMap;

                    _dnsServer.WriteLog("The app has successfully loaded domain block list file: " + _blockListFile);
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("The app failed to read domain block list file: " + _blockListFile + "\r\n" + ex.ToString());
                }
            }

            #endregion

            #region private

            private static string GetParentZone(string domain)
            {
                int i = domain.IndexOf('.');
                if (i > -1)
                    return domain.Substring(i + 1);

                //dont return root zone
                return null;
            }

            private bool IsDomainBlocked(string domain, out BlockEntry<string> domainEntry)
            {
                do
                {
                    if (_domainMap.TryGetValue(domain, out domainEntry))
                    {
                        return true;
                    }

                    domain = GetParentZone(domain);
                }
                while (domain is not null);

                return false;
            }

            #endregion

            #region public

            public override bool IsBlocked(string domain, out string foundDomain, out IPAddress responseA, out string responseTXT)
            {
                if (IsDomainBlocked(domain.ToLowerInvariant(), out BlockEntry<string> domainEntry))
                {
                    foundDomain = domainEntry.Key;
                    responseA = domainEntry.ResponseA is null ? _responseA : domainEntry.ResponseA;
                    responseTXT = domainEntry.ResponseTXT is null ? _responseTXT : domainEntry.ResponseTXT;
                    return true;
                }

                foundDomain = null;
                responseA = null;
                responseTXT = null;
                return false;
            }

            #endregion
        }
    }
}
