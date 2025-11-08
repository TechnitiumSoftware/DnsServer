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

using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace AdvancedForwarding
{
    public sealed class App : IDnsApplication, IDnsAuthoritativeRequestHandler, IDnsApplicationPreference
    {
        #region variables

        IDnsServer _dnsServer;

        byte _appPreference;

        bool _enableForwarding;
        Dictionary<string, ConfigProxyServer> _configProxyServers;
        Dictionary<string, ConfigForwarder> _configForwarders;
        Dictionary<NetworkAddress, string> _networkGroupMap;
        Dictionary<string, Group> _groups;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_groups is not null)
            {
                foreach (KeyValuePair<string, Group> group in _groups)
                    group.Value.Dispose();
            }
        }

        #endregion

        #region private

        private static List<DnsForwarderRecordData> GetUpdatedForwarderRecords(IReadOnlyList<DnsForwarderRecordData> forwarderRecords, bool dnssecValidation, ConfigProxyServer configProxyServer)
        {
            List<DnsForwarderRecordData> newForwarderRecords = new List<DnsForwarderRecordData>(forwarderRecords.Count);

            foreach (DnsForwarderRecordData forwarderRecord in forwarderRecords)
                newForwarderRecords.Add(GetForwarderRecord(forwarderRecord.Protocol, forwarderRecord.Forwarder, dnssecValidation, configProxyServer));

            return newForwarderRecords;
        }

        private static DnsForwarderRecordData GetForwarderRecord(NameServerAddress forwarder, bool dnssecValidation, ConfigProxyServer configProxyServer)
        {
            return GetForwarderRecord(forwarder.Protocol, forwarder.ToString(), dnssecValidation, configProxyServer);
        }

        private static DnsForwarderRecordData GetForwarderRecord(DnsTransportProtocol protocol, string forwarder, bool dnssecValidation, ConfigProxyServer configProxyServer)
        {
            DnsForwarderRecordData forwarderRecord;

            if (configProxyServer is null)
                forwarderRecord = new DnsForwarderRecordData(protocol, forwarder, dnssecValidation, DnsForwarderRecordProxyType.DefaultProxy, null, 0, null, null, 0);
            else
                forwarderRecord = new DnsForwarderRecordData(protocol, forwarder, dnssecValidation, configProxyServer.Type, configProxyServer.ProxyAddress, configProxyServer.ProxyPort, configProxyServer.ProxyUsername, configProxyServer.ProxyPassword, 0);

            return forwarderRecord;
        }

        private Tuple<string, Group> ReadGroup(JsonElement jsonGroup)
        {
            string name = jsonGroup.GetProperty("name").GetString();

            if ((_groups is not null) && _groups.TryGetValue(name, out Group group))
                group.ReloadConfig(_configProxyServers, _configForwarders, jsonGroup);
            else
                group = new Group(_dnsServer, _configProxyServers, _configForwarders, jsonGroup);

            return new Tuple<string, Group>(group.Name, group);
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _appPreference = Convert.ToByte(jsonConfig.GetPropertyValue("appPreference", 200));

            _enableForwarding = jsonConfig.GetPropertyValue("enableForwarding", true);

            if (jsonConfig.TryReadArrayAsMap("proxyServers", delegate (JsonElement jsonProxy)
            {
                ConfigProxyServer proxyServer = new ConfigProxyServer(jsonProxy);
                return new Tuple<string, ConfigProxyServer>(proxyServer.Name, proxyServer);
            }, out Dictionary<string, ConfigProxyServer> configProxyServers))
                _configProxyServers = configProxyServers;
            else
                _configProxyServers = null;

            if (jsonConfig.TryReadArrayAsMap("forwarders", delegate (JsonElement jsonForwarder)
            {
                ConfigForwarder forwarder = new ConfigForwarder(jsonForwarder, _configProxyServers);
                return new Tuple<string, ConfigForwarder>(forwarder.Name, forwarder);
            }, out Dictionary<string, ConfigForwarder> configForwarders))
                _configForwarders = configForwarders;
            else
                _configForwarders = null;

            _networkGroupMap = jsonConfig.ReadObjectAsMap("networkGroupMap", delegate (string network, JsonElement jsonGroup)
            {
                if (!NetworkAddress.TryParse(network, out NetworkAddress networkAddress))
                    throw new FormatException("Network group map contains an invalid network address: " + network);

                return new Tuple<NetworkAddress, string>(networkAddress, jsonGroup.GetString());
            });

            if (jsonConfig.TryReadArrayAsMap("groups", ReadGroup, out Dictionary<string, Group> groups))
            {
                if (_groups is not null)
                {
                    foreach (KeyValuePair<string, Group> group in _groups)
                    {
                        if (!groups.ContainsKey(group.Key))
                            group.Value.Dispose();
                    }
                }

                _groups = groups;
            }
            else
            {
                throw new FormatException("Groups array was not defined.");
            }

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (!_enableForwarding || !request.RecursionDesired)
                return Task.FromResult<DnsDatagram>(null);

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

            if ((groupName is null) || !_groups.TryGetValue(groupName, out Group group) || !group.EnableForwarding)
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];
            string qname = question.Name;

            if (!group.TryGetForwarderRecords(qname, out IReadOnlyList<DnsForwarderRecordData> forwarderRecords))
                return Task.FromResult<DnsDatagram>(null);

            request.SetShadowEDnsClientSubnetOption(network, true);

            DnsResourceRecord[] authority = new DnsResourceRecord[forwarderRecords.Count];

            for (int i = 0; i < forwarderRecords.Count; i++)
                authority[i] = new DnsResourceRecord(qname, DnsResourceRecordType.FWD, DnsClass.IN, 0, forwarderRecords[i]);

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, authority));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Performs bulk conditional forwarding for configured domain names and AdGuard Upstream config files."; } }

        public byte Preference
        { get { return _appPreference; } }

        #endregion

        class Group : IDisposable
        {
            #region variables

            readonly IDnsServer _dnsServer;
            Dictionary<string, ConfigProxyServer> _configProxyServers;
            Dictionary<string, ConfigForwarder> _configForwarders;

            readonly string _name;
            bool _enableForwarding;
            Forwarding[] _forwardings;
            Dictionary<string, AdGuardUpstream> _adguardUpstreams;

            #endregion

            #region constructor

            public Group(IDnsServer dnsServer, Dictionary<string, ConfigProxyServer> configProxyServers, Dictionary<string, ConfigForwarder> configForwarders, JsonElement jsonGroup)
            {
                _dnsServer = dnsServer;

                _name = jsonGroup.GetProperty("name").GetString();

                ReloadConfig(configProxyServers, configForwarders, jsonGroup);
            }

            #endregion

            #region IDisposable

            public void Dispose()
            {
                if (_adguardUpstreams is not null)
                {
                    foreach (KeyValuePair<string, AdGuardUpstream> adguardUpstream in _adguardUpstreams)
                        adguardUpstream.Value.Dispose();

                    _adguardUpstreams = null;
                }
            }

            #endregion

            #region private

            private Tuple<string, AdGuardUpstream> ReadAdGuardUpstream(JsonElement jsonAdguardUpstream)
            {
                string name = jsonAdguardUpstream.GetProperty("configFile").GetString();

                if ((_adguardUpstreams is not null) && _adguardUpstreams.TryGetValue(name, out AdGuardUpstream adGuardUpstream))
                    adGuardUpstream.ReloadConfig(_configProxyServers, jsonAdguardUpstream);
                else
                    adGuardUpstream = new AdGuardUpstream(_dnsServer, _configProxyServers, jsonAdguardUpstream);

                return new Tuple<string, AdGuardUpstream>(adGuardUpstream.Name, adGuardUpstream);
            }

            #endregion

            #region public

            public void ReloadConfig(Dictionary<string, ConfigProxyServer> configProxyServers, Dictionary<string, ConfigForwarder> configForwarders, JsonElement jsonGroup)
            {
                _configProxyServers = configProxyServers;
                _configForwarders = configForwarders;

                _enableForwarding = jsonGroup.GetPropertyValue("enableForwarding", true);

                if (jsonGroup.TryReadArray("forwardings", delegate (JsonElement jsonForwarding) { return new Forwarding(jsonForwarding, _configForwarders); }, out Forwarding[] forwardings))
                    _forwardings = forwardings;
                else
                    _forwardings = null;

                if (jsonGroup.TryReadArrayAsMap("adguardUpstreams", ReadAdGuardUpstream, out Dictionary<string, AdGuardUpstream> adguardUpstreams))
                {
                    if (_adguardUpstreams is not null)
                    {
                        foreach (KeyValuePair<string, AdGuardUpstream> adguardUpstream in _adguardUpstreams)
                        {
                            if (!adguardUpstreams.ContainsKey(adguardUpstream.Key))
                                adguardUpstream.Value.Dispose();
                        }
                    }

                    _adguardUpstreams = adguardUpstreams;
                }
                else
                {
                    if (_adguardUpstreams is not null)
                    {
                        foreach (KeyValuePair<string, AdGuardUpstream> adguardUpstream in _adguardUpstreams)
                            adguardUpstream.Value.Dispose();
                    }

                    _adguardUpstreams = null;
                }
            }

            public bool TryGetForwarderRecords(string domain, out IReadOnlyList<DnsForwarderRecordData> forwarderRecords)
            {
                domain = domain.ToLowerInvariant();

                if ((_forwardings is not null) && (_forwardings.Length > 0) && Forwarding.TryGetForwarderRecords(domain, _forwardings, out forwarderRecords))
                    return true;

                if (_adguardUpstreams is not null)
                {
                    foreach (KeyValuePair<string, AdGuardUpstream> adguardUpstream in _adguardUpstreams)
                    {
                        if (adguardUpstream.Value.TryGetForwarderRecords(domain, out forwarderRecords))
                            return true;
                    }
                }

                forwarderRecords = null;
                return false;
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            public bool EnableForwarding
            { get { return _enableForwarding; } }

            #endregion
        }

        class Forwarding
        {
            #region variables

            IReadOnlyList<DnsForwarderRecordData> _forwarderRecords;
            readonly Dictionary<string, object> _domainMap;

            #endregion

            #region constructor

            public Forwarding(JsonElement jsonForwarding, Dictionary<string, ConfigForwarder> configForwarders)
            {
                JsonElement jsonForwarders = jsonForwarding.GetProperty("forwarders");
                List<DnsForwarderRecordData> forwarderRecords = new List<DnsForwarderRecordData>();

                foreach (JsonElement jsonForwarder in jsonForwarders.EnumerateArray())
                {
                    string forwarderName = jsonForwarder.GetString();

                    if ((configForwarders is null) || !configForwarders.TryGetValue(forwarderName, out ConfigForwarder configForwarder))
                        throw new FormatException("Forwarder was not defined: " + forwarderName);

                    forwarderRecords.AddRange(configForwarder.ForwarderRecords);
                }

                _forwarderRecords = forwarderRecords;

                _domainMap = jsonForwarding.ReadArrayAsMap("domains", delegate (JsonElement jsonDomain)
                {
                    return new Tuple<string, object>(jsonDomain.GetString().ToLowerInvariant(), null);
                });
            }

            public Forwarding(IReadOnlyList<string> domains, NameServerAddress forwarder, bool dnssecValidation, ConfigProxyServer proxy)
                : this(new DnsForwarderRecordData[] { GetForwarderRecord(forwarder, dnssecValidation, proxy) }, domains)
            { }

            public Forwarding(IReadOnlyList<DnsForwarderRecordData> forwarderRecords, IReadOnlyList<string> domains)
            {
                _forwarderRecords = forwarderRecords;

                Dictionary<string, object> domainMap = new Dictionary<string, object>(domains.Count);

                foreach (string domain in domains)
                {
                    if (DnsClient.IsDomainNameValid(domain))
                        domainMap.TryAdd(domain.ToLowerInvariant(), null);
                }

                _domainMap = domainMap;
            }

            #endregion

            #region static

            public static bool TryGetForwarderRecords(string domain, IReadOnlyList<Forwarding> forwardings, out IReadOnlyList<DnsForwarderRecordData> forwarderRecords)
            {
                if (forwardings.Count == 1)
                {
                    if (forwardings[0].TryGetForwarderRecords(domain, out forwarderRecords, out _))
                        return true;
                }
                else
                {
                    Dictionary<string, List<DnsForwarderRecordData>> fwdMap = new Dictionary<string, List<DnsForwarderRecordData>>(forwardings.Count);

                    foreach (Forwarding forwarding in forwardings)
                    {
                        if (forwarding.TryGetForwarderRecords(domain, out IReadOnlyList<DnsForwarderRecordData> fwdRecords, out string matchedDomain))
                        {
                            if (fwdMap.TryGetValue(matchedDomain, out List<DnsForwarderRecordData> fwdRecordsList))
                            {
                                fwdRecordsList.AddRange(fwdRecords);
                            }
                            else
                            {
                                fwdRecordsList = new List<DnsForwarderRecordData>(fwdRecords);
                                fwdMap.Add(matchedDomain, fwdRecordsList);
                            }
                        }
                    }

                    if (fwdMap.Count > 0)
                    {
                        forwarderRecords = null;
                        string lastMatchedDomain = null;

                        foreach (KeyValuePair<string, List<DnsForwarderRecordData>> fwdEntry in fwdMap)
                        {
                            if ((lastMatchedDomain is null) || (fwdEntry.Key.Length > lastMatchedDomain.Length) || ((fwdEntry.Key.Length == lastMatchedDomain.Length) && lastMatchedDomain.StartsWith("*.")))
                            {
                                lastMatchedDomain = fwdEntry.Key;
                                forwarderRecords = fwdEntry.Value;
                            }
                        }

                        return true;
                    }
                }

                forwarderRecords = null;
                return false;
            }

            public static bool IsForwarderDomain(string domain, IReadOnlyList<Forwarding> forwardings)
            {
                foreach (Forwarding forwarding in forwardings)
                {
                    if (IsForwarderDomain(domain, forwarding._forwarderRecords))
                        return true;
                }

                return false;
            }

            public static bool IsForwarderDomain(string domain, IReadOnlyList<DnsForwarderRecordData> forwarderRecords)
            {
                foreach (DnsForwarderRecordData forwarderRecord in forwarderRecords)
                {
                    if (domain.Equals(forwarderRecord.NameServer.Host, StringComparison.OrdinalIgnoreCase))
                        return true;
                }

                return false;
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

            private bool IsDomainMatching(string domain, out string matchedDomain)
            {
                string parent;

                do
                {
                    if (_domainMap.TryGetValue(domain, out _))
                    {
                        matchedDomain = domain;
                        return true;
                    }

                    parent = GetParentZone(domain);
                    if (parent is null)
                    {
                        if (_domainMap.TryGetValue("*", out _))
                        {
                            matchedDomain = "*";
                            return true;
                        }

                        break;
                    }

                    domain = "*." + parent;

                    if (_domainMap.TryGetValue(domain, out _))
                    {
                        matchedDomain = domain;
                        return true;
                    }

                    domain = parent;
                }
                while (true);

                matchedDomain = null;
                return false;
            }

            private bool TryGetForwarderRecords(string domain, out IReadOnlyList<DnsForwarderRecordData> forwarderRecords, out string matchedDomain)
            {
                if (IsDomainMatching(domain, out matchedDomain))
                {
                    forwarderRecords = _forwarderRecords;
                    return true;
                }

                forwarderRecords = null;
                return false;
            }

            #endregion

            #region public

            public void UpdateForwarderRecords(bool dnssecValidation, ConfigProxyServer proxy)
            {
                _forwarderRecords = GetUpdatedForwarderRecords(_forwarderRecords, dnssecValidation, proxy);
            }

            #endregion
        }

        class AdGuardUpstream : IDisposable
        {
            #region variables

            static readonly char[] _popWordSeperator = new char[] { ' ' };

            readonly IDnsServer _dnsServer;

            readonly string _name;
            ConfigProxyServer _configProxyServer;
            bool _dnssecValidation;

            List<DnsForwarderRecordData> _defaultForwarderRecords;
            List<Forwarding> _forwardings;

            readonly string _configFile;
            DateTime _configFileLastModified;

            Timer _autoReloadTimer;
            const int AUTO_RELOAD_TIMER_INTERVAL = 60000;

            #endregion

            #region constructor

            public AdGuardUpstream(IDnsServer dnsServer, Dictionary<string, ConfigProxyServer> configProxyServers, JsonElement jsonAdguardUpstream)
            {
                _dnsServer = dnsServer;

                _name = jsonAdguardUpstream.GetProperty("configFile").GetString();

                _configFile = _name;

                if (!Path.IsPathRooted(_configFile))
                    _configFile = Path.Combine(_dnsServer.ApplicationFolder, _configFile);

                _autoReloadTimer = new Timer(delegate (object state)
                {
                    try
                    {
                        DateTime configFileLastModified = File.GetLastWriteTimeUtc(_configFile);
                        if (configFileLastModified > _configFileLastModified)
                        {
                            ReloadUpstreamsFile();

                            //force GC collection to remove old cache data from memory quickly
                            GC.Collect();
                        }
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

                ReloadConfig(configProxyServers, jsonAdguardUpstream);
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

            #region private

            private void ReloadUpstreamsFile()
            {
                try
                {
                    _dnsServer.WriteLog("The app is reading AdGuard Upstreams config file: " + _configFile);

                    List<DnsForwarderRecordData> defaultForwarderRecords = new List<DnsForwarderRecordData>();
                    List<Forwarding> forwardings = new List<Forwarding>();

                    using (FileStream fS = new FileStream(_configFile, FileMode.Open, FileAccess.Read))
                    {
                        StreamReader sR = new StreamReader(fS, true);
                        string line;

                        while (true)
                        {
                            line = sR.ReadLine();
                            if (line is null)
                                break; //eof

                            line = line.TrimStart();

                            if (line.Length == 0)
                                continue; //skip empty line

                            if (line.StartsWith('#'))
                                continue; //skip comment line

                            if (line.StartsWith('['))
                            {
                                int i = line.LastIndexOf(']');
                                if (i < 0)
                                    throw new FormatException("Invalid AdGuard Upstreams config file format: missing ']' bracket.");

                                string[] domains = line.Substring(1, i - 1).Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                                string forwarder = line.Substring(i + 1);

                                if (forwarder == "#")
                                {
                                    if (defaultForwarderRecords.Count == 0)
                                        throw new FormatException("Invalid AdGuard Upstreams config file format: missing default upstream servers.");

                                    forwardings.Add(new Forwarding(defaultForwarderRecords, domains));
                                }
                                else
                                {
                                    List<DnsForwarderRecordData> forwarderRecords = new List<DnsForwarderRecordData>();
                                    string word = PopWord(ref forwarder);

                                    while (word.Length > 0)
                                    {
                                        string nextWord = PopWord(ref forwarder);

                                        if (nextWord.StartsWith('('))
                                        {
                                            word += " " + nextWord;
                                            nextWord = PopWord(ref forwarder);
                                        }

                                        forwarderRecords.Add(GetForwarderRecord(NameServerAddress.Parse(word), _dnssecValidation, _configProxyServer));

                                        word = nextWord;
                                    }

                                    if (forwarderRecords.Count == 0)
                                        throw new FormatException("Invalid AdGuard Upstreams config file format: missing upstream servers.");

                                    forwardings.Add(new Forwarding(forwarderRecords, domains));
                                }
                            }
                            else
                            {
                                defaultForwarderRecords.Add(GetForwarderRecord(NameServerAddress.Parse(line), _dnssecValidation, _configProxyServer));
                            }
                        }

                        _configFileLastModified = File.GetLastWriteTimeUtc(fS.SafeFileHandle);
                    }

                    _defaultForwarderRecords = defaultForwarderRecords;
                    _forwardings = forwardings;

                    _dnsServer.WriteLog("The app has successfully loaded AdGuard Upstreams config file: " + _configFile);
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("The app failed to read AdGuard Upstreams config file: " + _configFile + "\r\n" + ex.ToString());
                }
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

            #endregion

            #region public

            public void ReloadConfig(Dictionary<string, ConfigProxyServer> configProxyServers, JsonElement jsonAdguardUpstream)
            {
                string proxyName = jsonAdguardUpstream.GetPropertyValue("proxy", null);
                _dnssecValidation = jsonAdguardUpstream.GetPropertyValue("dnssecValidation", true);

                ConfigProxyServer configProxyServer = null;

                if (!string.IsNullOrEmpty(proxyName) && ((configProxyServers is null) || !configProxyServers.TryGetValue(proxyName, out configProxyServer)))
                    throw new FormatException("Proxy server was not defined: " + proxyName);

                _configProxyServer = configProxyServer;

                DateTime configFileLastModified = File.GetLastWriteTimeUtc(_configFile);
                if (configFileLastModified > _configFileLastModified)
                {
                    //reload complete config file
                    _autoReloadTimer.Change(0, Timeout.Infinite);
                }
                else
                {
                    //update only forwarder records
                    _defaultForwarderRecords = GetUpdatedForwarderRecords(_defaultForwarderRecords, _dnssecValidation, _configProxyServer);

                    foreach (Forwarding forwarding in _forwardings)
                        forwarding.UpdateForwarderRecords(_dnssecValidation, _configProxyServer);
                }
            }

            public bool TryGetForwarderRecords(string domain, out IReadOnlyList<DnsForwarderRecordData> forwarderRecords)
            {
                if ((_forwardings is not null) && (_forwardings.Count > 0))
                {
                    if (Forwarding.IsForwarderDomain(domain, _forwardings))
                    {
                        forwarderRecords = null;
                        return false;
                    }

                    if (Forwarding.TryGetForwarderRecords(domain, _forwardings, out forwarderRecords))
                        return true;
                }

                if ((_defaultForwarderRecords is not null) && (_defaultForwarderRecords.Count > 0))
                {
                    if (Forwarding.IsForwarderDomain(domain, _defaultForwarderRecords))
                    {
                        forwarderRecords = null;
                        return false;
                    }

                    forwarderRecords = _defaultForwarderRecords;
                    return true;
                }

                forwarderRecords = null;
                return false;
            }

            #endregion

            #region property

            public string Name
            { get { return _name; } }

            #endregion
        }

        class ConfigProxyServer
        {
            #region variables

            readonly string _name;
            readonly DnsForwarderRecordProxyType _type;
            readonly string _proxyAddress;
            readonly ushort _proxyPort;
            readonly string _proxyUsername;
            readonly string _proxyPassword;

            #endregion

            #region constructor

            public ConfigProxyServer(JsonElement jsonProxy)
            {
                _name = jsonProxy.GetProperty("name").GetString();
                _type = jsonProxy.GetPropertyEnumValue("type", DnsForwarderRecordProxyType.Http);
                _proxyAddress = jsonProxy.GetProperty("proxyAddress").GetString();
                _proxyPort = jsonProxy.GetProperty("proxyPort").GetUInt16();
                _proxyUsername = jsonProxy.GetPropertyValue("proxyUsername", null);
                _proxyPassword = jsonProxy.GetPropertyValue("proxyPassword", null);
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            public DnsForwarderRecordProxyType Type
            { get { return _type; } }

            public string ProxyAddress
            { get { return _proxyAddress; } }

            public ushort ProxyPort
            { get { return _proxyPort; } }

            public string ProxyUsername
            { get { return _proxyUsername; } }

            public string ProxyPassword
            { get { return _proxyPassword; } }

            #endregion
        }

        class ConfigForwarder
        {
            #region variables

            readonly string _name;
            readonly DnsForwarderRecordData[] _forwarderRecords;

            #endregion

            #region constructor

            public ConfigForwarder(JsonElement jsonForwarder, Dictionary<string, ConfigProxyServer> configProxyServers)
            {
                _name = jsonForwarder.GetProperty("name").GetString();

                string proxyName = jsonForwarder.GetPropertyValue("proxy", null);
                bool dnssecValidation = jsonForwarder.GetPropertyValue("dnssecValidation", true);
                DnsTransportProtocol forwarderProtocol = jsonForwarder.GetPropertyEnumValue("forwarderProtocol", DnsTransportProtocol.Udp);

                ConfigProxyServer configProxyServer = null;

                if (!string.IsNullOrEmpty(proxyName) && ((configProxyServers is null) || !configProxyServers.TryGetValue(proxyName, out configProxyServer)))
                    throw new FormatException("Proxy server was not defined: " + proxyName);

                _forwarderRecords = jsonForwarder.ReadArray("forwarderAddresses", delegate (string address)
                {
                    return GetForwarderRecord(forwarderProtocol, address, dnssecValidation, configProxyServer);
                });
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            public DnsForwarderRecordData[] ForwarderRecords
            { get { return _forwarderRecords; } }

            #endregion
        }
    }
}
