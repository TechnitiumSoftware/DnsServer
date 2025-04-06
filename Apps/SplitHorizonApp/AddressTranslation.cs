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
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace SplitHorizon
{
    public sealed class AddressTranslation : IDnsApplication, IDnsPostProcessor, IDnsAuthoritativeRequestHandler, IDnsApplicationPreference
    {
        #region variables

        byte _appPreference;

        bool _enableAddressTranslation;
        Dictionary<NetworkAddress, string> _networkGroupMap;
        Dictionary<string, Group> _groups;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            if (string.IsNullOrEmpty(config) || config.StartsWith('#'))
            {
                //replace old config with default config
                config = """
{
    "networks": {
        "custom-networks": [
            "172.16.1.0/24",
            "172.16.10.0/24",
            "172.16.2.1"
        ]
    },
    "enableAddressTranslation": false,
    "networkGroupMap": {
        "10.0.0.0/8": "local1",
        "172.16.0.0/12": "local2",
        "192.168.0.0/16": "local3"
    },
    "groups": [
        {
            "name": "local1",
            "enabled": true,
            "translateReverseLookups": true,
            "externalToInternalTranslation": {
               "1.2.3.0/24": "10.0.0.0/24",
               "5.6.7.8": "10.0.0.5"
            }
        },
        {
            "name": "local2",
            "enabled": true,
            "translateReverseLookups": true,
            "externalToInternalTranslation": {
               "1.2.3.4": "172.16.0.4",
               "5.6.7.8": "172.16.0.5"
            }
        },
        {
            "name": "local3",
            "enabled": true,
            "translateReverseLookups": true,
            "externalToInternalTranslation": {
               "1.2.3.4": "192.168.0.4",
               "5.6.7.8": "192.168.0.5"
            }
        }
    ]
}
""";

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }

            do
            {
                using JsonDocument jsonDocument = JsonDocument.Parse(config);
                JsonElement jsonConfig = jsonDocument.RootElement;

                _appPreference = Convert.ToByte(jsonConfig.GetPropertyValue("appPreference", 40));

                if (!jsonConfig.TryGetProperty("enableAddressTranslation", out _))
                {
                    //update old config with default config
                    config = config.TrimEnd(' ', '\t', '\r', '\n');
                    config = config.Substring(0, config.Length - 1);
                    config = config.TrimEnd(' ', '\t', '\r', '\n');
                    config += """
,
    "enableAddressTranslation": false,
    "networkGroupMap": {
        "10.0.0.0/8": "local1",
        "172.16.0.0/12": "local2",
        "192.168.0.0/16": "local3"
    },
    "groups": [
        {
            "name": "local1",
            "enabled": true,
            "translateReverseLookups": true,
            "externalToInternalTranslation": {
               "1.2.3.0/24": "10.0.0.0/24",
               "5.6.7.8": "10.0.0.5"
            }
        },
        {
            "name": "local2",
            "enabled": true,
            "translateReverseLookups": true,
            "externalToInternalTranslation": {
               "1.2.3.4": "172.16.0.4",
               "5.6.7.8": "172.16.0.5"
            }
        },
        {
            "name": "local3",
            "enabled": true,
            "translateReverseLookups": true,
            "externalToInternalTranslation": {
               "1.2.3.4": "192.168.0.4",
               "5.6.7.8": "192.168.0.5"
            }
        }
    ]
}
""";
                    await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);

                    //reparse config
                    continue;
                }

                _enableAddressTranslation = jsonConfig.GetProperty("enableAddressTranslation").GetBoolean();

                _networkGroupMap = jsonConfig.ReadObjectAsMap("networkGroupMap", delegate (string strNetworkAddress, JsonElement jsonGroupName)
                {
                    if (!NetworkAddress.TryParse(strNetworkAddress, out NetworkAddress networkAddress))
                        throw new InvalidOperationException("Network group map contains an invalid network address: " + strNetworkAddress);

                    return new Tuple<NetworkAddress, string>(networkAddress, jsonGroupName.GetString());
                });

                _groups = jsonConfig.ReadArrayAsMap("groups", delegate (JsonElement jsonGroup)
                {
                    Group group = new Group(jsonGroup);
                    return new Tuple<string, Group>(group.Name, group);
                });

                break;
            }
            while (true);
        }

        public Task<DnsDatagram> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (!_enableAddressTranslation)
                return Task.FromResult(response);

            if (response.RCODE != DnsResponseCode.NoError)
                return Task.FromResult(response);

            DnsQuestionRecord question = request.Question[0];

            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    break;

                default:
                    return Task.FromResult(response);
            }

            if (response.Answer.Count == 0)
                return Task.FromResult(response);

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

            if ((groupName is null) || !_groups.TryGetValue(groupName, out Group group) || !group.Enabled)
                return Task.FromResult(response);

            List<DnsResourceRecord> newAnswer = new List<DnsResourceRecord>(response.Answer.Count);

            foreach (DnsResourceRecord answer in response.Answer)
            {
                switch (answer.Type)
                {
                    case DnsResourceRecordType.A:
                        {
                            IPAddress externalIp = (answer.RDATA as DnsARecordData).Address;

                            if (group.TryExternalToInternalTranslation(externalIp, out IPAddress internalIp))
                                newAnswer.Add(new DnsResourceRecord(answer.Name, answer.Type, answer.Class, answer.TTL, new DnsARecordData(internalIp)));
                            else
                                newAnswer.Add(answer);
                        }
                        break;

                    case DnsResourceRecordType.AAAA:
                        {
                            IPAddress externalIp = (answer.RDATA as DnsAAAARecordData).Address;

                            if (group.TryExternalToInternalTranslation(externalIp, out IPAddress internalIp))
                                newAnswer.Add(new DnsResourceRecord(answer.Name, answer.Type, answer.Class, answer.TTL, new DnsAAAARecordData(internalIp)));
                            else
                                newAnswer.Add(answer);
                        }
                        break;

                    default:
                        newAnswer.Add(answer);
                        break;
                }
            }

            return Task.FromResult(response.Clone(newAnswer));
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (!_enableAddressTranslation)
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];
            if (question.Type != DnsResourceRecordType.PTR)
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

            if ((groupName is null) || !_groups.TryGetValue(groupName, out Group group) || !group.Enabled || !group.TranslateReverseLookups)
                return Task.FromResult<DnsDatagram>(null);

            IPAddress ptrIpAddress = IPAddressExtensions.ParseReverseDomain(question.Name);

            if (!group.TryInternalToExternalTranslation(ptrIpAddress, out IPAddress externalIp))
                return Task.FromResult<DnsDatagram>(null);

            IReadOnlyList<DnsResourceRecord> answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, question.Class, 600, new DnsCNAMERecordData(externalIp.GetReverseDomain())) };

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answer));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Translates IP addresses in DNS response for A & AAAA type request based on the client's network address and the configured 1:1 translation. Also supports reverse (PTR) queries for translated addresses."; } }

        public byte Preference
        { get { return _appPreference; } }

        #endregion

        class Group
        {
            #region variables

            readonly string _name;
            readonly bool _enabled;
            readonly bool _translateReverseLookups;
            readonly Dictionary<IPAddress, IPAddress> _externalToInternalTranslation;
            readonly Dictionary<IPAddress, IPAddress> _internalToExternalTranslation;
            readonly List<KeyValuePair<NetworkAddress, NetworkAddress>> _externalToInternalNetworkTranslation;

            #endregion

            #region constructor

            public Group(JsonElement jsonGroup)
            {
                _name = jsonGroup.GetProperty("name").GetString();
                _enabled = jsonGroup.GetProperty("enabled").GetBoolean();
                _translateReverseLookups = jsonGroup.GetProperty("translateReverseLookups").GetBoolean();

                JsonElement jsonExternalToInternalTranslation = jsonGroup.GetProperty("externalToInternalTranslation");

                Dictionary<IPAddress, IPAddress> externalToInternalIpTranslation = new Dictionary<IPAddress, IPAddress>();
                Dictionary<IPAddress, IPAddress> internalToExternalIpTranslation = new Dictionary<IPAddress, IPAddress>();
                List<KeyValuePair<NetworkAddress, NetworkAddress>> externalToInternalNetworkTranslation = new List<KeyValuePair<NetworkAddress, NetworkAddress>>();

                foreach (JsonProperty jsonProperty in jsonExternalToInternalTranslation.EnumerateObject())
                {
                    string strExternal = jsonProperty.Name;
                    string strInternal = jsonProperty.Value.GetString();

                    NetworkAddress external = NetworkAddress.Parse(strExternal);
                    NetworkAddress @internal = NetworkAddress.Parse(strInternal);

                    if (external.AddressFamily != @internal.AddressFamily)
                        throw new InvalidDataException("External to internal translation entries must have same address family: " + strExternal + " - " + strInternal);

                    if (external.PrefixLength != @internal.PrefixLength)
                        throw new InvalidDataException("External to internal translation entries must have same prefix length: " + strExternal + " - " + strInternal);

                    if (
                        ((external.AddressFamily == AddressFamily.InterNetwork) && (external.PrefixLength == 32)) ||
                        ((external.AddressFamily == AddressFamily.InterNetworkV6) && (external.PrefixLength == 128))
                       )
                    {
                        externalToInternalIpTranslation.TryAdd(external.Address, @internal.Address);

                        if (_translateReverseLookups)
                            internalToExternalIpTranslation.TryAdd(@internal.Address, external.Address);
                    }
                    else
                    {
                        externalToInternalNetworkTranslation.Add(new KeyValuePair<NetworkAddress, NetworkAddress>(external, @internal));
                    }
                }

                _externalToInternalTranslation = externalToInternalIpTranslation;

                if (_translateReverseLookups)
                    _internalToExternalTranslation = internalToExternalIpTranslation;

                _externalToInternalNetworkTranslation = externalToInternalNetworkTranslation;
            }

            #endregion

            #region public

            public bool TryExternalToInternalTranslation(IPAddress externalIp, out IPAddress internalIp)
            {
                if (_externalToInternalTranslation.TryGetValue(externalIp, out internalIp))
                    return true;

                foreach (KeyValuePair<NetworkAddress, NetworkAddress> networkEntry in _externalToInternalNetworkTranslation)
                {
                    NetworkAddress external = networkEntry.Key;

                    if (external.AddressFamily != externalIp.AddressFamily)
                        continue;

                    if (external.Contains(externalIp))
                    {
                        NetworkAddress @internal = networkEntry.Value;

                        switch (external.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                {
                                    uint hostMask = ~(0xFFFFFFFFu << (32 - external.PrefixLength));
                                    uint host = externalIp.ConvertIpToNumber() & hostMask;
                                    uint addr = @internal.Address.ConvertIpToNumber();
                                    uint internalAddr = addr | host;

                                    internalIp = IPAddressExtensions.ConvertNumberToIp(internalAddr);
                                    return true;
                                }

                            case AddressFamily.InterNetworkV6:
                                {
                                    byte[] externalIpBytes = externalIp.GetAddressBytes();
                                    byte[] internalIpBytes = @internal.Address.GetAddressBytes();
                                    int copyBytes = external.PrefixLength / 8;
                                    int balanceBits = external.PrefixLength - (copyBytes * 8);

                                    Buffer.BlockCopy(externalIpBytes, copyBytes + 1, internalIpBytes, copyBytes + 1, 16 - copyBytes - 1);

                                    if (balanceBits > 0)
                                    {
                                        int mask = 0xFF << (8 - balanceBits);
                                        internalIpBytes[copyBytes] = (byte)((internalIpBytes[copyBytes] & mask) | (externalIpBytes[copyBytes] & ~mask));
                                    }

                                    internalIp = new IPAddress(internalIpBytes);
                                    return true;
                                }

                            default:
                                throw new InvalidOperationException();
                        }
                    }
                }

                internalIp = null;
                return false;
            }

            public bool TryInternalToExternalTranslation(IPAddress internalIp, out IPAddress externalIp)
            {
                if (_internalToExternalTranslation.TryGetValue(internalIp, out externalIp))
                    return true;

                foreach (KeyValuePair<NetworkAddress, NetworkAddress> networkEntry in _externalToInternalNetworkTranslation)
                {
                    NetworkAddress @internal = networkEntry.Value;

                    if (@internal.AddressFamily != internalIp.AddressFamily)
                        continue;

                    if (@internal.Contains(internalIp))
                    {
                        NetworkAddress external = networkEntry.Key;

                        switch (@internal.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                {
                                    uint hostMask = ~(0xFFFFFFFFu << (32 - @internal.PrefixLength));
                                    uint host = internalIp.ConvertIpToNumber() & hostMask;
                                    uint addr = external.Address.ConvertIpToNumber();
                                    uint externalAddr = addr | host;

                                    externalIp = IPAddressExtensions.ConvertNumberToIp(externalAddr);
                                    return true;
                                }

                            case AddressFamily.InterNetworkV6:
                                {
                                    byte[] internalIpBytes = internalIp.GetAddressBytes();
                                    byte[] externalIpBytes = external.Address.GetAddressBytes();
                                    int copyBytes = @internal.PrefixLength / 8;
                                    int balanceBits = @internal.PrefixLength - (copyBytes * 8);

                                    Buffer.BlockCopy(internalIpBytes, copyBytes + 1, externalIpBytes, copyBytes + 1, 16 - copyBytes - 1);

                                    if (balanceBits > 0)
                                    {
                                        int mask = 0xFF << (8 - balanceBits);
                                        externalIpBytes[copyBytes] = (byte)((externalIpBytes[copyBytes] & mask) | (internalIpBytes[copyBytes] & ~mask));
                                    }

                                    externalIp = new IPAddress(externalIpBytes);
                                    return true;
                                }

                            default:
                                throw new InvalidOperationException();
                        }
                    }
                }

                externalIp = null;
                return false;
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            public bool Enabled
            { get { return _enabled; } }

            public bool TranslateReverseLookups
            { get { return _translateReverseLookups; } }

            #endregion
        }
    }
}
