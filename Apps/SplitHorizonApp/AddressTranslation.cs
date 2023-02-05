/*
Technitium DNS Server
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace SplitHorizon
{
    public class AddressTranslation : IDnsApplication, IDnsPostProcessor, IDnsAuthoritativeRequestHandler
    {
        #region variables

        bool _enableAddressTranslation;
        IReadOnlyDictionary<NetworkAddress, string> _networkGroupMap;
        IReadOnlyDictionary<string, Group> _groups;

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
               "1.2.3.4": "10.0.0.4",
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
               "1.2.3.4": "10.0.0.4",
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

            if (request.DnssecOk)
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

                            if (group.ExternalToInternalTranslation.TryGetValue(externalIp, out IPAddress internalIp))
                                newAnswer.Add(new DnsResourceRecord(answer.Name, answer.Type, answer.Class, answer.TTL, new DnsARecordData(internalIp)));
                            else
                                newAnswer.Add(answer);
                        }
                        break;

                    case DnsResourceRecordType.AAAA:
                        {
                            IPAddress externalIp = (answer.RDATA as DnsAAAARecordData).Address;

                            if (group.ExternalToInternalTranslation.TryGetValue(externalIp, out IPAddress internalIp))
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

            if (request.DnssecOk)
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

            if (!group.InternalToExternalTranslation.TryGetValue(ptrIpAddress, out IPAddress externalIp))
                return Task.FromResult<DnsDatagram>(null);

            IReadOnlyList<DnsResourceRecord> answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, question.Class, 600, new DnsCNAMERecordData(externalIp.GetReverseDomain())) };

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answer));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Translates IP addresses in DNS response for A & AAAA type request based on the client's network address and the configured 1:1 translation. Also supports reverse (PTR) queries for translated addresses."; } }

        #endregion

        class Group
        {
            #region variables

            readonly string _name;
            readonly bool _enabled;
            readonly bool _translateReverseLookups;
            readonly IReadOnlyDictionary<IPAddress, IPAddress> _externalToInternalTranslation;
            readonly IReadOnlyDictionary<IPAddress, IPAddress> _internalToExternalTranslation;

            #endregion

            #region constructor

            public Group(JsonElement jsonGroup)
            {
                _name = jsonGroup.GetProperty("name").GetString();
                _enabled = jsonGroup.GetProperty("enabled").GetBoolean();
                _translateReverseLookups = jsonGroup.GetProperty("translateReverseLookups").GetBoolean();

                JsonElement jsonExternalToInternalTranslation = jsonGroup.GetProperty("externalToInternalTranslation");

                if (_translateReverseLookups)
                {
                    Dictionary<IPAddress, IPAddress> externalToInternalTranslation = new Dictionary<IPAddress, IPAddress>();
                    Dictionary<IPAddress, IPAddress> internalToExternalTranslation = new Dictionary<IPAddress, IPAddress>();

                    foreach (JsonProperty jsonProperty in jsonExternalToInternalTranslation.EnumerateObject())
                    {
                        string strExternalIp = jsonProperty.Name;
                        string strInternalIp = jsonProperty.Value.GetString();

                        IPAddress externalIp = IPAddress.Parse(strExternalIp);
                        IPAddress internalIp = IPAddress.Parse(strInternalIp);

                        externalToInternalTranslation.TryAdd(externalIp, internalIp);
                        internalToExternalTranslation.TryAdd(internalIp, externalIp);
                    }

                    _externalToInternalTranslation = externalToInternalTranslation;
                    _internalToExternalTranslation = internalToExternalTranslation;
                }
                else
                {
                    Dictionary<IPAddress, IPAddress> externalToInternalTranslation = new Dictionary<IPAddress, IPAddress>();

                    foreach (JsonProperty jsonProperty in jsonExternalToInternalTranslation.EnumerateObject())
                    {
                        string strExternalIp = jsonProperty.Name;
                        string strInternalIp = jsonProperty.Value.GetString();

                        IPAddress externalIp = IPAddress.Parse(strExternalIp);
                        IPAddress internalIp = IPAddress.Parse(strInternalIp);

                        externalToInternalTranslation.TryAdd(externalIp, internalIp);
                    }

                    _externalToInternalTranslation = externalToInternalTranslation;
                }
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            public bool Enabled
            { get { return _enabled; } }

            public bool TranslateReverseLookups
            { get { return _translateReverseLookups; } }

            public IReadOnlyDictionary<IPAddress, IPAddress> ExternalToInternalTranslation
            { get { return _externalToInternalTranslation; } }

            public IReadOnlyDictionary<IPAddress, IPAddress> InternalToExternalTranslation
            { get { return _internalToExternalTranslation; } }

            #endregion
        }
    }
}
