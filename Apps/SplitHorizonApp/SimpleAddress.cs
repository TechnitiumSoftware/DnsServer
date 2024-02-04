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
    public sealed class SimpleAddress : IDnsApplication, IDnsAppRecordRequestHandler
    {
        #region variables

        static Dictionary<string, List<NetworkAddress>> _networks;

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

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            if (jsonConfig.TryGetProperty("networks", out JsonElement jsonNetworks))
            {
                Dictionary<string, List<NetworkAddress>> networks = new Dictionary<string, List<NetworkAddress>>();

                foreach (JsonProperty jsonProperty in jsonNetworks.EnumerateObject())
                {
                    string networkName = jsonProperty.Name;

                    JsonElement jsonNetworkAddresses = jsonProperty.Value;
                    if (jsonNetworkAddresses.ValueKind == JsonValueKind.Array)
                    {
                        List<NetworkAddress> networkAddresses = new List<NetworkAddress>(jsonNetworkAddresses.GetArrayLength());

                        foreach (JsonElement jsonNetworkAddress in jsonNetworkAddresses.EnumerateArray())
                            networkAddresses.Add(NetworkAddress.Parse(jsonNetworkAddress.GetString()));

                        networks.TryAdd(networkName, networkAddresses);
                    }
                }

                _networks = networks;
            }
            else
            {
                _networks = new Dictionary<string, List<NetworkAddress>>(1);
            }
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];

            if (!question.Name.Equals(appRecordName, StringComparison.OrdinalIgnoreCase) && !appRecordName.StartsWith('*'))
                return Task.FromResult<DnsDatagram>(null);

            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    using (JsonDocument jsonDocument = JsonDocument.Parse(appRecordData))
                    {
                        JsonElement jsonAppRecordData = jsonDocument.RootElement;
                        JsonElement jsonAddresses = default;

                        NetworkAddress selectedNetwork = null;

                        foreach (JsonProperty jsonProperty in jsonAppRecordData.EnumerateObject())
                        {
                            string name = jsonProperty.Name;

                            if ((name == "public") || (name == "private"))
                                continue;

                            if (_networks.TryGetValue(name, out List<NetworkAddress> networkAddresses))
                            {
                                foreach (NetworkAddress networkAddress in networkAddresses)
                                {
                                    if (networkAddress.Contains(remoteEP.Address))
                                    {
                                        jsonAddresses = jsonProperty.Value;
                                        break;
                                    }
                                }

                                if (jsonAddresses.ValueKind != JsonValueKind.Undefined)
                                    break;
                            }
                            else if (NetworkAddress.TryParse(name, out NetworkAddress networkAddress))
                            {
                                if (networkAddress.Contains(remoteEP.Address) && ((selectedNetwork is null) || (networkAddress.PrefixLength > selectedNetwork.PrefixLength)))
                                {
                                    selectedNetwork = networkAddress;
                                    jsonAddresses = jsonProperty.Value;
                                }
                            }
                        }

                        if (jsonAddresses.ValueKind == JsonValueKind.Undefined)
                        {
                            if (NetUtilities.IsPrivateIP(remoteEP.Address))
                            {
                                if (!jsonAppRecordData.TryGetProperty("private", out jsonAddresses))
                                    return Task.FromResult<DnsDatagram>(null);
                            }
                            else
                            {
                                if (!jsonAppRecordData.TryGetProperty("public", out jsonAddresses))
                                    return Task.FromResult<DnsDatagram>(null);
                            }
                        }

                        List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                        switch (question.Type)
                        {
                            case DnsResourceRecordType.A:
                                foreach (JsonElement jsonAddress in jsonAddresses.EnumerateArray())
                                {
                                    if (IPAddress.TryParse(jsonAddress.GetString(), out IPAddress address) && (address.AddressFamily == AddressFamily.InterNetwork))
                                        answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN, appRecordTtl, new DnsARecordData(address)));
                                }
                                break;

                            case DnsResourceRecordType.AAAA:
                                foreach (JsonElement jsonAddress in jsonAddresses.EnumerateArray())
                                {
                                    if (IPAddress.TryParse(jsonAddress.GetString(), out IPAddress address) && (address.AddressFamily == AddressFamily.InterNetworkV6))
                                        answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, DnsClass.IN, appRecordTtl, new DnsAAAARecordData(address)));
                                }
                                break;
                        }

                        if (answers.Count == 0)
                            return Task.FromResult<DnsDatagram>(null);

                        if (answers.Count > 1)
                            answers.Shuffle();

                        return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers));
                    }

                default:
                    return Task.FromResult<DnsDatagram>(null);
            }
        }

        #endregion

        #region properties

        internal static Dictionary<string, List<NetworkAddress>> Networks
        { get { return _networks; } }

        public string Description
        { get { return "Returns A or AAAA records with different set of IP addresses for clients querying over public, private, or other specified networks."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""public"": [
    ""1.1.1.1"",
    ""2.2.2.2""
  ],
  ""private"": [
    ""192.168.1.1"",
    ""::1""
  ],
  ""custom-networks"": [
    ""172.16.1.1""
  ],
  ""10.0.0.0/8"": [
    ""10.1.1.1""
  ]
}";
            }
        }

        #endregion
    }
}
