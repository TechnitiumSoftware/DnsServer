/*
Technitium DNS Server
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using Newtonsoft.Json;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace SplitHorizon
{
    public class SimpleAddress : IDnsApplication, IDnsAppRecordRequestHandler
    {
        #region variables

        static IReadOnlyDictionary<string, List<NetworkAddress>> _networks;

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
            if (config.StartsWith('#'))
            {
                //replace old config with default config
                config = @"{
    ""networks"": {
        ""custom-networks"": [
            ""172.16.1.0/24"",
            ""172.16.10.0/24"",
            ""172.16.2.1""
        ]
    }
}
";

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }

            dynamic jsonConfig = JsonConvert.DeserializeObject(config);

            dynamic jsonNetworks = jsonConfig.networks;
            if (jsonNetworks is null)
            {
                _networks = new Dictionary<string, List<NetworkAddress>>(1);
            }
            else
            {
                Dictionary<string, List<NetworkAddress>> networks = new Dictionary<string, List<NetworkAddress>>();

                foreach (dynamic jsonProperty in jsonNetworks)
                {
                    string networkName = jsonProperty.Name;

                    dynamic jsonNetworkAddresses = jsonProperty.Value;
                    if (jsonNetworkAddresses is not null)
                    {
                        List<NetworkAddress> networkAddresses = new List<NetworkAddress>();

                        foreach (dynamic jsonNetworkAddress in jsonNetworkAddresses)
                            networkAddresses.Add(NetworkAddress.Parse(jsonNetworkAddress.Value));

                        networks.TryAdd(networkName, networkAddresses);
                    }
                }

                _networks = networks;
            }
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];
            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    dynamic jsonAppRecordData = JsonConvert.DeserializeObject(appRecordData);
                    dynamic jsonAddresses = null;

                    foreach (dynamic jsonProperty in jsonAppRecordData)
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

                            if (jsonAddresses is not null)
                                break;
                        }
                        else if (NetworkAddress.TryParse(name, out NetworkAddress networkAddress))
                        {
                            if (networkAddress.Contains(remoteEP.Address))
                            {
                                jsonAddresses = jsonProperty.Value;
                                break;
                            }
                        }
                    }

                    if (jsonAddresses is null)
                    {
                        if (NetUtilities.IsPrivateIP(remoteEP.Address))
                            jsonAddresses = jsonAppRecordData.@private;
                        else
                            jsonAddresses = jsonAppRecordData.@public;

                        if (jsonAddresses is null)
                            return Task.FromResult<DnsDatagram>(null);
                    }

                    List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.A:
                            foreach (dynamic jsonAddress in jsonAddresses)
                            {
                                if (IPAddress.TryParse(jsonAddress.Value, out IPAddress address) && (address.AddressFamily == AddressFamily.InterNetwork))
                                    answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN, appRecordTtl, new DnsARecordData(address)));
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            foreach (dynamic jsonAddress in jsonAddresses)
                            {
                                if (IPAddress.TryParse(jsonAddress.Value, out IPAddress address) && (address.AddressFamily == AddressFamily.InterNetworkV6))
                                    answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, DnsClass.IN, appRecordTtl, new DnsAAAARecordData(address)));
                            }
                            break;
                    }

                    if (answers.Count == 0)
                        return Task.FromResult<DnsDatagram>(null);

                    if (answers.Count > 1)
                        answers.Shuffle();

                    return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers));

                default:
                    return Task.FromResult<DnsDatagram>(null);
            }
        }

        #endregion

        #region properties

        internal static IReadOnlyDictionary<string, List<NetworkAddress>> Networks
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
    ""172.16.1.1"", 
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
