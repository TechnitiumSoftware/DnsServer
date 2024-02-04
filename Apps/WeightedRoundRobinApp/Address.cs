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
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace WeightedRoundRobin
{
    public sealed class Address : IDnsApplication, IDnsAppRecordRequestHandler
    {
        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];

            if (!question.Name.Equals(appRecordName, StringComparison.OrdinalIgnoreCase) && !appRecordName.StartsWith('*'))
                return Task.FromResult<DnsDatagram>(null);

            string jsonPropertyName;

            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                    jsonPropertyName = "ipv4Addresses";
                    break;

                case DnsResourceRecordType.AAAA:
                    jsonPropertyName = "ipv6Addresses";
                    break;

                default:
                    return Task.FromResult<DnsDatagram>(null);
            }

            List<WeightedAddress> addresses;
            int totalWeight = 0;

            using (JsonDocument jsonDocument = JsonDocument.Parse(appRecordData))
            {
                JsonElement jsonAppRecordData = jsonDocument.RootElement;

                if (!jsonAppRecordData.TryGetProperty(jsonPropertyName, out JsonElement jsonAddresses) || (jsonAddresses.ValueKind == JsonValueKind.Null))
                    return Task.FromResult<DnsDatagram>(null);

                addresses = new List<WeightedAddress>(jsonAddresses.GetArrayLength());

                foreach (JsonElement jsonAddressEntry in jsonAddresses.EnumerateArray())
                {
                    if (jsonAddressEntry.TryGetProperty("enabled", out JsonElement jsonEnabled) && (jsonEnabled.ValueKind != JsonValueKind.Null) && !jsonEnabled.GetBoolean())
                        continue;

                    if (!jsonAddressEntry.TryGetProperty("address", out JsonElement jsonAddress) || (jsonAddress.ValueKind == JsonValueKind.Null) || !IPAddress.TryParse(jsonAddress.GetString(), out IPAddress address))
                        continue;

                    if (!jsonAddressEntry.TryGetProperty("weight", out JsonElement jsonWeight) || (jsonWeight.ValueKind == JsonValueKind.Null))
                        continue;

                    int weight = jsonWeight.GetInt32();
                    if (weight < 1)
                        continue;

                    addresses.Add(new WeightedAddress() { Address = address, Weight = weight });
                    totalWeight += weight;
                }
            }

            if (addresses.Count == 0)
                return Task.FromResult<DnsDatagram>(null);

            int randomSelection = RandomNumberGenerator.GetInt32(1, 101);
            int rangeFrom;
            int rangeTo = 0;
            DnsResourceRecord answer = null;

            for (int i = 0; i < addresses.Count; i++)
            {
                rangeFrom = rangeTo + 1;

                if (i == addresses.Count - 1)
                    rangeTo = 100;
                else
                    rangeTo += addresses[i].Weight * 100 / totalWeight;

                if ((rangeFrom <= randomSelection) && (randomSelection <= rangeTo))
                {
                    switch (question.Type)
                    {
                        case DnsResourceRecordType.A:
                            answer = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, appRecordTtl, new DnsARecordData(addresses[i].Address));
                            break;

                        case DnsResourceRecordType.AAAA:
                            answer = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, appRecordTtl, new DnsAAAARecordData(addresses[i].Address));
                            break;

                        default:
                            throw new InvalidOperationException();
                    }

                    break;
                }
            }

            if (answer is null)
                throw new InvalidOperationException();

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, new DnsResourceRecord[] { answer }));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns an A or AAAA record using weighted round-robin load balancing."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""ipv4Addresses"": [
    {
       ""address"": ""1.1.1.1"",
       ""weight"": 5,
       ""enabled"": true
    },
    {
       ""address"": ""2.2.2.2"",
       ""weight"": 3,
       ""enabled"": true
    }
  ],
  ""ipv6Addresses"": [
    {
       ""address"": ""::1"",
       ""weight"": 2,
       ""enabled"": true
    },
    {
       ""address"": ""::2"",
       ""weight"": 3,
       ""enabled"": true
    }
  ]
}";
            }
        }

        #endregion

        struct WeightedAddress
        {
            public IPAddress Address;
            public int Weight;
        }
    }
}
