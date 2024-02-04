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
    public sealed class CNAME : IDnsApplication, IDnsAppRecordRequestHandler
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

            List<WeightedDomain> domainNames;
            int totalWeight = 0;

            using (JsonDocument jsonDocument = JsonDocument.Parse(appRecordData))
            {
                JsonElement jsonAppRecordData = jsonDocument.RootElement;

                if (!jsonAppRecordData.TryGetProperty("cnames", out JsonElement jsonCnames) || (jsonCnames.ValueKind == JsonValueKind.Null))
                    return Task.FromResult<DnsDatagram>(null);

                domainNames = new List<WeightedDomain>(jsonCnames.GetArrayLength());

                foreach (JsonElement jsonCnameEntry in jsonCnames.EnumerateArray())
                {
                    if (jsonCnameEntry.TryGetProperty("enabled", out JsonElement jsonEnabled) && (jsonEnabled.ValueKind != JsonValueKind.Null) && !jsonEnabled.GetBoolean())
                        continue;

                    if (!jsonCnameEntry.TryGetProperty("domain", out JsonElement jsonDomain) || (jsonDomain.ValueKind == JsonValueKind.Null))
                        continue;

                    if (!jsonCnameEntry.TryGetProperty("weight", out JsonElement jsonWeight) || (jsonWeight.ValueKind == JsonValueKind.Null))
                        continue;

                    int weight = jsonWeight.GetInt32();
                    if (weight < 1)
                        continue;

                    domainNames.Add(new WeightedDomain() { Domain = jsonDomain.GetString(), Weight = weight });
                    totalWeight += weight;
                }
            }

            if (domainNames.Count == 0)
                return Task.FromResult<DnsDatagram>(null);

            int randomSelection = RandomNumberGenerator.GetInt32(1, 101);
            int rangeFrom;
            int rangeTo = 0;
            DnsResourceRecord answer = null;

            for (int i = 0; i < domainNames.Count; i++)
            {
                rangeFrom = rangeTo + 1;

                if (i == domainNames.Count - 1)
                    rangeTo = 100;
                else
                    rangeTo += domainNames[i].Weight * 100 / totalWeight;

                if ((rangeFrom <= randomSelection) && (randomSelection <= rangeTo))
                {
                    if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                        answer = new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, appRecordTtl, new DnsANAMERecordData(domainNames[i].Domain)); //use ANAME
                    else
                        answer = new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, appRecordTtl, new DnsCNAMERecordData(domainNames[i].Domain));

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
        { get { return "Returns a CNAME record using weighted round-robin load balancing."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""cnames"": [
    {
       ""domain"": ""example.com"",
       ""weight"": 5,
       ""enabled"": true
    },
    {
       ""domain"": ""example.net"",
       ""weight"": 3,
       ""enabled"": true
    }
  ]
}";
            }
        }

        #endregion

        struct WeightedDomain
        {
            public string Domain;
            public int Weight;
        }
    }
}
