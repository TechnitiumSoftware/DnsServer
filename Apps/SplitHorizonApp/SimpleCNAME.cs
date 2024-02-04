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
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace SplitHorizon
{
    public sealed class SimpleCNAME : IDnsApplication, IDnsAppRecordRequestHandler
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
            //SimpleAddress loads the shared config
            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];

            if (!question.Name.Equals(appRecordName, StringComparison.OrdinalIgnoreCase) && !appRecordName.StartsWith('*'))
                return Task.FromResult<DnsDatagram>(null);

            using JsonDocument jsonDocument = JsonDocument.Parse(appRecordData);
            JsonElement jsonAppRecordData = jsonDocument.RootElement;
            JsonElement jsonCname = default;

            NetworkAddress selectedNetwork = null;

            foreach (JsonProperty jsonProperty in jsonAppRecordData.EnumerateObject())
            {
                string name = jsonProperty.Name;

                if ((name == "public") || (name == "private"))
                    continue;

                if (SimpleAddress.Networks.TryGetValue(name, out List<NetworkAddress> networkAddresses))
                {
                    foreach (NetworkAddress networkAddress in networkAddresses)
                    {
                        if (networkAddress.Contains(remoteEP.Address))
                        {
                            jsonCname = jsonProperty.Value;
                            break;
                        }
                    }

                    if (jsonCname.ValueKind != JsonValueKind.Undefined)
                        break;
                }
                else if (NetworkAddress.TryParse(name, out NetworkAddress networkAddress))
                {
                    if (networkAddress.Contains(remoteEP.Address) && ((selectedNetwork is null) || (networkAddress.PrefixLength > selectedNetwork.PrefixLength)))
                    {
                        selectedNetwork = networkAddress;
                        jsonCname = jsonProperty.Value;
                    }
                }
            }

            if (jsonCname.ValueKind == JsonValueKind.Undefined)
            {
                if (NetUtilities.IsPrivateIP(remoteEP.Address))
                {
                    if (!jsonAppRecordData.TryGetProperty("private", out jsonCname))
                        return Task.FromResult<DnsDatagram>(null);
                }
                else
                {
                    if (!jsonAppRecordData.TryGetProperty("public", out jsonCname))
                        return Task.FromResult<DnsDatagram>(null);
                }
            }

            string cname = jsonCname.GetString();
            if (string.IsNullOrEmpty(cname))
                return Task.FromResult<DnsDatagram>(null);

            IReadOnlyList<DnsResourceRecord> answers;

            if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                answers = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, appRecordTtl, new DnsANAMERecordData(cname)) }; //use ANAME
            else
                answers = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, appRecordTtl, new DnsCNAMERecordData(cname)) };

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns different CNAME record for clients querying over public, private, or other specified networks. Note that the app will return ANAME record for an APP record at zone apex."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""public"": ""api.example.com"",
  ""private"": ""api.example.corp"",
  ""custom-networks"": ""custom.example.corp"",
  ""10.0.0.0/8"": ""api.intranet.example.corp""
}";
            }
        }

        #endregion
    }
}
