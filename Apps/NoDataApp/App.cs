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
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace NoData
{
    public sealed class App : IDnsApplication, IDnsAppRecordRequestHandler
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
            //do nothing
            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];

            if (!question.Name.Equals(appRecordName, StringComparison.OrdinalIgnoreCase) && !appRecordName.StartsWith('*'))
                return Task.FromResult<DnsDatagram>(null);

            using JsonDocument jsonDocument = JsonDocument.Parse(appRecordData);
            JsonElement jsonAppRecordData = jsonDocument.RootElement;

            foreach (JsonElement jsonBlockedType in jsonAppRecordData.GetProperty("blockedTypes").EnumerateArray())
            {
                DnsResourceRecordType blockedType = Enum.Parse<DnsResourceRecordType>(jsonBlockedType.GetString(), true);
                if ((blockedType == question.Type) || (blockedType == DnsResourceRecordType.ANY))
                    return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question));
            }

            return Task.FromResult<DnsDatagram>(null);
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns a NO DATA response for requests that query for the blocked resource record types in Conditional Forwarder zones."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""blockedTypes"": [
    ""A"", 
    ""AAAA"",
    ""ANY""
  ]
}";
            }
        }

        #endregion
    }
}