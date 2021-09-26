/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace SplitHorizon
{
    public class SimpleCNAME : IDnsApplication, IDnsAppRecordRequestHandler
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
            //no config needed
            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, uint appRecordTtl, string appRecordData)
        {
            dynamic jsonAppRecordData = JsonConvert.DeserializeObject(appRecordData);
            dynamic jsonCname = null;

            foreach (dynamic jsonProperty in jsonAppRecordData)
            {
                string name = jsonProperty.Name;

                if ((name == "public") || (name == "private"))
                    continue;

                NetworkAddress networkAddress = NetworkAddress.Parse(name);
                if (networkAddress.Contains(remoteEP.Address))
                {
                    jsonCname = jsonProperty.Value;
                    break;
                }
            }

            if (jsonCname is null)
            {
                if (NetUtilities.IsPrivateIP(remoteEP.Address))
                    jsonCname = jsonAppRecordData.@private;
                else
                    jsonCname = jsonAppRecordData.@public;

                if (jsonCname is null)
                    return Task.FromResult<DnsDatagram>(null);
            }

            string cname = jsonCname.Value;
            if (string.IsNullOrEmpty(cname))
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];
            IReadOnlyList<DnsResourceRecord> answers;

            if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                answers = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, appRecordTtl, new DnsANAMERecord(cname)) }; //use ANAME
            else
                answers = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, appRecordTtl, new DnsCNAMERecord(cname)) };

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
  ""10.0.0.0/8"": ""api.intranet.example.corp""
}";
            }
        }

        #endregion
    }
}
