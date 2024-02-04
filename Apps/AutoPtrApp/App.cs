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
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace AutoPtr
{
    public sealed class App : IDnsApplication, IDnsAppRecordRequestHandler
    {
        #region variables

        IDnsServer _dnsServer;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            return Task.CompletedTask;
        }

        public async Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];
            string qname = question.Name;

            if (qname.Length == appRecordName.Length)
                return null;

            if (!IPAddressExtensions.TryParseReverseDomain(qname.ToLowerInvariant(), out IPAddress address))
                return null;

            if (question.Type != DnsResourceRecordType.PTR)
            {
                //NODATA reponse
                DnsDatagram soaResponse = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(zoneName, DnsResourceRecordType.SOA, DnsClass.IN));

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, null, soaResponse.Answer);
            }

            string domain = null;

            using (JsonDocument jsonDocument = JsonDocument.Parse(appRecordData))
            {
                JsonElement jsonAppRecordData = jsonDocument.RootElement;

                string ipSeparator;

                if (jsonAppRecordData.TryGetProperty("ipSeparator", out JsonElement jsonSeparator) && (jsonSeparator.ValueKind != JsonValueKind.Null))
                    ipSeparator = jsonSeparator.ToString();
                else
                    ipSeparator = string.Empty;

                switch (address.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        {
                            byte[] buffer = address.GetAddressBytes();

                            foreach (byte b in buffer)
                            {
                                if (domain is null)
                                    domain = b.ToString();
                                else
                                    domain += ipSeparator + b.ToString();
                            }
                        }
                        break;

                    case AddressFamily.InterNetworkV6:
                        {
                            byte[] buffer = address.GetAddressBytes();

                            for (int i = 0; i < buffer.Length; i += 2)
                            {
                                if (domain is null)
                                    domain = buffer[i].ToString("x2") + buffer[i + 1].ToString("x2");
                                else
                                    domain += ipSeparator + buffer[i].ToString("x2") + buffer[i + 1].ToString("x2");
                            }
                        }
                        break;

                    default:
                        return null;
                }

                if (jsonAppRecordData.TryGetProperty("prefix", out JsonElement jsonPrefix) && (jsonPrefix.ValueKind != JsonValueKind.Null))
                    domain = jsonPrefix.GetString() + domain;

                if (jsonAppRecordData.TryGetProperty("suffix", out JsonElement jsonSuffix) && (jsonSuffix.ValueKind != JsonValueKind.Null))
                    domain += jsonSuffix.GetString();
            }

            DnsResourceRecord[] answer = new DnsResourceRecord[] { new DnsResourceRecord(qname, DnsResourceRecordType.PTR, DnsClass.IN, appRecordTtl, new DnsPTRRecordData(domain)) };

            return new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answer);
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns automatically generated response for a PTR request for both IPv4 and IPv6."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""prefix"": """",
  ""suffix"": "".example.com"",
  ""ipSeparator"": ""-""
}";
            }
        }

        #endregion
    }
}
