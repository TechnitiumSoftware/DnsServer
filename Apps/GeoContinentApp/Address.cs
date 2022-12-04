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
using MaxMind.GeoIP2.Responses;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace GeoContinent
{
    public sealed class Address : IDnsApplication, IDnsAppRecordRequestHandler
    {
        #region variables

        IDnsServer _dnsServer;
        MaxMind _maxMind;

        #endregion

        #region IDisposable

        bool _disposed;

        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_maxMind is not null)
                    _maxMind.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            _maxMind = MaxMind.Create(dnsServer);

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];
            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    dynamic jsonAppRecordData = JsonConvert.DeserializeObject(appRecordData);
                    dynamic jsonContinent = null;

                    bool ecsUsed = false;
                    EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                    if (requestECS is not null)
                    {
                        if (_maxMind.DatabaseReader.TryCountry(requestECS.Address, out CountryResponse csResponse))
                        {
                            ecsUsed = true;
                            jsonContinent = jsonAppRecordData[csResponse.Continent.Code];
                            if (jsonContinent is null)
                                jsonContinent = jsonAppRecordData["default"];
                        }
                    }

                    if (jsonContinent is null)
                    {
                        if (_maxMind.DatabaseReader.TryCountry(remoteEP.Address, out CountryResponse response))
                        {
                            jsonContinent = jsonAppRecordData[response.Continent.Code];
                            if (jsonContinent is null)
                                jsonContinent = jsonAppRecordData["default"];
                        }
                        else
                        {
                            jsonContinent = jsonAppRecordData["default"];
                        }
                    }

                    if (jsonContinent is null)
                        return Task.FromResult<DnsDatagram>(null);

                    List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.A:
                            foreach (dynamic jsonAddress in jsonContinent)
                            {
                                IPAddress address = IPAddress.Parse(jsonAddress.Value);

                                if (address.AddressFamily == AddressFamily.InterNetwork)
                                    answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN, appRecordTtl, new DnsARecordData(address)));
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            foreach (dynamic jsonAddress in jsonContinent)
                            {
                                IPAddress address = IPAddress.Parse(jsonAddress.Value);

                                if (address.AddressFamily == AddressFamily.InterNetworkV6)
                                    answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, DnsClass.IN, appRecordTtl, new DnsAAAARecordData(address)));
                            }
                            break;
                    }

                    if (answers.Count == 0)
                        return Task.FromResult<DnsDatagram>(null);

                    if (answers.Count > 1)
                        answers.Shuffle();

                    EDnsOption[] options;

                    if (requestECS is null)
                    {
                        options = null;
                    }
                    else
                    {
                        if (ecsUsed)
                            options = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(requestECS.SourcePrefixLength, requestECS.SourcePrefixLength, requestECS.AddressValue);
                        else
                            options = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(requestECS.SourcePrefixLength, 0, requestECS.AddressValue);
                    }

                    return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers, null, null, _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options));

                default:
                    return Task.FromResult<DnsDatagram>(null);
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns A or AAAA records based on the continent the client queries from using MaxMind GeoIP2 Country database. Use the two character continent code like \"NA\" (North America) or \"OC\" (Oceania)."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""EU"": [
    ""1.1.1.1"", 
    ""2.2.2.2""
  ],
  ""default"": [
    ""3.3.3.3""
  ]
}";
            }
        }

        #endregion
    }
}
