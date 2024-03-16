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
using MaxMind.GeoIP2.Responses;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace GeoCountry
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

            if (!question.Name.Equals(appRecordName, StringComparison.OrdinalIgnoreCase) && !appRecordName.StartsWith('*'))
                return Task.FromResult<DnsDatagram>(null);

            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    using (JsonDocument jsonDocument = JsonDocument.Parse(appRecordData))
                    {
                        JsonElement jsonAppRecordData = jsonDocument.RootElement;
                        JsonElement jsonCountry = default;

                        byte scopePrefixLength = 0;
                        EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                        if (requestECS is not null)
                        {
                            if ((_maxMind.IspReader is not null) && _maxMind.IspReader.TryIsp(requestECS.Address, out IspResponse csIsp) && (csIsp.Network is not null))
                                scopePrefixLength = (byte)csIsp.Network.PrefixLength;
                            else if ((_maxMind.AsnReader is not null) && _maxMind.AsnReader.TryAsn(requestECS.Address, out AsnResponse csAsn) && (csAsn.Network is not null))
                                scopePrefixLength = (byte)csAsn.Network.PrefixLength;
                            else
                                scopePrefixLength = requestECS.SourcePrefixLength;

                            if (_maxMind.CountryReader.TryCountry(requestECS.Address, out CountryResponse csResponse))
                            {
                                if (!jsonAppRecordData.TryGetProperty(csResponse.Country.IsoCode, out jsonCountry))
                                    jsonAppRecordData.TryGetProperty("default", out jsonCountry);
                            }
                        }

                        if (jsonCountry.ValueKind == JsonValueKind.Undefined)
                        {
                            if (_maxMind.CountryReader.TryCountry(remoteEP.Address, out CountryResponse response))
                            {
                                if (!jsonAppRecordData.TryGetProperty(response.Country.IsoCode, out jsonCountry))
                                    jsonAppRecordData.TryGetProperty("default", out jsonCountry);
                            }
                            else
                            {
                                jsonAppRecordData.TryGetProperty("default", out jsonCountry);
                            }

                            if (jsonCountry.ValueKind == JsonValueKind.Undefined)
                                return Task.FromResult<DnsDatagram>(null);
                        }

                        List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                        switch (question.Type)
                        {
                            case DnsResourceRecordType.A:
                                foreach (JsonElement jsonAddress in jsonCountry.EnumerateArray())
                                {
                                    IPAddress address = IPAddress.Parse(jsonAddress.GetString());

                                    if (address.AddressFamily == AddressFamily.InterNetwork)
                                        answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN, appRecordTtl, new DnsARecordData(address)));
                                }
                                break;

                            case DnsResourceRecordType.AAAA:
                                foreach (JsonElement jsonAddress in jsonCountry.EnumerateArray())
                                {
                                    IPAddress address = IPAddress.Parse(jsonAddress.GetString());

                                    if (address.AddressFamily == AddressFamily.InterNetworkV6)
                                        answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, DnsClass.IN, appRecordTtl, new DnsAAAARecordData(address)));
                                }
                                break;
                        }

                        if (answers.Count == 0)
                            return Task.FromResult<DnsDatagram>(null);

                        if (answers.Count > 1)
                            answers.Shuffle();

                        EDnsOption[] options = null;

                        if (requestECS is not null)
                            options = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(requestECS.SourcePrefixLength, scopePrefixLength, requestECS.Address);

                        return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers, null, null, _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options));
                    }

                default:
                    return Task.FromResult<DnsDatagram>(null);
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns A or AAAA records based on the country the client queries from using MaxMind GeoIP2 Country database. Use the two-character ISO 3166-1 alpha code for the country."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""IN"": [
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
