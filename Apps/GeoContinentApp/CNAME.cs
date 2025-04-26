/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace GeoContinent
{
    public sealed class CNAME : IDnsApplication, IDnsAppRecordRequestHandler
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

            using JsonDocument jsonDocument = JsonDocument.Parse(appRecordData);
            JsonElement jsonAppRecordData = jsonDocument.RootElement;
            JsonElement jsonContinent = default;
            string continentCode = null;

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
                    string cc = csResponse.Continent.Code;

                    if (!jsonAppRecordData.TryGetProperty(cc, out jsonContinent))
                    {
                        jsonAppRecordData.TryGetProperty("default", out jsonContinent);
                        continentCode = cc is null ? "default" : cc.ToLowerInvariant();
                    }
                }
            }

            if (jsonContinent.ValueKind == JsonValueKind.Undefined)
            {
                if (_maxMind.CountryReader.TryCountry(remoteEP.Address, out CountryResponse response))
                {
                    string cc = response.Continent.Code;

                    if (!jsonAppRecordData.TryGetProperty(cc, out jsonContinent))
                    {
                        jsonAppRecordData.TryGetProperty("default", out jsonContinent);
                        continentCode = cc is null ? "default" : cc.ToLowerInvariant();
                    }
                }
                else
                {
                    jsonAppRecordData.TryGetProperty("default", out jsonContinent);
                    continentCode = "default";
                }

                if (jsonContinent.ValueKind == JsonValueKind.Undefined)
                    return Task.FromResult<DnsDatagram>(null);
            }

            string cname = jsonContinent.GetString();
            if (string.IsNullOrEmpty(cname))
                return Task.FromResult<DnsDatagram>(null);

            if (continentCode is not null)
                cname = cname.Replace("{ContinentCode}", continentCode, StringComparison.OrdinalIgnoreCase);

            IReadOnlyList<DnsResourceRecord> answers;

            if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                answers = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, appRecordTtl, new DnsANAMERecordData(cname)) }; //use ANAME
            else
                answers = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, appRecordTtl, new DnsCNAMERecordData(cname)) };

            EDnsOption[] options = null;

            if (requestECS is not null)
                options = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(requestECS.SourcePrefixLength, scopePrefixLength, requestECS.Address);

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers, null, null, _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns CNAME record based on the continent the client queries from using MaxMind GeoIP2 Country database. Note that the app will return ANAME record for an APP record at zone apex. Use the two character continent code like \"NA\" (North America) or \"OC\" (Oceania). You can also use '{ContinentCode}' variable in the default case domain name which will get replaced by the app using the client's actual continent code or 'default' if not found."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""EU"": ""eu.example.com"",
  ""default"": ""example.com""
}";
            }
        }

        #endregion
    }
}
