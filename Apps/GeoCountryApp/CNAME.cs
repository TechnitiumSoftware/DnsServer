/*
Technitium DNS Server
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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

namespace GeoCountry
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
            using JsonDocument jsonDocument = JsonDocument.Parse(appRecordData);
            JsonElement jsonAppRecordData = jsonDocument.RootElement;
            JsonElement jsonCountry = default;

            bool ecsUsed = false;
            EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
            if (requestECS is not null)
            {
                if (_maxMind.DatabaseReader.TryCountry(requestECS.Address, out CountryResponse csResponse))
                {
                    ecsUsed = true;
                    if (!jsonAppRecordData.TryGetProperty(csResponse.Country.IsoCode, out jsonCountry))
                        jsonAppRecordData.TryGetProperty("default", out jsonCountry);
                }
            }

            if (jsonCountry.ValueKind == JsonValueKind.Undefined)
            {
                if (_maxMind.DatabaseReader.TryCountry(remoteEP.Address, out CountryResponse response))
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

            string cname = jsonCountry.GetString();
            if (string.IsNullOrEmpty(cname))
                return Task.FromResult<DnsDatagram>(null);

            IReadOnlyList<DnsResourceRecord> answers;

            if (request.Question[0].Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                answers = new DnsResourceRecord[] { new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.ANAME, DnsClass.IN, appRecordTtl, new DnsANAMERecordData(cname)) }; //use ANAME
            else
                answers = new DnsResourceRecord[] { new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.CNAME, DnsClass.IN, appRecordTtl, new DnsCNAMERecordData(cname)) };

            EDnsOption[] options;

            if (requestECS is null)
            {
                options = null;
            }
            else
            {
                if (ecsUsed)
                    options = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(requestECS.SourcePrefixLength, requestECS.SourcePrefixLength, requestECS.Address);
                else
                    options = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(requestECS.SourcePrefixLength, 0, requestECS.Address);
            }

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers, null, null, _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns CNAME record based on the country the client queries from using MaxMind GeoIP2 Country database. Note that the app will return ANAME record for an APP record at zone apex. Use the two-character ISO 3166-1 alpha code for the country."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""IN"": ""in.example.com"",
  ""default"": ""example.com""
}";
            }
        }

        #endregion
    }
}
