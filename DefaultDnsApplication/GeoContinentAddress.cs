﻿/*
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

using DnsApplicationCommon;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Responses;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DefaultDnsApplication
{
    public class GeoContinentAddress : IDnsApplicationRequestHandler
    {
        #region variables

        DatabaseReader _mmCountryReader;

        #endregion

        #region IDisposable

        bool _disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_mmCountryReader != null)
                    _mmCountryReader.Dispose();
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
            if (_mmCountryReader == null)
            {
                string mmFile = Path.Combine(dnsServer.ApplicationFolder, "GeoIP2-Country.mmdb");

                if (!File.Exists(mmFile))
                    mmFile = Path.Combine(dnsServer.ApplicationFolder, "GeoLite2-Country.mmdb");

                if (!File.Exists(mmFile))
                    throw new FileNotFoundException("MaxMind Country file is missing!");

                _mmCountryReader = new DatabaseReader(mmFile);
            }

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, string zoneName, uint appRecordTtl, string appRecordData, bool isRecursionAllowed, IDnsServer dnsServer)
        {
            switch (request.Question[0].Type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    string continent;

                    if (_mmCountryReader.TryCountry(remoteEP.Address, out CountryResponse response))
                        continent = response.Continent.Code;
                    else
                        continent = "default";

                    dynamic jsonAppRecordData = JsonConvert.DeserializeObject(appRecordData);
                    dynamic jsonContinent = jsonAppRecordData[continent];

                    List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                    foreach (dynamic jsonAddress in jsonContinent)
                    {
                        IPAddress address = IPAddress.Parse(jsonAddress.Value);

                        switch (request.Question[0].Type)
                        {
                            case DnsResourceRecordType.A:
                                if (address.AddressFamily == AddressFamily.InterNetwork)
                                    answers.Add(new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.A, DnsClass.IN, appRecordTtl, new DnsARecord(address)));

                                break;

                            case DnsResourceRecordType.AAAA:
                                if (address.AddressFamily == AddressFamily.InterNetworkV6)
                                    answers.Add(new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.AAAA, DnsClass.IN, appRecordTtl, new DnsAAAARecord(address)));

                                break;
                        }
                    }

                    if (answers.Count == 0)
                        return Task.FromResult<DnsDatagram>(null);

                    return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers));

                default:
                    return Task.FromResult<DnsDatagram>(null);
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns A or AAAA records based on the continent the client queries from using MaxMind GeoIP2 Country database."; } }

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
