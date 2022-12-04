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
using MaxMind.GeoIP2.Model;
using MaxMind.GeoIP2.Responses;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace GeoDistance
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

        #region private

        private static double GetDistance(double lat1, double long1, double lat2, double long2)
        {
            double d1 = lat1 * (Math.PI / 180.0);
            double num1 = long1 * (Math.PI / 180.0);
            double d2 = lat2 * (Math.PI / 180.0);
            double num2 = long2 * (Math.PI / 180.0) - num1;
            double d3 = Math.Pow(Math.Sin((d2 - d1) / 2.0), 2.0) + Math.Cos(d1) * Math.Cos(d2) * Math.Pow(Math.Sin(num2 / 2.0), 2.0);

            return 6376500.0 * (2.0 * Math.Atan2(Math.Sqrt(d3), Math.Sqrt(1.0 - d3)));
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
                    Location location = null;

                    bool ecsUsed = false;
                    EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                    if (requestECS is not null)
                    {
                        if (_maxMind.DatabaseReader.TryCity(requestECS.Address, out CityResponse csResponse) && csResponse.Location.HasCoordinates)
                        {
                            ecsUsed = true;
                            location = csResponse.Location;
                        }
                    }

                    if ((location is null) && _maxMind.DatabaseReader.TryCity(remoteEP.Address, out CityResponse response) && response.Location.HasCoordinates)
                        location = response.Location;

                    dynamic jsonAppRecordData = JsonConvert.DeserializeObject(appRecordData);
                    dynamic jsonClosestServer = null;

                    if (location is null)
                    {
                        jsonClosestServer = jsonAppRecordData[0];
                    }
                    else
                    {
                        double lastDistance = double.MaxValue;

                        foreach (dynamic jsonServer in jsonAppRecordData)
                        {
                            double lat = Convert.ToDouble(jsonServer.lat.Value);
                            double @long = Convert.ToDouble(jsonServer.@long.Value);

                            double distance = GetDistance(lat, @long, location.Latitude.Value, location.Longitude.Value);

                            if (distance < lastDistance)
                            {
                                lastDistance = distance;
                                jsonClosestServer = jsonServer;
                            }
                        }
                    }

                    if (jsonClosestServer is null)
                        return Task.FromResult<DnsDatagram>(null);

                    List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.A:
                            foreach (dynamic jsonAddress in jsonClosestServer.addresses)
                            {
                                IPAddress address = IPAddress.Parse(jsonAddress.Value);

                                if (address.AddressFamily == AddressFamily.InterNetwork)
                                    answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN, appRecordTtl, new DnsARecordData(address)));
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            foreach (dynamic jsonAddress in jsonClosestServer.addresses)
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
        { get { return "Returns A or AAAA records of the server located geographically closest to the client using MaxMind GeoIP2 City database. Use the geographic coordinates in decimal degrees (DD) form for the city the server is located in."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"[
  {
    ""name"": ""server1-mumbai"",
    ""lat"": ""19.07283"",
    ""long"": ""72.88261"",
    ""addresses"": [
      ""1.1.1.1""
    ]
  },
  {
    ""name"": ""server2-london"",
    ""lat"": ""51.50853"",
    ""long"": ""-0.12574"",
    ""addresses"": [
      ""2.2.2.2""
    ]
  }
]";
            }
        }

        #endregion
    }
}
