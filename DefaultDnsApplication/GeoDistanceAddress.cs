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
using MaxMind.GeoIP2.Model;
using MaxMind.GeoIP2.Responses;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DefaultDnsApplication
{
    public class GeoDistanceAddress : IDnsApplicationRequestHandler
    {
        #region variables

        DatabaseReader _mmCityReader;

        #endregion

        #region IDisposable

        bool _disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_mmCityReader != null)
                    _mmCityReader.Dispose();
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
            if (_mmCityReader == null)
            {
                string mmFile = Path.Combine(dnsServer.ApplicationFolder, "GeoIP2-City.mmdb");

                if (!File.Exists(mmFile))
                    mmFile = Path.Combine(dnsServer.ApplicationFolder, "GeoLite2-City.mmdb");

                if (!File.Exists(mmFile))
                    throw new FileNotFoundException("MaxMind City file is missing!");

                _mmCityReader = new DatabaseReader(mmFile);
            }

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, string zoneName, uint appRecordTtl, string appRecordData, bool isRecursionAllowed, IDnsServer dnsServer)
        {
            switch (request.Question[0].Type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    Location location = null;

                    if (_mmCityReader.TryCity(remoteEP.Address, out CityResponse response))
                        location = response.Location;

                    dynamic jsonAppRecordData = JsonConvert.DeserializeObject(appRecordData);
                    dynamic jsonLastServer = null;

                    if ((location == null) || !location.HasCoordinates)
                    {
                        jsonLastServer = jsonAppRecordData[0];
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
                                jsonLastServer = jsonServer;
                            }
                        }
                    }

                    List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                    foreach (dynamic jsonAddress in jsonLastServer.addresses)
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
        { get { return "Returns A or AAAA records of the server located geographically closest to the client using MaxMind GeoIP2 City database."; } }

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
