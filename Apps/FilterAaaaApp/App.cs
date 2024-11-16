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
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace FilterAaaa
{
    public sealed class App : IDnsApplication, IDnsPostProcessor
    {
        #region variables

        IDnsServer _dnsServer;

        bool _enableFilterAaaa;
        uint _defaultTtl;
        bool _bypassLocalZones;
        NetworkAddress[] _bypassNetworks;
        string[] _bypassDomains;
        string[] _filterDomains;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _enableFilterAaaa = jsonConfig.GetPropertyValue("enableFilterAaaa", false);

            if (jsonConfig.TryGetProperty("defaultTtl", out JsonElement jsonValue))
            {
                if (!jsonValue.TryGetUInt32(out _defaultTtl))
                    _defaultTtl = 30u;
            }
            else
            {
                _defaultTtl = 30u;

                //update config for new option
                config = config.Replace("\"bypassLocalZones\"", "\"defaultTtl\": 30,\r\n  \"bypassLocalZones\"");
                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }

            _bypassLocalZones = jsonConfig.GetPropertyValue("bypassLocalZones", false);

            if (jsonConfig.TryReadArray("bypassNetworks", NetworkAddress.Parse, out NetworkAddress[] bypassNetworks))
                _bypassNetworks = bypassNetworks;
            else
                _bypassNetworks = [];

            if (jsonConfig.TryReadArray("bypassDomains", out string[] bypassDomains))
                _bypassDomains = bypassDomains;
            else
                _bypassDomains = [];

            if (jsonConfig.TryReadArray("filterDomains", out string[] filterDomains))
            {
                _filterDomains = filterDomains;
            }
            else
            {
                _filterDomains = [];

                //update config for new feature
                config = config.TrimEnd('\r', '\n', ' ', '}');
                config += ",\r\n  \"filterDomains\": [\r\n  ]\r\n}";
                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }
        }

        public async Task<DnsDatagram> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (!_enableFilterAaaa)
                return response;

            if (_bypassLocalZones && response.AuthoritativeAnswer)
                return response;

            if (response.RCODE != DnsResponseCode.NoError)
                return response;

            DnsQuestionRecord question = request.Question[0];
            if (question.Type != DnsResourceRecordType.AAAA)
                return response;

            bool hasAAAA = false;

            if (request.DnssecOk)
            {
                foreach (DnsResourceRecord record in response.Answer)
                {
                    switch (record.Type)
                    {
                        case DnsResourceRecordType.AAAA:
                            hasAAAA = true;
                            break;

                        case DnsResourceRecordType.RRSIG:
                            //response is signed and the client is DNSSEC aware; must not be modified
                            return response;
                    }
                }
            }
            else
            {
                foreach (DnsResourceRecord record in response.Answer)
                {
                    if (record.Type == DnsResourceRecordType.AAAA)
                    {
                        hasAAAA = true;
                        break;
                    }
                }
            }

            if (!hasAAAA)
                return response;

            IPAddress remoteIP = remoteEP.Address;

            foreach (NetworkAddress network in _bypassNetworks)
            {
                if (network.Contains(remoteIP))
                    return response;
            }

            string qname = question.Name;

            foreach (string allowedDomain in _bypassDomains)
            {
                if (qname.Equals(allowedDomain, StringComparison.OrdinalIgnoreCase) || qname.EndsWith("." + allowedDomain, StringComparison.OrdinalIgnoreCase))
                    return response;
            }

            bool filterDomain = _filterDomains.Length == 0;

            foreach (string blockedDomain in _filterDomains)
            {
                if (qname.Equals(blockedDomain, StringComparison.OrdinalIgnoreCase) || qname.EndsWith("." + blockedDomain, StringComparison.OrdinalIgnoreCase))
                {
                    filterDomain = true;
                    break;
                }
            }

            if (!filterDomain)
                return response;

            DnsDatagram aResponse = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(qname, DnsResourceRecordType.A, DnsClass.IN), 2000);

            if (aResponse.RCODE != DnsResponseCode.NoError)
                return response;

            foreach (DnsResourceRecord record in aResponse.Answer)
            {
                if (record.Type == DnsResourceRecordType.A)
                {
                    //domain has an A record; filter current AAAA response
                    List<DnsResourceRecord> answer = new List<DnsResourceRecord>();

                    foreach (DnsResourceRecord record2 in response.Answer)
                    {
                        if (record2.Type == DnsResourceRecordType.CNAME)
                        {
                            answer.Add(record2);
                            qname = (record2.RDATA as DnsCNAMERecordData).Domain;
                        }
                    }

                    DnsResourceRecord[] authority = [new DnsResourceRecord(qname, DnsResourceRecordType.SOA, DnsClass.IN, _defaultTtl, new DnsSOARecordData(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 3600, 900, 86400, _defaultTtl))];

                    return new DnsDatagram(response.Identifier, true, response.OPCODE, false, false, response.RecursionDesired, response.RecursionAvailable, false, false, DnsResponseCode.NoError, response.Question, answer, authority);
                }
            }

            //domain does not have an A record; return current response
            return response;
        }

        #endregion

        #region properties

        public string Description
        { get { return "Filters AAAA records by returning NO DATA response when A records for the same domain name are available."; } }

        #endregion
    }
}
