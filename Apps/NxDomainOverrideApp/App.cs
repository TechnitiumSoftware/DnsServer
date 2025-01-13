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
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace NxDomainOverride
{
    public sealed class App : IDnsApplication, IDnsPostProcessor
    {
        #region variables

        bool _enableOverride;
        uint _defaultTtl;
        Dictionary<string, string[]> _domainSetMap;
        Dictionary<string, Set> _sets;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            // No resources to dispose
        }

        #endregion

        #region private

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            // Do not return the root zone
            return null;
        }

        private bool TryGetMappedSets(string domain, out string[] setNames)
        {
            domain = domain.ToLowerInvariant();
            string parent;

            do
            {
                if (_domainSetMap.TryGetValue(domain, out setNames))
                    return true;

                parent = GetParentZone(domain);
                if (parent is null)
                {
                    // Check wildcard domain mapping
                    if (_domainSetMap.TryGetValue("*", out setNames))
                        return true;

                    break;
                }

                domain = "*." + parent;

                if (_domainSetMap.TryGetValue(domain, out setNames))
                    return true;

                domain = parent;
            }
            while (true);

            return false;
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            try
            {
                using JsonDocument jsonDocument = JsonDocument.Parse(config);
                JsonElement jsonConfig = jsonDocument.RootElement;

                _enableOverride = jsonConfig.GetPropertyValue("enableOverride", true);
                _defaultTtl = jsonConfig.GetPropertyValue("defaultTtl", 300u);

                _domainSetMap = jsonConfig.ReadObjectAsMap("domainSetMap", delegate (string domain, JsonElement jsonSets)
                {
                    string[] sets = jsonSets.GetArray();
                    return new Tuple<string, string[]>(domain.ToLowerInvariant(), sets);
                });

                _sets = jsonConfig.ReadArrayAsMap("sets", delegate (JsonElement jsonSet)
                {
                    Set set = new Set(jsonSet);
                    return new Tuple<string, Set>(set.Name, set);
                });

                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to initialize configuration.", ex);
            }
        }

        public Task<DnsDatagram> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (!_enableOverride)
                return Task.FromResult(response);

            if (response.DnssecOk || response.OPCODE != DnsOpcode.StandardQuery || response.RCODE != DnsResponseCode.NxDomain)
                return Task.FromResult(response);

            // Ensure there's at least one question
            if (request.Question.Count == 0)
                return Task.FromResult(response);

            DnsQuestionRecord question = request.Question[0];

            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    break;

                default:
                    // Return NO DATA response for unsupported query types
                    return Task.FromResult(new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, response.Truncation, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, DnsResponseCode.NoError, response.Question, response.Answer, response.Authority, response.Additional) { Tag = response.Tag });
            }

            string nxDomain = question.Name;

            foreach (DnsResourceRecord record in response.Answer)
            {
                if (record.Type == DnsResourceRecordType.CNAME && record.RDATA is DnsCNAMERecordData cnameData)
                    nxDomain = cnameData.Domain;
            }

            if (!TryGetMappedSets(nxDomain, out string[] setNames))
                return Task.FromResult(response);

            List<DnsResourceRecord> newAnswer = new List<DnsResourceRecord>(response.Answer);

            foreach (string setName in setNames)
            {
                if (_sets.TryGetValue(setName, out Set set))
                {
                    switch (question.Type)
                    {
                        case DnsResourceRecordType.A:
                            foreach (DnsResourceRecordData rdata in set.RecordDataAddresses)
                            {
                                if (rdata is DnsARecordData)
                                    newAnswer.Add(new DnsResourceRecord(nxDomain, DnsResourceRecordType.A, DnsClass.IN, _defaultTtl, rdata));
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            foreach (DnsResourceRecordData rdata in set.RecordDataAddresses)
                            {
                                if (rdata is DnsAAAARecordData)
                                    newAnswer.Add(new DnsResourceRecord(nxDomain, DnsResourceRecordType.AAAA, DnsClass.IN, _defaultTtl, rdata));
                            }
                            break;

                        default:
                            throw new InvalidOperationException("Unsupported resource record type.");
                    }
                }
            }

            return Task.FromResult(new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, response.Truncation, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, DnsResponseCode.NoError, response.Question, newAnswer) { Tag = response.Tag });
        }

        #endregion

        #region properties

        public string Description
        { get { return "Overrides NX Domain response with custom A/AAAA record response for configured domain names."; } }

        #endregion

        class Set
        {
            #region variables

            readonly string _name;
            readonly DnsResourceRecordData[] _rdataAddresses;

            #endregion

            #region constructor

            public Set(JsonElement jsonSet)
            {
                if (!jsonSet.TryGetProperty("name", out JsonElement nameElement) || !jsonSet.TryGetProperty("addresses", out JsonElement addressesElement))
                    throw new ArgumentException("Invalid set configuration.");

                _name = nameElement.GetString();
                _rdataAddresses = addressesElement.ReadArray<DnsResourceRecordData>("addresses", delegate (string item)
                {
                    IPAddress address = IPAddress.Parse(item);

                    switch (address.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            return new DnsARecordData(address);

                        case AddressFamily.InterNetworkV6:
                            return new DnsAAAARecordData(address);

                        default:
                            throw new NotSupportedException("Address family not supported: " + address.AddressFamily.ToString());
                    }
                });
            }

            #endregion

            #region properties

            public string Name => _name;

            public DnsResourceRecordData[] RecordDataAddresses => _rdataAddresses;

            #endregion
        }
    }
}
