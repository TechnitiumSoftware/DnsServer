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
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DefaultRecords
{
    public sealed class App : IDnsApplication, IDnsPostProcessor
    {
        #region variables

        IDnsServer _dnsServer;

        bool _enableDefaultRecords;
        uint _defaultTtl;
        Dictionary<string, string[]> _zoneSetMap;
        Dictionary<string, Set> _sets;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region private

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

        private bool TryGetMappedSets(string domain, out string zone, out string[] setNames)
        {
            domain = domain.ToLowerInvariant();

            string parent;

            do
            {
                if (_zoneSetMap.TryGetValue(domain, out setNames))
                {
                    zone = domain;
                    return true;
                }

                parent = GetParentZone(domain);
                if (parent is null)
                {
                    if (_zoneSetMap.TryGetValue("*", out setNames))
                    {
                        zone = "*";
                        return true;
                    }

                    break;
                }

                domain = "*." + parent;

                if (_zoneSetMap.TryGetValue(domain, out setNames))
                {
                    zone = domain;
                    return true;
                }

                domain = parent;
            }
            while (true);

            zone = null;
            return false;
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _enableDefaultRecords = jsonConfig.GetProperty("enableDefaultRecords").GetBoolean();
            _defaultTtl = jsonConfig.GetPropertyValue("defaultTtl", 3600u);

            _zoneSetMap = jsonConfig.ReadObjectAsMap("zoneSetMap", delegate (string zone, JsonElement jsonSets)
            {
                string[] sets = jsonSets.GetArray();

                return new Tuple<string, string[]>(zone.ToLowerInvariant(), sets);
            });

            _sets = jsonConfig.ReadArrayAsMap("sets", delegate (JsonElement jsonSet)
            {
                Set set = new Set(jsonSet);

                return new Tuple<string, Set>(set.Name, set);
            });

            return Task.CompletedTask;
        }

        public async Task<DnsDatagram> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (!_enableDefaultRecords)
                return response;

            if (!response.AuthoritativeAnswer || (response.OPCODE != DnsOpcode.StandardQuery))
                return response;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                case DnsResponseCode.NxDomain:
                    break;

                default:
                    return response;
            }

            DnsQuestionRecord question = request.Question[0];

            if (!TryGetMappedSets(question.Name, out string zone, out string[] setNames))
                return response;

            if (zone.StartsWith('*'))
            {
                DnsDatagram soaResponse = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(question.Name, DnsResourceRecordType.SOA, DnsClass.IN));
                if (soaResponse is null)
                    return response;

                if ((soaResponse.Answer.Count > 0) && (soaResponse.Answer[soaResponse.Answer.Count - 1].Type == DnsResourceRecordType.SOA))
                    zone = soaResponse.Answer[soaResponse.Answer.Count - 1].Name;
                else if ((soaResponse.Authority.Count > 0) && (soaResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                    zone = soaResponse.Authority[0].Name;
                else
                    return response;
            }

            StringBuilder sb = new StringBuilder();

            foreach (string setName in setNames)
            {
                if (_sets.TryGetValue(setName, out Set set) && set.Enable)
                {
                    foreach (string record in set.Records)
                        sb.AppendLine(record);
                }
            }

            if (sb.Length == 0)
                return response;

            StringReader sR = new StringReader(sb.ToString());
            List<DnsResourceRecord> records = ZoneFile.ReadZoneFileFromAsync(sR, zone, _defaultTtl).Sync();

            List<DnsResourceRecord> newAnswer = new List<DnsResourceRecord>(response.Answer.Count + records.Count);
            string qname = question.Name;

            if (response.Answer.Count > 0)
            {
                newAnswer.AddRange(response.Answer);

                DnsResourceRecord lastRR = response.Answer[response.Answer.Count - 1];
                if (lastRR.Type == DnsResourceRecordType.CNAME)
                    qname = (lastRR.RDATA as DnsCNAMERecordData).Domain;
            }

            foreach (DnsResourceRecord record in records)
            {
                if (record.Class != question.Class)
                    continue;

                if ((record.Type != question.Type) && (record.Type != DnsResourceRecordType.CNAME))
                    continue;

                if (!record.Name.Equals(qname, StringComparison.OrdinalIgnoreCase))
                    continue;

                newAnswer.Add(record);

                if (record.Type == DnsResourceRecordType.CNAME)
                    qname = (record.RDATA as DnsCNAMERecordData).Domain;
            }

            if (newAnswer.Count == response.Answer.Count)
                return response;

            return new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, response.Truncation, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, DnsResponseCode.NoError, response.Question, newAnswer) { Tag = response.Tag };
        }

        #endregion

        #region properties

        public string Description
        { get { return "Enables default records for configured local zones."; } }

        #endregion

        class Set
        {
            #region variables

            readonly string _name;
            readonly bool _enable;
            readonly string[] _records;

            #endregion

            #region constructor

            public Set(JsonElement jsonSet)
            {
                _name = jsonSet.GetProperty("name").GetString();
                _enable = jsonSet.GetProperty("enable").GetBoolean();
                _records = jsonSet.ReadArray("records");
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            public bool Enable
            { get { return _enable; } }

            public string[] Records
            { get { return _records; } }

            #endregion
        }
    }
}
