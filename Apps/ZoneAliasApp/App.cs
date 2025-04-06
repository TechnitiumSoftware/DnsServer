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
using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace ZoneAlias
{
    public sealed class App : IDnsApplication, IDnsAuthoritativeRequestHandler, IDnsApplicationPreference
    {
        #region variables

        IDnsServer _dnsServer;

        byte _appPreference;

        bool _enableAliasing;
        Dictionary<string, string> _aliases;

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

        private bool IsZoneAlias(string domain, out string zone, out string alias)
        {
            domain = domain.ToLowerInvariant();

            do
            {
                if (_aliases.TryGetValue(domain, out zone))
                {
                    //found alias
                    alias = domain;
                    return true;
                }

                domain = GetParentZone(domain);
            }
            while (domain is not null);

            alias = null;
            return false;
        }

        private static IReadOnlyList<DnsResourceRecord> ConvertRecords(IReadOnlyList<DnsResourceRecord> records, string zone, string alias)
        {
            if (records.Count == 0)
                return records;

            DnsResourceRecord[] newRecords = new DnsResourceRecord[records.Count];
            int j;

            for (int i = 0; i < records.Count; i++)
            {
                DnsResourceRecord record = records[i];

                j = record.Name.LastIndexOf(zone, StringComparison.OrdinalIgnoreCase);
                if (j == 0)
                    newRecords[i] = new DnsResourceRecord(alias, record.Type, record.Class, record.TTL, record.RDATA);
                else if (j > 0)
                    newRecords[i] = new DnsResourceRecord(string.Concat(record.Name.AsSpan(0, j), alias), record.Type, record.Class, record.TTL, record.RDATA);
                else
                    newRecords[i] = record;
            }

            return newRecords;
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _appPreference = Convert.ToByte(jsonConfig.GetPropertyValue("appPreference", 10));

            _enableAliasing = jsonConfig.GetPropertyValue("enableAliasing", true);

            if (jsonConfig.TryGetProperty("zoneAliases", out JsonElement jsonZoneAliases))
            {
                Dictionary<string, string> aliases = new Dictionary<string, string>();

                foreach (JsonProperty jsonZoneAlias in jsonZoneAliases.EnumerateObject())
                {
                    string zone = jsonZoneAlias.Name.ToLowerInvariant();

                    foreach (JsonElement jsonAlias in jsonZoneAlias.Value.EnumerateArray())
                        aliases.Add(jsonAlias.GetString().ToLowerInvariant(), zone);
                }

                aliases.TrimExcess();

                _aliases = aliases;
            }
            else
            {
                _aliases = null;
            }

            return Task.CompletedTask;
        }

        public async Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (!_enableAliasing || (_aliases is null))
                return null;

            DnsQuestionRecord question = request.Question[0];
            string qname = question.Name;

            if (!IsZoneAlias(qname, out string zone, out string alias))
                return null;

            string newQname;
            int i = qname.LastIndexOf(alias, StringComparison.OrdinalIgnoreCase);
            if (i == 0)
                newQname = zone;
            else if (i > 0)
                newQname = string.Concat(qname.AsSpan(0, i), zone);
            else
                return null;

            DnsQuestionRecord newQuestion = new DnsQuestionRecord(newQname, question.Type, question.Class);

            try
            {
                DnsDatagram response = await _dnsServer.DirectQueryAsync(newQuestion);

                IReadOnlyList<DnsResourceRecord> newAnswer = ConvertRecords(response.Answer, zone, alias);
                IReadOnlyList<DnsResourceRecord> newAuthority = ConvertRecords(response.Authority, zone, alias);
                IReadOnlyList<DnsResourceRecord> newAdditional = ConvertRecords(response.Additional, zone, alias);

                return new DnsDatagram(request.Identifier, true, request.OPCODE, response.AuthoritativeAnswer, response.Truncation, request.RecursionDesired, isRecursionAllowed, false, false, response.RCODE, request.Question, newAnswer, newAuthority, newAdditional) { Tag = response.Tag };
            }
            catch (TimeoutException)
            { }
            catch (Exception ex)
            {
                _dnsServer.WriteLog(ex);
            }

            return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.ServerFailure, request.Question);
        }

        #endregion

        #region properties

        public string Description
        { get { return "Allows configuring aliases for any zone (internal or external) such that they all return the same set of records."; } }

        public byte Preference
        { get { return _appPreference; } }

        #endregion
    }
}
