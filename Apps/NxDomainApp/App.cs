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
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace NxDomain
{
    public sealed class App : IDnsApplication, IDnsAuthoritativeRequestHandler, IDnsApplicationPreference
    {
        #region variables

        byte _appPreference;

        IDnsServer _dnsServer;
        DnsSOARecordData _soaRecord;

        bool _enableBlocking;
        bool _allowTxtBlockingReport;

        Dictionary<string, object> _blockListZone;

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

        private bool IsZoneBlocked(string domain, out string blockedDomain)
        {
            domain = domain.ToLowerInvariant();

            do
            {
                if (_blockListZone.TryGetValue(domain, out _))
                {
                    //found zone blocked
                    blockedDomain = domain;
                    return true;
                }

                domain = GetParentZone(domain);
            }
            while (domain is not null);

            blockedDomain = null;
            return false;
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            _soaRecord = new DnsSOARecordData(dnsServer.ServerDomain, dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, 60);

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _appPreference = Convert.ToByte(jsonConfig.GetPropertyValue("appPreference", 20));

            _enableBlocking = jsonConfig.GetProperty("enableBlocking").GetBoolean();
            _allowTxtBlockingReport = jsonConfig.GetProperty("allowTxtBlockingReport").GetBoolean();
            _blockListZone = jsonConfig.ReadArrayAsMap("blocked", delegate (JsonElement jsonDomainName) { return new Tuple<string, object>(jsonDomainName.GetString(), null); });

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (!_enableBlocking)
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];

            if (!IsZoneBlocked(question.Name, out string blockedDomain))
                return Task.FromResult<DnsDatagram>(null);

            if (_allowTxtBlockingReport && (question.Type == DnsResourceRecordType.TXT))
            {
                //return meta data
                DnsResourceRecord[] answer = [new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecordData("source=nx-domain-app; domain=" + blockedDomain))];

                return Task.FromResult(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answer) { Tag = DnsServerResponseType.Blocked });
            }
            else
            {
                EDnsOption[] options = null;

                if (_allowTxtBlockingReport && (request.EDNS is not null))
                    options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, "source=nx-domain-app; domain=" + blockedDomain))];

                string parentDomain = GetParentZone(blockedDomain);
                if (parentDomain is null)
                    parentDomain = string.Empty;

                IReadOnlyList<DnsResourceRecord> authority = [new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord)];

                return Task.FromResult(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NxDomain, request.Question, null, authority, null, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options) { Tag = DnsServerResponseType.Blocked });
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Blocks configured domain names with a NX Domain response."; } }

        public byte Preference
        { get { return _appPreference; } }

        #endregion
    }
}
