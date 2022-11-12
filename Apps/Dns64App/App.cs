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
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace Dns64
{
    // DNS64: DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers
    // https://www.rfc-editor.org/rfc/rfc6147

    public class App : IDnsApplication, IDnsPostProcessor, IDnsAuthoritativeRequestHandler
    {
        #region variables

        IDnsServer _dnsServer;

        bool _enableDns64;
        IReadOnlyDictionary<NetworkAddress, string> _networkGroupMap;
        IReadOnlyDictionary<string, Group> _groups;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region private

        private static IPAddress GetIpv6AddressFromPtrDomain(string ptrDomain)
        {
            //B.E.3.0.B.3.B.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.B.9.F.F.4.6.0.0.ip6.arpa
            //64:ff9b::8b3b:3eb

            string[] parts = ptrDomain.Split('.');
            byte[] buffer = new byte[16];

            for (int i = 0, j = parts.Length - 3; (i < 16) && (j > 0); i++, j -= 2)
                buffer[i] = (byte)(byte.Parse(parts[j], NumberStyles.HexNumber) << 4 | byte.Parse(parts[j - 1], NumberStyles.HexNumber));

            return new IPAddress(buffer);
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            dynamic jsonConfig = JsonConvert.DeserializeObject(config);

            _enableDns64 = jsonConfig.enableDns64.Value;

            {
                Dictionary<NetworkAddress, string> networkGroupMap = new Dictionary<NetworkAddress, string>();

                foreach (dynamic jsonProperty in jsonConfig.networkGroupMap)
                {
                    string network = jsonProperty.Name;
                    string group = jsonProperty.Value;

                    if (!NetworkAddress.TryParse(network, out NetworkAddress networkAddress))
                        throw new InvalidOperationException("Network group map contains an invalid network address: " + network);

                    if (networkAddress.Address.AddressFamily == AddressFamily.InterNetwork)
                        throw new InvalidOperationException("Network group map can only have IPv6 network addresses: " + network);

                    networkGroupMap.Add(networkAddress, group);
                }

                _networkGroupMap = networkGroupMap;
            }

            {
                Dictionary<string, Group> groups = new Dictionary<string, Group>();

                foreach (dynamic jsonGroup in jsonConfig.groups)
                {
                    Group group = new Group(jsonGroup);
                    groups.Add(group.Name, group);
                }

                _groups = groups;
            }

            return Task.CompletedTask;
        }

        public async Task<DnsDatagram> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (!_enableDns64)
                return response;

            if (request.DnssecOk)
                return response;

            switch (response.RCODE)
            {
                case DnsResponseCode.NxDomain:
                    return response;
            }

            DnsQuestionRecord question = request.Question[0];
            if (question.Type != DnsResourceRecordType.AAAA)
                return response;

            IPAddress remoteIP = remoteEP.Address;
            NetworkAddress network = null;
            string groupName = null;

            foreach (KeyValuePair<NetworkAddress, string> entry in _networkGroupMap)
            {
                if (entry.Key.Contains(remoteIP) && ((network is null) || (entry.Key.PrefixLength > network.PrefixLength)))
                {
                    network = entry.Key;
                    groupName = entry.Value;
                }
            }

            if ((groupName is null) || !_groups.TryGetValue(groupName, out Group group) || !group.EnableDns64)
                return response;

            List<DnsResourceRecord> newAnswer = new List<DnsResourceRecord>();

            bool synthesizeAAAA = true;

            foreach (DnsResourceRecord answer in response.Answer)
            {
                if (answer.Type != DnsResourceRecordType.AAAA)
                {
                    newAnswer.Add(answer);
                    continue;
                }

                IPAddress ipv6Address = (answer.RDATA as DnsAAAARecordData).Address;

                foreach (NetworkAddress excludedIpv6 in group.ExcludedIpv6)
                {
                    if (!excludedIpv6.Contains(ipv6Address))
                    {
                        //found non-excluded AAAA record so no need to synthesize AAAA
                        newAnswer.Add(answer);
                        synthesizeAAAA = false;
                    }
                }
            }

            if (!synthesizeAAAA)
                return new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, response.Truncation, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, response.RCODE, response.Question, newAnswer, response.Authority, response.Additional) { Tag = response.Tag };

            DnsDatagram newResponse = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(question.Name, DnsResourceRecordType.A, question.Class), 2000);

            uint soaTtl;
            {
                DnsResourceRecord soa = response.FindFirstAuthorityRecord();
                if ((soa is not null) && (soa.Type == DnsResourceRecordType.SOA))
                    soaTtl = soa.TtlValue;
                else
                    soaTtl = 600;
            }

            foreach (DnsResourceRecord answer in newResponse.Answer)
            {
                if (answer.Type != DnsResourceRecordType.A)
                    continue;

                IPAddress ipv4Address = (answer.RDATA as DnsARecordData).Address;
                NetworkAddress ipv4Network = null;
                NetworkAddress dns64Prefix = null;

                foreach (KeyValuePair<NetworkAddress, NetworkAddress> dns64PrefixEntry in group.Dns64PrefixMap)
                {
                    if (dns64PrefixEntry.Key.Contains(ipv4Address) && ((ipv4Network is null) || (dns64PrefixEntry.Key.PrefixLength > ipv4Network.PrefixLength)))
                    {
                        ipv4Network = dns64PrefixEntry.Key;
                        dns64Prefix = dns64PrefixEntry.Value;
                    }
                }

                if (dns64Prefix is null)
                    continue;

                IPAddress ipv6Address = ipv4Address.MapToIPv6(dns64Prefix);

                newAnswer.Add(new DnsResourceRecord(answer.Name, DnsResourceRecordType.AAAA, answer.Class, Math.Min(answer.TtlValue, soaTtl), new DnsAAAARecordData(ipv6Address)));
            }

            return new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, response.Truncation, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, newResponse.RCODE, response.Question, newAnswer, newResponse.Authority, newResponse.Additional) { Tag = response.Tag };
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (!_enableDns64)
                return Task.FromResult<DnsDatagram>(null);

            if (request.DnssecOk)
                return Task.FromResult<DnsDatagram>(null);

            DnsQuestionRecord question = request.Question[0];
            if ((question.Type != DnsResourceRecordType.PTR) || !question.Name.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult<DnsDatagram>(null);

            IPAddress remoteIP = remoteEP.Address;
            NetworkAddress network = null;
            string groupName = null;

            foreach (KeyValuePair<NetworkAddress, string> entry in _networkGroupMap)
            {
                if (entry.Key.Contains(remoteIP) && ((network is null) || (entry.Key.PrefixLength > network.PrefixLength)))
                {
                    network = entry.Key;
                    groupName = entry.Value;
                }
            }

            if ((groupName is null) || !_groups.TryGetValue(groupName, out Group group) || !group.EnableDns64)
                return Task.FromResult<DnsDatagram>(null);

            IPAddress ipv6Address = GetIpv6AddressFromPtrDomain(question.Name);
            NetworkAddress dns64Prefix = null;

            foreach (KeyValuePair<NetworkAddress, NetworkAddress> dns64PrefixEntry in group.Dns64PrefixMap)
            {
                if ((dns64PrefixEntry.Value is not null) && dns64PrefixEntry.Value.Contains(ipv6Address))
                {
                    dns64Prefix = dns64PrefixEntry.Value;
                    break;
                }
            }

            if (dns64Prefix is null)
                return Task.FromResult<DnsDatagram>(null);

            IPAddress ipv4Address = ipv6Address.MapToIPv4(dns64Prefix.PrefixLength);
            DnsQuestionRecord dummyPtrQuestion = new DnsQuestionRecord(ipv4Address, question.Class);
            IReadOnlyList<DnsResourceRecord> answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, question.Class, 600, new DnsCNAMERecordData(dummyPtrQuestion.Name)) };

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answer));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Enabled DNS64 function for both authoritative and recursive resolver responses."; } }

        #endregion

        class Group
        {
            #region variables

            readonly string _name;
            readonly bool _enableDns64;
            readonly IReadOnlyDictionary<NetworkAddress, NetworkAddress> _dns64PrefixMap;
            readonly IReadOnlyCollection<NetworkAddress> _excludedIpv6;

            #endregion

            #region constructor

            public Group(dynamic jsonGroup)
            {
                _name = jsonGroup.name.Value;
                _enableDns64 = jsonGroup.enableDns64.Value;

                {
                    Dictionary<NetworkAddress, NetworkAddress> dns64PrefixMap = new Dictionary<NetworkAddress, NetworkAddress>();

                    foreach (dynamic jsonProperty in jsonGroup.dns64PrefixMap)
                    {
                        string strNetwork = jsonProperty.Name;
                        string strDns64Prefix = jsonProperty.Value;

                        NetworkAddress network = NetworkAddress.Parse(strNetwork);
                        NetworkAddress dns64Prefix = null;

                        if (strDns64Prefix is not null)
                        {
                            dns64Prefix = NetworkAddress.Parse(strDns64Prefix);

                            switch (dns64Prefix.PrefixLength)
                            {
                                case 32:
                                case 40:
                                case 48:
                                case 56:
                                case 64:
                                case 96:
                                    break;

                                default:
                                    throw new NotSupportedException("DNS64 prefix can have only the following prefixes: 32, 40, 48, 56, 64, or 96.");
                            }
                        }

                        dns64PrefixMap.Add(network, dns64Prefix);
                    }

                    _dns64PrefixMap = dns64PrefixMap;
                }

                {
                    List<NetworkAddress> excludedIpv6 = new List<NetworkAddress>();

                    foreach (dynamic jsonItem in jsonGroup.excludedIpv6)
                    {
                        NetworkAddress networkAddress = NetworkAddress.Parse(jsonItem.Value);
                        if (networkAddress.Address.AddressFamily != AddressFamily.InterNetworkV6)
                            throw new InvalidOperationException("An IPv6 network address is expected for 'excludedIpv6' array.");

                        excludedIpv6.Add(networkAddress);
                    }

                    _excludedIpv6 = excludedIpv6;
                }
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            public bool EnableDns64
            { get { return _enableDns64; } }

            public IReadOnlyDictionary<NetworkAddress, NetworkAddress> Dns64PrefixMap
            { get { return _dns64PrefixMap; } }

            public IReadOnlyCollection<NetworkAddress> ExcludedIpv6
            { get { return _excludedIpv6; } }

            #endregion
        }
    }
}