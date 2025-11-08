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
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace Dns64
{
    // DNS64: DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers
    // https://www.rfc-editor.org/rfc/rfc6147

    public sealed class App : IDnsApplication, IDnsPostProcessor, IDnsAuthoritativeRequestHandler, IDnsApplicationPreference
    {
        #region variables

        IDnsServer _dnsServer;

        byte _appPreference;

        bool _enableDns64;
        Dictionary<NetworkAddress, string> _networkGroupMap;
        Dictionary<string, Group> _groups;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _appPreference = Convert.ToByte(jsonConfig.GetPropertyValue("appPreference", 30));

            _enableDns64 = jsonConfig.GetProperty("enableDns64").GetBoolean();

            _networkGroupMap = jsonConfig.ReadObjectAsMap("networkGroupMap", delegate (string network, JsonElement group)
            {
                if (!NetworkAddress.TryParse(network, out NetworkAddress networkAddress))
                    throw new InvalidOperationException("Network group map contains an invalid network address: " + network);

                return new Tuple<NetworkAddress, string>(networkAddress, group.GetString());
            });

            _groups = jsonConfig.ReadArrayAsMap("groups", delegate (JsonElement jsonGroup)
            {
                Group group = new Group(jsonGroup);
                return new Tuple<string, Group>(group.Name, group);
            });

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

            List<DnsResourceRecord> newAnswer = new List<DnsResourceRecord>(response.Answer.Count);

            bool synthesizeAAAA = true;

            if (group.ExcludedIpv6.Length == 0)
            {
                //no exclusions configured
                foreach (DnsResourceRecord answer in response.Answer)
                {
                    newAnswer.Add(answer);

                    if (answer.Type == DnsResourceRecordType.AAAA)
                        synthesizeAAAA = false; //found an AAAA record so no need to synthesize AAAA
                }
            }
            else
            {
                //check for exclusions
                foreach (DnsResourceRecord answer in response.Answer)
                {
                    if (answer.Type != DnsResourceRecordType.AAAA)
                    {
                        //keep non-AAAA record, most probably a CNAME record, in answer list
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
            }

            if (!synthesizeAAAA)
                return new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, response.Truncation, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, response.RCODE, response.Question, newAnswer, response.Authority, response.Additional) { Tag = response.Tag };

            DnsDatagram newResponse = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN), 2000);

            uint soaTtl;
            {
                DnsResourceRecord soa = response.FindFirstAuthorityRecord();
                if ((soa is not null) && (soa.Type == DnsResourceRecordType.SOA))
                    soaTtl = soa.TTL;
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

                newAnswer.Add(new DnsResourceRecord(answer.Name, DnsResourceRecordType.AAAA, answer.Class, Math.Min(answer.TTL, soaTtl), new DnsAAAARecordData(ipv6Address)));
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

            IPAddress ipv6Address = IPAddressExtensions.ParseReverseDomain(question.Name);
            if (ipv6Address.AddressFamily != AddressFamily.InterNetworkV6)
                return Task.FromResult<DnsDatagram>(null);

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
            IReadOnlyList<DnsResourceRecord> answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, question.Class, 600, new DnsCNAMERecordData(ipv4Address.GetReverseDomain())) };

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answer));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Enables DNS64 function for both authoritative and recursive resolver responses for use by IPv6 only clients."; } }

        public byte Preference
        { get { return _appPreference; } }

        #endregion

        class Group
        {
            #region variables

            readonly string _name;
            readonly bool _enableDns64;
            readonly Dictionary<NetworkAddress, NetworkAddress> _dns64PrefixMap;
            readonly NetworkAddress[] _excludedIpv6;

            #endregion

            #region constructor

            public Group(JsonElement jsonGroup)
            {
                _name = jsonGroup.GetProperty("name").GetString();
                _enableDns64 = jsonGroup.GetProperty("enableDns64").GetBoolean();

                _dns64PrefixMap = jsonGroup.ReadObjectAsMap("dns64PrefixMap", delegate (string strNetwork, JsonElement jsonDns64Prefix)
                {
                    string strDns64Prefix = jsonDns64Prefix.GetString();

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

                    return new Tuple<NetworkAddress, NetworkAddress>(network, dns64Prefix);
                });

                _excludedIpv6 = jsonGroup.ReadArray("excludedIpv6", delegate (string strNetworkAddress)
                {
                    NetworkAddress networkAddress = NetworkAddress.Parse(strNetworkAddress);
                    if (networkAddress.Address.AddressFamily != AddressFamily.InterNetworkV6)
                        throw new InvalidOperationException("An IPv6 network address is expected for 'excludedIpv6' array.");

                    return networkAddress;
                });
            }

            #endregion

            #region properties

            public string Name
            { get { return _name; } }

            public bool EnableDns64
            { get { return _enableDns64; } }

            public Dictionary<NetworkAddress, NetworkAddress> Dns64PrefixMap
            { get { return _dns64PrefixMap; } }

            public NetworkAddress[] ExcludedIpv6
            { get { return _excludedIpv6; } }

            #endregion
        }
    }
}