/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.Dns.ResourceRecords;
using System;
using System.Collections.Generic;
using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class SpecialZoneManager
    {
        #region variables

        readonly DnsServer _dnsServer;

        readonly AuthZoneManager _zoneManager;

        readonly IReadOnlyCollection<string> _locallyServedZones =
            [
                //RFC 6303 Locally Served DNS Zones
                //RFC 1918 Zones
                "10.IN-ADDR.ARPA",
                "16.172.IN-ADDR.ARPA",
                "17.172.IN-ADDR.ARPA",
                "18.172.IN-ADDR.ARPA",
                "19.172.IN-ADDR.ARPA",
                "20.172.IN-ADDR.ARPA",
                "21.172.IN-ADDR.ARPA",
                "22.172.IN-ADDR.ARPA",
                "23.172.IN-ADDR.ARPA",
                "24.172.IN-ADDR.ARPA",
                "25.172.IN-ADDR.ARPA",
                "26.172.IN-ADDR.ARPA",
                "27.172.IN-ADDR.ARPA",
                "28.172.IN-ADDR.ARPA",
                "29.172.IN-ADDR.ARPA",
                "30.172.IN-ADDR.ARPA",
                "31.172.IN-ADDR.ARPA",
                "168.192.IN-ADDR.ARPA",

                //RFC 5735 and RFC 5737 Zones
                "0.IN-ADDR.ARPA",
                "127.IN-ADDR.ARPA",
                "254.169.IN-ADDR.ARPA",
                "2.0.192.IN-ADDR.ARPA",
                "100.51.198.IN-ADDR.ARPA",
                "113.0.203.IN-ADDR.ARPA",
                "255.255.255.255.IN-ADDR.ARPA",

                //Local IPv6 Unicast Addresses
                "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA",

                //IPv6 Locally Assigned Local Addresses
                "D.F.IP6.ARPA",

                //IPv6 Link-Local Addresses
                "8.E.F.IP6.ARPA",
                "9.E.F.IP6.ARPA",
                "A.E.F.IP6.ARPA",
                "B.E.F.IP6.ARPA",

                //IPv6 Example Prefix
                "8.B.D.0.1.0.0.2.IP6.ARPA",

                //RFC 6761 Special-Use Domain Names
                "localhost",

                //RFC 7793 Adding 100.64.0.0/10 Prefixes to the IPv4 Locally-Served DNS Zones Registry
                "64.100.IN-ADDR.ARPA",
                "65.100.IN-ADDR.ARPA",
                "66.100.IN-ADDR.ARPA",
                "67.100.IN-ADDR.ARPA",
                "68.100.IN-ADDR.ARPA",
                "69.100.IN-ADDR.ARPA",
                "70.100.IN-ADDR.ARPA",
                "71.100.IN-ADDR.ARPA",
                "72.100.IN-ADDR.ARPA",
                "73.100.IN-ADDR.ARPA",
                "74.100.IN-ADDR.ARPA",
                "75.100.IN-ADDR.ARPA",
                "76.100.IN-ADDR.ARPA",
                "77.100.IN-ADDR.ARPA",
                "78.100.IN-ADDR.ARPA",
                "79.100.IN-ADDR.ARPA",
                "80.100.IN-ADDR.ARPA",
                "81.100.IN-ADDR.ARPA",
                "82.100.IN-ADDR.ARPA",
                "83.100.IN-ADDR.ARPA",
                "84.100.IN-ADDR.ARPA",
                "85.100.IN-ADDR.ARPA",
                "86.100.IN-ADDR.ARPA",
                "87.100.IN-ADDR.ARPA",
                "88.100.IN-ADDR.ARPA",
                "89.100.IN-ADDR.ARPA",
                "90.100.IN-ADDR.ARPA",
                "91.100.IN-ADDR.ARPA",
                "92.100.IN-ADDR.ARPA",
                "93.100.IN-ADDR.ARPA",
                "94.100.IN-ADDR.ARPA",
                "95.100.IN-ADDR.ARPA",
                "96.100.IN-ADDR.ARPA",
                "97.100.IN-ADDR.ARPA",
                "98.100.IN-ADDR.ARPA",
                "99.100.IN-ADDR.ARPA",
                "100.100.IN-ADDR.ARPA",
                "101.100.IN-ADDR.ARPA",
                "102.100.IN-ADDR.ARPA",
                "103.100.IN-ADDR.ARPA",
                "104.100.IN-ADDR.ARPA",
                "105.100.IN-ADDR.ARPA",
                "106.100.IN-ADDR.ARPA",
                "107.100.IN-ADDR.ARPA",
                "108.100.IN-ADDR.ARPA",
                "109.100.IN-ADDR.ARPA",
                "110.100.IN-ADDR.ARPA",
                "111.100.IN-ADDR.ARPA",
                "112.100.IN-ADDR.ARPA",
                "113.100.IN-ADDR.ARPA",
                "114.100.IN-ADDR.ARPA",
                "115.100.IN-ADDR.ARPA",
                "116.100.IN-ADDR.ARPA",
                "117.100.IN-ADDR.ARPA",
                "118.100.IN-ADDR.ARPA",
                "119.100.IN-ADDR.ARPA",
                "120.100.IN-ADDR.ARPA",
                "121.100.IN-ADDR.ARPA",
                "122.100.IN-ADDR.ARPA",
                "123.100.IN-ADDR.ARPA",
                "124.100.IN-ADDR.ARPA",
                "125.100.IN-ADDR.ARPA",
                "126.100.IN-ADDR.ARPA",
                "127.100.IN-ADDR.ARPA",

                //RFC 8375 Special-Use Domain 'home.arpa.'
                "home.arpa",

                //RFC 9462 Discovery of Designated Resolvers
                "resolver.arpa",

                //RFC 9665 Service Registration Protocol for DNS-Based Service Discovery
                "service.arpa"
            ];

        readonly IReadOnlyCollection<string> _nonExistentZones =
            [
                //RFC 6761 Special-Use Domain Names
                "test",
                "invalid",

                //RFC 6762
                "local",

                //RFC 7686
                "onion"
            ];

        #endregion

        #region constructor

        public SpecialZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _zoneManager = new AuthZoneManager(dnsServer);

            //load special zones
            foreach (string specialReverseZone in _locallyServedZones)
            {
                DnsSOARecordDataExtended soaRecord = new DnsSOARecordDataExtended(specialReverseZone, _dnsServer.DefaultResponsiblePerson?.Address ?? "nobody.invalid", 1, 3600, 1200, 604800, _dnsServer.AuthZoneManager.DefaultSoaRecordTtl);
                DnsNSRecordDataExtended nsRecord = new DnsNSRecordDataExtended(specialReverseZone);

                _zoneManager.CreateSpecialPrimaryZone(specialReverseZone, soaRecord, nsRecord);
            }

            //special zone records
            _zoneManager.SetRecord("127.IN-ADDR.ARPA", new DnsResourceRecord("1.0.0.127.IN-ADDR.ARPA", DnsResourceRecordType.PTR, DnsClass.IN, _dnsServer.AuthZoneManager.DefaultRecordTtl, new DnsPTRRecordData("localhost")));
            _zoneManager.SetRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA", new DnsResourceRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA", DnsResourceRecordType.PTR, DnsClass.IN, _dnsServer.AuthZoneManager.DefaultRecordTtl, new DnsPTRRecordData("localhost")));

            _zoneManager.SetRecord("localhost", new DnsResourceRecord("localhost", DnsResourceRecordType.A, DnsClass.IN, _dnsServer.AuthZoneManager.DefaultRecordTtl, new DnsARecordData(IPAddress.Loopback)));
            _zoneManager.SetRecord("localhost", new DnsResourceRecord("localhost", DnsResourceRecordType.AAAA, DnsClass.IN, _dnsServer.AuthZoneManager.DefaultRecordTtl, new DnsAAAARecordData(IPAddress.IPv6Loopback)));
        }

        #endregion

        #region public

        public DnsDatagram Query(DnsDatagram request)
        {
            DnsDatagram response = _zoneManager.Query(request, true);
            if (response is not null)
                return response;

            if (request.Question.Count > 0)
            {
                DnsQuestionRecord question = request.Question[0];
                string qname = question.Name;

                foreach (string nonExistentZone in _nonExistentZones)
                {
                    if (qname.Equals(nonExistentZone, StringComparison.OrdinalIgnoreCase) || qname.EndsWith("." + nonExistentZone, StringComparison.OrdinalIgnoreCase))
                    {
                        if (question.Type == DnsResourceRecordType.DS)
                            return null; //allow resolving DS from parent zone

                        string parentZone = AuthZoneManager.GetParentZone(nonExistentZone) ?? "";
                        DnsResourceRecord soaRecord = new DnsResourceRecord(parentZone, DnsResourceRecordType.SOA, DnsClass.IN, _dnsServer.AuthZoneManager.DefaultSoaRecordTtl, new DnsSOARecordData(parentZone, _dnsServer.DefaultResponsiblePerson?.Address ?? "nobody.invalid", 1, 3600, 1200, 604800, _dnsServer.AuthZoneManager.DefaultSoaRecordTtl));

                        return new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, true, true, false, false, DnsResponseCode.NxDomain, request.Question, authority: [soaRecord]);
                    }
                }
            }

            return null;
        }

        public bool IsLocallyServedZone(string domain)
        {
            foreach (string locallyServedZone in _locallyServedZones)
            {
                if (domain.Equals(locallyServedZone, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + locallyServedZone, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            foreach (string nonExistentZone in _nonExistentZones)
            {
                if (domain.Equals(nonExistentZone, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + nonExistentZone, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        #endregion
    }
}
