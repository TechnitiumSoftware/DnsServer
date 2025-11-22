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

using DnsServerCore.Dns;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Cluster
{
    class InternalDnsClient : IDnsClient
    {
        #region variables

        readonly DnsServer _dnsServer;
        readonly ClusterNode _clusterNode;
        readonly IReadOnlyList<IPAddress> _ipAddresses;

        #endregion

        #region constructor

        public InternalDnsClient(DnsServer dnsServer, ClusterNode clusterNode)
        {
            _dnsServer = dnsServer;
            _clusterNode = clusterNode;
        }

        public InternalDnsClient(DnsServer dnsServer, IReadOnlyList<IPAddress> ipAddresses)
        {
            _dnsServer = dnsServer;
            _ipAddresses = ipAddresses;
        }

        #endregion

        #region protected

        public Task<DnsDatagram> ResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken = default)
        {
            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    IReadOnlyList<IPAddress> ipAddresses;

                    if (_clusterNode is null)
                        ipAddresses = _ipAddresses;
                    else
                        ipAddresses = _clusterNode.IPAddresses;

                    List<DnsResourceRecord> answer = new List<DnsResourceRecord>();

                    foreach (IPAddress ipAddress in ipAddresses)
                    {
                        DnsResourceRecordData rdata = null;

                        switch (ipAddress.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                if (question.Type == DnsResourceRecordType.A)
                                    rdata = new DnsARecordData(ipAddress);

                                break;

                            case AddressFamily.InterNetworkV6:
                                if (question.Type == DnsResourceRecordType.AAAA)
                                    rdata = new DnsAAAARecordData(ipAddress);

                                break;
                        }

                        if (rdata is not null)
                            answer.Add(new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, 30, rdata));
                    }

                    return Task.FromResult(new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.NoError, [question], answer));

                default:
                    DirectDnsClient dnsClient = new DirectDnsClient(_dnsServer);
                    dnsClient.DnssecValidation = true;

                    //load latest trust anchors into dns client
                    _dnsServer.AuthZoneManager.LoadTrustAnchorsTo(dnsClient, question.Name, question.Type);

                    return dnsClient.ResolveAsync(question, cancellationToken);
            }
        }

        #endregion
    }
}
