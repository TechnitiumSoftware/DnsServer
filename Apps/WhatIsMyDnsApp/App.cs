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
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace WhatIsMyDns
{
    public sealed class App : IDnsApplication, IDnsAppRecordRequestHandler
    {
        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            //do nothing
            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];

            if (!question.Name.Equals(appRecordName, StringComparison.OrdinalIgnoreCase) && !appRecordName.StartsWith('*'))
                return Task.FromResult<DnsDatagram>(null);

            DnsResourceRecord answer;

            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                    if (remoteEP.AddressFamily != AddressFamily.InterNetwork)
                        return Task.FromResult<DnsDatagram>(null);

                    answer = new DnsResourceRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN, appRecordTtl, new DnsARecordData(remoteEP.Address));
                    break;

                case DnsResourceRecordType.AAAA:
                    if (remoteEP.AddressFamily != AddressFamily.InterNetworkV6)
                        return Task.FromResult<DnsDatagram>(null);

                    answer = new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, DnsClass.IN, appRecordTtl, new DnsAAAARecordData(remoteEP.Address));
                    break;

                case DnsResourceRecordType.TXT:
                    answer = new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, DnsClass.IN, appRecordTtl, new DnsTXTRecordData(remoteEP.Address.ToString()));
                    break;

                default:
                    return Task.FromResult<DnsDatagram>(null);
            }

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, new DnsResourceRecord[] { answer }));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns the IP address of the user's DNS Server for A, AAAA, and TXT queries."; } }

        public string ApplicationRecordDataTemplate
        { get { return null; } }

        #endregion
    }
}
