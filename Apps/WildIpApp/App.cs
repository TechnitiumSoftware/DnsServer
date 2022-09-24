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
using System;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace WildIp
{
    public class App : IDnsApplication, IDnsAppRecordRequestHandler
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
            string qname = request.Question[0].Name;

            if (qname.Length == appRecordName.Length)
                return Task.FromResult<DnsDatagram>(null);

            DnsResourceRecord answer;

            switch (request.Question[0].Type)
            {
                case DnsResourceRecordType.A:
                    {
                        string subdomain = qname.Substring(0, qname.Length - appRecordName.Length);
                        string[] parts = subdomain.Split(new char[] { '.', '-' }, StringSplitOptions.RemoveEmptyEntries);
                        byte[] rawIp = new byte[4];
                        int i = 0;

                        for (int j = 0; (j < parts.Length) && (i < 4); j++)
                        {
                            if (byte.TryParse(parts[j], out byte x))
                                rawIp[i++] = x;
                        }

                        if (i < 4)
                            return Task.FromResult<DnsDatagram>(null);

                        IPAddress address = new IPAddress(rawIp);

                        answer = new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.A, DnsClass.IN, appRecordTtl, new DnsARecordData(address));
                    }
                    break;

                case DnsResourceRecordType.AAAA:
                    {
                        string subdomain = qname.Substring(0, qname.Length - appRecordName.Length - 1);
                        string[] parts = subdomain.Split(new char[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
                        IPAddress address = null;

                        foreach (string part in parts)
                        {
                            if (part.Contains('-') && IPAddress.TryParse(part.Replace('-', ':'), out address))
                                break;
                        }

                        if (address is null)
                            return Task.FromResult<DnsDatagram>(null);

                        answer = new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.AAAA, DnsClass.IN, appRecordTtl, new DnsAAAARecordData(address));
                    }
                    break;

                default:
                    return Task.FromResult<DnsDatagram>(null);
            }

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, new DnsResourceRecord[] { answer }));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns the IP address that was embedded in the subdomain name for A and AAAA queries. It works similar to sslip.io."; } }

        public string ApplicationRecordDataTemplate
        { get { return null; } }

        #endregion
    }
}
