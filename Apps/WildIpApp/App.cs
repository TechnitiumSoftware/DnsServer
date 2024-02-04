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
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace WildIp
{
    public sealed class App : IDnsApplication, IDnsAppRecordRequestHandler
    {
        #region variables

        static readonly char[] aRecordSeparator = new char[] { '.', '-' };
        static readonly char[] aaaaRecordSeparator = new char[] { '.' };

        IDnsServer _dnsServer;

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

            return Task.CompletedTask;
        }

        public async Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            string qname = request.Question[0].Name;

            if (qname.Length == appRecordName.Length)
                return null;

            DnsResourceRecord answer = null;

            switch (request.Question[0].Type)
            {
                case DnsResourceRecordType.A:
                    {
                        string subdomain = qname.Substring(0, qname.Length - appRecordName.Length);
                        string[] parts = subdomain.Split(aRecordSeparator, StringSplitOptions.RemoveEmptyEntries);
                        byte[] rawIp = new byte[4];
                        int i = 0;

                        for (int j = 0; (j < parts.Length) && (i < 4); j++)
                        {
                            if (byte.TryParse(parts[j], out byte x))
                                rawIp[i++] = x;
                        }

                        if (i == 4)
                            answer = new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.A, DnsClass.IN, appRecordTtl, new DnsARecordData(new IPAddress(rawIp)));
                    }
                    break;

                case DnsResourceRecordType.AAAA:
                    {
                        string subdomain = qname.Substring(0, qname.Length - appRecordName.Length - 1);
                        string[] parts = subdomain.Split(aaaaRecordSeparator, StringSplitOptions.RemoveEmptyEntries);
                        IPAddress address = null;

                        foreach (string part in parts)
                        {
                            if (part.Contains('-') && IPAddress.TryParse(part.Replace('-', ':'), out address))
                            {
                                break;
                            }
                            else if (part.Length == 32)
                            {
                                string addr = null;

                                for (int i = 0; i < 32; i += 4)
                                {
                                    if (addr is null)
                                        addr = part.Substring(i, 4);
                                    else
                                        addr += string.Concat(":", part.AsSpan(i, 4));
                                }

                                if (IPAddress.TryParse(addr, out address))
                                    break;
                            }
                        }

                        if (address is not null)
                            answer = new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.AAAA, DnsClass.IN, appRecordTtl, new DnsAAAARecordData(address));
                    }
                    break;
            }

            if (answer is null)
            {
                //NODATA reponse
                DnsDatagram soaResponse = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(zoneName, DnsResourceRecordType.SOA, DnsClass.IN));

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, null, soaResponse.Answer);
            }

            return new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, new DnsResourceRecord[] { answer });
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
