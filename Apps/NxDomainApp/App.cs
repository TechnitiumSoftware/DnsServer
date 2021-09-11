/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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

using DnsApplicationCommon;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace NxDomain
{
    public class App : IDnsAuthoritativeRequestHandler
    {
        #region variables

        DnsSOARecord _soaRecord;

        IReadOnlyDictionary<string, object> _blockListZone;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region private

        private static string PopWord(ref string line)
        {
            if (line.Length == 0)
                return line;

            line = line.TrimStart(' ', '\t');

            int i = line.IndexOfAny(new char[] { ' ', '\t' });
            string word;

            if (i < 0)
            {
                word = line;
                line = "";
            }
            else
            {
                word = line.Substring(0, i);
                line = line.Substring(i + 1);
            }

            return word;
        }

        private static Queue<string> ReadDomainNames(string config)
        {
            Queue<string> domains = new Queue<string>();

            using (StringReader sR = new StringReader(config))
            {
                //parse config file
                string line;
                string hostname;

                while (true)
                {
                    line = sR.ReadLine();
                    if (line == null)
                        break; //eof

                    line = line.TrimStart(' ', '\t');

                    if (line.Length == 0)
                        continue; //skip empty line

                    if (line.StartsWith("#"))
                        continue; //skip comment line

                    hostname = PopWord(ref line).Trim('.').ToLower();

                    if (!DnsClient.IsDomainNameValid(hostname))
                        continue;

                    domains.Enqueue(hostname);
                }
            }

            return domains;
        }

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
            domain = domain.ToLower();

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
            _soaRecord = new DnsSOARecord(dnsServer.ServerDomain, "hostadmin." + dnsServer.ServerDomain, 1, 14400, 3600, 604800, 60);

            Queue<string> domainQueue = ReadDomainNames(config);
            Dictionary<string, object> blockListZone = new Dictionary<string, object>(domainQueue.Count);
            object dummyValue = new object();

            foreach (string domain in domainQueue)
                blockListZone[domain] = dummyValue;

            _blockListZone = blockListZone;

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            DnsQuestionRecord question = request.Question[0];

            if (!IsZoneBlocked(question.Name, out string blockedDomain))
                return Task.FromResult<DnsDatagram>(null);

            if (question.Type == DnsResourceRecordType.TXT)
            {
                //return meta data
                DnsResourceRecord[] answer = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, 60, new DnsTXTRecord("blockList=nx-domain-app; domain=" + blockedDomain)) };

                return Task.FromResult(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answer) { Tag = DnsServerResponseType.Blocked });
            }
            else
            {
                string parentDomain = GetParentZone(blockedDomain);
                if (parentDomain is null)
                    parentDomain = string.Empty;

                IReadOnlyList<DnsResourceRecord> authority = new DnsResourceRecord[] { new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, 60, _soaRecord) };

                return Task.FromResult(new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NxDomain, request.Question, null, authority) { Tag = DnsServerResponseType.Blocked });
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Blocks domain names with NX Domain response."; } }

        #endregion
    }
}
