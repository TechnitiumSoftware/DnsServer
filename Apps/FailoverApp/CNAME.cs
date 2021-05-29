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
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace Failover
{
    public class CNAME : IDnsApplicationRequestHandler
    {
        #region variables

        HealthMonitoringService _healthMonitor;

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            if (_healthMonitor is not null)
                _healthMonitor.Dispose();

            _disposed = true;
        }

        #endregion

        #region private

        private IReadOnlyList<DnsResourceRecord> GetAnswers(string domain, DnsQuestionRecord question, string zoneName, uint appRecordTtl, string healthCheck)
        {
            HealthCheckStatus status = _healthMonitor.QueryStatus(domain, question.Type, healthCheck, true);
            if (status is null)
            {
                if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                    return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, 30, new DnsANAMERecord(domain)) }; //use ANAME
                else
                    return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, 30, new DnsCNAMERecord(domain)) };
            }
            else if (status.IsHealthy)
            {
                if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                    return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, appRecordTtl, new DnsANAMERecord(domain)) }; //use ANAME
                else
                    return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, appRecordTtl, new DnsCNAMERecord(domain)) };
            }

            return null;
        }

        private void GetStatusAnswers(string domain, bool primary, DnsQuestionRecord question, uint appRecordTtl, string healthCheck, List<DnsResourceRecord> answers)
        {
            {
                HealthCheckStatus status = _healthMonitor.QueryStatus(domain, DnsResourceRecordType.A, healthCheck, false);

                string text = "app=failover; cnameType=" + (primary ? "primary" : "secondary") + "; domain=" + domain + "; qType: A; healthCheck=" + healthCheck;

                if (status is null)
                    text += "; healthStatus=Unknown;";
                else if (status.IsHealthy)
                    text += "; healthStatus=Healthy;";
                else
                    text += "; healthStatus=Failed; failureReason=" + status.FailureReason + ";";

                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, appRecordTtl, new DnsTXTRecord(text)));
            }

            {
                HealthCheckStatus status = _healthMonitor.QueryStatus(domain, DnsResourceRecordType.AAAA, healthCheck, false);

                string text = "app=failover; cnameType=" + (primary ? "primary" : "secondary") + "; domain=" + domain + "; qType: AAAA; healthCheck=" + healthCheck;

                if (status is null)
                    text += "; healthStatus=Unknown;";
                else if (status.IsHealthy)
                    text += "; healthStatus=Healthy;";
                else
                    text += "; healthStatus=Failed; failureReason=" + status.FailureReason + ";";

                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, appRecordTtl, new DnsTXTRecord(text)));
            }
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            if (_healthMonitor is null)
                _healthMonitor = HealthMonitoringService.Create(dnsServer);

            //let Address class initialize config

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, string zoneName, uint appRecordTtl, string appRecordData, bool isRecursionAllowed, IDnsServer dnsServer)
        {
            DnsQuestionRecord question = request.Question[0];

            dynamic jsonAppRecordData = JsonConvert.DeserializeObject(appRecordData);

            string healthCheck = jsonAppRecordData.healthCheck?.Value;

            IReadOnlyList<DnsResourceRecord> answers;

            if (question.Type == DnsResourceRecordType.TXT)
            {
                bool allowTxtStatus;

                if (jsonAppRecordData.allowTxtStatus == null)
                    allowTxtStatus = false;
                else
                    allowTxtStatus = jsonAppRecordData.allowTxtStatus.Value;

                if (!allowTxtStatus)
                    return Task.FromResult<DnsDatagram>(null);

                List<DnsResourceRecord> txtAnswers = new List<DnsResourceRecord>();

                GetStatusAnswers(jsonAppRecordData.primary.Value, true, question, 30, healthCheck, txtAnswers);

                foreach (dynamic jsonDomain in jsonAppRecordData.secondary)
                    GetStatusAnswers(jsonDomain.Value, false, question, 30, healthCheck, txtAnswers);

                answers = txtAnswers;
            }
            else
            {
                answers = GetAnswers(jsonAppRecordData.primary.Value, question, zoneName, appRecordTtl, healthCheck);
                if (answers is null)
                {
                    foreach (dynamic jsonDomain in jsonAppRecordData.secondary)
                    {
                        answers = GetAnswers(jsonDomain.Value, question, zoneName, appRecordTtl, healthCheck);
                        if (answers is not null)
                            break;
                    }

                    if (answers is null)
                        return Task.FromResult<DnsDatagram>(null);
                }
            }

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns CNAME record for primary domain name with a continous health check as configured in the app config. When the primary domain name is unhealthy, the app returns one of the secondary domain names in order of preference that is healthy. Note that the app will return ANAME record for an APP record at zone apex.\n\nSet 'allowTxtStatus' to 'true' in your APP record data to allow checking health status by querying for TXT record."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""primary"": ""in.example.org"",
  ""secondary"": [
    ""sg.example.org"",
    ""eu.example.org""
  ],
  ""healthCheck"": ""tcp443"",
  ""allowTxtStatus"": false
}";
            }
        }

        #endregion
    }
}
