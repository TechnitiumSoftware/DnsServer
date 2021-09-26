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

using DnsServerCore.ApplicationCommon;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace Failover
{
    public class CNAME : IDnsApplication, IDnsAppRecordRequestHandler
    {
        #region variables

        HealthService _healthService;

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            if (_healthService is not null)
                _healthService.Dispose();

            _disposed = true;
        }

        #endregion

        #region private

        private IReadOnlyList<DnsResourceRecord> GetAnswers(string domain, DnsQuestionRecord question, string zoneName, uint appRecordTtl, string healthCheck, Uri healthCheckUrl)
        {
            HealthCheckResponse response = _healthService.QueryStatus(domain, question.Type, healthCheck, healthCheckUrl, true);
            switch (response.Status)
            {
                case HealthStatus.Unknown:
                    if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                        return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, 30, new DnsANAMERecord(domain)) }; //use ANAME
                    else
                        return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, 30, new DnsCNAMERecord(domain)) };

                case HealthStatus.Healthy:
                    if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                        return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, appRecordTtl, new DnsANAMERecord(domain)) }; //use ANAME
                    else
                        return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, appRecordTtl, new DnsCNAMERecord(domain)) };
            }

            return null;
        }

        private void GetStatusAnswers(string domain, FailoverType type, DnsQuestionRecord question, uint appRecordTtl, string healthCheck, Uri healthCheckUrl, List<DnsResourceRecord> answers)
        {
            {
                HealthCheckResponse response = _healthService.QueryStatus(domain, DnsResourceRecordType.A, healthCheck, healthCheckUrl, false);

                string text = "app=failover; cnameType=" + type.ToString() + "; domain=" + domain + "; qType: A; healthCheck=" + healthCheck + (healthCheckUrl is null ? "" : "; healthCheckUrl=" + healthCheckUrl.AbsoluteUri) + "; healthStatus=" + response.Status.ToString() + ";";

                if (response.Status == HealthStatus.Failed)
                    text += " failureReason=" + response.FailureReason + ";";

                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, appRecordTtl, new DnsTXTRecord(text)));
            }

            {
                HealthCheckResponse response = _healthService.QueryStatus(domain, DnsResourceRecordType.AAAA, healthCheck, healthCheckUrl, false);

                string text = "app=failover; cnameType=" + type.ToString() + "; domain=" + domain + "; qType: AAAA; healthCheck=" + healthCheck + (healthCheckUrl is null ? "" : "; healthCheckUrl=" + healthCheckUrl.AbsoluteUri) + "; healthStatus=" + response.Status.ToString() + ";";

                if (response.Status == HealthStatus.Failed)
                    text += " failureReason=" + response.FailureReason + ";";

                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, appRecordTtl, new DnsTXTRecord(text)));
            }
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            if (_healthService is null)
                _healthService = HealthService.Create(dnsServer);

            //let Address class initialize config

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];

            dynamic jsonAppRecordData = JsonConvert.DeserializeObject(appRecordData);

            string healthCheck = jsonAppRecordData.healthCheck?.Value;
            Uri healthCheckUrl = null;

            if (_healthService.HealthChecks.TryGetValue(healthCheck, out HealthCheck hc) && ((hc.Type == HealthCheckType.Https) || (hc.Type == HealthCheckType.Http)) && (hc.Url is null))
            {
                //read health check url only for http/https type checks and only when app config does not have an url configured
                if ((jsonAppRecordData.healthCheckUrl is not null) && (jsonAppRecordData.healthCheckUrl.Value is not null))
                {
                    healthCheckUrl = new Uri(jsonAppRecordData.healthCheckUrl.Value);
                }
                else
                {
                    if (hc.Type == HealthCheckType.Https)
                        healthCheckUrl = new Uri("https://" + question.Name);
                    else
                        healthCheckUrl = new Uri("http://" + question.Name);
                }
            }

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

                GetStatusAnswers(jsonAppRecordData.primary.Value, FailoverType.Primary, question, 30, healthCheck, healthCheckUrl, txtAnswers);

                foreach (dynamic jsonDomain in jsonAppRecordData.secondary)
                    GetStatusAnswers(jsonDomain.Value, FailoverType.Secondary, question, 30, healthCheck, healthCheckUrl, txtAnswers);

                answers = txtAnswers;
            }
            else
            {
                answers = GetAnswers(jsonAppRecordData.primary.Value, question, zoneName, appRecordTtl, healthCheck, healthCheckUrl);
                if (answers is null)
                {
                    foreach (dynamic jsonDomain in jsonAppRecordData.secondary)
                    {
                        answers = GetAnswers(jsonDomain.Value, question, zoneName, appRecordTtl, healthCheck, healthCheckUrl);
                        if (answers is not null)
                            break;
                    }

                    if (answers is null)
                    {
                        if ((jsonAppRecordData.serverDown is null) || (jsonAppRecordData.serverDown.Value is null))
                            return Task.FromResult<DnsDatagram>(null);

                        string serverDown = jsonAppRecordData.serverDown.Value;

                        if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                            answers = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, 30, new DnsANAMERecord(serverDown)) }; //use ANAME
                        else
                            answers = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, 30, new DnsCNAMERecord(serverDown)) };
                    }
                }
            }

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers));
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns CNAME record for primary domain name with a continous health check as configured in the app config. When the primary domain name is unhealthy, the app returns one of the secondary domain names in the given order of preference that is healthy. When none of the primary and secondary domain names are healthy, the app returns the server down domain name. The server down feature is expected to be used for showing a service status page and not to serve the actual content. Note that the app will return ANAME record for an APP record at zone apex.\n\nIf an URL is provided for the health check in the app's config then it will override the 'healthCheckUrl' parameter. When an URL is not provided in 'healthCheckUrl' parameter for 'http' or 'https' type health check, the domain name of the APP record will be used to auto generate an URL.\n\nSet 'allowTxtStatus' parameter to 'true' in your APP record data to allow checking health status by querying for TXT record."; } }

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
  ""serverDown"": ""status.example.org"",
  ""healthCheck"": ""tcp443"",
  ""healthCheckUrl"": null,
  ""allowTxtStatus"": false
}";
            }
        }

        #endregion
    }
}
