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
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace Failover
{
    public sealed class CNAME : IDnsApplication, IDnsAppRecordRequestHandler
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

        private DnsResourceRecord[] GetAnswers(string domain, DnsQuestionRecord question, string zoneName, uint appRecordTtl, string healthCheck, Uri healthCheckUrl)
        {
            DnsResourceRecordType healthCheckRecordType;

            if (question.Type == DnsResourceRecordType.AAAA)
                healthCheckRecordType = DnsResourceRecordType.AAAA;
            else
                healthCheckRecordType = DnsResourceRecordType.A;

            HealthCheckResponse response = _healthService.QueryStatus(domain, healthCheckRecordType, healthCheck, healthCheckUrl, true);
            switch (response.Status)
            {
                case HealthStatus.Unknown:
                    if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                        return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, 10, new DnsANAMERecordData(domain)) }; //use ANAME
                    else
                        return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, 10, new DnsCNAMERecordData(domain)) };

                case HealthStatus.Healthy:
                    if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                        return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, appRecordTtl, new DnsANAMERecordData(domain)) }; //use ANAME
                    else
                        return new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, appRecordTtl, new DnsCNAMERecordData(domain)) };
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

                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, appRecordTtl, new DnsTXTRecordData(text)));
            }

            {
                HealthCheckResponse response = _healthService.QueryStatus(domain, DnsResourceRecordType.AAAA, healthCheck, healthCheckUrl, false);

                string text = "app=failover; cnameType=" + type.ToString() + "; domain=" + domain + "; qType: AAAA; healthCheck=" + healthCheck + (healthCheckUrl is null ? "" : "; healthCheckUrl=" + healthCheckUrl.AbsoluteUri) + "; healthStatus=" + response.Status.ToString() + ";";

                if (response.Status == HealthStatus.Failed)
                    text += " failureReason=" + response.FailureReason + ";";

                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, appRecordTtl, new DnsTXTRecordData(text)));
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

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];

            if (!question.Name.Equals(appRecordName, StringComparison.OrdinalIgnoreCase) && !appRecordName.StartsWith('*'))
                return Task.FromResult<DnsDatagram>(null);

            using JsonDocument jsonDocument = JsonDocument.Parse(appRecordData);
            JsonElement jsonAppRecordData = jsonDocument.RootElement;

            string healthCheck = jsonAppRecordData.GetPropertyValue("healthCheck", null);
            Uri healthCheckUrl = null;

            if (_healthService.HealthChecks.TryGetValue(healthCheck, out HealthCheck hc) && ((hc.Type == HealthCheckType.Https) || (hc.Type == HealthCheckType.Http)) && (hc.Url is null))
            {
                //read health check url only for http/https type checks and only when app config does not have an url configured
                if (jsonAppRecordData.TryGetProperty("healthCheckUrl", out JsonElement jsonHealthCheckUrl) && (jsonHealthCheckUrl.ValueKind != JsonValueKind.Null))
                {
                    healthCheckUrl = new Uri(jsonHealthCheckUrl.GetString());
                }
                else
                {
                    if (hc.Type == HealthCheckType.Https)
                        healthCheckUrl = new Uri("https://" + question.Name);
                    else
                        healthCheckUrl = new Uri("http://" + question.Name);
                }
            }

            IReadOnlyList<DnsResourceRecord> answers = null;

            if (question.Type == DnsResourceRecordType.TXT)
            {
                bool allowTxtStatus = jsonAppRecordData.GetPropertyValue("allowTxtStatus", false);
                if (!allowTxtStatus)
                    return Task.FromResult<DnsDatagram>(null);

                List<DnsResourceRecord> txtAnswers = new List<DnsResourceRecord>();

                if (jsonAppRecordData.TryGetProperty("primary", out JsonElement jsonPrimary))
                    GetStatusAnswers(jsonPrimary.GetString(), FailoverType.Primary, question, 30, healthCheck, healthCheckUrl, txtAnswers);

                if (jsonAppRecordData.TryGetProperty("secondary", out JsonElement jsonSecondary))
                {
                    foreach (JsonElement jsonDomain in jsonSecondary.EnumerateArray())
                        GetStatusAnswers(jsonDomain.GetString(), FailoverType.Secondary, question, 30, healthCheck, healthCheckUrl, txtAnswers);
                }

                answers = txtAnswers;
            }
            else
            {
                if (jsonAppRecordData.TryGetProperty("primary", out JsonElement jsonPrimary))
                    answers = GetAnswers(jsonPrimary.GetString(), question, zoneName, appRecordTtl, healthCheck, healthCheckUrl);

                if (answers is null)
                {
                    if (jsonAppRecordData.TryGetProperty("secondary", out JsonElement jsonSecondary))
                    {
                        foreach (JsonElement jsonDomain in jsonSecondary.EnumerateArray())
                        {
                            answers = GetAnswers(jsonDomain.GetString(), question, zoneName, appRecordTtl, healthCheck, healthCheckUrl);
                            if (answers is not null)
                                break;
                        }
                    }

                    if (answers is null)
                    {
                        if (!jsonAppRecordData.TryGetProperty("serverDown", out JsonElement jsonServerDown) || (jsonServerDown.ValueKind == JsonValueKind.Null))
                            return Task.FromResult<DnsDatagram>(null);

                        string serverDown = jsonServerDown.GetString();

                        if (question.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase)) //check for zone apex
                            answers = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANAME, DnsClass.IN, 30, new DnsANAMERecordData(serverDown)) }; //use ANAME
                        else
                            answers = new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, 30, new DnsCNAMERecordData(serverDown)) };
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
