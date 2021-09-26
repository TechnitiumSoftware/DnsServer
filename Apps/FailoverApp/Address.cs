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
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace Failover
{
    enum FailoverType
    {
        Unknown = 0,
        Primary = 1,
        Secondary = 2
    }

    public class Address : IDnsApplication, IDnsAppRecordRequestHandler
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

        private void GetAnswers(dynamic jsonAddresses, DnsQuestionRecord question, uint appRecordTtl, string healthCheck, Uri healthCheckUrl, List<DnsResourceRecord> answers)
        {
            if (jsonAddresses == null)
                return;

            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                    foreach (dynamic jsonAddress in jsonAddresses)
                    {
                        IPAddress address = IPAddress.Parse(jsonAddress.Value);

                        if (address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            HealthCheckResponse response = _healthService.QueryStatus(address, healthCheck, healthCheckUrl, true);
                            switch (response.Status)
                            {
                                case HealthStatus.Unknown:
                                    answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, 30, new DnsARecord(address)));
                                    break;

                                case HealthStatus.Healthy:
                                    answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, appRecordTtl, new DnsARecord(address)));
                                    break;
                            }
                        }
                    }
                    break;

                case DnsResourceRecordType.AAAA:
                    foreach (dynamic jsonAddress in jsonAddresses)
                    {
                        IPAddress address = IPAddress.Parse(jsonAddress.Value);

                        if (address.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            HealthCheckResponse response = _healthService.QueryStatus(address, healthCheck, healthCheckUrl, true);
                            switch (response.Status)
                            {
                                case HealthStatus.Unknown:
                                    answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, 30, new DnsAAAARecord(address)));
                                    break;

                                case HealthStatus.Healthy:
                                    answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, appRecordTtl, new DnsAAAARecord(address)));
                                    break;
                            }
                        }
                    }
                    break;
            }
        }

        private void GetStatusAnswers(dynamic jsonAddresses, FailoverType type, DnsQuestionRecord question, uint appRecordTtl, string healthCheck, Uri healthCheckUrl, List<DnsResourceRecord> answers)
        {
            if (jsonAddresses == null)
                return;

            foreach (dynamic jsonAddress in jsonAddresses)
            {
                IPAddress address = IPAddress.Parse(jsonAddress.Value);
                HealthCheckResponse response = _healthService.QueryStatus(address, healthCheck, healthCheckUrl, false);

                string text = "app=failover; addressType=" + type.ToString() + "; address=" + address.ToString() + "; healthCheck=" + healthCheck + (healthCheckUrl is null ? "" : "; healthCheckUrl=" + healthCheckUrl.AbsoluteUri) + "; healthStatus=" + response.Status.ToString() + ";";

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

            _healthService.Initialize(JsonConvert.DeserializeObject(config));

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, uint appRecordTtl, string appRecordData)
        {
            DnsQuestionRecord question = request.Question[0];
            switch (question.Type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
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

                        List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                        GetAnswers(jsonAppRecordData.primary, question, appRecordTtl, healthCheck, healthCheckUrl, answers);
                        if (answers.Count == 0)
                        {
                            GetAnswers(jsonAppRecordData.secondary, question, appRecordTtl, healthCheck, healthCheckUrl, answers);
                            if (answers.Count == 0)
                            {
                                if (jsonAppRecordData.serverDown is not null)
                                {
                                    if (question.Type == DnsResourceRecordType.A)
                                    {
                                        foreach (dynamic jsonAddress in jsonAppRecordData.serverDown)
                                        {
                                            IPAddress address = IPAddress.Parse(jsonAddress.Value);

                                            if (address.AddressFamily == AddressFamily.InterNetwork)
                                                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, 30, new DnsARecord(address)));
                                        }
                                    }
                                    else
                                    {
                                        foreach (dynamic jsonAddress in jsonAppRecordData.serverDown)
                                        {
                                            IPAddress address = IPAddress.Parse(jsonAddress.Value);

                                            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                                                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, 30, new DnsAAAARecord(address)));
                                        }
                                    }
                                }

                                if (answers.Count == 0)
                                    return Task.FromResult<DnsDatagram>(null);
                            }
                        }

                        if (answers.Count > 1)
                            answers.Shuffle();

                        return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers));
                    }

                case DnsResourceRecordType.TXT:
                    {
                        dynamic jsonAppRecordData = JsonConvert.DeserializeObject(appRecordData);

                        bool allowTxtStatus;

                        if (jsonAppRecordData.allowTxtStatus == null)
                            allowTxtStatus = false;
                        else
                            allowTxtStatus = jsonAppRecordData.allowTxtStatus.Value;

                        if (!allowTxtStatus)
                            return Task.FromResult<DnsDatagram>(null);

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

                        List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                        GetStatusAnswers(jsonAppRecordData.primary, FailoverType.Primary, question, 30, healthCheck, healthCheckUrl, answers);
                        GetStatusAnswers(jsonAppRecordData.secondary, FailoverType.Secondary, question, 30, healthCheck, healthCheckUrl, answers);

                        return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers));
                    }

                default:
                    return Task.FromResult<DnsDatagram>(null);
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns A or AAAA records from primary set of addresses with a continous health check as configured in the app config. When none of the primary addresses are healthy, the app returns healthy addresses from the secondary set of addresses. When none of the primary and secondary addresses are healthy, the app returns all addresses from the server down set of addresses. The server down feature is expected to be used for showing a service status page and not to serve the actual content.\n\nIf an URL is provided for the health check in the app's config then it will override the 'healthCheckUrl' parameter. When an URL is not provided in 'healthCheckUrl' parameter for 'http' or 'https' type health check, the domain name of the APP record will be used to auto generate an URL.\n\nSet 'allowTxtStatus' parameter to 'true' in your APP record data to allow checking health status by querying for TXT record."; } }

        public string ApplicationRecordDataTemplate
        {
            get
            {
                return @"{
  ""primary"": [
    ""1.1.1.1"",
    ""::1""
  ],
  ""secondary"": [
    ""2.2.2.2"",
    ""::2""
  ],
  ""serverDown"": [
    ""3.3.3.3""
  ],
  ""healthCheck"": ""https"",
  ""healthCheckUrl"": ""https://www.example.com/"",
  ""allowTxtStatus"": false
}";
            }
        }

        #endregion
    }
}
