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
        Secondary = 2,
        ServerDown = 3
    }

    public class Address : IDnsApplicationRequestHandler
    {
        #region variables

        HealthMonitoringService _healthService;

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
                            HealthCheckStatus status = _healthService.QueryStatus(address, healthCheck, healthCheckUrl, true);
                            if (status is null)
                                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, 30, new DnsARecord(address)));
                            else if (status.IsHealthy)
                                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, appRecordTtl, new DnsARecord(address)));
                        }
                    }
                    break;

                case DnsResourceRecordType.AAAA:
                    foreach (dynamic jsonAddress in jsonAddresses)
                    {
                        IPAddress address = IPAddress.Parse(jsonAddress.Value);

                        if (address.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            HealthCheckStatus status = _healthService.QueryStatus(address, healthCheck, healthCheckUrl, true);
                            if (status is null)
                                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, 30, new DnsAAAARecord(address)));
                            else if (status.IsHealthy)
                                answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, appRecordTtl, new DnsAAAARecord(address)));
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
                HealthCheckStatus status = _healthService.QueryStatus(address, healthCheck, healthCheckUrl, false);

                string text = "app=failover; addressType=" + type.ToString() + "; address=" + address.ToString() + "; healthCheck=" + healthCheck;

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
            if (_healthService is null)
                _healthService = HealthMonitoringService.Create(dnsServer);

            _healthService.Initialize(JsonConvert.DeserializeObject(config));

            return Task.CompletedTask;
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, string zoneName, uint appRecordTtl, string appRecordData, bool isRecursionAllowed, IDnsServer dnsServer)
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

                        if (jsonAppRecordData.healthCheckUrl != null)
                            healthCheckUrl = new Uri(jsonAppRecordData.healthCheckUrl.Value);

                        List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                        GetAnswers(jsonAppRecordData.primary, question, appRecordTtl, healthCheck, healthCheckUrl, answers);
                        if (answers.Count == 0)
                        {
                            GetAnswers(jsonAppRecordData.secondary, question, appRecordTtl, healthCheck, healthCheckUrl, answers);
                            if (answers.Count == 0)
                            {
                                GetAnswers(jsonAppRecordData.serverDown, question, appRecordTtl, healthCheck, healthCheckUrl, answers);
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

                        if (jsonAppRecordData.healthCheckUrl != null)
                            healthCheckUrl = new Uri(jsonAppRecordData.healthCheckUrl.Value);

                        List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                        GetStatusAnswers(jsonAppRecordData.primary, FailoverType.Primary, question, 30, healthCheck, healthCheckUrl, answers);
                        GetStatusAnswers(jsonAppRecordData.secondary, FailoverType.Secondary, question, 30, healthCheck, healthCheckUrl, answers);
                        GetStatusAnswers(jsonAppRecordData.serverDown, FailoverType.ServerDown, question, 30, healthCheck, healthCheckUrl, answers);

                        return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers));
                    }

                default:
                    return Task.FromResult<DnsDatagram>(null);
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Returns A or AAAA records from primary set of addresses with a continous health check as configured in the app config. When none of the primary addresses are healthy, the app returns healthy addresses from the secondary set of addresses. When none of the primary and secondary addresses are healthy, the app returns healthy addresses from the server down set of addresses. The server down feature is expected to be used for showing a service status page and not to serve the actual content.\n\nSet 'allowTxtStatus' to 'true' in your APP record data to allow checking health status by querying for TXT record."; } }

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
  ""healthCheck"": ""http"",
  ""healthCheckUrl"": ""https://www.example.com"",
  ""allowTxtStatus"": false
}";
            }
        }

        #endregion
    }
}
