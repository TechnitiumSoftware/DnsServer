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

using SyslogNet.Client;
using SyslogNet.Client.Serialization;
using SyslogNet.Client.Transport;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public class SyslogExportStrategy : IExportStrategy
    {
        #region variables

        private const string _appName = "Technitium DNS Server";

        private const string _msgId = "dnslog";

        private const string _sdId = "dnsparams";

        private const string DEFAUL_PROTOCOL = "udp";

        private const int DEFAULT_PORT = 514;

        private readonly string _host;

        private readonly string _processId;

        private readonly ISyslogMessageSender _sender;

        private readonly ISyslogMessageSerializer _serializer;

        private bool disposedValue;

        #endregion variables

        #region constructor

        public SyslogExportStrategy(string address, int? port, string? protocol)
        {
            port ??= DEFAULT_PORT;
            protocol ??= DEFAUL_PROTOCOL;

            _sender = protocol switch
            {
                "tls" => new SyslogEncryptedTcpSender(address, port.Value),
                "tcp" => new SyslogTcpSender(address, port.Value),
                "udp" => new SyslogUdpSender(address, port.Value),
                "local" => new SyslogLocalSender(),
                _ => throw new Exception("Invalid protocol specified"),
            };

            _serializer = new SyslogRfc5424MessageSerializer();
            _processId = Environment.ProcessId.ToString();
            _host = Environment.MachineName;
        }

        #endregion constructor

        #region public

        public Task ExportLogsAsync(List<LogEntry> logs, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                var messages = new List<SyslogMessage>(logs.Select(Convert));
                _sender.Send(messages, _serializer);
            }
             , cancellationToken);
        }

        #endregion public

        #region IDisposable

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _sender.Dispose();
                }

                disposedValue = true;
            }
        }

        #endregion IDisposable

        #region private

        private SyslogMessage Convert(LogEntry log)
        {
            // Create the structured data with all key details from LogEntry
            var elements = new StructuredDataElement(_sdId, new Dictionary<string, string>
            {
                { "timestamp", log.Timestamp.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") },
                { "clientIp", log.ClientIp },
                { "clientPort", log.ClientPort.ToString() },
                { "dnssecOk", log.DnssecOk.ToString() },
                { "protocol", log.Protocol.ToString() },
                { "rCode", log.ResponseCode.ToString() }
            });

            // Add each question to the structured data
            if (log.Questions != null && log.Questions.Count > 0)
            {
                for (int i = 0; i < log.Questions.Count; i++)
                {
                    var question = log.Questions[i];
                    elements.Parameters.Add($"qName_{i}", question.QuestionName);
                    elements.Parameters.Add($"qType_{i}", question.QuestionType.HasValue ? question.QuestionType.Value.ToString() : "unknown");
                    elements.Parameters.Add($"qClass_{i}", question.QuestionClass.HasValue ? question.QuestionClass.Value.ToString() : "unknown");
                    elements.Parameters.Add($"qSize_{i}", question.Size.ToString());
                }
            }

            // Add each answer to the structured data
            if (log.Answers != null && log.Answers.Count > 0)
            {
                for (int i = 0; i < log.Answers.Count; i++)
                {
                    var answer = log.Answers[i];
                    elements.Parameters.Add($"aType_{i}", answer.RecordType.ToString());
                    elements.Parameters.Add($"aData_{i}", answer.RecordData);
                    elements.Parameters.Add($"aClass_{i}", answer.RecordClass.ToString());
                    elements.Parameters.Add($"aTtl_{i}", answer.RecordTtl.ToString());
                    elements.Parameters.Add($"aSize_{i}", answer.Size.ToString());
                    elements.Parameters.Add($"aDnssecStatus_{i}", answer.DnssecStatus.ToString());
                }
            }

            // Include request and response tags if present
            if (log.RequestTag != null)
            {
                elements.Parameters.Add("requestTag", log.RequestTag.ToString());
            }

            if (log.ResponseTag != null)
            {
                elements.Parameters.Add("responseTag", log.ResponseTag.ToString());
            }

            // Build a comprehensive message summary
            string questionSummary = log.Questions?.Count > 0
            ? string.Join("; ", log.Questions.Select(q =>
                $"QNAME: {q.QuestionName}; QTYPE: {q.QuestionType?.ToString() ?? "unknown"}; QCLASS: {q.QuestionClass?.ToString() ?? "unknown"}"))
            : "No Questions";

            // Build the answer summary in the desired format
            string answerSummary = log.Answers?.Count > 0
                ? string.Join(", ", log.Answers.Select(a => a.RecordData))
                : "No Answers";

            // Construct the message summary string to match the desired format
            string messageSummary = $"{questionSummary}; RCODE: {log.ResponseCode}; ANSWER: [{answerSummary}]";


            // Create and return the syslog message
            return new SyslogMessage(
                log.Timestamp,
                Facility.UserLevelMessages,
                Severity.Informational,
                _host,
                _appName,
                _processId,
                _msgId,
                messageSummary,
                elements
            );
        }

        #endregion private
    }
}