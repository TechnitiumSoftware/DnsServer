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

using Serilog;
using Serilog.Events;
using Serilog.Parsing;
using Serilog.Sinks.Syslog;
using System;
using System.Collections.Generic;
using System.Linq;

namespace LogExporter.Strategy
{
    public class SyslogExportStrategy : IExportStrategy
    {
        #region variables

        private const string _appName = "Technitium DNS Server";

        private const string _sdId = "meta";

        private const string DEFAUL_PROTOCOL = "udp";

        private const int DEFAULT_PORT = 514;

        private readonly Facility _facility = Facility.Local6;

        private readonly Rfc5424Formatter _formatter;

        private readonly Serilog.Core.Logger _sender;

        private bool disposedValue;

        #endregion variables

        #region constructor

        public SyslogExportStrategy(string address, int? port, string? protocol)
        {
            port ??= DEFAULT_PORT;
            protocol ??= DEFAUL_PROTOCOL;

            var conf = new LoggerConfiguration();

            _sender = protocol.ToLowerInvariant() switch
            {
                "tls" => conf.WriteTo.TcpSyslog(address, port.Value, _appName, FramingType.OCTET_COUNTING, SyslogFormat.RFC5424, _facility, useTls: true).Enrich.FromLogContext().CreateLogger(),
                "tcp" => conf.WriteTo.TcpSyslog(address, port.Value, _appName, FramingType.OCTET_COUNTING, SyslogFormat.RFC5424, _facility, useTls: false).Enrich.FromLogContext().CreateLogger(),
                "udp" => conf.WriteTo.UdpSyslog(address, port.Value, _appName, SyslogFormat.RFC5424, _facility).Enrich.FromLogContext().CreateLogger(),
                "local" => conf.WriteTo.LocalSyslog(_appName, _facility).Enrich.FromLogContext().CreateLogger(),
                _ => throw new Exception("Invalid protocol specified"),
            };

            _formatter = new Rfc5424Formatter(_facility, _appName, null, _sdId, Environment.MachineName);
        }

        #endregion constructor

        #region public

        public void Export(List<LogEntry> logs)
        {

            foreach (var log in logs)
            {
                Log.Information(_formatter.FormatMessage(Convert(log)));
            }
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

        private LogEvent Convert(LogEntry log)
        {
            // Initialize properties with base log details
            var properties = new List<LogEventProperty>
            {
                new LogEventProperty("timestamp", new ScalarValue(log.Timestamp.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))),
                new LogEventProperty("clientIp", new ScalarValue(log.ClientIp)),
                new LogEventProperty("clientPort", new ScalarValue(log.ClientPort.ToString())),
                new LogEventProperty("dnssecOk", new ScalarValue(log.DnssecOk.ToString())),
                new LogEventProperty("protocol", new ScalarValue(log.Protocol.ToString())),
                new LogEventProperty("rCode", new ScalarValue(log.ResponseCode.ToString()))
            };

            // Add each question as properties
            if (log.Questions?.Count > 0)
            {
                for (int i = 0; i < log.Questions.Count; i++)
                {
                    var question = log.Questions[i];
                    properties.Add(new LogEventProperty($"qName_{i}", new ScalarValue(question.QuestionName)));
                    properties.Add(new LogEventProperty($"qType_{i}", new ScalarValue(question.QuestionType?.ToString() ?? "unknown")));
                    properties.Add(new LogEventProperty($"qClass_{i}", new ScalarValue(question.QuestionClass?.ToString() ?? "unknown")));
                    properties.Add(new LogEventProperty($"qSize_{i}", new ScalarValue(question.Size.ToString())));
                }

                // Generate questions summary
                var questionSummary = string.Join("; ", log.Questions.Select((q, i) =>
                    $"QNAME_{i}: {q.QuestionName}, QTYPE: {q.QuestionType?.ToString() ?? "unknown"}, QCLASS: {q.QuestionClass?.ToString() ?? "unknown"}"));
                properties.Add(new LogEventProperty("questionsSummary", new ScalarValue(questionSummary)));
            }
            else
            {
                properties.Add(new LogEventProperty("questionsSummary", new ScalarValue(string.Empty)));
            }

            // Add each answer as properties
            if (log.Answers?.Count > 0)
            {
                for (int i = 0; i < log.Answers.Count; i++)
                {
                    var answer = log.Answers[i];
                    properties.Add(new LogEventProperty($"aType_{i}", new ScalarValue(answer.RecordType.ToString())));
                    properties.Add(new LogEventProperty($"aData_{i}", new ScalarValue(answer.RecordData)));
                    properties.Add(new LogEventProperty($"aClass_{i}", new ScalarValue(answer.RecordClass.ToString())));
                    properties.Add(new LogEventProperty($"aTtl_{i}", new ScalarValue(answer.RecordTtl.ToString())));
                    properties.Add(new LogEventProperty($"aSize_{i}", new ScalarValue(answer.Size.ToString())));
                    properties.Add(new LogEventProperty($"aDnssecStatus_{i}", new ScalarValue(answer.DnssecStatus.ToString())));
                }

                // Generate answers summary
                var answerSummary = string.Join(", ", log.Answers.Select(a => a.RecordData));
                properties.Add(new LogEventProperty("answersSummary", new ScalarValue(answerSummary)));
            }
            else
            {
                properties.Add(new LogEventProperty("answersSummary", new ScalarValue(string.Empty)));
            }

            // Add request and response tags if present
            if (log.RequestTag != null)
            {
                properties.Add(new LogEventProperty("requestTag", new ScalarValue(log.RequestTag.ToString())));
            }

            if (log.ResponseTag != null)
            {
                properties.Add(new LogEventProperty("responseTag", new ScalarValue(log.ResponseTag.ToString())));
            }

            // Define the message template to match the original summary format
            const string templateText = "{questionsSummary}; RCODE: {rCode}; ANSWER: [{answersSummary}]";

            // Parse the template
            var template = new MessageTemplateParser().Parse(templateText);

            // Create the LogEvent and return it
            return new LogEvent(
                timestamp: log.Timestamp,
                level: LogEventLevel.Information,
                exception: null,
                messageTemplate: template,
                properties: properties
            );
        }

        #endregion private
    }
}