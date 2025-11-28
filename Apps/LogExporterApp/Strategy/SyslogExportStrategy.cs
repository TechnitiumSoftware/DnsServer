/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)
Copyright (C) 2025  Zafer Balkan (zafer@zaferbalkan.com)

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
using System.Text;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public sealed class SyslogExportStrategy : IExportStrategy
    {
        #region variables

        const string _appName = "Technitium DNS Server";
        const string _sdId = "meta";
        const string DEFAULT_PROTOCOL = "udp";
        const int DEFAULT_PORT = 514;

        readonly Facility _facility = Facility.Local6;

        readonly Rfc5424Formatter _formatter;
        readonly Serilog.Core.Logger _sender;

        bool _disposed;

        // Reuse the message template instead of parsing it per-log
        const string TemplateText = "{questionsSummary}; RCODE: {rCode}; ANSWER: [{answersSummary}]";
        static readonly MessageTemplate Template =
            new MessageTemplateParser().Parse(TemplateText);

        #endregion

        #region constructor

        public SyslogExportStrategy(string address, int? port, string? protocol)
        {
            port ??= DEFAULT_PORT;
            protocol ??= DEFAULT_PROTOCOL;

            LoggerConfiguration conf = new LoggerConfiguration();

            _sender = protocol.ToLowerInvariant() switch
            {
                "tls" => conf.WriteTo.TcpSyslog(
                            address,
                            port.Value,
                            _appName,
                            FramingType.OCTET_COUNTING,
                            SyslogFormat.RFC5424,
                            _facility,
                            useTls: true)
                        .Enrich.FromLogContext()
                        .CreateLogger(),

                "tcp" => conf.WriteTo.TcpSyslog(
                            address,
                            port.Value,
                            _appName,
                            FramingType.OCTET_COUNTING,
                            SyslogFormat.RFC5424,
                            _facility,
                            useTls: false)
                        .Enrich.FromLogContext()
                        .CreateLogger(),

                "udp" => conf.WriteTo.UdpSyslog(
                            address,
                            port.Value,
                            _appName,
                            SyslogFormat.RFC5424,
                            _facility)
                        .Enrich.FromLogContext()
                        .CreateLogger(),

                "local" => conf.WriteTo.LocalSyslog(
                            _appName,
                            _facility)
                        .Enrich.FromLogContext()
                        .CreateLogger(),

                _ => throw new NotSupportedException("Syslog protocol is not supported: " + protocol),
            };

            // Serilog's RFC5424 formatter used as before
            _formatter = new Rfc5424Formatter(
                facility: _facility,
                applicationName: _appName,
                templateFormatter: null,
                messageIdPropertyName: _sdId,
                sourceHost: Environment.MachineName,
                severityMapping: null);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_disposed)
                return;

            _sender.Dispose();
            _disposed = true;
        }

        #endregion

        #region public

        public Task ExportAsync(IReadOnlyList<LogEntry> logs)
        {
            foreach (LogEntry log in logs)
                _sender.Information(_formatter.FormatMessage(Convert(log)));

            return Task.CompletedTask;
        }

        #endregion

        #region private

        private static LogEvent Convert(LogEntry log)
        {
            // Rough capacity: 9 base + 4 question + some answers + edns
            // This avoids repeated List resizes
            List<LogEventProperty> properties = new List<LogEventProperty>(16)
            {
                // Base fields (unchanged semantics)
                new LogEventProperty(
                "timestamp",
                new ScalarValue(log.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))),
                new LogEventProperty(
                "clientIp",
                new ScalarValue(log.ClientIp)),
                new LogEventProperty(
                "protocol",
                new ScalarValue(log.Protocol.ToString())),
                new LogEventProperty(
                "responseType",
                new ScalarValue(log.ResponseType.ToString())),
                new LogEventProperty(
                "responseRtt",
                new ScalarValue(log.ResponseRtt?.ToString())),
                new LogEventProperty(
                "rCode",
                new ScalarValue(log.ResponseCode.ToString())),
                new LogEventProperty(
                "domain_tld",
                new ScalarValue(log.DomainInfo.TLD)),
                new LogEventProperty(
                "domain_basedomain",
                new ScalarValue(log.DomainInfo.BaseDomain)),
                new LogEventProperty(
                "domain_subdomain",
                new ScalarValue(log.DomainInfo.Subdomain))
            };

            // Question
            if (log.Question != null)
            {
                LogEntry.DnsQuestion question = log.Question;

                properties.Add(new LogEventProperty(
                    "qName",
                    new ScalarValue(question.QuestionName)));

                properties.Add(new LogEventProperty(
                    "qType",
                    new ScalarValue(question.QuestionType.ToString())));

                properties.Add(new LogEventProperty(
                    "qClass",
                    new ScalarValue(question.QuestionClass.ToString())));

                string questionSummary =
                    $"QNAME: {question.QuestionName}, " +
                    $"QTYPE: {question.QuestionType}, " +
                    $"QCLASS: {question.QuestionClass}";

                properties.Add(new LogEventProperty(
                    "questionsSummary",
                    new ScalarValue(questionSummary)));
            }
            else
            {
                properties.Add(new LogEventProperty(
                    "questionsSummary",
                    new ScalarValue(string.Empty)));
            }

            // Answers
            if (log.Answers.Count > 0)
            {
                // Build answersSummary without LINQ
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < log.Answers.Count; i++)
                {
                    LogEntry.DnsResourceRecord answer = log.Answers[i];

                    properties.Add(new LogEventProperty(
                        $"aName_{i}",
                        new ScalarValue(answer.Name)));

                    properties.Add(new LogEventProperty(
                        $"aType_{i}",
                        new ScalarValue(answer.RecordType.ToString())));

                    properties.Add(new LogEventProperty(
                        $"aClass_{i}",
                        new ScalarValue(answer.RecordClass.ToString())));

                    properties.Add(new LogEventProperty(
                        $"aTtl_{i}",
                        new ScalarValue(answer.RecordTtl.ToString())));

                    properties.Add(new LogEventProperty(
                        $"aRData_{i}",
                        new ScalarValue(answer.RecordData)));

                    properties.Add(new LogEventProperty(
                        $"aDnssecStatus_{i}",
                        new ScalarValue(answer.DnssecStatus.ToString())));

                    if (i > 0)
                        sb.Append(", ");
                    sb.Append(answer.RecordData);
                }

                properties.Add(new LogEventProperty(
                    "answersSummary",
                    new ScalarValue(sb.ToString())));
            }
            else
            {
                properties.Add(new LogEventProperty(
                    "answersSummary",
                    new ScalarValue(string.Empty)));
            }

            // EDNS
            if (log.EDNS.Count > 0)
            {
                for (int i = 0; i < log.EDNS.Count; i++)
                {
                    LogEntry.EDNSLog ednsLog = log.EDNS[i];

                    properties.Add(new LogEventProperty(
                        $"ednsErrType_{i}",
                        new ScalarValue(ednsLog.ErrType)));

                    properties.Add(new LogEventProperty(
                        $"ednsMessage_{i}",
                        new ScalarValue(ednsLog.Message)));
                }
            }

            // Reuse the static MessageTemplate 'Template'
            return new LogEvent(
                timestamp: log.Timestamp,
                level: LogEventLevel.Information,
                exception: null,
                messageTemplate: Template,
                properties: properties);
        }

        #endregion
    }
}
