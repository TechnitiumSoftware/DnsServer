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
along with this program.  If not, see <http://www.gnu.org/licenses/>

*/
using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace LogExporter
{
    public class LogEntry
    {
        // Reuse empty lists to avoid allocations when there are no answers or EDNS data
        private static readonly DnsResourceRecord[] EmptyAnswers = Array.Empty<DnsResourceRecord>();
        private static readonly EDNSLog[] EmptyEdns = Array.Empty<EDNSLog>();

        public LogEntry(DateTime timestamp, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram request, DnsDatagram response, bool ednsLogging = false)
        {
            // Assign timestamp and ensure it's in UTC
            Timestamp = timestamp.Kind == DateTimeKind.Utc ? timestamp : timestamp.ToUniversalTime();

            // Set hostname
            NameServer = request.Metadata.NameServer.Host;

            // Extract client information
            ClientIp = remoteEP.Address.ToString();
            Protocol = protocol;
            ResponseType = response.Tag == null ? DnsServerResponseType.Recursive : (DnsServerResponseType)response.Tag;

            if ((ResponseType == DnsServerResponseType.Recursive) && (response.Metadata is not null))
                ResponseRtt = response.Metadata.RoundTripTime;

            ResponseCode = response.RCODE;

            // Extract request information
            if (request.Question.Count > 0)
            {
                DnsQuestionRecord query = request.Question[0];

                Question = new DnsQuestion
                {
                    QuestionName = query.Name,
                    QuestionType = query.Type,
                    QuestionClass = query.Class,
                };
            }

            // Convert answer section - reuse empty list when no answers
            if (response.Answer.Count > 0)
            {
                Answers = new List<DnsResourceRecord>(
                    response.Answer.Select(record => new DnsResourceRecord
                    {
                        Name = record.Name,
                        RecordType = record.Type,
                        RecordClass = record.Class,
                        RecordTtl = record.TTL,
                        RecordData = record.RDATA.ToString(),
                        DnssecStatus = record.DnssecStatus,
                    })).ToArray();
            }
            else
            {
                Answers = EmptyAnswers;
            }

            PopulateEDNSLgs(response, ednsLogging);
        }

        private void PopulateEDNSLgs(DnsDatagram response, bool ednsLogging)
        {
            // Handle EDNS - reuse empty list when no EDNS logging or no errors
            if (!ednsLogging || response.EDNS is null)
            {
                EDNS = EmptyEdns;
                return;
            }

            List<EDnsOption> ednsErrors = response.EDNS.Options.Where(o => o.Code == EDnsOptionCode.EXTENDED_DNS_ERROR).ToList();
            if (ednsErrors.Count == 0)
            {
                EDNS = EmptyEdns;
                return;
            }

            List<EDNSLog> edns = new List<EDNSLog>(ednsErrors.Count);
            foreach (EDnsOption extendedErrorLog in ednsErrors)
            {
                // ADR: EDNS extended error comes from network input and may not follow
                // the expected "type: message" format. Previously this code assumed
                // a well-formed structure and could throw IndexOutOfRangeException,
                // allowing remote parties to crash the logging pipeline.
                // We now parse defensively and treat malformed data as a best-effort message.

                string? raw = extendedErrorLog.Data?.ToString();
                if (string.IsNullOrWhiteSpace(raw))
                    continue;

                raw = raw.Replace("[", "").Replace("]", "");

                string? errType = null;
                string? message = null;

                string[] parts = raw.Split(':', 2, StringSplitOptions.TrimEntries);
                if (parts.Length == 2)
                {
                    errType = parts[0];
                    message = parts[1];
                }
                else
                {
                    // fallback: treat the raw payload as the message
                    message = raw;
                }

                edns.Add(new EDNSLog
                {
                    ErrType = errType,
                    Message = message
                });
            }

            // If no valid EDNS entries were added, use the empty list
            EDNS = edns.Count == 0 ? EmptyEdns : edns.ToArray();
        }

        public DnsResourceRecord[] Answers { get; }

        public string ClientIp { get; }

        public EDNSLog[] EDNS { get; private set; }

        public string NameServer { get; }

        public DnsTransportProtocol Protocol { get; }

        public DnsQuestion? Question { get; }

        public DnsResponseCode ResponseCode { get; }

        public double? ResponseRtt { get; private set; }

        public DnsServerResponseType ResponseType { get; }

        public DateTime Timestamp { get; }

        // Meta bag populated by pipeline stages
        public Dictionary<string, object> Meta { get; } = new();

        public override string ToString()
        {
            return JsonSerializer.Serialize(this, DnsLogSerializerOptions.Default);
        }

        public static class DnsLogSerializerOptions
        {
            public static readonly JsonSerializerOptions Default = new JsonSerializerOptions
            {
                WriteIndented = false,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                Converters = { new JsonStringEnumConverter(), new JsonDateTimeConverter() },
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                NumberHandling = JsonNumberHandling.Strict,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
        }

        public class DnsQuestion
        {
            public DnsClass QuestionClass { get; set; }
            public string QuestionName { get; set; }
            public DnsResourceRecordType QuestionType { get; set; }
        }

        public class DnsResourceRecord
        {
            public DnssecStatus DnssecStatus { get; set; }
            public string Name { get; set; }
            public DnsClass RecordClass { get; set; }
            public string RecordData { get; set; }
            public uint RecordTtl { get; set; }
            public DnsResourceRecordType RecordType { get; set; }
        }

        public class EDNSLog
        {
            public string? ErrType { get; set; }
            public string? Message { get; set; }
        }

        public class JsonDateTimeConverter : JsonConverter<DateTime>
        {
            public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                string? dts = reader.GetString();
                return dts == null ? DateTime.MinValue : DateTime.Parse(dts);
            }

            public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
            {
                writer.WriteStringValue(value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
            }
        }
    }
}