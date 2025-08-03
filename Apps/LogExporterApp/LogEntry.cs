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

using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace LogExporter
{
    public class LogEntry
    {
        public LogEntry(DateTime timestamp, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram request, DnsDatagram response, bool ednsLogging = false)
        {
            // Assign timestamp and ensure it's in UTC
            Timestamp = timestamp.Kind == DateTimeKind.Utc ? timestamp : timestamp.ToUniversalTime();

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

            // Convert answer section into a simple string summary (comma-separated for multiple answers)
            Answers = new List<DnsResourceRecord>(response.Answer.Count);
            if (response.Answer.Count > 0)
            {
                Answers.AddRange(response.Answer.Select(record => new DnsResourceRecord
                {
                    Name = record.Name,
                    RecordType = record.Type,
                    RecordClass = record.Class,
                    RecordTtl = record.TTL,
                    RecordData = record.RDATA.ToString(),
                    DnssecStatus = record.DnssecStatus,
                }));
            }

            EDNS = new List<EDNSLog>();
            if (ednsLogging && response.EDNS != null)
            {
                foreach (var log in response.EDNS.Options)
                {
                    string[] extractedData = log.Data.ToString().Replace("[", string.Empty).Replace("]", string.Empty).Split(":", StringSplitOptions.TrimEntries);

                    EDNS.Add(new EDNSLog
                    {
                        Code = Enum.GetName(log.Code)!,
                        ErrType = extractedData[0],
                        Message = extractedData[1]
                    });
                }
            }
        }

        public List<DnsResourceRecord> Answers { get; private set; }
        public string ClientIp { get; private set; }
        public List<EDNSLog> EDNS { get; private set; }
        public DnsTransportProtocol Protocol { get; private set; }
        public DnsQuestion? Question { get; private set; }
        public DnsResponseCode ResponseCode { get; private set; }
        public double? ResponseRtt { get; private set; }
        public DnsServerResponseType ResponseType { get; private set; }
        public DateTime Timestamp { get; private set; }
        public override string ToString()
        {
            return JsonSerializer.Serialize(this, DnsLogSerializerOptions.Default);
        }

        public static class DnsLogSerializerOptions
        {
            public static readonly JsonSerializerOptions Default = new JsonSerializerOptions
            {
                WriteIndented = false, // Newline delimited logs should not be multiline
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase, // Convert properties to camelCase
                Converters = { new JsonStringEnumConverter(), new JsonDateTimeConverter() }, // Handle enums and DateTime conversion
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping, // For safe encoding
                NumberHandling = JsonNumberHandling.Strict,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull // Ignore null values
            };
        }

        public class DnsQuestion
        {
            public DnsClass QuestionClass { get; set; }
            public required string QuestionName { get; set; }
            public DnsResourceRecordType QuestionType { get; set; }
        }

        public class DnsResourceRecord
        {
            public DnssecStatus DnssecStatus { get; set; }
            public required string Name { get; set; }
            public DnsClass RecordClass { get; set; }
            public required string RecordData { get; set; }
            public uint RecordTtl { get; set; }
            public DnsResourceRecordType RecordType { get; set; }
        }

        public class EDNSLog
        {
            public string Code { get; set; }
            public string ErrType { get; set; }
            public string Message { get; set; }
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