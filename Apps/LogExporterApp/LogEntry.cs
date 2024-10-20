using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace LogExporter
{
    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public string ClientIp { get; set; }
        public int ClientPort { get; set; }
        public bool DnssecOk { get; set; }
        public DnsTransportProtocol Protocol { get; set; }
        public DnsResponseCode ResponseCode { get; set; }
        public List<Question> Questions { get; set; }
        public List<Answer> Answers { get; set; }
        public object? RequestTag { get; set; }
        public object? ResponseTag { get; set; }

        public LogEntry(DateTime timestamp, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram request, DnsDatagram response)
        {
            // Assign timestamp and ensure it's in UTC
            Timestamp = timestamp.Kind == DateTimeKind.Utc ? timestamp : timestamp.ToUniversalTime();

            // Extract client information
            ClientIp = remoteEP.Address.ToString();
            ClientPort = remoteEP.Port;
            DnssecOk = request.DnssecOk;
            Protocol = protocol;
            ResponseCode = response.RCODE;

            // Extract request information
            Questions = new List<Question>(request.Question.Count);
            if (request.Question?.Count > 0)
            {
                Questions.AddRange(request.Question.Select(questionRecord => new Question
                {
                    QuestionName = questionRecord.Name,
                    QuestionType = questionRecord.Type,
                    QuestionClass = questionRecord.Class,
                    Size = questionRecord.UncompressedLength,
                }));
            }

            // Convert answer section into a simple string summary (comma-separated for multiple answers)
            Answers = new List<Answer>(response.Answer.Count);
            if (response.Answer?.Count > 0)
            {
                Answers.AddRange(response.Answer.Select(record => new Answer
                {
                    RecordType = record.Type,
                    RecordData = record.RDATA.ToString(),
                    RecordClass = record.Class,
                    RecordTtl = record.TTL,
                    Size = record.UncompressedLength,
                    DnssecStatus = record.DnssecStatus,
                }));
            }

            if (request.Tag != null)
            {
                RequestTag = request.Tag;
            }

            if (response.Tag != null)
            {
                ResponseTag = response.Tag;
            }
        }

        public class Question
        {
            public string QuestionName { get; set; }
            public DnsResourceRecordType? QuestionType { get; set; }
            public DnsClass? QuestionClass { get; set; }
            public int Size { get; set; }
        }

        public class Answer
        {
            public DnsResourceRecordType RecordType { get; set; }
            public string RecordData { get; set; }
            public DnsClass RecordClass { get; set; }
            public uint RecordTtl { get; set; }
            public int Size { get; set; }
            public DnssecStatus DnssecStatus { get; set; }
        }

        public override string ToString()
        {
            return JsonSerializer.Serialize(this, DnsLogSerializerOptions.Default);
        }

        // Custom DateTime converter to handle UTC serialization in ISO 8601 format
        public class JsonDateTimeConverter : JsonConverter<DateTime>
        {
            public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                var dts = reader.GetString();
                return dts == null ? DateTime.MinValue : DateTime.Parse(dts);
            }

            public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
            {
                writer.WriteStringValue(value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
            }
        }

        // Setup reusable options with a single instance
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
    }
}