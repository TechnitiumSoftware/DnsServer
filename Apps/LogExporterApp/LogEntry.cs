using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
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

        public ReadOnlySpan<char> AsSpan()
        {
            // Initialize a ValueStringBuilder with some initial capacity
            var buffer = new GrowableBuffer<byte>(256);

            using var writer = new Utf8JsonWriter(buffer);

            // Manually serialize the LogEntry as JSON
            writer.WriteStartObject();

            writer.WriteString("timestamp", Timestamp.ToUniversalTime().ToString("O"));
            writer.WriteString("clientIp", ClientIp);
            writer.WriteNumber("clientPort", ClientPort);
            writer.WriteBoolean("dnssecOk", DnssecOk);
            writer.WriteString("protocol", Protocol.ToString());
            writer.WriteString("responseCode", ResponseCode.ToString());

            // Write Questions array
            writer.WriteStartArray("questions");
            foreach (var question in Questions)
            {
                writer.WriteStartObject();
                writer.WriteString("questionName", question.QuestionName);
                writer.WriteString("questionType", question.QuestionType.ToString());
                writer.WriteString("questionClass", question.QuestionClass.ToString());
                writer.WriteNumber("size", question.Size);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();

            // Write Answers array (if exists)
            if (Answers != null && Answers.Count > 0)
            {
                writer.WriteStartArray("answers");
                foreach (var answer in Answers)
                {
                    writer.WriteStartObject();
                    writer.WriteString("recordType", answer.RecordType.ToString());
                    writer.WriteString("recordData", answer.RecordData);
                    writer.WriteString("recordClass", answer.RecordClass.ToString());
                    writer.WriteNumber("recordTtl", answer.RecordTtl);
                    writer.WriteNumber("size", answer.Size);
                    writer.WriteString("dnssecStatus", answer.DnssecStatus.ToString());
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
            }

            writer.WriteEndObject();
            writer.Flush();

            return ConvertBytesToChars(buffer.ToSpan());
        }

        public static Span<char> ConvertBytesToChars(ReadOnlySpan<byte> byteSpan)
        {
            // Calculate the maximum required length for the char array
            int maxCharCount = Encoding.UTF8.GetCharCount(byteSpan);

            // Allocate a char array large enough to hold the converted characters
            char[] charArray = new char[maxCharCount];

            // Decode the byteSpan into the char array
            int actualCharCount = Encoding.UTF8.GetChars(byteSpan, charArray);

            // Return a span of only the relevant portion of the char array
            return new Span<char>(charArray, 0, actualCharCount);
        }
    };
}
