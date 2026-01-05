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
using DuckDB.NET.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Channels;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace QueryLogsDuckDB
{
    public sealed class App : IDnsApplication, IDnsQueryLogger, IDnsQueryLogs
    {
        #region variables

        private const int CHANNEL_CAPACITY = 200_000;
        private const int MAX_BATCH_SIZE = 10_000;
        private Channel<LogEntry> _channel;
        private DuckDBConnection _conn;
        private Task _consumerTask;
        private bool _disposed;
        private IDnsServer _dnsServer;
        private bool _enableLogging;

        #endregion variables

        #region IDisposable

        public void Dispose()
        {
            if (_disposed)
                return;

            try { _channel?.Writer.TryComplete(); } catch { }
            try { _consumerTask?.Wait(5000); } catch { }
            try { _conn?.Dispose(); } catch { }

            _disposed = true;
        }

        #endregion IDisposable

        #region private

        private static string? FormatAnswer(DnsDatagram resp)
        {
            if (resp.Answer.Count == 0)
                return null;

            if (resp.Answer.Count > 2 && resp.IsZoneTransfer)
                return "[ZONE TRANSFER]";

            return string.Join(", ",
                resp.Answer.Select(r => $"{r.Type} {r.RDATA}"));
        }

        private async Task BulkInsertAsync(List<LogEntry> logs)
        {
            try
            {
                using var appender = _conn.CreateAppender("dns_logs");

                foreach (var log in logs)
                {
                    if (log.Request is null || log.Response is null)
                        continue;

                    var question =
                        log.Request.Question.Count > 0
                            ? log.Request.Question[0]
                            : null;

                    double? rtt =
                        (log.Response.Tag is null && log.Response.Metadata is not null)
                        ? log.Response.Metadata.RoundTripTime
                        : null;

                    var row = appender.CreateRow();

                    row.AppendValue(_dnsServer.ServerDomain);
                    row.AppendValue(log.Timestamp);
                    row.AppendValue(log.RemoteEP.Address.ToString());
                    row.AppendValue((byte)log.Protocol);

                    if (log.Response.Tag is null)
                        row.AppendNullValue();
                    else
                        row.AppendValue((byte)log.Response.Tag);

                    if (rtt is null)
                        row.AppendNullValue();
                    else
                        row.AppendValue(rtt.Value);

                    row.AppendValue((byte)log.Response.RCODE);

                    if (question is null)
                    {
                        row.AppendNullValue();
                        row.AppendNullValue();
                        row.AppendNullValue();
                    }
                    else
                    {
                        row.AppendValue(question.Name.ToLowerInvariant());
                        row.AppendValue((ushort)question.Type);
                        row.AppendValue((ushort)question.Class);
                    }

                    var answer = FormatAnswer(log.Response);
                    if (answer is null)
                        row.AppendNullValue();
                    else
                        row.AppendValue(answer);

                    row.EndRow();
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
        }

        private async Task CreateSchemaAsync()
        {
            using DuckDBCommand cmd = _conn.CreateCommand();

            cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS dns_logs (
    server         VARCHAR(255) NOT NULL,
    timestamp      TIMESTAMP NOT NULL,
    client_ip      VARCHAR(39) NOT NULL,
    protocol       UTINYINT NOT NULL,
    response_type  UTINYINT,
    response_rtt   DOUBLE,
    rcode          UTINYINT NOT NULL,
    qname          VARCHAR(255),
    qtype          USMALLINT,
    qclass         USMALLINT,
    answer         TEXT
);";
            await cmd.ExecuteNonQueryAsync();

            string[] indexes =
            [
                "CREATE INDEX IF NOT EXISTS idx_srv ON dns_logs(server);",
                "CREATE INDEX IF NOT EXISTS idx_ts ON dns_logs(timestamp);",
                "CREATE INDEX IF NOT EXISTS idx_ip ON dns_logs(client_ip);",
                "CREATE INDEX IF NOT EXISTS idx_proto ON dns_logs(protocol);",
                "CREATE INDEX IF NOT EXISTS idx_resp ON dns_logs(response_type);",
                "CREATE INDEX IF NOT EXISTS idx_rcode ON dns_logs(rcode);",
                "CREATE INDEX IF NOT EXISTS idx_qname ON dns_logs(qname);",
                "CREATE INDEX IF NOT EXISTS idx_qtype ON dns_logs(qtype);",
                "CREATE INDEX IF NOT EXISTS idx_qclass ON dns_logs(qclass);"
            ];

            foreach (string sql in indexes)
            {
                cmd.CommandText = sql;
                await cmd.ExecuteNonQueryAsync();
            }
        }

        private async Task ProcessLogsAsync()
        {
            var batch = new List<LogEntry>(MAX_BATCH_SIZE);

            while (await _channel.Reader.WaitToReadAsync())
            {
                while (batch.Count < MAX_BATCH_SIZE &&
                       _channel.Reader.TryRead(out var log))
                {
                    batch.Add(log);
                }

                if (batch.Count > 0)
                {
                    await BulkInsertAsync(batch);
                    batch.Clear();
                }
            }

            if (batch.Count > 0)
                await BulkInsertAsync(batch);
        }

        #endregion private

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument json = JsonDocument.Parse(config);
            JsonElement cfg = json.RootElement;

            _enableLogging = cfg.GetPropertyValue("enableLogging", true);

            string dbPath = cfg.GetPropertyValue("dbPath", "querylogs.db");

            if (!System.IO.Path.IsPathRooted(dbPath))
                dbPath = System.IO.Path.Combine(dnsServer.ApplicationFolder, dbPath);

            _channel = Channel.CreateBounded<LogEntry>(
                 new BoundedChannelOptions(CHANNEL_CAPACITY)
                 {
                     SingleReader = true,
                     FullMode = BoundedChannelFullMode.DropWrite
                 });

            _conn = new DuckDBConnection($"Data Source={dbPath}");
            await _conn.OpenAsync();
            await CreateSchemaAsync();

            _consumerTask = Task.Run(ProcessLogsAsync);
        }

        public Task InsertLogAsync(
            DateTime timestamp,
            DnsDatagram request,
            IPEndPoint remoteEP,
            DnsTransportProtocol protocol,
            DnsDatagram response)
        {
            if (_enableLogging)
                _channel.Writer.TryWrite(
                    new LogEntry(timestamp, request, remoteEP, protocol, response));

            return Task.CompletedTask;
        }

        public async Task<DnsLogPage> QueryLogsAsync(
            long pageNumber,
            int entriesPerPage,
            bool descendingOrder,
            DateTime? start,
            DateTime? end,
            IPAddress clientIpAddress,
            DnsTransportProtocol? protocol,
            DnsServerResponseType? responseType,
            DnsResponseCode? rcode,
            string qname,
            DnsResourceRecordType? qtype,
            DnsClass? qclass)
        {
            using DuckDBCommand cmd = _conn.CreateCommand();

            List<string> filters = new List<string>();

            if (start is not null)
            {
                filters.Add("timestamp >= @s");
                cmd.Parameters.Add(new DuckDBParameter("@s", start));
            }

            if (end is not null)
            {
                filters.Add("timestamp <= @e");
                cmd.Parameters.Add(new DuckDBParameter("@e", end));
            }

            string whereSql = filters.Count > 0
                    ? " WHERE " + string.Join(" AND ", filters)
                : string.Empty;

            cmd.CommandText = $"SELECT count() FROM dns_logs {whereSql}";
            long totalEntries = Convert.ToInt64(await cmd.ExecuteScalarAsync());

            long totalPages =
                (long)Math.Ceiling((double)totalEntries / entriesPerPage);

            pageNumber = Math.Clamp(pageNumber, 1, Math.Max(1, totalPages));

            cmd.CommandText = $@"
SELECT server, timestamp, client_ip, protocol, response_type,
       response_rtt, rcode, qname, qtype, qclass, answer
FROM dns_logs
{whereSql}
ORDER BY timestamp {(descendingOrder ? "DESC" : "ASC")}
LIMIT {entriesPerPage}
OFFSET {(pageNumber - 1) * entriesPerPage}";

            List<DnsLogEntry> list = new List<DnsLogEntry>();

            using System.Data.Common.DbDataReader reader = await cmd.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                var server = reader.GetString(0);
                DateTime ts = reader.GetDateTime(1);
                IPAddress ip = IPAddress.Parse(reader.GetString(2));
                DnsTransportProtocol proto = (DnsTransportProtocol)reader.GetByte(3);

                DnsServerResponseType respType =
                    reader.IsDBNull(4)
                        ? default
                        : (DnsServerResponseType)reader.GetByte(4);

                double? rtt =
                    reader.IsDBNull(5)
                        ? null
                        : reader.GetDouble(5);

                DnsResponseCode rc = (DnsResponseCode)reader.GetByte(6);

                string? qn =
                    reader.IsDBNull(7) ? null : reader.GetString(7);

                DnsQuestionRecord? question = null;

                if (!reader.IsDBNull(8) &&
                    !reader.IsDBNull(9) &&
                    qn is not null)
                {
                    question = new DnsQuestionRecord(
                        qn,
                        (DnsResourceRecordType)reader.GetInt16(8),
                        (DnsClass)reader.GetInt16(9),
                        false);
                }

                string? ans =
                    reader.IsDBNull(10) ? null : reader.GetString(10);

                list.Add(
                    new DnsLogEntry(
                        0, ts, ip, proto, respType, rtt, rc, question, ans));
            }

            return new DnsLogPage(pageNumber, totalPages, totalEntries, list);
        }

        #endregion public

        #region properties

        public string Description
        { get { return "Logs DNS requests to DuckDB using Parquet for high-performance analytical storage."; } }

        #endregion properties

        private readonly struct LogEntry
        {
            #region variables

            public readonly DnsTransportProtocol Protocol;
            public readonly IPEndPoint RemoteEP;
            public readonly DnsDatagram Request;
            public readonly DnsDatagram Response;
            public readonly DateTime Timestamp;

            #endregion variables

            #region constructor

            public LogEntry(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
            {
                Timestamp = timestamp;
                Request = request;
                RemoteEP = remoteEP;
                Protocol = protocol;
                Response = response;
            }

            #endregion constructor
        }
    }
}