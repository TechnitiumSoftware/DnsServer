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
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace QueryLogsDuckDB
{
    public sealed class App : IDnsApplication, IDnsQueryLogger, IDnsQueryLogs
    {
        #region variables
        // Initial capacity for answer StringBuilder
        private const int DEFAULT_ANSWER_SIZE = 256;

        // To prevent excessive memory usage, answers larger than this will be truncated. Used the value of MySQL app.
        private const int MAX_ANSWER_SIZE = 4000;

        // Maximum number of log entries to process in a single batch
        private const int MAX_BATCH_SIZE = 1000;

        [ThreadStatic]
        private static StringBuilder? _sb;
        private Channel<LogEntry>? _channel;
        Config? _config;
        private DuckDBConnection? _conn;
        private Task? _consumerTask;
        private Task? _retentionTask;
        private bool _disposed;
        private IDnsServer? _dnsServer;
        private readonly SemaphoreSlim _dbGate = new(1, 1);

        #endregion variables

        #region IDisposable

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // To prevent blocking shutdown, we attempt to complete the channel and wait for the consumer task to finish.
                    // This ensures that the application can shut down gracefully without being hindered by logging operations.
                    try { _channel?.Writer.TryComplete(); }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine("QueryLogsDuckDB.App: Error while completing log channel during Dispose: " + ex);
                    }
                    try { _consumerTask?.Wait(5000); _consumerTask?.Dispose(); }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine("QueryLogsDuckDB.App: Error while waiting for consumer task during Dispose: " + ex);
                    }
                    try { _retentionTask?.Wait(5000); _retentionTask?.Dispose(); }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine("QueryLogsDuckDB.App: Error while waiting for retention task during Dispose: " + ex);
                    }
                    try { _conn?.Close(); _conn?.Dispose(); }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine("QueryLogsDuckDB.App: Error while closing/disposing DuckDB connection during Dispose: " + ex);
                    }
                }

                _disposed = true;
            }
        }
        #endregion IDisposable

        #region private

        private static StringBuilder GetStringBuilder()
        {
            StringBuilder? sb = _sb;

            if (sb is null)
                return _sb = new StringBuilder(DEFAULT_ANSWER_SIZE, MAX_ANSWER_SIZE);

            sb.Clear();
            return sb;
        }

        private async Task BulkInsertAsync(List<LogEntry> logs)
        {
            await _dbGate.WaitAsync();
            try
            {
                // We create a new appender for each batch to avoid issues with concurrent usage
                // By default, the appender performs commits every 204,800 rows.
                // Since we are using smaller batches, we are forcing appender to close after each batch.
                // It makes the flush to disk more frequent, but ensures data integrity in case of crashes.
                // Each batch flush is atomic.
                using DuckDBAppender appender = _conn!.CreateAppender("dns_logs");
                foreach (LogEntry log in logs
                    .Where(log => log.Request is not null && log.Response is not null))
                {
                    DnsQuestionRecord? question =
                        log.Request.Question.Count > 0
                            ? log.Request.Question[0]
                            : null;

                    //Response Type(Aligned)
                    DnsServerResponseType responseType = log.Response.Tag is null
                        ? DnsServerResponseType.Recursive
                        : (DnsServerResponseType)log.Response.Tag;

                    //RTT
                    double? rtt = null;

                    if (responseType == DnsServerResponseType.Recursive &&
                        log.Response.Metadata is not null)
                    {
                        rtt = log.Response.Metadata.RoundTripTime;
                    }

                    // Answer (bounded, safe)
                    string? answer = null;

                    if (log.Response.Answer.Count > 0)
                    {
                        if (log.Response.IsZoneTransfer && log.Response.Answer.Count > 2)
                        {
                            answer = "[ZONE TRANSFER]";
                        }
                        else
                        {
                            StringBuilder sb = GetStringBuilder();
                            bool first = true;

                            foreach (DnsResourceRecord record in log.Response.Answer)
                            {
                                if (!first)
                                {
                                    if (sb.Length + 2 >= MAX_ANSWER_SIZE)
                                        break;

                                    sb.Append(", ");
                                }

                                string part = $"{record.Type} {record.RDATA}";

                                int remaining =
                                    MAX_ANSWER_SIZE - sb.Length;

                                if (remaining <= 0)
                                    break;

                                if (part.Length > remaining)
                                {
                                    sb.Append(part.AsSpan(0, remaining));
                                    break;
                                }

                                sb.Append(part);
                                first = false;
                            }

                            answer = sb.Length == 0 ? null : sb.ToString();
                        }
                    }

                    //Insert Row
                    IDuckDBAppenderRow row = appender.CreateRow();

                    row.AppendValue(_dnsServer!.ServerDomain);
                    row.AppendValue(log.Timestamp);
                    row.AppendValue(log.RemoteEP.Address.ToString());
                    row.AppendValue((byte)log.Protocol);

                    row.AppendValue((byte)responseType);

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
                // No need for a wait as this is running synchronously in the background,
                // we just log and continue.
                // No risk of concurrency issues and waiting here would block the logging thread.
            }
            finally
            {
                _dbGate.Release();
            }
        }

        private async Task CreateSchemaAsync()
        {
            using DuckDBCommand cmd = _conn!.CreateCommand();

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

            string index = "CREATE INDEX IF NOT EXISTS idx_ts_srv_ip ON dns_logs(timestamp, server, client_ip);";
            cmd.CommandText = index;
            await cmd.ExecuteNonQueryAsync();
        }

        private async Task ProcessLogsAsync()
        {
            List<LogEntry> batch = new List<LogEntry>(MAX_BATCH_SIZE);

            while (!_disposed && await _channel!.Reader.WaitToReadAsync())
            {
                while (batch.Count < MAX_BATCH_SIZE &&
                       _channel.Reader.TryRead(out LogEntry log))
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

        private async Task RetentionLoopAsync()
        {
            await Task.Delay(TimeSpan.FromMinutes(1));

            while (!_disposed)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(15));
                    if (_disposed) break;
                    await RunRetentionAsync();
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(ex);
                }
            }
        }

        private async Task RunRetentionAsync()
        {
            if (_conn is null || _config is null)
                return;

            await _dbGate.WaitAsync();
            try
            {
                using DuckDBCommand cmd = _conn.CreateCommand();

                long deleted = 0;

                /* ---------------------------------
                   Max records
                   --------------------------------- */

                if (_config.MaxLogRecords > 0)
                {
                    // Count first to avoid running a DELETE when there is nothing to prune.
                    cmd.Parameters.Clear();
                    cmd.CommandText = "SELECT count() FROM dns_logs;";
                    long totalRows = Convert.ToInt64(await cmd.ExecuteScalarAsync());
                    if (totalRows > _config.MaxLogRecords)
                    {
                        // Keep newest N rows (by timestamp). The cutoff is the Nth newest row.
                        // NOTE: Timestamp collisions can still cause >N rows to be retained; strict N
                        // requires a stable tiebreaker column (handled in a separate PR if needed).
                        cmd.Parameters.Clear();


                        cmd.CommandText = @"
WITH cutoff AS (
    SELECT timestamp
    FROM dns_logs
    ORDER BY timestamp DESC
    OFFSET ($limit - 1)
    LIMIT 1
)
DELETE FROM dns_logs
WHERE timestamp < (SELECT timestamp FROM cutoff);
";
                        cmd.Parameters.Clear();
                        cmd.Parameters.Add(
                            new DuckDBParameter("limit", _config.MaxLogRecords));

                        deleted += await cmd.ExecuteNonQueryAsync();
                    }
                }

                /* ---------------------------------
                   Max days
                   --------------------------------- */

                if (_config.MaxLogDays > 0)
                {
                    DateTime cutoff =
                        DateTime.UtcNow.AddDays(-_config.MaxLogDays);

                    cmd.CommandText =
                        "DELETE FROM dns_logs WHERE timestamp < $cutoff;";

                    cmd.Parameters.Clear();
                    cmd.Parameters.Add(
                        new DuckDBParameter("cutoff", cutoff));

                    deleted += await cmd.ExecuteNonQueryAsync();
                }

                if (deleted > 0)
                {
                    cmd.Parameters.Clear();
                    cmd.CommandText = "CHECKPOINT;";
                    await cmd.ExecuteNonQueryAsync();
                    _dnsServer?.WriteLog($"DuckDB retention removed {deleted} records.");
                }
            }
            finally
            {
                _dbGate.Release();
            }
        }
        #endregion private

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            JsonSerializerOptions options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            _config = JsonSerializer.Deserialize<Config>(config, options);
            _config ??= new Config();
            Validator.ValidateObject(_config, new ValidationContext(_config), validateAllProperties: true);

            if (!System.IO.Path.IsPathRooted(_config.DbPath))
                _config.DbPath = System.IO.Path.Combine(dnsServer.ApplicationFolder, _config.DbPath);

            _channel = Channel.CreateBounded<LogEntry>(
                 new BoundedChannelOptions(_config.MaxQueueSize)
                 {
                     SingleReader = true,
                     SingleWriter = true,
                     FullMode = BoundedChannelFullMode.DropWrite
                 });

            _conn = new DuckDBConnection($"Data Source={_config.DbPath}");
            await _conn.OpenAsync();
            await CreateSchemaAsync();

            _consumerTask = Task.Run(ProcessLogsAsync).ContinueWith(
                t => { var _ = t.Exception; },
                TaskContinuationOptions.OnlyOnFaulted);
            _retentionTask = Task.Run(RetentionLoopAsync).ContinueWith(
                t => { var _ = t.Exception; },
                TaskContinuationOptions.OnlyOnFaulted);
        }

        public Task InsertLogAsync(
            DateTime timestamp,
            DnsDatagram request,
            IPEndPoint remoteEP,
            DnsTransportProtocol protocol,
            DnsDatagram response)
        {
            if (_disposed) return Task.CompletedTask;
            if (_config is null) return Task.CompletedTask;
            if (_conn is null) return Task.CompletedTask;

            if (_config.EnableLogging)
                _channel!.Writer.TryWrite(
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
            if (entriesPerPage <= 0)
                throw new ArgumentOutOfRangeException(
                    nameof(entriesPerPage),
                    "entriesPerPage must be greater than zero.");

            // Prevent pathological page sizes (DoS / memory abuse)
            const int MaxPageSize = 10_000;

            if (entriesPerPage > MaxPageSize)
                entriesPerPage = MaxPageSize;

            if (pageNumber < 1)
                pageNumber = 1;

            // Normalize inverted time ranges
            if (start is not null &&
                end is not null &&
                start > end)
            {
                (start, end) = (end, start);
            }

            using DuckDBCommand cmd = _conn!.CreateCommand();

            List<string> filters = new List<string>();

            /* ---------------------------------
               Filters
               --------------------------------- */

            if (start is not null)
            {
                filters.Add("timestamp >= $s");
                cmd.Parameters.Add(new DuckDBParameter("s", start));
            }

            if (end is not null)
            {
                filters.Add("timestamp <= $e");
                cmd.Parameters.Add(new DuckDBParameter("e", end));
            }

            if (clientIpAddress is not null)
            {
                filters.Add("client_ip = $cip");
                cmd.Parameters.Add(
                    new DuckDBParameter("cip", clientIpAddress.ToString()));
            }

            if (protocol is not null)
            {
                filters.Add("protocol = $proto");
                cmd.Parameters.Add(
                    new DuckDBParameter("proto", (byte)protocol.Value));
            }

            if (responseType is not null)
            {
                filters.Add("response_type = $rtype");
                cmd.Parameters.Add(
                    new DuckDBParameter("rtype", (byte)responseType.Value));
            }

            if (rcode is not null)
            {
                filters.Add("rcode = $rcode");
                cmd.Parameters.Add(
                    new DuckDBParameter("rcode", (byte)rcode.Value));
            }

            if (!string.IsNullOrWhiteSpace(qname))
            {
                qname = qname.Trim().ToLowerInvariant();
                if (qname.Contains('*'))
                {
                    qname = qname.Replace('*', '%');
                }
                filters.Add("qname LIKE $qname");
                cmd.Parameters.Add(
                    new DuckDBParameter("qname", qname));
            }

            if (qtype is not null)
            {
                filters.Add("qtype = $qtype");
                cmd.Parameters.Add(
                    new DuckDBParameter("qtype", (ushort)qtype.Value));
            }

            if (qclass is not null)
            {
                filters.Add("qclass = $qclass");
                cmd.Parameters.Add(
                    new DuckDBParameter("qclass", (ushort)qclass.Value));
            }

            string whereSql =
                filters.Count > 0
                    ? " WHERE " + string.Join(" AND ", filters)
                    : string.Empty;

            /* ---------------------------------
               Count
               --------------------------------- */

            cmd.CommandText =
                $"SELECT count() FROM dns_logs {whereSql}";

            long totalEntries =
                Convert.ToInt64(await cmd.ExecuteScalarAsync());

            long totalPages =
                totalEntries == 0
                    ? 1
                    : (long)Math.Ceiling(
                        (double)totalEntries / entriesPerPage);

            pageNumber =
                Math.Clamp(pageNumber, 1, totalPages);

            /* ---------------------------------
               Offset (overflow-safe)
               --------------------------------- */

            long offset;

            try
            {
                checked
                {
                    offset =
                        (pageNumber - 1) * entriesPerPage;
                }
            }
            catch (OverflowException)
            {
                offset = 0;
                pageNumber = 1;
            }

            /* ---------------------------------
               Pagination parameters
               --------------------------------- */

            cmd.Parameters.Add(
                new DuckDBParameter("limit", entriesPerPage));

            cmd.Parameters.Add(
                new DuckDBParameter("offset", offset));

            /* ---------------------------------
               Main query
               --------------------------------- */

            cmd.CommandText = $@"
SELECT server,
       timestamp,
       client_ip,
       protocol,
       response_type,
       response_rtt,
       rcode,
       qname,
       qtype,
       qclass,
       answer
FROM dns_logs
{whereSql}
ORDER BY timestamp {(descendingOrder ? "DESC" : "ASC")}
LIMIT $limit
OFFSET $offset";

            List<DnsLogEntry> list = new List<DnsLogEntry>(entriesPerPage);

            /* ---------------------------------
               Read
               --------------------------------- */

            using System.Data.Common.DbDataReader reader =
                await cmd.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                DateTime ts = reader.GetDateTime(1);

                IPAddress ip =
                    IPAddress.Parse(reader.GetString(2));

                DnsTransportProtocol proto =
                    (DnsTransportProtocol)reader.GetByte(3);

                DnsServerResponseType respType =
                    (DnsServerResponseType)reader.GetByte(4);

                double? rtt =
                    reader.IsDBNull(5)
                        ? null
                        : reader.GetDouble(5);

                DnsResponseCode rc =
                    (DnsResponseCode)reader.GetByte(6);

                string? qn =
                    reader.IsDBNull(7)
                        ? null
                        : reader.GetString(7);

                DnsQuestionRecord? question = null;

                if (qn is not null &&
                    !reader.IsDBNull(8) &&
                    !reader.IsDBNull(9))
                {
                    question = new DnsQuestionRecord(
                        qn,
                        (DnsResourceRecordType)reader.GetFieldValue<ushort>(8),
                        (DnsClass)reader.GetFieldValue<ushort>(9),
                        false);
                }

                string? ans =
                    reader.IsDBNull(10)
                        ? null
                        : reader.GetString(10);

                list.Add(
                    new DnsLogEntry(
                        0,
                        ts,
                        ip,
                        proto,
                        respType,
                        rtt,
                        rc,
                        question,
                        ans));
            }

            return new DnsLogPage(
                pageNumber,
                totalPages,
                totalEntries,
                list);
        }

        #endregion public

        #region properties

        public string Description
        { get { return "Logs all incoming DNS requests and their responses in a DuckDB database that can be queried from the DNS Server web console."; } }

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

        private class Config
        {
            [JsonPropertyName("dbPath")]
            public string DbPath { get; set; } = "querylogs.db";

            [JsonPropertyName("enableLogging")]
            public bool EnableLogging { get; set; } = true;

            [JsonPropertyName("maxLogDays")]
            [Range(1, 365)]
            public int MaxLogDays { get; set; } = 30;

            [JsonPropertyName("maxLogRecords")]
            [Range(1, 5_000_000)]
            public long MaxLogRecords { get; set; } = 1_000_000;

            [JsonPropertyName("maxQueueSize")]
            [Range(1_000, 1_000_000)]
            public int MaxQueueSize { get; set; } = 200_000;
        }
    }
}