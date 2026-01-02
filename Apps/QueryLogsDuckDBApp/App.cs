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
using System.Data;
using System.IO;
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

        private IDnsServer _dnsServer;
        private DuckDBConnection _conn;
        private string _parquetPath;
        private string _dbPath;

        private bool _enableLogging;
        private int _bufferedRows = 0;
        private const int MAX_BATCH_SIZE = 10000;
        private const string BUFFER_TABLE = "dns_buffer";
        private const string UNIFIED_VIEW = "dns_logs";

        private Channel<LogEntry> _channel;
        private Task _consumerTask;
        private bool _disposed;

        #endregion variables

        #region IDisposable

        public void Dispose()
        {
            if (_disposed) return;
            _channel?.Writer.TryComplete();
            _consumerTask?.Wait(5000);
            FlushToParquetAsync().GetAwaiter().GetResult();
            _conn?.Dispose();
            _disposed = true;
        }

        #endregion IDisposable

        #region private

        private async Task RefreshViewAsync()
        {
            string parquetSource = File.Exists(_parquetPath)
                ? $"read_parquet('{_parquetPath}')"
                : $"(SELECT * FROM {BUFFER_TABLE} WHERE 1=0)";

            using var cmd = _conn.CreateCommand();
            cmd.CommandText = $"CREATE OR REPLACE VIEW {UNIFIED_VIEW} AS SELECT * FROM {BUFFER_TABLE} UNION ALL SELECT * FROM {parquetSource};";
            await cmd.ExecuteNonQueryAsync();
        }

        private async Task ProcessLogsAsync()
        {
            var batch = new List<LogEntry>(MAX_BATCH_SIZE);
            while (await _channel.Reader.WaitToReadAsync())
            {
                while (batch.Count < MAX_BATCH_SIZE && _channel.Reader.TryRead(out var log))
                {
                    batch.Add(log);
                }

                if (batch.Count > 0)
                {
                    await BulkInsertInternalAsync(batch);
                    batch.Clear();
                }
            }
        }

        private async Task BulkInsertInternalAsync(List<LogEntry> logs)
        {
            try
            {
                using (var appender = _conn.CreateAppender(BUFFER_TABLE))
                {
                    foreach (var log in logs)
                    {
                        if (log.Request is null || log.Response is null)
                            continue; // skip corrupt entries defensively

                        var question = log.Request.Question?[0];
                        var row = appender.CreateRow();

                        // RTT is only meaningful when Metadata exists and Tag is null
                        double? rtt =
                            (log.Response.Tag is null && log.Response.Metadata is not null)
                            ? log.Response.Metadata.RoundTripTime
                            : null;

                        // Nullable values prepared up front
                        byte? tag =
                            log.Response.Tag is null ? (byte?)null : ((byte)log.Response.Tag);

                        byte rcode =  (byte)log.Response.RCODE;

                        string? qname =
                            question?.Name is null ? null : question.Name.ToLowerInvariant();

                        ushort? qtype =
                            question is null ? (ushort?)null : (ushort)question.Type;

                        ushort? qclass =
                            question is null ? (ushort?)null : (ushort)question.Class;

                        // Append values — emit NULLs where appropriate
                        row.AppendValue(log.Timestamp);

                        row.AppendValue(
                            log.RemoteEP?.Address is null
                                ? null
                                : log.RemoteEP.Address.ToString());

                        row.AppendValue((byte)log.Protocol);

                        if (tag is null) row.AppendNullValue(); else row.AppendValue(tag.Value);

                        if (rtt is null) row.AppendNullValue(); else row.AppendValue(rtt.Value);

                        row.AppendValue(rcode);

                        if (qname is null) row.AppendNullValue(); else row.AppendValue(qname);

                        if (qtype is null) row.AppendNullValue(); else row.AppendValue(qtype.Value);

                        if (qclass is null) row.AppendNullValue(); else row.AppendValue(qclass.Value);

                        var answer = FormatAnswer(log.Response);
                        if (answer is null) row.AppendNullValue(); else row.AppendValue(answer);

                        row.EndRow();

                        _bufferedRows++;
                    }

                }

                if (_bufferedRows >= MAX_BATCH_SIZE)
                {
                    await FlushToParquetAsync();
                }
            }
            catch (Exception ex) { _dnsServer.WriteLog(ex); }
        }

        private string? FormatAnswer(DnsDatagram response)
        {
            if (response.Answer.Count == 0) return null;
            return string.Join(", ", response.Answer.Select(r => $"{r.Type} {r.RDATA}"));
        }

        private async Task FlushToParquetAsync()
        {
            if (_bufferedRows == 0) return;
            string tempFile = _parquetPath + ".tmp";

            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = $"COPY (SELECT * FROM {UNIFIED_VIEW} ORDER BY timestamp ASC) TO '{tempFile}' (FORMAT PARQUET, COMPRESSION 'ZSTD');";
                await cmd.ExecuteNonQueryAsync();

                cmd.CommandText = $"DELETE FROM {BUFFER_TABLE};";
                await cmd.ExecuteNonQueryAsync();
            }

            if (File.Exists(_parquetPath)) File.Delete(_parquetPath);
            File.Move(tempFile, _parquetPath);

            _bufferedRows = 0;
            await RefreshViewAsync();
        }

        #endregion private

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _enableLogging = jsonConfig.GetPropertyValue("enableLogging", true);
            string dbFileName = jsonConfig.GetPropertyValue("dbPath", "querylogs.duckdb");
            _dbPath = Path.IsPathRooted(dbFileName) ? dbFileName : Path.Combine(_dnsServer.ApplicationFolder, dbFileName);
            _parquetPath = Path.ChangeExtension(_dbPath, ".parquet");

            // Initialize DuckDB Connection
            _conn = new DuckDBConnection($"Data Source={_dbPath}");
            await _conn.OpenAsync();

            // Load plugin
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = "INSTALL parquet;LOAD parquet;";
                await cmd.ExecuteNonQueryAsync();
            }

            // Setup Schema
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = $@"
                    CREATE TEMP TABLE IF NOT EXISTS {BUFFER_TABLE} (
                        timestamp TIMESTAMP,
                        client_ip VARCHAR(39),
                        protocol UTINYINT,
                        response_type UTINYINT,
                        response_rtt DOUBLE,
                        rcode UTINYINT,
                        qname VARCHAR(255),
                        qtype USMALLINT,
                        qclass USMALLINT,
                        answer TEXT
                    );";
                await cmd.ExecuteNonQueryAsync();
            }

            await RefreshViewAsync();

            // Start Producer-Consumer Channel
            _channel = Channel.CreateBounded<LogEntry>(new BoundedChannelOptions(200000)
            {
                SingleReader = true,
                FullMode = BoundedChannelFullMode.DropWrite
            });

            _consumerTask = Task.Run(ProcessLogsAsync);
        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (_enableLogging)
                _channel.Writer.TryWrite(new LogEntry(timestamp, request, remoteEP, protocol, response));

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
            using var cmd = _conn.CreateCommand();
            var filters = new List<string>();

            // ----- filters -----

            if (start.HasValue)
            {
                filters.Add("timestamp >= @start");
                cmd.Parameters.Add(new DuckDBParameter("@start", start.Value));
            }

            if (end.HasValue)
            {
                filters.Add("timestamp <= @end");
                cmd.Parameters.Add(new DuckDBParameter("@end", end.Value));
            }

            if (clientIpAddress is not null)
            {
                filters.Add("client_ip = @ip");
                cmd.Parameters.Add(new DuckDBParameter("@ip", clientIpAddress.ToString()));
            }

            if (protocol.HasValue)
            {
                filters.Add("protocol = @p");
                cmd.Parameters.Add(new DuckDBParameter("@p", (byte)protocol.Value));
            }

            if (responseType.HasValue)
            {
                filters.Add("response_type = @rt");
                cmd.Parameters.Add(new DuckDBParameter("@rt", (byte)responseType.Value));
            }

            if (rcode.HasValue)
            {
                filters.Add("rcode = @rc");
                cmd.Parameters.Add(new DuckDBParameter("@rc", (byte)rcode.Value));
            }

            if (qtype.HasValue)
            {
                filters.Add("qtype = @qt");
                cmd.Parameters.Add(new DuckDBParameter("@qt", (ushort)qtype.Value));
            }

            if (qclass.HasValue)
            {
                filters.Add("qclass = @qc");
                cmd.Parameters.Add(new DuckDBParameter("@qc", (ushort)qclass.Value));
            }

            if (!string.IsNullOrWhiteSpace(qname))
            {
                filters.Add("LOWER(qname) LIKE @qn");
                cmd.Parameters.Add(new DuckDBParameter("@qn", $"%{qname.ToLowerInvariant()}%"));
            }

            string whereSql = filters.Count > 0
                ? " WHERE " + string.Join(" AND ", filters)
                : string.Empty;

            // ----- count -----

            cmd.CommandText = $"SELECT COUNT(*) FROM {UNIFIED_VIEW} {whereSql}";
            long totalEntries = Convert.ToInt64(await cmd.ExecuteScalarAsync());
            long totalPages = (long)Math.Ceiling((double)totalEntries / entriesPerPage);
            pageNumber = Math.Clamp(pageNumber, 1, Math.Max(1, totalPages));

            // ----- data query -----

            cmd.CommandText = $@"
        SELECT
            timestamp,        -- 0
            client_ip,        -- 1
            protocol,         -- 2 (UTINYINT, may be NULL)
            response_type,    -- 3 (UTINYINT, may be NULL)
            response_rtt,     -- 4 (DOUBLE, may be NULL)
            rcode,            -- 5 (UTINYINT, may be NULL)
            qname,            -- 6 (TEXT, may be NULL)
            qtype,            -- 7 (USMALLINT, may be NULL)
            qclass,           -- 8 (USMALLINT, may be NULL)
            answer            -- 9 (TEXT, may be NULL)
        FROM {UNIFIED_VIEW}
        {whereSql}
        ORDER BY timestamp {(descendingOrder ? "DESC" : "ASC")}
        LIMIT {entriesPerPage}
        OFFSET {(pageNumber - 1) * entriesPerPage}
    ";


            var entries = new List<DnsLogEntry>();

            using var reader = await cmd.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                DateTime timestamp = reader.GetDateTime(0);

                IPAddress clientIp =
                    reader.IsDBNull(1)
                        ? IPAddress.None
                        : IPAddress.Parse(reader.GetString(1));

                // protocol (nullable in DB)
                DnsTransportProtocol? proto =
                    reader.IsDBNull(2)
                        ? null
                        : SafeEnum<DnsTransportProtocol, byte>(reader.GetByte(2));

                // response_type (nullable in DB)
                DnsServerResponseType? respType =
                    reader.IsDBNull(3)
                        ? null
                        : SafeEnum<DnsServerResponseType, byte>(reader.GetByte(3));

                // rtt (nullable)
                double? rtt =
                    reader.IsDBNull(4) ? null : reader.GetDouble(4);

                // rcode (nullable in DB)
                DnsResponseCode? respCode =
                    reader.IsDBNull(5)
                        ? null
                        : SafeEnum<DnsResponseCode, byte>(reader.GetByte(5));

                string? qn = reader.IsDBNull(6) ? null : reader.GetString(6);

                DnsResourceRecordType? qt =
                    reader.IsDBNull(7)
                        ? null
                        : SafeEnum<DnsResourceRecordType, ushort>((ushort)reader.GetInt16(7));

                DnsClass? qc =
                    reader.IsDBNull(8)
                        ? null
                        : SafeEnum<DnsClass, ushort>((ushort)reader.GetInt16(8));

                string? answer =
                    reader.IsDBNull(9) ? null : reader.GetString(9);

                DnsQuestionRecord? question = null;

                if (qn is not null && qt.HasValue && qc.HasValue)
                {
                    question = new DnsQuestionRecord(
                        qn,
                        qt.Value,
                        qc.Value,
                        false
                    );
                }

                // DnsLogEntry takes NON-nullable enums → we must provide defaults
                entries.Add(
                    new DnsLogEntry(
                        0,
                        timestamp,
                        clientIp,
                        proto ?? default,          // safe fallback
                        respType ?? default,       // ← avoids InvalidCastException
                        rtt ?? 0d,
                        respCode ?? default,
                        question,
                        answer
                    )
                );
            }

            return new DnsLogPage(pageNumber, totalPages, totalEntries, entries);
        }

        private static TEnum? SafeEnum<TEnum, TRaw>(TRaw? value)
            where TEnum : struct, Enum
            where TRaw : struct, IConvertible
        {
            if (value is null) return null;

            // normalize value to UInt64 for comparison
            ulong v = Convert.ToUInt64(value);

            // compare against enum values (normalized)
            foreach (var ev in Enum.GetValues(typeof(TEnum)))
            {
                if (Convert.ToUInt64(ev) == v)
                    return (TEnum)Enum.ToObject(typeof(TEnum), v);
            }

            // not a valid enum member
            return null;
        }


        #endregion public

        #region properties

        public string Description
        { get { return "Logs DNS requests to DuckDB using Parquet for high-performance analytical storage."; } }

        #endregion properties

        private readonly struct LogEntry
        {
            #region variables

            public readonly DateTime Timestamp;
            public readonly DnsDatagram Request;
            public readonly IPEndPoint RemoteEP;
            public readonly DnsTransportProtocol Protocol;
            public readonly DnsDatagram Response;

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