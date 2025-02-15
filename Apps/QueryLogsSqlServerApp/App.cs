/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using Microsoft.Data.SqlClient;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace QueryLogsSqlServer
{
    public sealed class App : IDnsApplication, IDnsQueryLogger, IDnsQueryLogs
    {
        #region variables

        IDnsServer? _dnsServer;

        bool _enableLogging;
        int _maxQueueSize;
        int _maxLogDays;
        int _maxLogRecords;
        string? _databaseName;
        string? _connectionString;

        readonly ConcurrentQueue<LogEntry> _queuedLogs = new ConcurrentQueue<LogEntry>();
        readonly Timer _queueTimer;
        const int QUEUE_TIMER_INTERVAL = 10000;
        const int BULK_INSERT_COUNT = 190; //sql server supports a maximum of 2100 parameters per query

        readonly Timer _cleanupTimer;
        const int CLEAN_UP_TIMER_INITIAL_INTERVAL = 5 * 1000;
        const int CLEAN_UP_TIMER_PERIODIC_INTERVAL = 15 * 60 * 1000;

        #endregion

        #region constructor

        public App()
        {
            _queueTimer = new Timer(async delegate (object? state)
            {
                try
                {
                    await BulkInsertLogsAsync();
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(ex);
                }
                finally
                {
                    try
                    {
                        _queueTimer?.Change(QUEUE_TIMER_INTERVAL, Timeout.Infinite);
                    }
                    catch (ObjectDisposedException)
                    { }
                }
            });

            _cleanupTimer = new Timer(async delegate (object? state)
            {
                try
                {
                    await using (SqlConnection connection = new SqlConnection(_connectionString + $" Initial Catalog={_databaseName};"))
                    {
                        await connection.OpenAsync();

                        if (_maxLogRecords > 0)
                        {
                            int totalRecords;

                            await using (SqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "SELECT Count(*) FROM dns_logs;";

                                totalRecords = Convert.ToInt32(await command.ExecuteScalarAsync() ?? 0);
                            }

                            int recordsToRemove = totalRecords - _maxLogRecords;
                            if (recordsToRemove > 0)
                            {
                                await using (SqlCommand command = connection.CreateCommand())
                                {
                                    command.CommandText = $"DELETE FROM dns_logs WHERE dlid IN (SELECT TOP {recordsToRemove} dlid FROM dns_logs ORDER BY dlid);";

                                    await command.ExecuteNonQueryAsync();
                                }
                            }
                        }

                        if (_maxLogDays > 0)
                        {
                            await using (SqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "DELETE FROM dns_logs WHERE timestamp < @timestamp;";

                                command.Parameters.AddWithValue("@timestamp", DateTime.UtcNow.AddDays(_maxLogDays * -1));

                                await command.ExecuteNonQueryAsync();
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(ex);
                }
                finally
                {
                    try
                    {
                        _cleanupTimer?.Change(CLEAN_UP_TIMER_PERIODIC_INTERVAL, Timeout.Infinite);
                    }
                    catch (ObjectDisposedException)
                    { }
                }
            });
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _enableLogging = false; //turn off logging

            _queueTimer?.Dispose();

            BulkInsertLogsAsync().Sync(); //flush any pending logs
        }

        #endregion

        #region private

        private async Task BulkInsertLogsAsync()
        {
            try
            {
                List<LogEntry> logs = new List<LogEntry>(BULK_INSERT_COUNT);
                StringBuilder sb = new StringBuilder(4096);

                while (true)
                {
                    while ((logs.Count < BULK_INSERT_COUNT) && _queuedLogs.TryDequeue(out LogEntry? log))
                    {
                        logs.Add(log);
                    }

                    if (logs.Count < 1)
                        break;

                    await using (SqlConnection connection = new SqlConnection(_connectionString + $" Initial Catalog={_databaseName};"))
                    {
                        await connection.OpenAsync();

                        await using (SqlCommand command = connection.CreateCommand())
                        {
                            sb.Length = 0;
                            sb.Append("INSERT INTO dns_logs (server, timestamp, client_ip, protocol, response_type, response_rtt, rcode, qname, qtype, qclass, answer) VALUES ");

                            for (int i = 0; i < logs.Count; i++)
                            {
                                if (i == 0)
                                    sb.Append($"(@server{i}, @timestamp{i}, @client_ip{i}, @protocol{i}, @response_type{i}, @response_rtt{i}, @rcode{i}, @qname{i}, @qtype{i}, @qclass{i}, @answer{i})");
                                else
                                    sb.Append($", (@server{i}, @timestamp{i}, @client_ip{i}, @protocol{i}, @response_type{i}, @response_rtt{i}, @rcode{i}, @qname{i}, @qtype{i}, @qclass{i}, @answer{i})");
                            }

                            command.CommandText = sb.ToString();

                            for (int i = 0; i < logs.Count; i++)
                            {
                                LogEntry log = logs[i];

                                SqlParameter paramServer = command.Parameters.Add("@server" + i, SqlDbType.VarChar);
                                SqlParameter paramTimestamp = command.Parameters.Add("@timestamp" + i, SqlDbType.DateTime);
                                SqlParameter paramClientIp = command.Parameters.Add("@client_ip" + i, SqlDbType.VarChar);
                                SqlParameter paramProtocol = command.Parameters.Add("@protocol" + i, SqlDbType.TinyInt);
                                SqlParameter paramResponseType = command.Parameters.Add("@response_type" + i, SqlDbType.TinyInt);
                                SqlParameter paramResponseRtt = command.Parameters.Add("@response_rtt" + i, SqlDbType.Real);
                                SqlParameter paramRcode = command.Parameters.Add("@rcode" + i, SqlDbType.TinyInt);
                                SqlParameter paramQname = command.Parameters.Add("@qname" + i, SqlDbType.VarChar);
                                SqlParameter paramQtype = command.Parameters.Add("@qtype" + i, SqlDbType.SmallInt);
                                SqlParameter paramQclass = command.Parameters.Add("@qclass" + i, SqlDbType.SmallInt);
                                SqlParameter paramAnswer = command.Parameters.Add("@answer" + i, SqlDbType.VarChar);

                                paramServer.Value = _dnsServer?.ServerDomain;
                                paramTimestamp.Value = log.Timestamp;
                                paramClientIp.Value = log.RemoteEP.Address.ToString();
                                paramProtocol.Value = (byte)log.Protocol;

                                DnsServerResponseType responseType;

                                if (log.Response.Tag == null)
                                    responseType = DnsServerResponseType.Recursive;
                                else
                                    responseType = (DnsServerResponseType)log.Response.Tag;

                                paramResponseType.Value = (byte)responseType;

                                if ((responseType == DnsServerResponseType.Recursive) && (log.Response.Metadata is not null))
                                    paramResponseRtt.Value = log.Response.Metadata.RoundTripTime;
                                else
                                    paramResponseRtt.Value = DBNull.Value;

                                paramRcode.Value = (byte)log.Response.RCODE;

                                if (log.Request.Question.Count > 0)
                                {
                                    DnsQuestionRecord query = log.Request.Question[0];

                                    paramQname.Value = query.Name.ToLowerInvariant();
                                    paramQtype.Value = (short)query.Type;
                                    paramQclass.Value = (short)query.Class;
                                }
                                else
                                {
                                    paramQname.Value = DBNull.Value;
                                    paramQtype.Value = DBNull.Value;
                                    paramQclass.Value = DBNull.Value;
                                }

                                if (log.Response.Answer.Count == 0)
                                {
                                    paramAnswer.Value = DBNull.Value;
                                }
                                else if ((log.Response.Answer.Count > 2) && log.Response.IsZoneTransfer)
                                {
                                    paramAnswer.Value = "[ZONE TRANSFER]";
                                }
                                else
                                {
                                    string? answer = null;

                                    foreach (DnsResourceRecord record in log.Response.Answer)
                                    {
                                        if (answer is null)
                                            answer = record.Type.ToString() + " " + record.RDATA.ToString();
                                        else
                                            answer += ", " + record.Type.ToString() + " " + record.RDATA.ToString();
                                    }

                                    if (answer?.Length > 4000)
                                        answer = answer.Substring(0, 4000);

                                    paramAnswer.Value = answer;
                                }
                            }

                            await command.ExecuteNonQueryAsync();
                        }
                    }

                    logs.Clear();
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _enableLogging = jsonConfig.GetPropertyValue("enableLogging", false);
            _maxQueueSize = jsonConfig.GetPropertyValue("maxQueueSize", 1000000);
            _maxLogDays = jsonConfig.GetPropertyValue("maxLogDays", 0);
            _maxLogRecords = jsonConfig.GetPropertyValue("maxLogRecords", 0);
            _databaseName = jsonConfig.GetPropertyValue("databaseName", "DnsQueryLogs");
            _connectionString = jsonConfig.GetPropertyValue("connectionString", null);

            if (_connectionString is null)
                throw new Exception("Please specify a valid connection string in 'connectionString' parameter.");

            if (_connectionString.Contains("Initial Catalog", StringComparison.OrdinalIgnoreCase))
                throw new Exception("The 'connectionString' parameter must not define 'Initial Catalog'. Configure the 'databaseName' parameter above instead.");

            if (!_connectionString.TrimEnd().EndsWith(';'))
                _connectionString += ";";

            if (_enableLogging)
            {
                await using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    await using (SqlCommand command = connection.CreateCommand())
                    {
                        command.CommandText = @$"
IF NOT EXISTS(SELECT * FROM sys.databases WHERE name = '{_databaseName}')
BEGIN
    CREATE DATABASE {_databaseName};
END
";

                        await command.ExecuteNonQueryAsync();
                    }

                    await using (SqlCommand command = connection.CreateCommand())
                    {
                        command.CommandText = @$"
USE {_databaseName};

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name='dns_logs' and type='U')
BEGIN
    CREATE TABLE dns_logs
    (
        dlid INT IDENTITY(1,1) PRIMARY KEY,
        server varchar(255),
        timestamp DATETIME NOT NULL,
        client_ip VARCHAR(39) NOT NULL,
        protocol TINYINT NOT NULL,
        response_type TINYINT NOT NULL,
        response_rtt REAL,
        rcode TINYINT NOT NULL,
        qname VARCHAR(255),
        qtype SMALLINT,
        qclass SMALLINT,
        answer VARCHAR(4000)
    );
END

IF NOT EXISTS(SELECT * FROM sys.columns WHERE name = 'server' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    ALTER TABLE dns_logs ADD server varchar(255);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_server' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_server ON dns_logs (server);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_timestamp' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_timestamp ON dns_logs (timestamp);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_client_ip' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_client_ip ON dns_logs (client_ip);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_protocol' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_protocol ON dns_logs (protocol);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_response_type' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_response_type ON dns_logs (response_type);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_rcode' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_rcode ON dns_logs (rcode);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_qname' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_qname ON dns_logs (qname)
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_qtype' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_qtype ON dns_logs (qtype);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_qclass' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_qclass ON dns_logs (qclass);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_timestamp_client_ip' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_timestamp_client_ip ON dns_logs (timestamp, client_ip);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_timestamp_qname' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_timestamp_qname ON dns_logs (timestamp, qname);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_client_qname' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_client_qname ON dns_logs (client_ip, qname);
END

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_query' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_query ON dns_logs (qname, qtype);
END 

IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name = 'index_all' AND object_id = OBJECT_ID('dns_logs'))
BEGIN
    CREATE INDEX index_all ON dns_logs (server, timestamp, client_ip, protocol, response_type, rcode, qname, qtype, qclass);
END
";

                        await command.ExecuteNonQueryAsync();
                    }
                }

                _queueTimer.Change(QUEUE_TIMER_INTERVAL, Timeout.Infinite);
            }
            else
            {
                _queueTimer.Change(Timeout.Infinite, Timeout.Infinite);
            }

            if ((_maxLogDays > 0) || (_maxLogRecords > 0))
                _cleanupTimer.Change(CLEAN_UP_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            else
                _cleanupTimer.Change(Timeout.Infinite, Timeout.Infinite);
        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (_enableLogging)
            {
                if (_queuedLogs.Count < _maxQueueSize)
                    _queuedLogs.Enqueue(new LogEntry(timestamp, request, remoteEP, protocol, response));
            }

            return Task.CompletedTask;
        }

        public async Task<DnsLogPage> QueryLogsAsync(long pageNumber, int entriesPerPage, bool descendingOrder, DateTime? start, DateTime? end, IPAddress clientIpAddress, DnsTransportProtocol? protocol, DnsServerResponseType? responseType, DnsResponseCode? rcode, string qname, DnsResourceRecordType? qtype, DnsClass? qclass)
        {
            if (pageNumber == 0)
                pageNumber = 1;

            if (qname is not null)
                qname = qname.ToLowerInvariant();

            string whereClause = $"server = '{_dnsServer?.ServerDomain}' AND ";

            if (start is not null)
                whereClause += "timestamp >= @start AND ";

            if (end is not null)
                whereClause += "timestamp <= @end AND ";

            if (clientIpAddress is not null)
                whereClause += "client_ip = @client_ip AND ";

            if (protocol is not null)
                whereClause += "protocol = @protocol AND ";

            if (responseType is not null)
                whereClause += "response_type = @response_type AND ";

            if (rcode is not null)
                whereClause += "rcode = @rcode AND ";

            if (qname is not null)
            {
                if (qname.Contains('*'))
                {
                    whereClause += "qname like @qname AND ";
                    qname = qname.Replace("*", "%");
                }
                else
                {
                    whereClause += "qname = @qname AND ";
                }
            }

            if (qtype is not null)
                whereClause += "qtype = @qtype AND ";

            if (qclass is not null)
                whereClause += "qclass = @qclass AND ";

            if (!string.IsNullOrEmpty(whereClause))
                whereClause = whereClause.Substring(0, whereClause.Length - 5);

            await using (SqlConnection connection = new SqlConnection(_connectionString + $" Initial Catalog={_databaseName};"))
            {
                await connection.OpenAsync();

                //find total entries
                long totalEntries;

                await using (SqlCommand command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT Count(*) FROM dns_logs" + (string.IsNullOrEmpty(whereClause) ? ";" : " WHERE " + whereClause + ";");

                    if (start is not null)
                        command.Parameters.AddWithValue("@start", start);

                    if (end is not null)
                        command.Parameters.AddWithValue("@end", end);

                    if (clientIpAddress is not null)
                        command.Parameters.AddWithValue("@client_ip", clientIpAddress.ToString());

                    if (protocol is not null)
                        command.Parameters.AddWithValue("@protocol", (byte)protocol);

                    if (responseType is not null)
                        command.Parameters.AddWithValue("@response_type", (byte)responseType);

                    if (rcode is not null)
                        command.Parameters.AddWithValue("@rcode", (byte)rcode);

                    if (qname is not null)
                        command.Parameters.AddWithValue("@qname", qname);

                    if (qtype is not null)
                        command.Parameters.AddWithValue("@qtype", (short)qtype);

                    if (qclass is not null)
                        command.Parameters.AddWithValue("@qclass", (ushort)qclass);

                    totalEntries = Convert.ToInt64(await command.ExecuteScalarAsync() ?? 0L);
                }

                long totalPages = (totalEntries / entriesPerPage) + (totalEntries % entriesPerPage > 0 ? 1 : 0);

                if ((pageNumber > totalPages) || (pageNumber < 0))
                    pageNumber = totalPages;

                long endRowNum;
                long startRowNum;

                if (descendingOrder)
                {
                    endRowNum = totalEntries - ((pageNumber - 1) * entriesPerPage);
                    startRowNum = endRowNum - entriesPerPage;
                }
                else
                {
                    endRowNum = pageNumber * entriesPerPage;
                    startRowNum = endRowNum - entriesPerPage;
                }

                List<DnsLogEntry> entries = new List<DnsLogEntry>(entriesPerPage);

                await using (SqlCommand command = connection.CreateCommand())
                {
                    command.CommandText = @"
SELECT * FROM (
    SELECT
        ROW_NUMBER() OVER ( 
            ORDER BY dlid
        ) row_num,
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
    FROM
        dns_logs
" + (string.IsNullOrEmpty(whereClause) ? "" : "WHERE " + whereClause) + @"
) t
WHERE 
    row_num > @start_row_num AND row_num <= @end_row_num
ORDER BY row_num" + (descendingOrder ? " DESC" : "");

                    command.Parameters.AddWithValue("@start_row_num", startRowNum);
                    command.Parameters.AddWithValue("@end_row_num", endRowNum);

                    if (start is not null)
                        command.Parameters.AddWithValue("@start", start);

                    if (end is not null)
                        command.Parameters.AddWithValue("@end", end);

                    if (clientIpAddress is not null)
                        command.Parameters.AddWithValue("@client_ip", clientIpAddress.ToString());

                    if (protocol is not null)
                        command.Parameters.AddWithValue("@protocol", (byte)protocol);

                    if (responseType is not null)
                        command.Parameters.AddWithValue("@response_type", (byte)responseType);

                    if (rcode is not null)
                        command.Parameters.AddWithValue("@rcode", (byte)rcode);

                    if (qname is not null)
                        command.Parameters.AddWithValue("@qname", qname);

                    if (qtype is not null)
                        command.Parameters.AddWithValue("@qtype", (short)qtype);

                    if (qclass is not null)
                        command.Parameters.AddWithValue("@qclass", (ushort)qclass);

                    await using (SqlDataReader reader = await command.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            double? responseRtt;

                            if (reader.IsDBNull(5))
                                responseRtt = null;
                            else
                                responseRtt = reader.GetFloat(5);

                            DnsQuestionRecord? question;

                            if (reader.IsDBNull(7))
                                question = null;
                            else
                                question = new DnsQuestionRecord(reader.GetString(7), (DnsResourceRecordType)reader.GetInt16(8), (DnsClass)reader.GetInt16(9), false);

                            string? answer;

                            if (reader.IsDBNull(10))
                                answer = null;
                            else
                                answer = reader.GetString(10);

                            entries.Add(new DnsLogEntry(reader.GetInt64(0), reader.GetDateTime(1), IPAddress.Parse(reader.GetString(2)), (DnsTransportProtocol)reader.GetByte(3), (DnsServerResponseType)reader.GetByte(4), responseRtt, (DnsResponseCode)reader.GetByte(6), question, answer));
                        }
                    }
                }

                return new DnsLogPage(pageNumber, totalPages, totalEntries, entries);
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Logs all incoming DNS requests and their responses in a Microsoft SQL Server database that can be queried from the DNS Server web console."; } }

        #endregion

        class LogEntry
        {
            #region variables

            public readonly DateTime Timestamp;
            public readonly DnsDatagram Request;
            public readonly IPEndPoint RemoteEP;
            public readonly DnsTransportProtocol Protocol;
            public readonly DnsDatagram Response;

            #endregion

            #region constructor

            public LogEntry(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
            {
                Timestamp = timestamp;
                Request = request;
                RemoteEP = remoteEP;
                Protocol = protocol;
                Response = response;
            }

            #endregion
        }
    }
}
