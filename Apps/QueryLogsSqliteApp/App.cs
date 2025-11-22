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
using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace QueryLogsSqlite
{
    public sealed class App : IDnsApplication, IDnsQueryLogger, IDnsQueryLogs
    {
        #region variables

        IDnsServer? _dnsServer;

        bool _enableLogging;
        int _maxQueueSize;
        int _maxLogDays;
        int _maxLogRecords;
        bool _enableVacuum;
        bool _useInMemoryDb;
        string? _connectionString;

        SqliteConnection? _inMemoryConnection;

        Channel<LogEntry>? _channel;
        ChannelWriter<LogEntry>? _channelWriter;
        Thread? _consumerThread;
        const int BULK_INSERT_COUNT = 1000;
        const int BULK_INSERT_ERROR_DELAY = 10000;

        readonly Timer _cleanupTimer;
        const int CLEAN_UP_TIMER_INITIAL_INTERVAL = 5 * 1000;
        const int CLEAN_UP_TIMER_PERIODIC_INTERVAL = 15 * 60 * 1000;

        #endregion

        #region constructor

        public App()
        {
            _cleanupTimer = new Timer(async delegate (object? state)
            {
                try
                {
                    await using (SqliteConnection connection = new SqliteConnection(_connectionString))
                    {
                        await connection.OpenAsync();

                        int deletedRecords = 0;

                        if (_maxLogRecords > 0)
                        {
                            await using (SqliteCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "DELETE FROM dns_logs WHERE ROWID IN (SELECT ROWID FROM dns_logs ORDER BY ROWID DESC LIMIT -1 OFFSET @maxLogRecords);";

                                command.Parameters.AddWithValue("@maxLogRecords", _maxLogRecords);

                                deletedRecords += await command.ExecuteNonQueryAsync();
                            }
                        }

                        if (_maxLogDays > 0)
                        {
                            await using (SqliteCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "DELETE FROM dns_logs WHERE timestamp < @timestamp;";

                                command.Parameters.AddWithValue("@timestamp", DateTime.UtcNow.AddDays(_maxLogDays * -1));

                                deletedRecords += await command.ExecuteNonQueryAsync();
                            }
                        }

                        if (_enableVacuum && (deletedRecords > 0))
                        {
                            await using (SqliteCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "VACUUM;";

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

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _enableLogging = false; //turn off logging

            _cleanupTimer?.Dispose();

            StopChannel();

            if (_inMemoryConnection is not null)
            {
                _inMemoryConnection.Dispose();
                _inMemoryConnection = null;
            }

            SqliteConnection.ClearAllPools(); //close db file

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        #endregion

        #region private

        private void StartNewChannel(int maxQueueSize)
        {
            ChannelWriter<LogEntry>? existingChannelWriter = _channelWriter;

            //start new channel and consumer thread
            BoundedChannelOptions options = new BoundedChannelOptions(maxQueueSize);
            options.SingleWriter = true;
            options.SingleReader = true;
            options.FullMode = BoundedChannelFullMode.DropWrite;

            _channel = Channel.CreateBounded<LogEntry>(options);
            _channelWriter = _channel.Writer;
            ChannelReader<LogEntry> channelReader = _channel.Reader;

            _consumerThread = new Thread(async delegate ()
            {
                try
                {
                    List<LogEntry> logs = new List<LogEntry>(BULK_INSERT_COUNT);

                    while (!_disposed && await channelReader.WaitToReadAsync())
                    {
                        while (!_disposed && (logs.Count < BULK_INSERT_COUNT) && channelReader.TryRead(out LogEntry log))
                        {
                            logs.Add(log);
                        }

                        if (logs.Count < 1)
                            continue;

                        await BulkInsertLogsAsync(logs);

                        logs.Clear();
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(ex);
                }
            });

            _consumerThread.Name = GetType().Name;
            _consumerThread.IsBackground = true;
            _consumerThread.Start();

            //complete old channel to stop its consumer thread
            existingChannelWriter?.TryComplete();
        }

        private void StopChannel()
        {
            _channel?.Writer.TryComplete();
        }

        private async Task BulkInsertLogsAsync(List<LogEntry> logs)
        {
            try
            {
                await using (SqliteConnection connection = new SqliteConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    await using (DbTransaction transaction = await connection.BeginTransactionAsync())
                    {
                        await using (SqliteCommand command = connection.CreateCommand())
                        {
                            command.CommandText = "INSERT INTO dns_logs (timestamp, client_ip, protocol, response_type, response_rtt, rcode, qname, qtype, qclass, answer) VALUES (@timestamp, @client_ip, @protocol, @response_type, @response_rtt, @rcode, @qname, @qtype, @qclass, @answer);";

                            SqliteParameter paramTimestamp = command.Parameters.Add("@timestamp", SqliteType.Text);
                            SqliteParameter paramClientIp = command.Parameters.Add("@client_ip", SqliteType.Text);
                            SqliteParameter paramProtocol = command.Parameters.Add("@protocol", SqliteType.Integer);
                            SqliteParameter paramResponseType = command.Parameters.Add("@response_type", SqliteType.Integer);
                            SqliteParameter paramResponseRtt = command.Parameters.Add("@response_rtt", SqliteType.Real);
                            SqliteParameter paramRcode = command.Parameters.Add("@rcode", SqliteType.Integer);
                            SqliteParameter paramQname = command.Parameters.Add("@qname", SqliteType.Text);
                            SqliteParameter paramQtype = command.Parameters.Add("@qtype", SqliteType.Integer);
                            SqliteParameter paramQclass = command.Parameters.Add("@qclass", SqliteType.Integer);
                            SqliteParameter paramAnswer = command.Parameters.Add("@answer", SqliteType.Text);

                            foreach (LogEntry log in logs)
                            {
                                paramTimestamp.Value = log.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.FFFFFFF");
                                paramClientIp.Value = log.RemoteEP.Address.ToString();
                                paramProtocol.Value = (int)log.Protocol;

                                DnsServerResponseType responseType;

                                if (log.Response.Tag == null)
                                    responseType = DnsServerResponseType.Recursive;
                                else
                                    responseType = (DnsServerResponseType)log.Response.Tag;

                                paramResponseType.Value = (int)responseType;

                                if ((responseType == DnsServerResponseType.Recursive) && (log.Response.Metadata is not null))
                                    paramResponseRtt.Value = log.Response.Metadata.RoundTripTime;
                                else
                                    paramResponseRtt.Value = DBNull.Value;

                                paramRcode.Value = (int)log.Response.RCODE;

                                if (log.Request.Question.Count > 0)
                                {
                                    DnsQuestionRecord query = log.Request.Question[0];

                                    paramQname.Value = query.Name.ToLowerInvariant();
                                    paramQtype.Value = (int)query.Type;
                                    paramQclass.Value = (int)query.Class;
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

                                    paramAnswer.Value = answer;
                                }

                                await command.ExecuteNonQueryAsync();
                            }

                            await transaction.CommitAsync();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);

                await Task.Delay(BULK_INSERT_ERROR_DELAY);
            }
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            bool enableLogging = jsonConfig.GetPropertyValue("enableLogging", true);
            int maxQueueSize = jsonConfig.GetPropertyValue("maxQueueSize", 200000);
            _maxLogDays = jsonConfig.GetPropertyValue("maxLogDays", 0);
            _maxLogRecords = jsonConfig.GetPropertyValue("maxLogRecords", 0);
            _enableVacuum = jsonConfig.GetPropertyValue("enableVacuum", false);
            _useInMemoryDb = jsonConfig.GetPropertyValue("useInMemoryDb", false);

            if (_useInMemoryDb)
            {
                if (_inMemoryConnection is null)
                {
                    SqliteConnection.ClearAllPools(); //close db file, if any

                    _connectionString = "Data Source=QueryLogs;Mode=Memory;Cache=Shared";

                    _inMemoryConnection = new SqliteConnection(_connectionString);
                    await _inMemoryConnection.OpenAsync();
                }
            }
            else
            {
                if (_inMemoryConnection is not null)
                {
                    await _inMemoryConnection.DisposeAsync();
                    _inMemoryConnection = null;
                }

                string sqliteDbPath = jsonConfig.GetPropertyValue("sqliteDbPath", "querylogs.db");
                string connectionString = jsonConfig.GetPropertyValue("connectionString", "Data Source='{sqliteDbPath}'; Cache=Shared;");

                if (!Path.IsPathRooted(sqliteDbPath))
                    sqliteDbPath = Path.Combine(_dnsServer.ApplicationFolder, sqliteDbPath);

                connectionString = connectionString.Replace("{sqliteDbPath}", sqliteDbPath);

                if ((_connectionString is not null) && !_connectionString.Equals(connectionString))
                    SqliteConnection.ClearAllPools(); //close previous db file

                _connectionString = connectionString;
            }

            await using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = @"
CREATE TABLE IF NOT EXISTS dns_logs
(
    dlid INTEGER PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    client_ip VARCHAR(39) NOT NULL,
    protocol TINYINT NOT NULL,
    response_type TINYINT NOT NULL,
    response_rtt REAL,
    rcode TINYINT NOT NULL,
    qname VARCHAR(255),
    qtype SMALLINT,
    qclass SMALLINT,
    answer TEXT
);
";
                    await command.ExecuteNonQueryAsync();
                }

                try
                {
                    await using (SqliteCommand command = connection.CreateCommand())
                    {
                        command.CommandText = "ALTER TABLE dns_logs ADD COLUMN response_rtt REAL;";
                        await command.ExecuteNonQueryAsync();
                    }
                }
                catch
                { }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_timestamp ON dns_logs (timestamp);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_client_ip ON dns_logs (client_ip);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_protocol ON dns_logs (protocol);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_response_type ON dns_logs (response_type);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_rcode ON dns_logs (rcode);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_qname ON dns_logs (qname);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_qtype ON dns_logs (qtype);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_qclass ON dns_logs (qclass);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_timestamp_client_ip ON dns_logs (timestamp, client_ip);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_timestamp_qname ON dns_logs (timestamp, qname);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_client_qname ON dns_logs (client_ip, qname);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_query ON dns_logs (qname, qtype);";
                    await command.ExecuteNonQueryAsync();
                }

                await using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_all ON dns_logs (timestamp, client_ip, protocol, response_type, rcode, qname, qtype, qclass);";
                    await command.ExecuteNonQueryAsync();
                }
            }

            if (enableLogging)
            {
                if (!_enableLogging || (_maxQueueSize != maxQueueSize))
                    StartNewChannel(maxQueueSize);
            }
            else
            {
                StopChannel();
            }

            _enableLogging = enableLogging;
            _maxQueueSize = maxQueueSize;

            if ((_maxLogDays > 0) || (_maxLogRecords > 0))
                _cleanupTimer.Change(CLEAN_UP_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            else
                _cleanupTimer.Change(Timeout.Infinite, Timeout.Infinite);

            if (!jsonConfig.TryGetProperty("maxLogRecords", out _))
            {
                config = config.Replace("\"sqliteDbPath\"", "\"maxLogRecords\": 0,\r\n  \"useInMemoryDb\": false,\r\n  \"sqliteDbPath\"");

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }

            if (!jsonConfig.TryGetProperty("enableVacuum", out _))
            {
                config = config.Replace("\"useInMemoryDb\"", "\"enableVacuum\": false,\r\n  \"useInMemoryDb\"");

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }

            if (!jsonConfig.TryGetProperty("maxQueueSize", out _))
            {
                config = config.Replace("\"maxLogDays\"", "\"maxQueueSize\": 200000,\r\n  \"maxLogDays\"");

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }
        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (_enableLogging)
                _channelWriter?.TryWrite(new LogEntry(timestamp, request, remoteEP, protocol, response));

            return Task.CompletedTask;
        }

        public async Task<DnsLogPage> QueryLogsAsync(long pageNumber, int entriesPerPage, bool descendingOrder, DateTime? start, DateTime? end, IPAddress clientIpAddress, DnsTransportProtocol? protocol, DnsServerResponseType? responseType, DnsResponseCode? rcode, string qname, DnsResourceRecordType? qtype, DnsClass? qclass)
        {
            if (pageNumber == 0)
                pageNumber = 1;

            if (qname is not null)
                qname = qname.ToLowerInvariant();

            string whereClause = string.Empty;

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

            await using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();

                //find total entries
                long totalEntries;

                await using (SqliteCommand command = connection.CreateCommand())
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
                        command.Parameters.AddWithValue("@qtype", (ushort)qtype);

                    if (qclass is not null)
                        command.Parameters.AddWithValue("@qclass", (ushort)qclass);

                    totalEntries = Convert.ToInt64(await command.ExecuteScalarAsync());
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

                await using (SqliteCommand command = connection.CreateCommand())
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
                        command.Parameters.AddWithValue("@qtype", (ushort)qtype);

                    if (qclass is not null)
                        command.Parameters.AddWithValue("@qclass", (ushort)qclass);

                    await using (SqliteDataReader reader = await command.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            double? responseRtt;

                            if (reader.IsDBNull(5))
                                responseRtt = null;
                            else
                                responseRtt = reader.GetDouble(5);

                            DnsQuestionRecord? question;

                            if (reader.IsDBNull(7))
                                question = null;
                            else
                                question = new DnsQuestionRecord(reader.GetString(7), (DnsResourceRecordType)reader.GetInt32(8), (DnsClass)reader.GetInt32(9), false);

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
        { get { return "Logs all incoming DNS requests and their responses in a Sqlite database that can be queried from the DNS Server web console."; } }

        #endregion

        readonly struct LogEntry
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
