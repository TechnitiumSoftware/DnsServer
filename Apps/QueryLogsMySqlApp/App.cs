/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using MySqlConnector;
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace QueryLogsMySql
{
    public sealed class App : IDnsApplication, IDnsQueryLogger, IDnsQueryLogs
    {
        #region variables

        readonly static JsonDocumentOptions _jsonParseOptions = new JsonDocumentOptions() { CommentHandling = JsonCommentHandling.Skip };

        IDnsServer? _dnsServer;

        bool _enableLogging;
        int _maxQueueSize;
        int _maxLogDays;
        int _maxLogRecords;
        string? _databaseName;
        string? _connectionString;

        Channel<LogEntry>? _channel;
        ChannelWriter<LogEntry>? _channelWriter;
        Thread? _consumerThread;
        const int BULK_INSERT_COUNT = 1000;
        const int BULK_INSERT_ERROR_DELAY = 10000;
        const int BULK_REMOVE_COUNT = 10000;

        readonly Timer _cleanupTimer;
        const int CLEAN_UP_TIMER_INITIAL_INTERVAL = 5 * 1000;
        const int CLEAN_UP_TIMER_PERIODIC_INTERVAL = 15 * 60 * 1000;

        bool _isStartupInit = true;

        #endregion

        #region constructor

        public App()
        {
            _cleanupTimer = new Timer(async delegate (object? state)
            {
                try
                {
                    await using (MySqlConnection connection = new MySqlConnection(_connectionString + $" Database={_databaseName};"))
                    {
                        await connection.OpenAsync();

                        if (_maxLogRecords > 0)
                        {
                            int totalRecords;

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "SELECT Count(*) FROM dns_logs;";

                                totalRecords = Convert.ToInt32(await command.ExecuteScalarAsync());
                            }

                            int recordsToRemove = totalRecords - _maxLogRecords;
                            if (recordsToRemove > 0)
                                await BatchRemove(recordsToRemove);
                        }

                        if (_maxLogDays > 0)
                        {
                            int recordsToRemove;

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "SELECT Count(*) FROM dns_logs WHERE timestamp < @timestamp;";

                                command.Parameters.AddWithValue("@timestamp", DateTime.UtcNow.AddDays(_maxLogDays * -1));

                                recordsToRemove = Convert.ToInt32(await command.ExecuteScalarAsync());
                            }

                            if (recordsToRemove > 0)
                                await BatchRemove(recordsToRemove);
                        }

                        async Task BatchRemove(int recordsToRemove)
                        {
                            int batchToRemove;

                            while (recordsToRemove > 0)
                            {
                                batchToRemove = Math.Min(recordsToRemove, BULK_REMOVE_COUNT);

                                await using (MySqlCommand command = connection.CreateCommand())
                                {
                                    command.CommandText = $"DELETE FROM dns_logs WHERE dlid IN (SELECT * FROM (SELECT dlid FROM dns_logs ORDER BY dlid LIMIT {batchToRemove}) AS T1);";

                                    await command.ExecuteNonQueryAsync();
                                }

                                recordsToRemove -= batchToRemove;
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
                    StringBuilder sb = new StringBuilder(4096);

                    while (!_disposed && await channelReader.WaitToReadAsync())
                    {
                        while (!_disposed && (logs.Count < BULK_INSERT_COUNT) && channelReader.TryRead(out LogEntry log))
                        {
                            logs.Add(log);
                        }

                        if (logs.Count < 1)
                            continue;

                        await BulkInsertLogsAsync(logs, sb);

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

        private async Task BulkInsertLogsAsync(List<LogEntry> logs, StringBuilder sb)
        {
            try
            {
                await using (MySqlConnection connection = new MySqlConnection(_connectionString + $" Database={_databaseName};"))
                {
                    await connection.OpenAsync();

                    await using (MySqlCommand command = connection.CreateCommand())
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

                            MySqlParameter paramServer = command.Parameters.Add("@server" + i, MySqlDbType.VarChar);
                            MySqlParameter paramTimestamp = command.Parameters.Add("@timestamp" + i, MySqlDbType.DateTime);
                            MySqlParameter paramClientIp = command.Parameters.Add("@client_ip" + i, MySqlDbType.VarChar);
                            MySqlParameter paramProtocol = command.Parameters.Add("@protocol" + i, MySqlDbType.Byte);
                            MySqlParameter paramResponseType = command.Parameters.Add("@response_type" + i, MySqlDbType.Byte);
                            MySqlParameter paramResponseRtt = command.Parameters.Add("@response_rtt" + i, MySqlDbType.Double);
                            MySqlParameter paramRcode = command.Parameters.Add("@rcode" + i, MySqlDbType.Byte);
                            MySqlParameter paramQname = command.Parameters.Add("@qname" + i, MySqlDbType.VarChar);
                            MySqlParameter paramQtype = command.Parameters.Add("@qtype" + i, MySqlDbType.UInt16);
                            MySqlParameter paramQclass = command.Parameters.Add("@qclass" + i, MySqlDbType.Int16);
                            MySqlParameter paramAnswer = command.Parameters.Add("@answer" + i, MySqlDbType.VarChar);

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
                                paramQtype.Value = (ushort)query.Type;
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
                                if (log.Response.Truncation)
                                    paramAnswer.Value = "[TRUNCATED]";
                                else
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
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);

                await Task.Delay(BULK_INSERT_ERROR_DELAY);
            }
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string? config)
        {
            try
            {
                _dnsServer = dnsServer;

                if (config is null)
                    throw new InvalidOperationException();

                using JsonDocument jsonDocument = JsonDocument.Parse(config, _jsonParseOptions);
                JsonElement jsonConfig = jsonDocument.RootElement;

                bool enableLogging = jsonConfig.GetPropertyValue("enableLogging", false);
                int maxQueueSize = jsonConfig.GetPropertyValue("maxQueueSize", 1000000);
                _maxLogDays = jsonConfig.GetPropertyValue("maxLogDays", 0);
                _maxLogRecords = jsonConfig.GetPropertyValue("maxLogRecords", 0);
                _databaseName = jsonConfig.GetPropertyValue("databaseName", "DnsQueryLogs");
                _connectionString = jsonConfig.GetPropertyValue("connectionString", null);

                if (_connectionString is null)
                    throw new Exception("Please specify a valid connection string in 'connectionString' parameter.");

                if (_connectionString.Replace(" ", "").Contains("Database=", StringComparison.OrdinalIgnoreCase))
                    throw new Exception("The 'connectionString' parameter must not define 'Database'. Configure the 'databaseName' parameter above instead.");

                if (!_connectionString.TrimEnd().EndsWith(';'))
                    _connectionString += ";";

                async Task ApplyConfig()
                {
                    if (enableLogging)
                    {
                        await using (MySqlConnection connection = new MySqlConnection(_connectionString))
                        {
                            await connection.OpenAsync();

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = @$"
CREATE DATABASE IF NOT EXISTS `{_databaseName}`;

USE `{_databaseName}`;

CREATE TABLE IF NOT EXISTS dns_logs
(
    dlid INT PRIMARY KEY AUTO_INCREMENT,
    server varchar(255),
    timestamp DATETIME NOT NULL,
    client_ip VARCHAR(39) NOT NULL,
    protocol TINYINT UNSIGNED NOT NULL,
    response_type TINYINT NOT NULL,
    response_rtt REAL,
    rcode TINYINT NOT NULL,
    qname VARCHAR(255),
    qtype SMALLINT UNSIGNED,
    qclass SMALLINT,
    answer VARCHAR(4000)
);
";

                                await command.ExecuteNonQueryAsync();
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "ALTER TABLE dns_logs ADD server varchar(255);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "ALTER TABLE dns_logs MODIFY protocol TINYINT UNSIGNED NOT NULL;";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "ALTER TABLE dns_logs MODIFY qtype SMALLINT UNSIGNED;";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_server ON dns_logs (server);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_timestamp ON dns_logs (timestamp);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_client_ip ON dns_logs (client_ip);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_protocol ON dns_logs (protocol);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_response_type ON dns_logs (response_type);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_rcode ON dns_logs (rcode);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_qname ON dns_logs (qname)";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_qtype ON dns_logs (qtype);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_qclass ON dns_logs (qclass);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_timestamp_client_ip ON dns_logs (timestamp, client_ip);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_timestamp_qname ON dns_logs (timestamp, qname);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_client_qname ON dns_logs (client_ip, qname);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_query ON dns_logs (qname, qtype);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }

                            await using (MySqlCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "CREATE INDEX index_all ON dns_logs (server, timestamp, client_ip, protocol, response_type, rcode, qname, qtype, qclass);";

                                try
                                {
                                    await command.ExecuteNonQueryAsync();
                                }
                                catch
                                { }
                            }
                        }

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
                }

                if (_isStartupInit)
                {
                    //this is the first time this app is being initialized
                    ThreadPool.QueueUserWorkItem(async delegate (object? state)
                    {
                        try
                        {
                            const int MAX_RETRIES = 20;
                            const int RETRY_DELAY = 30000; //30 seconds
                            int retryCount = 0;

                            while (true)
                            {
                                try
                                {
                                    await ApplyConfig();
                                    return;
                                }
                                catch (MySqlException ex)
                                {
                                    switch (ex.ErrorCode)
                                    {
                                        case MySqlErrorCode.UnableToConnectToHost:
                                        case MySqlErrorCode.TooManyUserConnections:
                                            retryCount++;

                                            if (retryCount < MAX_RETRIES)
                                            {
                                                _dnsServer?.WriteLog($"Failed to connect to the database server ({ex.ErrorCode}). Please check the app config and make sure the database server is online. Retrying in {RETRY_DELAY / 1000} seconds... (Attempt {retryCount})");
                                                _dnsServer?.WriteLog(ex);

                                                await Task.Delay(RETRY_DELAY);
                                            }
                                            else
                                            {
                                                _dnsServer?.WriteLog($"Failed to connect to the database server ({ex.ErrorCode}) after {retryCount} retries. Please check the app config and make sure the database server is online.");
                                                _dnsServer?.WriteLog(ex);
                                                return;
                                            }

                                            break;

                                        default:
                                            _dnsServer?.WriteLog($"Failed to connect to the database server ({ex.ErrorCode}). Please check the app config and make sure the database server is online.");
                                            _dnsServer?.WriteLog(ex);
                                            return;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _dnsServer?.WriteLog(ex);
                                    return;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsServer?.WriteLog(ex);
                        }
                    });
                }
                else
                {
                    //init via API call
                    await ApplyConfig();
                }
            }
            finally
            {
                _isStartupInit = false; //reset flag
            }
        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (_enableLogging)
                _channelWriter?.TryWrite(new LogEntry(timestamp, request, remoteEP, protocol, response));

            return Task.CompletedTask;
        }

        public async Task<DnsLogPage> QueryLogsAsync(long pageNumber, int entriesPerPage, bool descendingOrder, DateTime? start, DateTime? end, IPAddress? clientIpAddress, DnsTransportProtocol? protocol, DnsServerResponseType? responseType, DnsResponseCode? rcode, string? qname, DnsResourceRecordType? qtype, DnsClass? qclass)
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

            await using (MySqlConnection connection = new MySqlConnection(_connectionString + $" Database={_databaseName};"))
            {
                await connection.OpenAsync();

                //find total entries
                long totalEntries;

                await using (MySqlCommand command = connection.CreateCommand())
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
                        command.Parameters.AddWithValue("@qclass", (short)qclass);

                    totalEntries = Convert.ToInt64(await command.ExecuteScalarAsync());
                }

                long totalPages = (totalEntries / entriesPerPage) + (totalEntries % entriesPerPage > 0 ? 1 : 0);

                if (totalPages < 1)
                    pageNumber = 1;
                else if ((pageNumber > totalPages) || (pageNumber < 0))
                    pageNumber = totalPages;

                long offset = (pageNumber - 1) * entriesPerPage;

                List<DnsLogEntry> entries = new List<DnsLogEntry>(entriesPerPage);

                await using (MySqlCommand command = connection.CreateCommand())
                {
                    command.CommandText = @"
SELECT
    dlid,
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
ORDER BY dlid" + (descendingOrder ? " DESC" : "") + @"
LIMIT @limit OFFSET @offset";

                    command.Parameters.AddWithValue("@limit", entriesPerPage);
                    command.Parameters.AddWithValue("@offset", offset);

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
                        command.Parameters.AddWithValue("@qclass", (short)qclass);

                    long rowNumber = descendingOrder ? totalEntries - offset : offset + 1;

                    await using (DbDataReader reader = await command.ExecuteReaderAsync())
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
                                question = new DnsQuestionRecord(reader.GetString(7), (DnsResourceRecordType)reader.GetInt32(8), (DnsClass)reader.GetInt16(9), false);

                            string? answer;

                            if (reader.IsDBNull(10))
                                answer = null;
                            else
                                answer = reader.GetString(10);

                            entries.Add(new DnsLogEntry(rowNumber, reader.GetDateTime(1), IPAddress.Parse(reader.GetString(2)), (DnsTransportProtocol)reader.GetByte(3), (DnsServerResponseType)reader.GetByte(4), responseRtt, (DnsResponseCode)reader.GetByte(6), question, answer));

                            if (descendingOrder)
                                rowNumber--;
                            else
                                rowNumber++;
                        }
                    }
                }

                return new DnsLogPage(pageNumber, totalPages, totalEntries, entries);
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Logs all incoming DNS requests and their responses in a MySQL database that can be queried from the DNS Server web console."; } }

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
