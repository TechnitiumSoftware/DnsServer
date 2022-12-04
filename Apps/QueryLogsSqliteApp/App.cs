/*
Technitium DNS Server
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace QueryLogsSqlite
{
    public class App : IDnsApplication, IDnsQueryLogger
    {
        #region variables

        IDnsServer _dnsServer;

        bool _enableLogging;
        int _maxLogDays;
        string _connectionString;

        readonly ConcurrentQueue<LogEntry> _queuedLogs = new ConcurrentQueue<LogEntry>();
        Timer _queueTimer;
        const int QUEUE_TIMER_INTERVAL = 10000;
        const int BULK_INSERT_COUNT = 1000;

        Timer _cleanupTimer;
        const int CLEAN_UP_TIMER_INITIAL_INTERVAL = 5 * 1000;
        const int CLEAN_UP_TIMER_PERIODIC_INTERVAL = 15 * 60 * 1000;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _enableLogging = false; //turn off logging

            if (_queueTimer is not null)
            {
                _queueTimer.Dispose();
                _queueTimer = null;
            }

            if (_cleanupTimer is not null)
            {
                _cleanupTimer.Dispose();
                _cleanupTimer = null;
            }

            BulkInsertLogs(); //flush any pending logs
            SqliteConnection.ClearAllPools(); //close db file
        }

        #endregion

        #region private

        private void BulkInsertLogs()
        {
            try
            {
                List<LogEntry> logs = new List<LogEntry>(BULK_INSERT_COUNT);

                while (true)
                {
                    while ((logs.Count < BULK_INSERT_COUNT) && _queuedLogs.TryDequeue(out LogEntry log))
                    {
                        logs.Add(log);
                    }

                    if (logs.Count < 1)
                        break;

                    using (SqliteConnection connection = new SqliteConnection(_connectionString))
                    {
                        connection.Open();

                        using (SqliteTransaction transaction = connection.BeginTransaction())
                        {
                            using (SqliteCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "INSERT INTO dns_logs (timestamp, client_ip, protocol, response_type, rcode, qname, qtype, qclass, answer) VALUES (@timestamp, @client_ip, @protocol, @response_type, @rcode, @qname, @qtype, @qclass, @answer);";

                                SqliteParameter paramTimestamp = command.Parameters.Add("@timestamp", SqliteType.Text);
                                SqliteParameter paramClientIp = command.Parameters.Add("@client_ip", SqliteType.Text);
                                SqliteParameter paramProtocol = command.Parameters.Add("@protocol", SqliteType.Integer);
                                SqliteParameter paramResponseType = command.Parameters.Add("@response_type", SqliteType.Integer);
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

                                    if (log.Response.Tag == null)
                                        paramResponseType.Value = (int)DnsServerResponseType.Recursive;
                                    else
                                        paramResponseType.Value = (int)(DnsServerResponseType)log.Response.Tag;

                                    paramRcode.Value = (int)log.Response.RCODE;

                                    if (log.Request.Question.Count > 0)
                                    {
                                        DnsQuestionRecord query = log.Request.Question[0];

                                        paramQname.Value = query.Name.ToLower();
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
                                        string answer = null;

                                        for (int i = 0; i < log.Response.Answer.Count; i++)
                                        {
                                            if (answer is null)
                                                answer = log.Response.Answer[i].RDATA.ToString();
                                            else
                                                answer += ", " + log.Response.Answer[i].RDATA.ToString();
                                        }

                                        paramAnswer.Value = answer;
                                    }

                                    command.ExecuteNonQuery();
                                }

                                transaction.Commit();
                            }
                        }
                    }

                    logs.Clear();
                }
            }
            catch (Exception ex)
            {
                if (_dnsServer is not null)
                    _dnsServer.WriteLog(ex);
            }
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            dynamic jsonConfig = JsonConvert.DeserializeObject(config);

            _enableLogging = jsonConfig.enableLogging.Value;
            _maxLogDays = Convert.ToInt32(jsonConfig.maxLogDays.Value);

            string sqliteDbPath = jsonConfig.sqliteDbPath.Value;
            string connectionString = jsonConfig.connectionString.Value;

            if (!Path.IsPathRooted(sqliteDbPath))
                sqliteDbPath = Path.Combine(_dnsServer.ApplicationFolder, sqliteDbPath);

            _connectionString = connectionString.Replace("{sqliteDbPath}", sqliteDbPath);

            using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = @"
CREATE TABLE IF NOT EXISTS dns_logs
(
    dlid INTEGER PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    client_ip VARCHAR(39) NOT NULL,
    protocol TINYINT NOT NULL,
    response_type TINYINT NOT NULL,
    rcode TINYINT NOT NULL,
    qname VARCHAR(255),
    qtype SMALLINT,
    qclass SMALLINT,
    answer TEXT
);
";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_timestamp ON dns_logs (timestamp);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_client_ip ON dns_logs (client_ip);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_protocol ON dns_logs (protocol);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_response_type ON dns_logs (response_type);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_rcode ON dns_logs (rcode);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_qname ON dns_logs (qname);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_qtype ON dns_logs (qtype);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_qclass ON dns_logs (qclass);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_timestamp_client_ip ON dns_logs (timestamp, client_ip);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_timestamp_qname ON dns_logs (timestamp, qname);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_client_qname ON dns_logs (client_ip, qname);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_query ON dns_logs (qname, qtype);";
                    command.ExecuteNonQuery();
                }

                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = "CREATE INDEX IF NOT EXISTS index_all ON dns_logs (timestamp, client_ip, protocol, response_type, rcode, qname, qtype, qclass);";
                    command.ExecuteNonQuery();
                }
            }

            if (_enableLogging)
            {
                _queueTimer = new Timer(delegate (object state)
                {
                    try
                    {
                        BulkInsertLogs();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog(ex);
                    }
                    finally
                    {
                        if (_queueTimer is not null)
                            _queueTimer.Change(QUEUE_TIMER_INTERVAL, Timeout.Infinite);
                    }
                });

                _queueTimer.Change(QUEUE_TIMER_INTERVAL, Timeout.Infinite);
            }
            else
            {
                if (_queueTimer is not null)
                {
                    _queueTimer.Dispose();
                    _queueTimer = null;
                }
            }

            if (_maxLogDays < 1)
            {
                if (_cleanupTimer is not null)
                {
                    _cleanupTimer.Dispose();
                    _cleanupTimer = null;
                }
            }
            else
            {
                _cleanupTimer = new Timer(delegate (object state)
                {
                    try
                    {
                        using (SqliteConnection connection = new SqliteConnection(_connectionString))
                        {
                            connection.Open();

                            using (SqliteCommand command = connection.CreateCommand())
                            {
                                command.CommandText = "DELETE FROM dns_logs WHERE timestamp < @timestamp;";

                                command.Parameters.AddWithValue("@timestamp", DateTime.UtcNow.AddDays(_maxLogDays * -1));

                                command.ExecuteNonQuery();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog(ex);
                    }
                    finally
                    {
                        if (_cleanupTimer is not null)
                            _cleanupTimer.Change(CLEAN_UP_TIMER_PERIODIC_INTERVAL, Timeout.Infinite);
                    }
                });

                _cleanupTimer.Change(CLEAN_UP_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }

            return Task.CompletedTask;
        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (_enableLogging)
                _queuedLogs.Enqueue(new LogEntry(timestamp, request, remoteEP, protocol, response));

            return Task.CompletedTask;
        }

        public Task<DnsLogPage> QueryLogsAsync(long pageNumber, int entriesPerPage, bool descendingOrder, DateTime? start, DateTime? end, IPAddress clientIpAddress, DnsTransportProtocol? protocol, DnsServerResponseType? responseType, DnsResponseCode? rcode, string qname, DnsResourceRecordType? qtype, DnsClass? qclass)
        {
            if (pageNumber < 0)
                pageNumber = long.MaxValue;
            else if (pageNumber == 0)
                pageNumber = 1;

            if (qname is not null)
                qname = qname.ToLower();

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

            using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                //find total entries
                long totalEntries;

                using (SqliteCommand command = connection.CreateCommand())
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

                    totalEntries = (long)command.ExecuteScalar();
                }

                long totalPages = (totalEntries / entriesPerPage) + (totalEntries % entriesPerPage > 0 ? 1 : 0);

                if (pageNumber > totalPages)
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

                using (SqliteCommand command = connection.CreateCommand())
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

                    using (SqliteDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            DnsQuestionRecord question;

                            if (reader.IsDBNull(6))
                                question = null;
                            else
                                question = new DnsQuestionRecord(reader.GetString(6), (DnsResourceRecordType)reader.GetInt32(7), (DnsClass)reader.GetInt32(8), false);

                            string answer;

                            if (reader.IsDBNull(9))
                                answer = null;
                            else
                                answer = reader.GetString(9);

                            entries.Add(new DnsLogEntry(reader.GetInt64(0), reader.GetDateTime(1), IPAddress.Parse(reader.GetString(2)), (DnsTransportProtocol)reader.GetByte(3), (DnsServerResponseType)reader.GetByte(4), (DnsResponseCode)reader.GetByte(5), question, answer));
                        }
                    }
                }

                return Task.FromResult(new DnsLogPage(pageNumber, totalPages, totalEntries, entries));
            }
        }

        #endregion

        #region properties

        public string Description
        { get { return "Logs all incoming DNS requests and their responses in a Sqlite database that can be queried from the DNS Server web console. The query logging throughput is limited by the disk throughput on which the Sqlite db file is stored. This app is not recommended to be used with very high throughput (more than 20,000 requests/second)."; } }

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
