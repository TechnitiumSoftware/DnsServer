/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data.Common;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace QuerySyslog
{
    public sealed class App : IDnsApplication, IDnsQueryLogger
    {
        #region variables

        IDnsServer _dnsServer;

        bool _enableLogging;

        string[] _syslogServers;

        readonly Timer _queueTimer;
        const int QUEUE_TIMER_INTERVAL = 1000;
        const int BULK_INSERT_COUNT = 100;
        readonly ConcurrentQueue<LogEntry> _queuedLogs = new ConcurrentQueue<LogEntry>();

        #endregion

        #region constructor

        public App()
        {

            _queueTimer = new Timer(async delegate (object state)
            {
                try
                {
                    await BulkInsertLogsAsync();
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);
                }
                finally
                {
                    try
                    {
                        _queueTimer.Change(QUEUE_TIMER_INTERVAL, Timeout.Infinite);
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

            if (_queueTimer is not null)
                _queueTimer.Dispose();

            BulkInsertLogsAsync().Sync(); //flush any pending logs
        }

        #endregion

        #region private


        private async Task SendSyslog(UdpClient udpClient, LogEntry log, string ip, int port)
        {

            SimpleLogEntry simplifiedLog = new SimpleLogEntry(log);
            string jsonstring = JsonSerializer.Serialize(simplifiedLog);
            string message = $"<10>{simplifiedLog._time} {simplifiedLog.host} technitium_dns:" + jsonstring;

            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            await udpClient.SendAsync(messageBytes, messageBytes.Length, ip, port);

        }
        private async Task BulkInsertLogsAsync()
        {
            try
            {
                List<LogEntry> logs = new List<LogEntry>(BULK_INSERT_COUNT);
                UdpClient udpClient = new UdpClient();

                while (true)
                {
                    while (logs.Count < BULK_INSERT_COUNT && _queuedLogs.TryDequeue(out LogEntry logentry))
                    {
                        logs.Add(logentry);
                    }
                    if (logs.Count < 1)
                    {
                        break;
                    }


                    foreach (LogEntry log in logs)
                    {
                        foreach (string syslogServer in _syslogServers)
                        {

                            try
                            {
                                string ip = (syslogServer.Split(":"))[0];
                                int port = int.Parse((syslogServer.Split(":"))[1]);
                                await SendSyslog(udpClient, log, ip, port);
                            }
                            catch (Exception e) { _dnsServer.WriteLog(e.ToString()); }

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

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            using JsonDocument jsonDocument = JsonDocument.Parse(config);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _enableLogging = jsonConfig.GetPropertyValue("enableLogging", true);
            // We expect a JSON string array
            // ["192.168.0.1:514", "192.168.0.2:12345"]
            _syslogServers = jsonConfig.ReadArray("syslogServers");

            // If we haven't added any syslogservers we don't need to attempt to log anything.
            if (_syslogServers.Length < 1)
                _enableLogging = false;

            // If the user has not supplied a valid syslog target format.
            string ipAndPortPattern = @"^.*?:\d+$";
            foreach (string syslogServer in _syslogServers)
            {
                if (!(Regex.Match(syslogServer, ipAndPortPattern).Success))
                {
                    _enableLogging = false;
                    throw new FormatException($"Syslog server '{syslogServer}' does not match the pattern '<ip/hostname>:<port>'. Check your QuerySyslogApp configuration.");
                }
            }

            if (_enableLogging)
                _queueTimer.Change(QUEUE_TIMER_INTERVAL, Timeout.Infinite);
            else
                _queueTimer.Change(Timeout.Infinite, Timeout.Infinite);

        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (_enableLogging)
                _queuedLogs.Enqueue(new LogEntry(timestamp, request, remoteEP, protocol, response));

            return Task.CompletedTask;
        }

        public async Task<DnsLogPage> QueryLogsAsync(long pageNumber, int entriesPerPage, bool descendingOrder, DateTime? start, DateTime? end, IPAddress clientIpAddress, DnsTransportProtocol? protocol, DnsServerResponseType? responseType, DnsResponseCode? rcode, string qname, DnsResourceRecordType? qtype, DnsClass? qclass)
        {
            throw new NotSupportedException();
        }

        #endregion

        #region properties

        public string Description
        { get { return "Logs all incoming DNS queries to one or more remote syslog servers over UDP."; } }

        #endregion

        class SimpleLogEntry
        {

            // _time and host are index-time extracted fields in Splunk.
            // Using the same names here makes sure that we don't need much effort for Splunk-
            // to parse these fields.
            public string _time { get; set; }
            public string host { get; set; } = Environment.MachineName;
            public string _queryName { get; set; }
            public int _queryClass { get; set; }
            public int _queryType { get; set; }
            public int _protocol { get; set; }
            public string _sourceIp { get; set; }
            public List<string> _answer { get; set; }
            public int _answerType { get; set; }


            // As to not require further external dependencies, i.e. Newtonsoft.JSON
            // we need to make our log object friendly for serializing by the default Microsoft JSON serializer
            // To do this we create a new object that makes use of simple properties
            // instead of the nested complex objects found in LogEntry
            // I'm sure there is a better way to do this that doesn't require instancing additional objects, but here we are.
            public SimpleLogEntry(LogEntry log)
            {
                _time = log.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.FFFFFFF");
                _sourceIp = log.RemoteEP.Address.ToString();
                _protocol = (int)log.Protocol;
                _answer = new List<string>();

                if (log.Response.Tag == null)
                    _answerType = (int)DnsServerResponseType.Recursive;
                else
                    _answerType = (int)(DnsServerResponseType)log.Response.Tag;


                if (log.Request.Question.Count > 0)
                {
                    DnsQuestionRecord query = log.Request.Question[0];

                    _queryName = query.Name.ToLower();
                    _queryType = (int)query.Type;
                    _queryClass = (int)query.Class;
                }
                else
                {
                    _queryName = null;
                    _queryType = -1;
                    _queryClass = -1;
                }

                if (log.Response.Answer.Count == 0)
                {
                    _answer = null;
                }
                else if ((log.Response.Answer.Count > 2) && log.Response.IsZoneTransfer)
                {
                    _answer.Add("[ZONE TRANSFER]");
                }
                else
                {
                    for (int i = 0; i < log.Response.Answer.Count; i++)
                    {
                        _answer.Add(log.Response.Answer[i].RDATA.ToString());
                    }
                }
            }
        }

        class LogEntry
        {
            #region variables

            public DateTime Timestamp { get; set; }
            public DnsDatagram Request { get; set; }
            public IPEndPoint RemoteEP { get; set; }
            public DnsTransportProtocol Protocol { get; set; }
            public DnsDatagram Response { get; set; }

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
