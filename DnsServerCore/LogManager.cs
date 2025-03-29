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

using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore
{
    [Flags]
    public enum LoggingType : byte
    {
        None = 0,
        File = 1,
        Console = 2,
        FileAndConsole = 3
    }

    public sealed class LogManager : IDisposable
    {
        #region variables

        static readonly char[] commaSeparator = new char[] { ',' };

        readonly string _configFolder;

        LoggingType _loggingType;
        string _logFolder;
        int _maxLogFileDays;
        bool _useLocalTime;

        const string LOG_ENTRY_DATE_TIME_FORMAT = "yyyy-MM-dd HH:mm:ss";
        const string LOG_FILE_DATE_TIME_FORMAT = "yyyy-MM-dd";

        bool _isRunning;
        string _logFile;
        StreamWriter _logOut;
        DateTime _logDate;

        readonly BlockingCollection<LogQueueItem> _queue = new BlockingCollection<LogQueueItem>();
        Thread _consumerThread;
        readonly object _logFileLock = new object();
        readonly object _queueLock = new object();
        readonly AutoResetEvent _queueWait = new AutoResetEvent(false);
        CancellationTokenSource _queueCancellationTokenSource = new CancellationTokenSource();

        readonly Timer _logCleanupTimer;
        const int LOG_CLEANUP_TIMER_INITIAL_INTERVAL = 60 * 1000;
        const int LOG_CLEANUP_TIMER_PERIODIC_INTERVAL = 60 * 60 * 1000;

        readonly object _saveLock = new object();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 10000;

        #endregion

        #region constructor

        public LogManager(string configFolder)
        {
            _configFolder = configFolder;

            AppDomain.CurrentDomain.UnhandledException += delegate (object sender, UnhandledExceptionEventArgs e)
            {
                //log to console immediately
                Console.WriteLine(e.ExceptionObject.ToString());

                if (_loggingType.HasFlag(LoggingType.File))
                {
                    //try log to file
                    lock (_queueLock)
                    {
                        try
                        {
                            _queueCancellationTokenSource.Cancel();

                            lock (_logFileLock)
                            {
                                WriteLog(DateTime.UtcNow, e.ExceptionObject.ToString(), LoggingType.File);
                            }
                        }
                        catch (ObjectDisposedException)
                        { }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex.ToString());
                        }
                        finally
                        {
                            _queueWait.Set();
                        }
                    }
                }
            };

            _logCleanupTimer = new Timer(delegate (object state)
            {
                try
                {
                    if (_maxLogFileDays < 1)
                        return;

                    DateTime cutoffDate = DateTime.UtcNow.AddDays(_maxLogFileDays * -1).Date;
                    DateTimeStyles dateTimeStyles;

                    if (_useLocalTime)
                        dateTimeStyles = DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal;
                    else
                        dateTimeStyles = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal;

                    foreach (string logFile in ListLogFiles())
                    {
                        string logFileName = Path.GetFileNameWithoutExtension(logFile);

                        if (!DateTime.TryParseExact(logFileName, LOG_FILE_DATE_TIME_FORMAT, CultureInfo.InvariantCulture, dateTimeStyles, out DateTime logFileDate))
                            continue;

                        if (logFileDate < cutoffDate)
                        {
                            try
                            {
                                File.Delete(logFile);
                                Write("LogManager cleanup deleted the log file: " + logFile);
                            }
                            catch (Exception ex)
                            {
                                Write(ex);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Write(ex);
                }
            });

            LoadConfig();

            if (_loggingType != LoggingType.None)
                StartLogging();

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveConfigFileInternal();
                            _pendingSave = false;
                        }
                        catch (Exception ex)
                        {
                            Write(ex);

                            //set timer to retry again
                            _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                        }
                    }
                }
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        private void Dispose(bool disposing)
        {
            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave)
                {
                    try
                    {
                        SaveConfigFileInternal();
                    }
                    catch (Exception ex)
                    {
                        Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            lock (_queueLock)
            {
                try
                {
                    _queueCancellationTokenSource.Cancel();

                    lock (_logFileLock)
                    {
                        if (_disposed)
                            return;

                        if (disposing)
                        {
                            if (_logOut != null)
                            {
                                WriteLog(DateTime.UtcNow, "Logging stopped.", LoggingType.File);

                                _logOut.Dispose();
                                _logOut = null;
                            }

                            _logCleanupTimer.Dispose();
                        }

                        _disposed = true;
                    }
                }
                finally
                {
                    _queueWait.Set();
                }
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        internal void StartLogging()
        {
            lock (_queueLock)
            {
                if (_isRunning)
                    return;

                if (_loggingType.HasFlag(LoggingType.File))
                    StartNewLog();

                _queueWait.Set();

                //start consumer thread
                _consumerThread = new Thread(delegate ()
                {
                    while (true)
                    {
                        _queueWait.WaitOne();

                        Monitor.Enter(_logFileLock);
                        try
                        {
                            if (_disposed)
                                break;

                            foreach (LogQueueItem item in _queue.GetConsumingEnumerable(_queueCancellationTokenSource.Token))
                            {
                                if (_useLocalTime)
                                {
                                    DateTime messageLocalDateTime = item._dateTime.ToLocalTime();

                                    if (_loggingType.HasFlag(LoggingType.File) && (messageLocalDateTime.Date > _logDate))
                                    {
                                        WriteLog(DateTime.UtcNow, "Logging stopped.", LoggingType.File);
                                        StartNewLog();
                                    }

                                    WriteLog(messageLocalDateTime, item._message, _loggingType);
                                }
                                else
                                {
                                    if (_loggingType.HasFlag(LoggingType.File) && (item._dateTime.Date > _logDate))
                                    {
                                        WriteLog(DateTime.UtcNow, "Logging stopped.", LoggingType.File);
                                        StartNewLog();
                                    }

                                    WriteLog(item._dateTime, item._message, _loggingType);
                                }
                            }
                        }
                        catch (ObjectDisposedException)
                        { }
                        catch (OperationCanceledException)
                        { }
                        finally
                        {
                            Monitor.Exit(_logFileLock);
                        }

                        _queueCancellationTokenSource = new CancellationTokenSource();

                        lock (_queueLock)
                        {
                            if (!_isRunning)
                            {
                                Monitor.PulseAll(_queueLock); //signal stop logging of thread exit
                                break;
                            }
                        }
                    }
                });

                _consumerThread.Name = "Log";
                _consumerThread.IsBackground = true;
                _consumerThread.Start();

                _isRunning = true;
            }
        }

        internal void StopLogging()
        {
            lock (_queueLock)
            {
                if (!_isRunning)
                    return;

                try
                {
                    _queueCancellationTokenSource.Cancel();

                    lock (_logFileLock)
                    {
                        if (_logOut != null)
                        {
                            WriteLog(DateTime.UtcNow, "Logging stopped.", LoggingType.File);

                            _logOut.Dispose();
                            _logOut = null;
                        }
                    }
                }
                finally
                {
                    _isRunning = false;
                    _queueWait.Set();
                }

                Monitor.Wait(_queueLock); //wait for log consumer thread to exit to ensure that the thread stops
            }
        }

        internal void LoadConfig()
        {
            string logConfigFile = Path.Combine(_configFolder, "log.config");

            try
            {
                using (FileStream fS = new FileStream(logConfigFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader bR = new BinaryReader(fS);

                    if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "LS") //format
                        throw new InvalidDataException("DnsServer log config file format is invalid.");

                    byte version = bR.ReadByte();
                    switch (version)
                    {
                        case 1:
                            _loggingType = (LoggingType)bR.ReadByte();
                            _logFolder = bR.ReadShortString();
                            _maxLogFileDays = bR.ReadInt32();
                            _useLocalTime = bR.ReadBoolean();
                            break;

                        default:
                            throw new InvalidDataException("DnsServer log config version not supported.");
                    }
                }
            }
            catch (FileNotFoundException)
            {
                _loggingType = LoggingType.File;
                _logFolder = "logs";
                _maxLogFileDays = 365;
                _useLocalTime = false;

                SaveConfigFileInternal();
            }
            catch (Exception ex)
            {
                Console.Write(ex.ToString());
                SaveConfigFileInternal();
            }

            if (_maxLogFileDays == 0)
                _logCleanupTimer.Change(Timeout.Infinite, Timeout.Infinite);
            else
                _logCleanupTimer.Change(LOG_CLEANUP_TIMER_INITIAL_INTERVAL, LOG_CLEANUP_TIMER_PERIODIC_INTERVAL);
        }

        private void UpdateLogFileState()
        {
            lock (_queueLock)
            {
                try
                {
                    if (_isRunning)
                        _queueCancellationTokenSource.Cancel();

                    lock (_logFileLock)
                    {
                        if (_logOut != null)
                        {
                            WriteLog(DateTime.UtcNow, "Logging stopped.", LoggingType.File);

                            _logOut.Dispose();
                            _logOut = null;
                        }

                        if (_loggingType.HasFlag(LoggingType.File))
                            StartNewLog();
                    }
                }
                finally
                {
                    _queueWait.Set();
                }
            }
        }

        private string ConvertToRelativePath(string path)
        {
            if (path.StartsWith(_configFolder, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                path = path.Substring(_configFolder.Length).TrimStart(Path.DirectorySeparatorChar);

            return path;
        }

        private string ConvertToAbsolutePath(string path)
        {
            if (Path.IsPathRooted(path))
                return path;

            return Path.Combine(_configFolder, path);
        }

        private void SaveConfigFileInternal()
        {
            string logConfigFile = Path.Combine(_configFolder, "log.config");

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize config
                BinaryWriter bW = new BinaryWriter(mS);

                bW.Write(Encoding.ASCII.GetBytes("LS")); //format
                bW.Write((byte)1); //version

                bW.Write((byte)_loggingType);
                bW.WriteShortString(_logFolder);
                bW.Write(_maxLogFileDays);
                bW.Write(_useLocalTime);

                //write config
                mS.Position = 0;

                using (FileStream fS = new FileStream(logConfigFile, FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }
        }

        private void StartNewLog()
        {
            if (_logOut != null)
                _logOut.Dispose();

            string logFolder = ConvertToAbsolutePath(_logFolder);

            if (!Directory.Exists(logFolder))
                Directory.CreateDirectory(logFolder);

            DateTime logStartDateTime;

            if (_useLocalTime)
                logStartDateTime = DateTime.Now;
            else
                logStartDateTime = DateTime.UtcNow;

            _logFile = Path.Combine(logFolder, logStartDateTime.ToString(LOG_FILE_DATE_TIME_FORMAT) + ".log");
            _logOut = new StreamWriter(new FileStream(_logFile, FileMode.Append, FileAccess.Write, FileShare.Read));
            _logDate = logStartDateTime.Date;

            WriteLog(logStartDateTime, "Logging started.", LoggingType.File);
        }

        private void WriteLog(DateTime dateTime, string message, LoggingType loggingType)
        {
            string logEntry;

            if (_useLocalTime)
            {
                if (dateTime.Kind == DateTimeKind.Local)
                    logEntry = "[" + dateTime.ToString(LOG_ENTRY_DATE_TIME_FORMAT) + " Local] " + message;
                else
                    logEntry = "[" + dateTime.ToLocalTime().ToString(LOG_ENTRY_DATE_TIME_FORMAT) + " Local] " + message;
            }
            else
            {
                if (dateTime.Kind == DateTimeKind.Utc)
                    logEntry = "[" + dateTime.ToString(LOG_ENTRY_DATE_TIME_FORMAT) + " UTC] " + message;
                else
                    logEntry = "[" + dateTime.ToUniversalTime().ToString(LOG_ENTRY_DATE_TIME_FORMAT) + " UTC] " + message;
            }

            if (loggingType.HasFlag(LoggingType.File) && (_logOut is not null))
            {
                _logOut.WriteLine(logEntry);
                _logOut.Flush();
            }

            if (loggingType.HasFlag(LoggingType.Console))
                Console.WriteLine(logEntry);
        }

        #endregion

        #region public

        public string[] ListLogFiles()
        {
            return Directory.GetFiles(ConvertToAbsolutePath(_logFolder), "*.log", SearchOption.TopDirectoryOnly);
        }

        public async Task DownloadLogAsync(HttpContext context, string logName, long limit)
        {
            string logFileName = logName + ".log";

            using (FileStream fS = new FileStream(Path.Combine(ConvertToAbsolutePath(_logFolder), logFileName), FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024, true))
            {
                HttpResponse response = context.Response;

                response.ContentType = "text/plain";
                response.Headers.ContentDisposition = "attachment;filename=" + logFileName;

                if ((limit > fS.Length) || (limit < 1))
                    limit = fS.Length;

                OffsetStream oFS = new OffsetStream(fS, 0, limit);
                HttpRequest request = context.Request;
                Stream s;

                string acceptEncoding = request.Headers.AcceptEncoding;
                if (string.IsNullOrEmpty(acceptEncoding))
                {
                    s = response.Body;
                }
                else
                {
                    string[] acceptEncodingParts = acceptEncoding.Split(commaSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

                    if (acceptEncodingParts.Contains("br"))
                    {
                        response.Headers.ContentEncoding = "br";
                        s = new BrotliStream(response.Body, CompressionMode.Compress);
                    }
                    else if (acceptEncodingParts.Contains("gzip"))
                    {
                        response.Headers.ContentEncoding = "gzip";
                        s = new GZipStream(response.Body, CompressionMode.Compress);
                    }
                    else if (acceptEncodingParts.Contains("deflate"))
                    {
                        response.Headers.ContentEncoding = "deflate";
                        s = new DeflateStream(response.Body, CompressionMode.Compress);
                    }
                    else
                    {
                        s = response.Body;
                    }
                }

                await using (s)
                {
                    await oFS.CopyToAsync(s);

                    if (fS.Length > limit)
                        await s.WriteAsync(Encoding.UTF8.GetBytes("\r\n####___TRUNCATED___####"));
                }
            }
        }

        public void DeleteLog(string logName)
        {
            string logFile = Path.Combine(ConvertToAbsolutePath(_logFolder), logName + ".log");

            if (logFile.Equals(_logFile, StringComparison.OrdinalIgnoreCase))
                DeleteCurrentLogFile();
            else
                File.Delete(logFile);
        }

        public void DeleteAllLogs()
        {
            string[] logFiles = ListLogFiles();

            foreach (string logFile in logFiles)
            {
                if (logFile.Equals(_logFile, StringComparison.OrdinalIgnoreCase))
                    DeleteCurrentLogFile();
                else
                    File.Delete(logFile);
            }
        }

        public void Write(Exception ex)
        {
            Write(ex.ToString());
        }

        public void Write(IPEndPoint ep, Exception ex)
        {
            Write(ep, ex.ToString());
        }

        public void Write(IPEndPoint ep, string message)
        {
            string ipInfo;

            if (ep == null)
                ipInfo = "";
            else if (ep.Address.IsIPv4MappedToIPv6)
                ipInfo = "[" + ep.Address.MapToIPv4().ToString() + ":" + ep.Port + "] ";
            else
                ipInfo = "[" + ep.ToString() + "] ";

            Write(ipInfo + message);
        }

        public void Write(IPEndPoint ep, DnsTransportProtocol protocol, Exception ex)
        {
            Write(ep, protocol, ex.ToString());
        }

        public void Write(IPEndPoint ep, DnsTransportProtocol protocol, DnsDatagram request, DnsDatagram response)
        {
            DnsQuestionRecord q = null;

            if (request.Question.Count > 0)
                q = request.Question[0];

            string requestInfo;

            if (q is null)
                requestInfo = "MISSING QUESTION!";
            else
                requestInfo = "QNAME: " + q.Name + "; QTYPE: " + q.Type.ToString() + "; QCLASS: " + q.Class;

            if (request.Additional.Count > 0)
            {
                DnsResourceRecord lastRR = request.Additional[request.Additional.Count - 1];

                if ((lastRR.Type == DnsResourceRecordType.TSIG) && (lastRR.RDATA is DnsTSIGRecordData tsig))
                    requestInfo += "; TSIG KeyName: " + lastRR.Name.ToLowerInvariant() + "; TSIG Algo: " + tsig.AlgorithmName + "; TSIG Error: " + tsig.Error.ToString();
            }

            string responseInfo;

            if (response is null)
            {
                responseInfo = "; NO RESPONSE FROM SERVER!";
            }
            else
            {
                responseInfo = "; RCODE: " + response.RCODE.ToString();

                string answer;

                if (response.Answer.Count == 0)
                {
                    if (response.Truncation)
                        answer = "[TRUNCATED]";
                    else
                        answer = "[]";
                }
                else if ((response.Answer.Count > 2) && response.IsZoneTransfer)
                {
                    answer = "[ZONE TRANSFER]";
                }
                else
                {
                    answer = "[";

                    for (int i = 0; i < response.Answer.Count; i++)
                    {
                        if (i > 0)
                            answer += ", ";

                        answer += response.Answer[i].RDATA.ToString();
                    }

                    answer += "]";

                    if (response.Additional.Count > 0)
                    {
                        switch (q.Type)
                        {
                            case DnsResourceRecordType.NS:
                            case DnsResourceRecordType.MX:
                            case DnsResourceRecordType.SRV:
                                answer += "; ADDITIONAL: [";

                                for (int i = 0; i < response.Additional.Count; i++)
                                {
                                    DnsResourceRecord additional = response.Additional[i];

                                    switch (additional.Type)
                                    {
                                        case DnsResourceRecordType.A:
                                        case DnsResourceRecordType.AAAA:
                                            if (i > 0)
                                                answer += ", ";

                                            answer += additional.Name + " (" + additional.RDATA.ToString() + ")";
                                            break;
                                    }
                                }

                                answer += "]";
                                break;
                        }
                    }
                }

                EDnsClientSubnetOptionData responseECS = response.GetEDnsClientSubnetOption();
                if (responseECS is not null)
                    answer += "; ECS: " + responseECS.Address.ToString() + "/" + responseECS.ScopePrefixLength;

                responseInfo += "; ANSWER: " + answer;
            }

            Write(ep, protocol, requestInfo + responseInfo);
        }

        public void Write(IPEndPoint ep, DnsTransportProtocol protocol, string message)
        {
            Write(ep, protocol.ToString(), message);
        }

        public void Write(IPEndPoint ep, string protocol, string message)
        {
            string ipInfo;

            if (ep == null)
                ipInfo = "";
            else if (ep.Address.IsIPv4MappedToIPv6)
                ipInfo = "[" + ep.Address.MapToIPv4().ToString() + ":" + ep.Port + "] ";
            else
                ipInfo = "[" + ep.ToString() + "] ";

            Write(ipInfo + "[" + protocol.ToUpper() + "] " + message);
        }

        public void Write(string message)
        {
            if (_loggingType != LoggingType.None)
                _queue.Add(new LogQueueItem(message));
        }

        public void DeleteCurrentLogFile()
        {
            lock (_queueLock)
            {
                try
                {
                    if (_isRunning)
                        _queueCancellationTokenSource.Cancel();

                    lock (_logFileLock)
                    {
                        if (_logOut != null)
                        {
                            _logOut.Dispose();
                            _logOut = null;
                        }

                        File.Delete(_logFile);

                        if (_loggingType.HasFlag(LoggingType.File))
                            StartNewLog();
                    }
                }
                finally
                {
                    _queueWait.Set();
                }
            }
        }

        public void SaveConfig()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        #endregion

        #region properties

        public LoggingType LoggingType
        {
            get { return _loggingType; }
            set
            {
                _loggingType = value;

                if (_isRunning)
                {
                    //running
                    if (_loggingType == LoggingType.None)
                    {
                        StopLogging();
                    }
                    else if (_loggingType.HasFlag(LoggingType.File))
                    {
                        if ((_logOut is null) || !_logFile.StartsWith(ConvertToAbsolutePath(_logFolder)))
                        {
                            //file not being logged or log folder changed; start new log file
                            UpdateLogFileState();
                        }
                    }
                    else if (_loggingType == LoggingType.Console)
                    {
                        if (_logOut is not null)
                        {
                            //only console logging enabled; close any open log file
                            UpdateLogFileState();
                        }
                    }
                }
                else
                {
                    //stopped
                    if (_loggingType != LoggingType.None)
                        StartLogging();
                }
            }
        }

        public string LogFolder
        {
            get { return _logFolder; }
            set
            {
                string logFolder;

                if (string.IsNullOrEmpty(value))
                    logFolder = "logs";
                else if (value.Length > 255)
                    throw new ArgumentException("Log folder path length cannot exceed 255 characters.", nameof(LogFolder));
                else
                    logFolder = value;

                Directory.CreateDirectory(ConvertToAbsolutePath(logFolder));

                _logFolder = ConvertToRelativePath(logFolder);
            }
        }

        public int MaxLogFileDays
        {
            get { return _maxLogFileDays; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(MaxLogFileDays), "MaxLogFileDays must be greater than or equal to 0.");

                _maxLogFileDays = value;

                if (_maxLogFileDays == 0)
                    _logCleanupTimer.Change(Timeout.Infinite, Timeout.Infinite);
                else
                    _logCleanupTimer.Change(LOG_CLEANUP_TIMER_INITIAL_INTERVAL, LOG_CLEANUP_TIMER_PERIODIC_INTERVAL);
            }
        }

        public bool UseLocalTime
        {
            get { return _useLocalTime; }
            set { _useLocalTime = value; }
        }

        public string CurrentLogFile
        { get { return _logFile; } }

        public string LogFolderAbsolutePath
        { get { return ConvertToAbsolutePath(_logFolder); } }

        #endregion

        class LogQueueItem
        {
            #region variables

            public readonly DateTime _dateTime;
            public readonly string _message;

            #endregion

            #region constructor

            public LogQueueItem(string message)
            {
                _dateTime = DateTime.UtcNow;
                _message = message;
            }

            #endregion
        }
    }
}
