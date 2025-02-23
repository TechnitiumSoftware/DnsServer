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
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns
{
    public enum TopStatsType
    {
        Unknown = 0,
        TopClients = 1,
        TopDomains = 2,
        TopBlockedDomains = 3
    }

    public sealed class StatsManager : IDisposable
    {
        #region variables

        const int DAILY_STATS_FILE_TOP_LIMIT = 1000;

        readonly static HourlyStats _emptyHourlyStats = new HourlyStats();
        readonly static StatCounter _emptyDailyStats = new StatCounter();

        readonly DnsServer _dnsServer;
        readonly string _statsFolder;

        readonly StatCounter[] _lastHourStatCounters = new StatCounter[60];
        readonly StatCounter[] _lastHourStatCountersCopy = new StatCounter[60];
        readonly ConcurrentDictionary<DateTime, HourlyStats> _hourlyStatsCache = new ConcurrentDictionary<DateTime, HourlyStats>();
        readonly ConcurrentDictionary<DateTime, StatCounter> _dailyStatsCache = new ConcurrentDictionary<DateTime, StatCounter>();

        readonly Timer _maintenanceTimer;
        const int MAINTENANCE_TIMER_INITIAL_INTERVAL = 10000;
        const int MAINTENANCE_TIMER_PERIODIC_INTERVAL = 10000;

        readonly BlockingCollection<StatsQueueItem> _queue = new BlockingCollection<StatsQueueItem>();
        readonly Thread _consumerThread;

        readonly Timer _statsCleanupTimer;
        const int STATS_CLEANUP_TIMER_INITIAL_INTERVAL = 60 * 1000;
        const int STATS_CLEANUP_TIMER_PERIODIC_INTERVAL = 60 * 60 * 1000;

        bool _enableInMemoryStats;
        int _maxStatFileDays;

        #endregion

        #region constructor

        static StatsManager()
        {
            _emptyDailyStats.Lock();
        }

        public StatsManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;
            _statsFolder = Path.Combine(dnsServer.ConfigFolder, "stats");

            if (!Directory.Exists(_statsFolder))
                Directory.CreateDirectory(_statsFolder);

            //load stats
            LoadLastHourStats();

            try
            {
                //do first maintenance
                DoMaintenance();
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager?.Write(ex);
            }

            //start periodic maintenance timer
            _maintenanceTimer = new Timer(delegate (object state)
            {
                try
                {
                    DoMaintenance();
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager?.Write(ex);
                }
            }, null, MAINTENANCE_TIMER_INITIAL_INTERVAL, MAINTENANCE_TIMER_PERIODIC_INTERVAL);

            //stats consumer thread
            _consumerThread = new Thread(delegate ()
            {
                try
                {
                    foreach (StatsQueueItem item in _queue.GetConsumingEnumerable())
                    {
                        StatCounter statCounter = _lastHourStatCounters[item._timestamp.Minute];
                        if (statCounter is not null)
                        {
                            DnsQuestionRecord query;

                            if ((item._request is not null) && (item._request.Question.Count > 0))
                                query = item._request.Question[0];
                            else
                                query = null;

                            DnsServerResponseType responseType;

                            if (item._response is null)
                                responseType = DnsServerResponseType.Dropped;
                            else if (item._response.Tag is null)
                                responseType = DnsServerResponseType.Recursive;
                            else
                                responseType = (DnsServerResponseType)item._response.Tag;

                            statCounter.Update(query, item._response is null ? DnsResponseCode.NoError : item._response.RCODE, responseType, item._remoteEP.Address, item._protocol, item._rateLimited);
                        }

                        if ((item._request is null) || (item._response is null))
                            continue; //skip dropped requests for apps to prevent DOS

                        foreach (IDnsQueryLogger logger in _dnsServer.DnsApplicationManager.DnsQueryLoggers)
                        {
                            try
                            {
                                _ = logger.InsertLogAsync(item._timestamp, item._request, item._remoteEP, item._protocol, item._response);
                            }
                            catch (Exception ex)
                            {
                                LogManager log = dnsServer.LogManager;
                                if (log is not null)
                                    log.Write(ex);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager?.Write(ex);
                }
            });

            _consumerThread.Name = "Stats";
            _consumerThread.IsBackground = true;
            _consumerThread.Start();

            _statsCleanupTimer = new Timer(delegate (object state)
            {
                try
                {
                    if (_maxStatFileDays < 1)
                        return;

                    DateTime cutoffDate = DateTime.UtcNow.AddDays(_maxStatFileDays * -1).Date;
                    LogManager log = dnsServer.LogManager;

                    //delete hourly logs
                    {
                        string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_dnsServer.ConfigFolder, "stats"), "*.stat");

                        foreach (string hourlyStatsFile in hourlyStatsFiles)
                        {
                            string hourlyStatsFileName = Path.GetFileNameWithoutExtension(hourlyStatsFile);

                            if (!DateTime.TryParseExact(hourlyStatsFileName, "yyyyMMddHH", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime hourlyStatsFileDate))
                                continue;

                            if (hourlyStatsFileDate < cutoffDate)
                            {
                                try
                                {
                                    File.Delete(hourlyStatsFile);
                                    if (log != null)
                                        log.Write("StatsManager cleanup deleted the hourly stats file: " + hourlyStatsFile);
                                }
                                catch (Exception ex)
                                {
                                    if (log != null)
                                        log.Write(ex);
                                }
                            }
                        }
                    }

                    //delete daily logs
                    {
                        string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_dnsServer.ConfigFolder, "stats"), "*.dstat");

                        foreach (string dailyStatsFile in dailyStatsFiles)
                        {
                            string dailyStatsFileName = Path.GetFileNameWithoutExtension(dailyStatsFile);

                            if (!DateTime.TryParseExact(dailyStatsFileName, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime dailyStatsFileDate))
                                continue;

                            if (dailyStatsFileDate < cutoffDate)
                            {
                                try
                                {
                                    File.Delete(dailyStatsFile);
                                    if (log != null)
                                        log.Write("StatsManager cleanup deleted the daily stats file: " + dailyStatsFile);
                                }
                                catch (Exception ex)
                                {
                                    if (log != null)
                                        log.Write(ex);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager?.Write(ex);
                }
            });

            _statsCleanupTimer.Change(STATS_CLEANUP_TIMER_INITIAL_INTERVAL, STATS_CLEANUP_TIMER_PERIODIC_INTERVAL);
        }

        #endregion

        #region IDisposable

        bool _disposed;
        readonly object _disposeLock = new object();

        private void Dispose(bool disposing)
        {
            lock (_disposeLock)
            {
                if (_disposed)
                    return;

                if (disposing)
                {
                    _maintenanceTimer?.Dispose();
                    _statsCleanupTimer?.Dispose();

                    //do last maintenance
                    DoMaintenance();
                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private void LoadLastHourStats()
        {
            try
            {
                DateTime currentDateTime = DateTime.UtcNow;
                DateTime lastHourDateTime = currentDateTime.AddMinutes(-60);

                HourlyStats lastHourlyStats = null;
                DateTime lastHourlyStatsDateTime = new DateTime();

                for (int i = 0; i < 60; i++)
                {
                    DateTime lastDateTime = lastHourDateTime.AddMinutes(i);

                    if ((lastHourlyStats == null) || (lastDateTime.Hour != lastHourlyStatsDateTime.Hour))
                    {
                        lastHourlyStats = LoadHourlyStats(lastDateTime);
                        lastHourlyStatsDateTime = lastDateTime;
                    }

                    _lastHourStatCounters[lastDateTime.Minute] = lastHourlyStats.MinuteStats[lastDateTime.Minute];
                    _lastHourStatCountersCopy[lastDateTime.Minute] = _lastHourStatCounters[lastDateTime.Minute];
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager?.Write(ex);
            }
        }

        private void DoMaintenance()
        {
            //load new stats counter 5 min ahead of current time
            DateTime currentDateTime = DateTime.UtcNow;

            for (int i = 0; i < 5; i++)
            {
                int minute = currentDateTime.AddMinutes(i).Minute;

                StatCounter statCounter = _lastHourStatCounters[minute];
                if ((statCounter == null) || statCounter.IsLocked)
                    _lastHourStatCounters[minute] = new StatCounter();
            }

            //save data upto last 5 mins
            DateTime last5MinDateTime = currentDateTime.AddMinutes(-5);

            for (int i = 0; i < 5; i++)
            {
                DateTime lastDateTime = last5MinDateTime.AddMinutes(i);

                StatCounter lastStatCounter = _lastHourStatCounters[lastDateTime.Minute];
                if ((lastStatCounter != null) && !lastStatCounter.IsLocked)
                {
                    lastStatCounter.Lock();

                    if (!_enableInMemoryStats)
                    {
                        //load hourly stats data
                        HourlyStats hourlyStats = LoadHourlyStats(lastDateTime);

                        //update hourly stats file
                        hourlyStats.UpdateStat(lastDateTime, lastStatCounter);

                        //save hourly stats
                        SaveHourlyStats(lastDateTime, hourlyStats);
                    }

                    //keep copy for api
                    _lastHourStatCountersCopy[lastDateTime.Minute] = lastStatCounter;
                }
            }

            //load previous day stats to auto create daily stats file
            LoadDailyStats(currentDateTime.AddDays(-1));

            //remove old data from hourly stats cache
            {
                DateTime threshold = DateTime.UtcNow.AddHours(-24);
                threshold = new DateTime(threshold.Year, threshold.Month, threshold.Day, threshold.Hour, 0, 0, DateTimeKind.Utc);

                List<DateTime> _keysToRemove = new List<DateTime>();

                foreach (KeyValuePair<DateTime, HourlyStats> item in _hourlyStatsCache)
                {
                    if (item.Key < threshold)
                        _keysToRemove.Add(item.Key);
                }

                foreach (DateTime key in _keysToRemove)
                    _hourlyStatsCache.TryRemove(key, out _);
            }

            //unload minute stats data from hourly stats cache for data older than last hour
            {
                DateTime lastHourThreshold = DateTime.UtcNow.AddHours(-1);
                lastHourThreshold = new DateTime(lastHourThreshold.Year, lastHourThreshold.Month, lastHourThreshold.Day, lastHourThreshold.Hour, 0, 0, DateTimeKind.Utc);

                foreach (KeyValuePair<DateTime, HourlyStats> item in _hourlyStatsCache)
                {
                    if (item.Key < lastHourThreshold)
                        item.Value.UnloadMinuteStats();
                }
            }

            //remove old data from daily stats cache
            {
                DateTime threshold = DateTime.UtcNow.AddMonths(-12);
                threshold = new DateTime(threshold.Year, threshold.Month, 1, 0, 0, 0, DateTimeKind.Utc);

                List<DateTime> _keysToRemove = new List<DateTime>();

                foreach (KeyValuePair<DateTime, StatCounter> item in _dailyStatsCache)
                {
                    if (item.Key < threshold)
                        _keysToRemove.Add(item.Key);
                }

                foreach (DateTime key in _keysToRemove)
                    _dailyStatsCache.TryRemove(key, out _);
            }
        }

        private HourlyStats LoadHourlyStats(DateTime dateTime, bool forceReload = false, bool ifNotExistsReturnEmptyHourlyStats = false)
        {
            if (_enableInMemoryStats)
                return _emptyHourlyStats;

            DateTime hourlyDateTime = new DateTime(dateTime.Year, dateTime.Month, dateTime.Day, dateTime.Hour, 0, 0, 0, DateTimeKind.Utc);

            if (forceReload || !_hourlyStatsCache.TryGetValue(hourlyDateTime, out HourlyStats hourlyStats))
            {
                string hourlyStatsFile = Path.Combine(_statsFolder, dateTime.ToString("yyyyMMddHH") + ".stat");

                if (File.Exists(hourlyStatsFile))
                {
                    try
                    {
                        using (FileStream fS = new FileStream(hourlyStatsFile, FileMode.Open, FileAccess.Read))
                        {
                            hourlyStats = new HourlyStats(new BinaryReader(fS));
                        }
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager?.Write(ex);

                        if (ifNotExistsReturnEmptyHourlyStats)
                            hourlyStats = _emptyHourlyStats;
                        else
                            hourlyStats = new HourlyStats();
                    }
                }
                else
                {
                    if (ifNotExistsReturnEmptyHourlyStats)
                        hourlyStats = _emptyHourlyStats;
                    else
                        hourlyStats = new HourlyStats();
                }

                _hourlyStatsCache[hourlyDateTime] = hourlyStats;
            }

            return hourlyStats;
        }

        private StatCounter LoadDailyStats(DateTime dateTime)
        {
            if (_enableInMemoryStats)
                return _emptyDailyStats;

            DateTime dailyDateTime = new DateTime(dateTime.Year, dateTime.Month, dateTime.Day, 0, 0, 0, 0, DateTimeKind.Utc);

            if (!_dailyStatsCache.TryGetValue(dailyDateTime, out StatCounter dailyStats))
            {
                string dailyStatsFile = Path.Combine(_statsFolder, dateTime.ToString("yyyyMMdd") + ".dstat");

                if (File.Exists(dailyStatsFile))
                {
                    try
                    {
                        using (FileStream fS = new FileStream(dailyStatsFile, FileMode.Open, FileAccess.Read))
                        {
                            dailyStats = new StatCounter(new BinaryReader(fS));
                        }

                        //check if existing file could be truncated to avoid loading unnecessary data in memory
                        if (dailyStats.Truncate(DAILY_STATS_FILE_TOP_LIMIT))
                            SaveDailyStats(dailyDateTime, dailyStats); //save truncated file
                    }
                    catch (Exception ex)
                    {
                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write(ex);
                    }
                }

                if (dailyStats == null)
                {
                    dailyStats = new StatCounter();
                    dailyStats.Lock();

                    for (int hour = 0; hour < 24; hour++) //hours
                    {
                        HourlyStats hourlyStats = LoadHourlyStats(dailyDateTime.AddHours(hour), ifNotExistsReturnEmptyHourlyStats: true);
                        dailyStats.Merge(hourlyStats.HourStat);
                    }

                    if (dailyStats.TotalQueries > 0)
                    {
                        _ = dailyStats.Truncate(DAILY_STATS_FILE_TOP_LIMIT);
                        SaveDailyStats(dailyDateTime, dailyStats);
                    }
                }

                if (!_dailyStatsCache.TryAdd(dailyDateTime, dailyStats))
                {
                    if (!_dailyStatsCache.TryGetValue(dailyDateTime, out dailyStats))
                        throw new DnsServerException("Unable to load daily stats.");
                }
            }

            return dailyStats;
        }

        private void SaveHourlyStats(DateTime dateTime, HourlyStats hourlyStats)
        {
            string hourlyStatsFile = Path.Combine(_statsFolder, dateTime.ToString("yyyyMMddHH") + ".stat");

            try
            {
                using (FileStream fS = new FileStream(hourlyStatsFile, FileMode.Create, FileAccess.Write))
                {
                    hourlyStats.WriteTo(new BinaryWriter(fS));
                }
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write(ex);
            }
        }

        private void SaveDailyStats(DateTime dateTime, StatCounter dailyStats)
        {
            string dailyStatsFile = Path.Combine(_statsFolder, dateTime.ToString("yyyyMMdd") + ".dstat");

            try
            {
                using (FileStream fS = new FileStream(dailyStatsFile, FileMode.Create, FileAccess.Write))
                {
                    dailyStats.WriteTo(new BinaryWriter(fS));
                }
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write(ex);
            }
        }

        private void Flush()
        {
            //clear in memory stats
            for (int i = 0; i < _lastHourStatCountersCopy.Length; i++)
                _lastHourStatCountersCopy[i] = null;

            _hourlyStatsCache.Clear();
            _dailyStatsCache.Clear();
        }

        #endregion

        #region public

        public void ReloadStats()
        {
            Flush();
            LoadLastHourStats();
        }

        public void DeleteAllStats()
        {
            foreach (string hourlyStatsFile in Directory.GetFiles(Path.Combine(_dnsServer.ConfigFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly))
            {
                File.Delete(hourlyStatsFile);
            }

            foreach (string dailyStatsFile in Directory.GetFiles(Path.Combine(_dnsServer.ConfigFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly))
            {
                File.Delete(dailyStatsFile);
            }

            Flush();
        }

        public void QueueUpdate(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response, bool rateLimited)
        {
            _queue.Add(new StatsQueueItem(request, remoteEP, protocol, response, rateLimited));
        }

        public Dictionary<string, List<KeyValuePair<string, long>>> GetLastHourMinuteWiseStats(bool utcFormat)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, long>> totalQueriesPerInterval = new List<KeyValuePair<string, long>>(60);
            List<KeyValuePair<string, long>> totalNoErrorPerInterval = new List<KeyValuePair<string, long>>(60);
            List<KeyValuePair<string, long>> totalServerFailurePerInterval = new List<KeyValuePair<string, long>>(60);
            List<KeyValuePair<string, long>> totalNxDomainPerInterval = new List<KeyValuePair<string, long>>(60);
            List<KeyValuePair<string, long>> totalRefusedPerInterval = new List<KeyValuePair<string, long>>(60);

            List<KeyValuePair<string, long>> totalAuthHitPerInterval = new List<KeyValuePair<string, long>>(60);
            List<KeyValuePair<string, long>> totalRecursionsPerInterval = new List<KeyValuePair<string, long>>(60);
            List<KeyValuePair<string, long>> totalCacheHitPerInterval = new List<KeyValuePair<string, long>>(60);
            List<KeyValuePair<string, long>> totalBlockedPerInterval = new List<KeyValuePair<string, long>>(60);
            List<KeyValuePair<string, long>> totalDroppedPerInterval = new List<KeyValuePair<string, long>>(60);

            List<KeyValuePair<string, long>> totalClientsPerInterval = new List<KeyValuePair<string, long>>(60);

            DateTime lastHourDateTime = DateTime.UtcNow.AddMinutes(-60);
            lastHourDateTime = new DateTime(lastHourDateTime.Year, lastHourDateTime.Month, lastHourDateTime.Day, lastHourDateTime.Hour, lastHourDateTime.Minute, 0, DateTimeKind.Utc);

            for (int minute = 0; minute < 60; minute++)
            {
                DateTime lastDateTime = lastHourDateTime.AddMinutes(minute);
                string label;

                if (utcFormat)
                    label = lastDateTime.AddMinutes(1).ToString("O");
                else
                    label = lastDateTime.AddMinutes(1).ToLocalTime().ToString("HH:mm");

                StatCounter statCounter = _lastHourStatCountersCopy[lastDateTime.Minute];
                if ((statCounter != null) && statCounter.IsLocked)
                {
                    totalStatCounter.Merge(statCounter);

                    totalQueriesPerInterval.Add(new KeyValuePair<string, long>(label, statCounter.TotalQueries));
                    totalNoErrorPerInterval.Add(new KeyValuePair<string, long>(label, statCounter.TotalNoError));
                    totalServerFailurePerInterval.Add(new KeyValuePair<string, long>(label, statCounter.TotalServerFailure));
                    totalNxDomainPerInterval.Add(new KeyValuePair<string, long>(label, statCounter.TotalNxDomain));
                    totalRefusedPerInterval.Add(new KeyValuePair<string, long>(label, statCounter.TotalRefused));

                    totalAuthHitPerInterval.Add(new KeyValuePair<string, long>(label, statCounter.TotalAuthoritative));
                    totalRecursionsPerInterval.Add(new KeyValuePair<string, long>(label, statCounter.TotalRecursive));
                    totalCacheHitPerInterval.Add(new KeyValuePair<string, long>(label, statCounter.TotalCached));
                    totalBlockedPerInterval.Add(new KeyValuePair<string, long>(label, statCounter.TotalBlocked));
                    totalDroppedPerInterval.Add(new KeyValuePair<string, long>(label, statCounter.TotalDropped));

                    totalClientsPerInterval.Add(new KeyValuePair<string, long>(label, statCounter.TotalClients));
                }
                else
                {
                    totalQueriesPerInterval.Add(new KeyValuePair<string, long>(label, 0));
                    totalNoErrorPerInterval.Add(new KeyValuePair<string, long>(label, 0));
                    totalServerFailurePerInterval.Add(new KeyValuePair<string, long>(label, 0));
                    totalNxDomainPerInterval.Add(new KeyValuePair<string, long>(label, 0));
                    totalRefusedPerInterval.Add(new KeyValuePair<string, long>(label, 0));

                    totalAuthHitPerInterval.Add(new KeyValuePair<string, long>(label, 0));
                    totalRecursionsPerInterval.Add(new KeyValuePair<string, long>(label, 0));
                    totalCacheHitPerInterval.Add(new KeyValuePair<string, long>(label, 0));
                    totalBlockedPerInterval.Add(new KeyValuePair<string, long>(label, 0));
                    totalDroppedPerInterval.Add(new KeyValuePair<string, long>(label, 0));

                    totalClientsPerInterval.Add(new KeyValuePair<string, long>(label, 0));
                }
            }

            Dictionary<string, List<KeyValuePair<string, long>>> data = new Dictionary<string, List<KeyValuePair<string, long>>>();

            {
                List<KeyValuePair<string, long>> stats = new List<KeyValuePair<string, long>>(10);

                stats.Add(new KeyValuePair<string, long>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, long>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, long>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, long>("totalNxDomain", totalStatCounter.TotalNxDomain));
                stats.Add(new KeyValuePair<string, long>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, long>("totalAuthoritative", totalStatCounter.TotalAuthoritative));
                stats.Add(new KeyValuePair<string, long>("totalRecursive", totalStatCounter.TotalRecursive));
                stats.Add(new KeyValuePair<string, long>("totalCached", totalStatCounter.TotalCached));
                stats.Add(new KeyValuePair<string, long>("totalBlocked", totalStatCounter.TotalBlocked));
                stats.Add(new KeyValuePair<string, long>("totalDropped", totalStatCounter.TotalDropped));

                stats.Add(new KeyValuePair<string, long>("totalClients", totalStatCounter.TotalClients));

                data.Add("stats", stats);
            }

            data.Add("totalQueriesPerInterval", totalQueriesPerInterval);
            data.Add("totalNoErrorPerInterval", totalNoErrorPerInterval);
            data.Add("totalServerFailurePerInterval", totalServerFailurePerInterval);
            data.Add("totalNxDomainPerInterval", totalNxDomainPerInterval);
            data.Add("totalRefusedPerInterval", totalRefusedPerInterval);

            data.Add("totalAuthHitPerInterval", totalAuthHitPerInterval);
            data.Add("totalRecursionsPerInterval", totalRecursionsPerInterval);
            data.Add("totalCacheHitPerInterval", totalCacheHitPerInterval);
            data.Add("totalBlockedPerInterval", totalBlockedPerInterval);
            data.Add("totalDroppedPerInterval", totalDroppedPerInterval);

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(10));
            data.Add("protocolTypes", totalStatCounter.GetTopProtocolTypes());

            return data;
        }

        public Dictionary<string, List<KeyValuePair<string, long>>> GetLastDayHourWiseStats(bool utcFormat)
        {
            return GetHourWiseStats(DateTime.UtcNow.AddHours(-24), 24, utcFormat);
        }

        public Dictionary<string, List<KeyValuePair<string, long>>> GetLastWeekDayWiseStats(bool utcFormat)
        {
            return GetDayWiseStats(DateTime.UtcNow.AddDays(-7).Date, 7, utcFormat);
        }

        public Dictionary<string, List<KeyValuePair<string, long>>> GetLastMonthDayWiseStats(bool utcFormat)
        {
            return GetDayWiseStats(DateTime.UtcNow.AddDays(-31).Date, 31, utcFormat);
        }

        public Dictionary<string, List<KeyValuePair<string, long>>> GetLastYearMonthWiseStats(bool utcFormat)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, long>> totalQueriesPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalNoErrorPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalServerFailurePerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalNxDomainPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalRefusedPerInterval = new List<KeyValuePair<string, long>>();

            List<KeyValuePair<string, long>> totalAuthHitPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalRecursionsPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalCacheHitPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalBlockedPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalDroppedPerInterval = new List<KeyValuePair<string, long>>();

            List<KeyValuePair<string, long>> totalClientsPerInterval = new List<KeyValuePair<string, long>>();

            DateTime lastYearDateTime = DateTime.UtcNow.AddMonths(-12);
            lastYearDateTime = new DateTime(lastYearDateTime.Year, lastYearDateTime.Month, 1, 0, 0, 0, DateTimeKind.Utc);

            for (int month = 0; month < 12; month++) //months
            {
                StatCounter monthlyStatCounter = new StatCounter();
                monthlyStatCounter.Lock();

                DateTime lastMonthDateTime = lastYearDateTime.AddMonths(month);
                string label;

                if (utcFormat)
                    label = lastMonthDateTime.ToString("O");
                else
                    label = lastMonthDateTime.ToLocalTime().ToString("MM/yyyy");

                int days = DateTime.DaysInMonth(lastMonthDateTime.Year, lastMonthDateTime.Month);

                for (int day = 0; day < days; day++) //days
                {
                    StatCounter dailyStatCounter = LoadDailyStats(lastMonthDateTime.AddDays(day));
                    monthlyStatCounter.Merge(dailyStatCounter, true);
                }

                totalStatCounter.Merge(monthlyStatCounter, true);

                totalQueriesPerInterval.Add(new KeyValuePair<string, long>(label, monthlyStatCounter.TotalQueries));
                totalNoErrorPerInterval.Add(new KeyValuePair<string, long>(label, monthlyStatCounter.TotalNoError));
                totalServerFailurePerInterval.Add(new KeyValuePair<string, long>(label, monthlyStatCounter.TotalServerFailure));
                totalNxDomainPerInterval.Add(new KeyValuePair<string, long>(label, monthlyStatCounter.TotalNxDomain));
                totalRefusedPerInterval.Add(new KeyValuePair<string, long>(label, monthlyStatCounter.TotalRefused));

                totalAuthHitPerInterval.Add(new KeyValuePair<string, long>(label, monthlyStatCounter.TotalAuthoritative));
                totalRecursionsPerInterval.Add(new KeyValuePair<string, long>(label, monthlyStatCounter.TotalRecursive));
                totalCacheHitPerInterval.Add(new KeyValuePair<string, long>(label, monthlyStatCounter.TotalCached));
                totalBlockedPerInterval.Add(new KeyValuePair<string, long>(label, monthlyStatCounter.TotalBlocked));
                totalDroppedPerInterval.Add(new KeyValuePair<string, long>(label, monthlyStatCounter.TotalDropped));

                totalClientsPerInterval.Add(new KeyValuePair<string, long>(label, monthlyStatCounter.TotalClients));
            }

            Dictionary<string, List<KeyValuePair<string, long>>> data = new Dictionary<string, List<KeyValuePair<string, long>>>();

            {
                List<KeyValuePair<string, long>> stats = new List<KeyValuePair<string, long>>(6);

                stats.Add(new KeyValuePair<string, long>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, long>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, long>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, long>("totalNxDomain", totalStatCounter.TotalNxDomain));
                stats.Add(new KeyValuePair<string, long>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, long>("totalAuthoritative", totalStatCounter.TotalAuthoritative));
                stats.Add(new KeyValuePair<string, long>("totalRecursive", totalStatCounter.TotalRecursive));
                stats.Add(new KeyValuePair<string, long>("totalCached", totalStatCounter.TotalCached));
                stats.Add(new KeyValuePair<string, long>("totalBlocked", totalStatCounter.TotalBlocked));
                stats.Add(new KeyValuePair<string, long>("totalDropped", totalStatCounter.TotalDropped));

                stats.Add(new KeyValuePair<string, long>("totalClients", totalStatCounter.TotalClients));

                data.Add("stats", stats);
            }

            data.Add("totalQueriesPerInterval", totalQueriesPerInterval);
            data.Add("totalNoErrorPerInterval", totalNoErrorPerInterval);
            data.Add("totalServerFailurePerInterval", totalServerFailurePerInterval);
            data.Add("totalNxDomainPerInterval", totalNxDomainPerInterval);
            data.Add("totalRefusedPerInterval", totalRefusedPerInterval);

            data.Add("totalAuthHitPerInterval", totalAuthHitPerInterval);
            data.Add("totalRecursionsPerInterval", totalRecursionsPerInterval);
            data.Add("totalCacheHitPerInterval", totalCacheHitPerInterval);
            data.Add("totalBlockedPerInterval", totalBlockedPerInterval);
            data.Add("totalDroppedPerInterval", totalDroppedPerInterval);

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(10));
            data.Add("protocolTypes", totalStatCounter.GetTopProtocolTypes());

            return data;
        }

        public Dictionary<string, List<KeyValuePair<string, long>>> GetMinuteWiseStats(DateTime startDate, DateTime endDate, bool utcFormat)
        {
            return GetMinuteWiseStats(startDate, Convert.ToInt32((endDate - startDate).TotalMinutes) + 1, utcFormat);
        }

        public Dictionary<string, List<KeyValuePair<string, long>>> GetMinuteWiseStats(DateTime startDate, int minutes, bool utcFormat)
        {
            startDate = startDate.AddMinutes(-1);

            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, long>> totalQueriesPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalNoErrorPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalServerFailurePerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalNxDomainPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalRefusedPerInterval = new List<KeyValuePair<string, long>>();

            List<KeyValuePair<string, long>> totalAuthHitPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalRecursionsPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalCacheHitPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalBlockedPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalDroppedPerInterval = new List<KeyValuePair<string, long>>();

            List<KeyValuePair<string, long>> totalClientsPerInterval = new List<KeyValuePair<string, long>>();

            for (int minute = 0; minute < minutes; minute++)
            {
                DateTime lastDateTime = startDate.AddMinutes(minute);

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime, ifNotExistsReturnEmptyHourlyStats: true);
                if (hourlyStats.MinuteStats is null)
                    hourlyStats = LoadHourlyStats(lastDateTime, true);

                StatCounter minuteStatCounter = hourlyStats.MinuteStats[lastDateTime.Minute];

                string label;

                if (utcFormat)
                    label = lastDateTime.AddMinutes(1).ToString("O");
                else
                    label = lastDateTime.AddMinutes(1).ToLocalTime().ToString("MM/dd HH:mm");

                totalStatCounter.Merge(minuteStatCounter);

                totalQueriesPerInterval.Add(new KeyValuePair<string, long>(label, minuteStatCounter.TotalQueries));
                totalNoErrorPerInterval.Add(new KeyValuePair<string, long>(label, minuteStatCounter.TotalNoError));
                totalServerFailurePerInterval.Add(new KeyValuePair<string, long>(label, minuteStatCounter.TotalServerFailure));
                totalNxDomainPerInterval.Add(new KeyValuePair<string, long>(label, minuteStatCounter.TotalNxDomain));
                totalRefusedPerInterval.Add(new KeyValuePair<string, long>(label, minuteStatCounter.TotalRefused));

                totalAuthHitPerInterval.Add(new KeyValuePair<string, long>(label, minuteStatCounter.TotalAuthoritative));
                totalRecursionsPerInterval.Add(new KeyValuePair<string, long>(label, minuteStatCounter.TotalRecursive));
                totalCacheHitPerInterval.Add(new KeyValuePair<string, long>(label, minuteStatCounter.TotalCached));
                totalBlockedPerInterval.Add(new KeyValuePair<string, long>(label, minuteStatCounter.TotalBlocked));
                totalDroppedPerInterval.Add(new KeyValuePair<string, long>(label, minuteStatCounter.TotalDropped));

                totalClientsPerInterval.Add(new KeyValuePair<string, long>(label, minuteStatCounter.TotalClients));
            }

            Dictionary<string, List<KeyValuePair<string, long>>> data = new Dictionary<string, List<KeyValuePair<string, long>>>();

            {
                List<KeyValuePair<string, long>> stats = new List<KeyValuePair<string, long>>(6);

                stats.Add(new KeyValuePair<string, long>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, long>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, long>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, long>("totalNxDomain", totalStatCounter.TotalNxDomain));
                stats.Add(new KeyValuePair<string, long>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, long>("totalAuthoritative", totalStatCounter.TotalAuthoritative));
                stats.Add(new KeyValuePair<string, long>("totalRecursive", totalStatCounter.TotalRecursive));
                stats.Add(new KeyValuePair<string, long>("totalCached", totalStatCounter.TotalCached));
                stats.Add(new KeyValuePair<string, long>("totalBlocked", totalStatCounter.TotalBlocked));
                stats.Add(new KeyValuePair<string, long>("totalDropped", totalStatCounter.TotalDropped));

                stats.Add(new KeyValuePair<string, long>("totalClients", totalStatCounter.TotalClients));

                data.Add("stats", stats);
            }

            data.Add("totalQueriesPerInterval", totalQueriesPerInterval);
            data.Add("totalNoErrorPerInterval", totalNoErrorPerInterval);
            data.Add("totalServerFailurePerInterval", totalServerFailurePerInterval);
            data.Add("totalNxDomainPerInterval", totalNxDomainPerInterval);
            data.Add("totalRefusedPerInterval", totalRefusedPerInterval);

            data.Add("totalAuthHitPerInterval", totalAuthHitPerInterval);
            data.Add("totalRecursionsPerInterval", totalRecursionsPerInterval);
            data.Add("totalCacheHitPerInterval", totalCacheHitPerInterval);
            data.Add("totalBlockedPerInterval", totalBlockedPerInterval);
            data.Add("totalDroppedPerInterval", totalDroppedPerInterval);

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(10));
            data.Add("protocolTypes", totalStatCounter.GetTopProtocolTypes());

            return data;
        }

        public Dictionary<string, List<KeyValuePair<string, long>>> GetHourWiseStats(DateTime startDate, DateTime endDate, bool utcFormat)
        {
            return GetHourWiseStats(startDate, Convert.ToInt32((endDate - startDate).TotalHours) + 1, utcFormat);
        }

        public Dictionary<string, List<KeyValuePair<string, long>>> GetHourWiseStats(DateTime startDate, int hours, bool utcFormat)
        {
            startDate = new DateTime(startDate.Year, startDate.Month, startDate.Day, startDate.Hour, 0, 0, 0, DateTimeKind.Utc);

            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, long>> totalQueriesPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalNoErrorPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalServerFailurePerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalNxDomainPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalRefusedPerInterval = new List<KeyValuePair<string, long>>();

            List<KeyValuePair<string, long>> totalAuthHitPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalRecursionsPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalCacheHitPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalBlockedPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalDroppedPerInterval = new List<KeyValuePair<string, long>>();

            List<KeyValuePair<string, long>> totalClientsPerInterval = new List<KeyValuePair<string, long>>();

            for (int hour = 0; hour < hours; hour++)
            {
                DateTime lastDateTime = startDate.AddHours(hour);
                string label;

                if (utcFormat)
                    label = lastDateTime.AddHours(1).ToString("O");
                else
                    label = lastDateTime.AddHours(1).ToLocalTime().ToString("MM/dd HH") + ":00";

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime, ifNotExistsReturnEmptyHourlyStats: true);
                StatCounter hourlyStatCounter = hourlyStats.HourStat;

                totalStatCounter.Merge(hourlyStatCounter);

                totalQueriesPerInterval.Add(new KeyValuePair<string, long>(label, hourlyStatCounter.TotalQueries));
                totalNoErrorPerInterval.Add(new KeyValuePair<string, long>(label, hourlyStatCounter.TotalNoError));
                totalServerFailurePerInterval.Add(new KeyValuePair<string, long>(label, hourlyStatCounter.TotalServerFailure));
                totalNxDomainPerInterval.Add(new KeyValuePair<string, long>(label, hourlyStatCounter.TotalNxDomain));
                totalRefusedPerInterval.Add(new KeyValuePair<string, long>(label, hourlyStatCounter.TotalRefused));

                totalAuthHitPerInterval.Add(new KeyValuePair<string, long>(label, hourlyStatCounter.TotalAuthoritative));
                totalRecursionsPerInterval.Add(new KeyValuePair<string, long>(label, hourlyStatCounter.TotalRecursive));
                totalCacheHitPerInterval.Add(new KeyValuePair<string, long>(label, hourlyStatCounter.TotalCached));
                totalBlockedPerInterval.Add(new KeyValuePair<string, long>(label, hourlyStatCounter.TotalBlocked));
                totalDroppedPerInterval.Add(new KeyValuePair<string, long>(label, hourlyStatCounter.TotalDropped));

                totalClientsPerInterval.Add(new KeyValuePair<string, long>(label, hourlyStatCounter.TotalClients));
            }

            Dictionary<string, List<KeyValuePair<string, long>>> data = new Dictionary<string, List<KeyValuePair<string, long>>>();

            {
                List<KeyValuePair<string, long>> stats = new List<KeyValuePair<string, long>>(6);

                stats.Add(new KeyValuePair<string, long>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, long>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, long>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, long>("totalNxDomain", totalStatCounter.TotalNxDomain));
                stats.Add(new KeyValuePair<string, long>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, long>("totalAuthoritative", totalStatCounter.TotalAuthoritative));
                stats.Add(new KeyValuePair<string, long>("totalRecursive", totalStatCounter.TotalRecursive));
                stats.Add(new KeyValuePair<string, long>("totalCached", totalStatCounter.TotalCached));
                stats.Add(new KeyValuePair<string, long>("totalBlocked", totalStatCounter.TotalBlocked));
                stats.Add(new KeyValuePair<string, long>("totalDropped", totalStatCounter.TotalDropped));

                stats.Add(new KeyValuePair<string, long>("totalClients", totalStatCounter.TotalClients));

                data.Add("stats", stats);
            }

            data.Add("totalQueriesPerInterval", totalQueriesPerInterval);
            data.Add("totalNoErrorPerInterval", totalNoErrorPerInterval);
            data.Add("totalServerFailurePerInterval", totalServerFailurePerInterval);
            data.Add("totalNxDomainPerInterval", totalNxDomainPerInterval);
            data.Add("totalRefusedPerInterval", totalRefusedPerInterval);

            data.Add("totalAuthHitPerInterval", totalAuthHitPerInterval);
            data.Add("totalRecursionsPerInterval", totalRecursionsPerInterval);
            data.Add("totalCacheHitPerInterval", totalCacheHitPerInterval);
            data.Add("totalBlockedPerInterval", totalBlockedPerInterval);
            data.Add("totalDroppedPerInterval", totalDroppedPerInterval);

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(10));
            data.Add("protocolTypes", totalStatCounter.GetTopProtocolTypes());

            return data;
        }

        public Dictionary<string, List<KeyValuePair<string, long>>> GetDayWiseStats(DateTime startDate, DateTime endDate, bool utcFormat)
        {
            return GetDayWiseStats(startDate, Convert.ToInt32((endDate - startDate).TotalDays) + 1, utcFormat);
        }

        public Dictionary<string, List<KeyValuePair<string, long>>> GetDayWiseStats(DateTime startDate, int days, bool utcFormat)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, long>> totalQueriesPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalNoErrorPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalServerFailurePerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalNxDomainPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalRefusedPerInterval = new List<KeyValuePair<string, long>>();

            List<KeyValuePair<string, long>> totalAuthHitPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalRecursionsPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalCacheHitPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalBlockedPerInterval = new List<KeyValuePair<string, long>>();
            List<KeyValuePair<string, long>> totalDroppedPerInterval = new List<KeyValuePair<string, long>>();

            List<KeyValuePair<string, long>> totalClientsPerInterval = new List<KeyValuePair<string, long>>();

            for (int day = 0; day < days; day++) //days
            {
                DateTime lastDayDateTime = startDate.AddDays(day);
                string label;

                if (utcFormat)
                    label = lastDayDateTime.ToString("O");
                else
                    label = lastDayDateTime.ToLocalTime().ToString("MM/dd");

                StatCounter dailyStatCounter = LoadDailyStats(lastDayDateTime);
                totalStatCounter.Merge(dailyStatCounter, true);

                totalQueriesPerInterval.Add(new KeyValuePair<string, long>(label, dailyStatCounter.TotalQueries));
                totalNoErrorPerInterval.Add(new KeyValuePair<string, long>(label, dailyStatCounter.TotalNoError));
                totalServerFailurePerInterval.Add(new KeyValuePair<string, long>(label, dailyStatCounter.TotalServerFailure));
                totalNxDomainPerInterval.Add(new KeyValuePair<string, long>(label, dailyStatCounter.TotalNxDomain));
                totalRefusedPerInterval.Add(new KeyValuePair<string, long>(label, dailyStatCounter.TotalRefused));

                totalAuthHitPerInterval.Add(new KeyValuePair<string, long>(label, dailyStatCounter.TotalAuthoritative));
                totalRecursionsPerInterval.Add(new KeyValuePair<string, long>(label, dailyStatCounter.TotalRecursive));
                totalCacheHitPerInterval.Add(new KeyValuePair<string, long>(label, dailyStatCounter.TotalCached));
                totalBlockedPerInterval.Add(new KeyValuePair<string, long>(label, dailyStatCounter.TotalBlocked));
                totalDroppedPerInterval.Add(new KeyValuePair<string, long>(label, dailyStatCounter.TotalDropped));

                totalClientsPerInterval.Add(new KeyValuePair<string, long>(label, dailyStatCounter.TotalClients));
            }

            Dictionary<string, List<KeyValuePair<string, long>>> data = new Dictionary<string, List<KeyValuePair<string, long>>>();

            {
                List<KeyValuePair<string, long>> stats = new List<KeyValuePair<string, long>>(6);

                stats.Add(new KeyValuePair<string, long>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, long>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, long>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, long>("totalNxDomain", totalStatCounter.TotalNxDomain));
                stats.Add(new KeyValuePair<string, long>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, long>("totalAuthoritative", totalStatCounter.TotalAuthoritative));
                stats.Add(new KeyValuePair<string, long>("totalRecursive", totalStatCounter.TotalRecursive));
                stats.Add(new KeyValuePair<string, long>("totalCached", totalStatCounter.TotalCached));
                stats.Add(new KeyValuePair<string, long>("totalBlocked", totalStatCounter.TotalBlocked));
                stats.Add(new KeyValuePair<string, long>("totalDropped", totalStatCounter.TotalDropped));

                stats.Add(new KeyValuePair<string, long>("totalClients", totalStatCounter.TotalClients));

                data.Add("stats", stats);
            }

            data.Add("totalQueriesPerInterval", totalQueriesPerInterval);
            data.Add("totalNoErrorPerInterval", totalNoErrorPerInterval);
            data.Add("totalServerFailurePerInterval", totalServerFailurePerInterval);
            data.Add("totalNxDomainPerInterval", totalNxDomainPerInterval);
            data.Add("totalRefusedPerInterval", totalRefusedPerInterval);

            data.Add("totalAuthHitPerInterval", totalAuthHitPerInterval);
            data.Add("totalRecursionsPerInterval", totalRecursionsPerInterval);
            data.Add("totalCacheHitPerInterval", totalCacheHitPerInterval);
            data.Add("totalBlockedPerInterval", totalBlockedPerInterval);
            data.Add("totalDroppedPerInterval", totalDroppedPerInterval);

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(10));
            data.Add("protocolTypes", totalStatCounter.GetTopProtocolTypes());

            return data;
        }

        public List<KeyValuePair<string, long>> GetLastHourTopStats(TopStatsType type, int limit)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            DateTime lastHourDateTime = DateTime.UtcNow.AddMinutes(-60);
            lastHourDateTime = new DateTime(lastHourDateTime.Year, lastHourDateTime.Month, lastHourDateTime.Day, lastHourDateTime.Hour, lastHourDateTime.Minute, 0, DateTimeKind.Utc);

            for (int minute = 0; minute < 60; minute++)
            {
                DateTime lastDateTime = lastHourDateTime.AddMinutes(minute);

                StatCounter statCounter = _lastHourStatCountersCopy[lastDateTime.Minute];
                if ((statCounter != null) && statCounter.IsLocked)
                    totalStatCounter.Merge(statCounter);
            }

            switch (type)
            {
                case TopStatsType.TopDomains:
                    return totalStatCounter.GetTopDomains(limit);

                case TopStatsType.TopBlockedDomains:
                    return totalStatCounter.GetTopBlockedDomains(limit);

                case TopStatsType.TopClients:
                    return totalStatCounter.GetTopClients(limit);

                default:
                    throw new NotSupportedException();
            }
        }

        public List<KeyValuePair<string, long>> GetLastDayTopStats(TopStatsType type, int limit)
        {
            return GetHourWiseTopStats(DateTime.UtcNow.AddHours(-24), 24, type, limit);
        }

        public List<KeyValuePair<string, long>> GetLastWeekTopStats(TopStatsType type, int limit)
        {
            return GetDayWiseTopStats(DateTime.UtcNow.AddDays(-7).Date, 7, type, limit);
        }

        public List<KeyValuePair<string, long>> GetLastMonthTopStats(TopStatsType type, int limit)
        {
            return GetDayWiseTopStats(DateTime.UtcNow.AddDays(-31).Date, 31, type, limit);
        }

        public List<KeyValuePair<string, long>> GetLastYearTopStats(TopStatsType type, int limit)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            DateTime lastYearDateTime = DateTime.UtcNow.AddMonths(-12);
            lastYearDateTime = new DateTime(lastYearDateTime.Year, lastYearDateTime.Month, 1, 0, 0, 0, DateTimeKind.Utc);

            for (int month = 0; month < 12; month++) //months
            {
                StatCounter monthlyStatCounter = new StatCounter();
                monthlyStatCounter.Lock();

                DateTime lastMonthDateTime = lastYearDateTime.AddMonths(month);

                int days = DateTime.DaysInMonth(lastMonthDateTime.Year, lastMonthDateTime.Month);

                for (int day = 0; day < days; day++) //days
                {
                    StatCounter dailyStatCounter = LoadDailyStats(lastMonthDateTime.AddDays(day));
                    monthlyStatCounter.Merge(dailyStatCounter, true);
                }

                totalStatCounter.Merge(monthlyStatCounter, true);
            }

            switch (type)
            {
                case TopStatsType.TopDomains:
                    return totalStatCounter.GetTopDomains(limit);

                case TopStatsType.TopBlockedDomains:
                    return totalStatCounter.GetTopBlockedDomains(limit);

                case TopStatsType.TopClients:
                    return totalStatCounter.GetTopClients(limit);

                default:
                    throw new NotSupportedException();
            }
        }

        public List<KeyValuePair<string, long>> GetMinuteWiseTopStats(DateTime startDate, DateTime endDate, TopStatsType type, int limit)
        {
            return GetMinuteWiseTopStats(startDate, Convert.ToInt32((endDate - startDate).TotalMinutes) + 1, type, limit);
        }

        public List<KeyValuePair<string, long>> GetMinuteWiseTopStats(DateTime startDate, int minutes, TopStatsType type, int limit)
        {
            startDate = startDate.AddMinutes(-1);

            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            for (int minute = 0; minute < minutes; minute++)
            {
                DateTime lastDateTime = startDate.AddMinutes(minute);

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime, ifNotExistsReturnEmptyHourlyStats: true);
                if (hourlyStats.MinuteStats is null)
                    hourlyStats = LoadHourlyStats(lastDateTime, true);

                StatCounter minuteStatCounter = hourlyStats.MinuteStats[lastDateTime.Minute];

                totalStatCounter.Merge(minuteStatCounter);
            }

            switch (type)
            {
                case TopStatsType.TopDomains:
                    return totalStatCounter.GetTopDomains(limit);

                case TopStatsType.TopBlockedDomains:
                    return totalStatCounter.GetTopBlockedDomains(limit);

                case TopStatsType.TopClients:
                    return totalStatCounter.GetTopClients(limit);

                default:
                    throw new NotSupportedException();
            }
        }

        public List<KeyValuePair<string, long>> GetHourWiseTopStats(DateTime startDate, DateTime endDate, TopStatsType type, int limit)
        {
            return GetHourWiseTopStats(startDate, Convert.ToInt32((endDate - startDate).TotalHours) + 1, type, limit);
        }

        public List<KeyValuePair<string, long>> GetHourWiseTopStats(DateTime startDate, int hours, TopStatsType type, int limit)
        {
            startDate = new DateTime(startDate.Year, startDate.Month, startDate.Day, startDate.Hour, 0, 0, 0, DateTimeKind.Utc);

            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            for (int hour = 0; hour < hours; hour++)
            {
                DateTime lastDateTime = startDate.AddHours(hour);

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime, ifNotExistsReturnEmptyHourlyStats: true);
                StatCounter hourlyStatCounter = hourlyStats.HourStat;

                totalStatCounter.Merge(hourlyStatCounter);
            }

            switch (type)
            {
                case TopStatsType.TopDomains:
                    return totalStatCounter.GetTopDomains(limit);

                case TopStatsType.TopBlockedDomains:
                    return totalStatCounter.GetTopBlockedDomains(limit);

                case TopStatsType.TopClients:
                    return totalStatCounter.GetTopClients(limit);

                default:
                    throw new NotSupportedException();
            }
        }

        public List<KeyValuePair<string, long>> GetDayWiseTopStats(DateTime startDate, DateTime endDate, TopStatsType type, int limit)
        {
            return GetDayWiseTopStats(startDate, Convert.ToInt32((endDate - startDate).TotalDays) + 1, type, limit);
        }

        public List<KeyValuePair<string, long>> GetDayWiseTopStats(DateTime startDate, int days, TopStatsType type, int limit)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            for (int day = 0; day < days; day++) //days
            {
                DateTime lastDayDateTime = startDate.AddDays(day);

                StatCounter dailyStatCounter = LoadDailyStats(lastDayDateTime);
                totalStatCounter.Merge(dailyStatCounter, true);
            }

            switch (type)
            {
                case TopStatsType.TopDomains:
                    return totalStatCounter.GetTopDomains(limit);

                case TopStatsType.TopBlockedDomains:
                    return totalStatCounter.GetTopBlockedDomains(limit);

                case TopStatsType.TopClients:
                    return totalStatCounter.GetTopClients(limit);

                default:
                    throw new NotSupportedException();
            }
        }

        public List<KeyValuePair<DnsQuestionRecord, long>> GetLastHourEligibleQueries(int minimumHitsPerHour)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            DateTime lastHourDateTime = DateTime.UtcNow.AddMinutes(-60);
            lastHourDateTime = new DateTime(lastHourDateTime.Year, lastHourDateTime.Month, lastHourDateTime.Day, lastHourDateTime.Hour, lastHourDateTime.Minute, 0, DateTimeKind.Utc);

            for (int minute = 0; minute < 60; minute++)
            {
                DateTime lastDateTime = lastHourDateTime.AddMinutes(minute);

                StatCounter statCounter = _lastHourStatCountersCopy[lastDateTime.Minute];
                if ((statCounter != null) && statCounter.IsLocked)
                    totalStatCounter.Merge(statCounter);
            }

            return totalStatCounter.GetEligibleQueries(minimumHitsPerHour);
        }

        public void GetLatestClientSubnetStats(int minutes, int ipv4PrefixLength, int ipv6PrefixLength, out IReadOnlyDictionary<IPAddress, long> clientSubnetStats, out IReadOnlyDictionary<IPAddress, long> errorClientSubnetStats)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            DateTime lastHourDateTime = DateTime.UtcNow.AddMinutes(1 - minutes);
            lastHourDateTime = new DateTime(lastHourDateTime.Year, lastHourDateTime.Month, lastHourDateTime.Day, lastHourDateTime.Hour, lastHourDateTime.Minute, 0, DateTimeKind.Utc);

            for (int minute = 0; minute < minutes; minute++)
            {
                DateTime lastDateTime = lastHourDateTime.AddMinutes(minute);

                StatCounter statCounter = _lastHourStatCounters[lastDateTime.Minute];
                if (statCounter is not null)
                    totalStatCounter.Merge(statCounter, false, true);
            }

            clientSubnetStats = totalStatCounter.GetClientSubnetStats(ipv4PrefixLength, ipv6PrefixLength);
            errorClientSubnetStats = totalStatCounter.GetErrorClientSubnetStats(ipv4PrefixLength, ipv6PrefixLength);
        }

        #endregion

        #region properties

        public bool EnableInMemoryStats
        {
            get { return _enableInMemoryStats; }
            set
            {
                if (_enableInMemoryStats != value)
                {
                    _enableInMemoryStats = value;

                    if (_enableInMemoryStats)
                    {
                        _hourlyStatsCache.Clear();
                        _dailyStatsCache.Clear();
                    }
                }
            }
        }

        public int MaxStatFileDays
        {
            get { return _maxStatFileDays; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(MaxStatFileDays), "MaxStatFileDays must be greater than or equal to 0.");

                _maxStatFileDays = value;

                if (_maxStatFileDays == 0)
                    _statsCleanupTimer.Change(Timeout.Infinite, Timeout.Infinite);
                else
                    _statsCleanupTimer.Change(STATS_CLEANUP_TIMER_INITIAL_INTERVAL, STATS_CLEANUP_TIMER_PERIODIC_INTERVAL);
            }
        }

        #endregion

        class HourlyStats
        {
            #region variables

            readonly StatCounter _hourStat; //calculated value
            StatCounter[] _minuteStats = new StatCounter[60];

            #endregion

            #region constructor

            public HourlyStats()
            {
                _hourStat = new StatCounter();
                _hourStat.Lock();

                for (int i = 0; i < _minuteStats.Length; i++)
                {
                    _minuteStats[i] = new StatCounter();
                    _minuteStats[i].Lock();
                }
            }

            public HourlyStats(BinaryReader bR)
            {
                if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "HS") //format
                    throw new InvalidDataException("HourlyStats format is invalid.");

                byte version = bR.ReadByte();
                switch (version)
                {
                    case 1:
                        _hourStat = new StatCounter();
                        _hourStat.Lock();

                        for (int i = 0; i < _minuteStats.Length; i++)
                        {
                            _minuteStats[i] = new StatCounter(bR);
                            _hourStat.Merge(_minuteStats[i]);
                        }

                        break;

                    default:
                        throw new InvalidDataException("HourlyStats version not supported.");
                }
            }

            #endregion

            #region public

            public void UpdateStat(DateTime dateTime, StatCounter minuteStat)
            {
                if (!minuteStat.IsLocked)
                    throw new DnsServerException("StatCounter must be locked.");

                _hourStat.Merge(minuteStat);
                _minuteStats[dateTime.Minute] = minuteStat;
            }

            public void UnloadMinuteStats()
            {
                _minuteStats = null;
            }

            public void WriteTo(BinaryWriter bW)
            {
                bW.Write(Encoding.ASCII.GetBytes("HS")); //format
                bW.Write((byte)1); //version

                for (int i = 0; i < _minuteStats.Length; i++)
                {
                    if (_minuteStats[i] == null)
                    {
                        _minuteStats[i] = new StatCounter();
                        _minuteStats[i].Lock();
                    }

                    _minuteStats[i].WriteTo(bW);
                }
            }

            #endregion

            #region properties

            public StatCounter HourStat
            { get { return _hourStat; } }

            public StatCounter[] MinuteStats
            {
                get { return _minuteStats; }
            }

            #endregion
        }

        class StatCounter
        {
            #region variables

            volatile bool _locked;

            long _totalQueries;
            long _totalNoError;
            long _totalServerFailure;
            long _totalNxDomain;
            long _totalRefused;

            long _totalAuthoritative;
            long _totalRecursive;
            long _totalCached;
            long _totalBlocked;
            long _totalDropped;

            long _totalClients;

            readonly ConcurrentDictionary<string, Counter> _queryDomains;
            readonly ConcurrentDictionary<string, Counter> _queryBlockedDomains;
            readonly ConcurrentDictionary<DnsResourceRecordType, Counter> _queryTypes;
            readonly ConcurrentDictionary<DnsTransportProtocol, Counter> _protocolTypes;
            readonly ConcurrentDictionary<IPAddress, Counter> _clientIpAddresses; //includes all queries
            readonly ConcurrentDictionary<IPAddress, Counter> _errorIpAddresses; //includes REFUSED, FORMERR and SERVFAIL
            readonly ConcurrentDictionary<DnsQuestionRecord, Counter> _queries;

            bool _truncationFoundDuringMerge;
            long _totalClientsDailyStatsSummation;

            #endregion

            #region constructor

            public StatCounter()
            {
                _queryDomains = new ConcurrentDictionary<string, Counter>();
                _queryBlockedDomains = new ConcurrentDictionary<string, Counter>();
                _queryTypes = new ConcurrentDictionary<DnsResourceRecordType, Counter>();
                _protocolTypes = new ConcurrentDictionary<DnsTransportProtocol, Counter>();
                _clientIpAddresses = new ConcurrentDictionary<IPAddress, Counter>();
                _errorIpAddresses = new ConcurrentDictionary<IPAddress, Counter>();
                _queries = new ConcurrentDictionary<DnsQuestionRecord, Counter>();
            }

            public StatCounter(BinaryReader bR)
            {
                if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "SC") //format
                    throw new InvalidDataException("StatCounter format is invalid.");

                byte version = bR.ReadByte();
                switch (version)
                {
                    case 1:
                    case 2:
                    case 3:
                    case 4:
                    case 5:
                    case 6:
                        _totalQueries = bR.ReadInt32();
                        _totalNoError = bR.ReadInt32();
                        _totalServerFailure = bR.ReadInt32();
                        _totalNxDomain = bR.ReadInt32();
                        _totalRefused = bR.ReadInt32();

                        if (version >= 3)
                        {
                            _totalAuthoritative = bR.ReadInt32();
                            _totalRecursive = bR.ReadInt32();
                            _totalCached = bR.ReadInt32();
                            _totalBlocked = bR.ReadInt32();
                        }
                        else
                        {
                            _totalBlocked = bR.ReadInt32();

                            if (version >= 2)
                                _totalCached = bR.ReadInt32();
                        }

                        if (version >= 6)
                            _totalClients = bR.ReadInt32();

                        {
                            int count = bR.ReadInt32();
                            _queryDomains = new ConcurrentDictionary<string, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryDomains.TryAdd(bR.ReadShortString(), new Counter(bR.ReadInt32()));
                        }

                        {
                            int count = bR.ReadInt32();
                            _queryBlockedDomains = new ConcurrentDictionary<string, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryBlockedDomains.TryAdd(bR.ReadShortString(), new Counter(bR.ReadInt32()));
                        }

                        {
                            int count = bR.ReadInt32();
                            _queryTypes = new ConcurrentDictionary<DnsResourceRecordType, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryTypes.TryAdd((DnsResourceRecordType)bR.ReadUInt16(), new Counter(bR.ReadInt32()));
                        }

                        _protocolTypes = new ConcurrentDictionary<DnsTransportProtocol, Counter>(1, 0);

                        {
                            int count = bR.ReadInt32();
                            _clientIpAddresses = new ConcurrentDictionary<IPAddress, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _clientIpAddresses.TryAdd(IPAddressExtensions.ReadFrom(bR), new Counter(bR.ReadInt32()));

                            if (version < 6)
                                _totalClients = count;
                        }

                        if (version >= 4)
                        {
                            int count = bR.ReadInt32();
                            _queries = new ConcurrentDictionary<DnsQuestionRecord, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queries.TryAdd(new DnsQuestionRecord(bR.BaseStream), new Counter(bR.ReadInt32()));
                        }
                        else
                        {
                            _queries = new ConcurrentDictionary<DnsQuestionRecord, Counter>(1, 0);
                        }

                        if (version >= 5)
                        {
                            int count = bR.ReadInt32();
                            _errorIpAddresses = new ConcurrentDictionary<IPAddress, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _errorIpAddresses.TryAdd(IPAddressExtensions.ReadFrom(bR), new Counter(bR.ReadInt32()));
                        }
                        else
                        {
                            _errorIpAddresses = new ConcurrentDictionary<IPAddress, Counter>(1, 0);
                        }

                        break;

                    case 7:
                    case 8:
                        _totalQueries = bR.ReadInt64();
                        _totalNoError = bR.ReadInt64();
                        _totalServerFailure = bR.ReadInt64();
                        _totalNxDomain = bR.ReadInt64();
                        _totalRefused = bR.ReadInt64();

                        _totalAuthoritative = bR.ReadInt64();
                        _totalRecursive = bR.ReadInt64();
                        _totalCached = bR.ReadInt64();
                        _totalBlocked = bR.ReadInt64();

                        if (version >= 8)
                            _totalDropped = bR.ReadInt64();

                        _totalClients = bR.ReadInt64();

                        {
                            int count = bR.ReadInt32();
                            _queryDomains = new ConcurrentDictionary<string, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryDomains.TryAdd(bR.ReadShortString(), new Counter(bR.ReadInt64()));
                        }

                        {
                            int count = bR.ReadInt32();
                            _queryBlockedDomains = new ConcurrentDictionary<string, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryBlockedDomains.TryAdd(bR.ReadShortString(), new Counter(bR.ReadInt64()));
                        }

                        {
                            int count = bR.ReadInt32();
                            _queryTypes = new ConcurrentDictionary<DnsResourceRecordType, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryTypes.TryAdd((DnsResourceRecordType)bR.ReadUInt16(), new Counter(bR.ReadInt64()));
                        }

                        if (version >= 8)
                        {
                            int count = bR.ReadInt32();
                            _protocolTypes = new ConcurrentDictionary<DnsTransportProtocol, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _protocolTypes.TryAdd((DnsTransportProtocol)bR.ReadByte(), new Counter(bR.ReadInt64()));
                        }
                        else
                        {
                            _protocolTypes = new ConcurrentDictionary<DnsTransportProtocol, Counter>(1, 0);
                        }

                        {
                            int count = bR.ReadInt32();
                            _clientIpAddresses = new ConcurrentDictionary<IPAddress, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _clientIpAddresses.TryAdd(IPAddressExtensions.ReadFrom(bR), new Counter(bR.ReadInt64()));
                        }

                        {
                            int count = bR.ReadInt32();
                            _queries = new ConcurrentDictionary<DnsQuestionRecord, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queries.TryAdd(new DnsQuestionRecord(bR.BaseStream), new Counter(bR.ReadInt64()));
                        }

                        {
                            int count = bR.ReadInt32();
                            _errorIpAddresses = new ConcurrentDictionary<IPAddress, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _errorIpAddresses.TryAdd(IPAddressExtensions.ReadFrom(bR), new Counter(bR.ReadInt64()));
                        }

                        break;

                    default:
                        throw new InvalidDataException("StatCounter version not supported.");
                }

                _locked = true;
            }

            #endregion

            #region private

            private static List<KeyValuePair<string, long>> GetTopList(List<KeyValuePair<string, long>> list, int limit)
            {
                list.Sort(delegate (KeyValuePair<string, long> item1, KeyValuePair<string, long> item2)
                {
                    return item2.Value.CompareTo(item1.Value);
                });

                if (list.Count > limit)
                    list.RemoveRange(limit, list.Count - limit);

                return list;
            }

            private static Counter GetNewCounter<T>(T key)
            {
                return new Counter();
            }

            #endregion

            #region public

            public void Lock()
            {
                _locked = true;
            }

            public void Update(DnsQuestionRecord query, DnsResponseCode responseCode, DnsServerResponseType responseType, IPAddress clientIpAddress, DnsTransportProtocol protocol, bool rateLimited)
            {
                if (_locked)
                    return;

                if (clientIpAddress.IsIPv4MappedToIPv6)
                    clientIpAddress = clientIpAddress.MapToIPv4();

                _totalQueries++;

                if (responseType == DnsServerResponseType.Dropped)
                {
                    _totalDropped++;

                    if (rateLimited)
                    {
                        _clientIpAddresses.GetOrAdd(clientIpAddress, GetNewCounter).Increment();
                        _totalClients = _clientIpAddresses.Count;
                    }
                }
                else
                {
                    switch (responseCode)
                    {
                        case DnsResponseCode.NoError:
                            if (query is not null)
                            {
                                switch (responseType)
                                {
                                    case DnsServerResponseType.Blocked:
                                    case DnsServerResponseType.UpstreamBlocked:
                                    case DnsServerResponseType.CacheBlocked:
                                        //skip blocked domains
                                        break;

                                    default:
                                        _queryDomains.GetOrAdd(query.Name.ToLowerInvariant(), GetNewCounter).Increment();
                                        _queries.GetOrAdd(query, GetNewCounter).Increment();
                                        break;
                                }
                            }

                            _totalNoError++;
                            break;

                        case DnsResponseCode.ServerFailure:
                            _errorIpAddresses.GetOrAdd(clientIpAddress, GetNewCounter).Increment();
                            _totalServerFailure++;
                            break;

                        case DnsResponseCode.NxDomain:
                            _totalNxDomain++;
                            break;

                        case DnsResponseCode.Refused:
                            _errorIpAddresses.GetOrAdd(clientIpAddress, GetNewCounter).Increment();
                            _totalRefused++;
                            break;

                        case DnsResponseCode.FormatError:
                            _errorIpAddresses.GetOrAdd(clientIpAddress, GetNewCounter).Increment();
                            break;
                    }

                    switch (responseType)
                    {
                        case DnsServerResponseType.Authoritative:
                            _totalAuthoritative++;
                            break;

                        case DnsServerResponseType.Recursive:
                            _totalRecursive++;
                            break;

                        case DnsServerResponseType.Cached:
                            _totalCached++;
                            break;

                        case DnsServerResponseType.Blocked:
                            if (query is not null)
                                _queryBlockedDomains.GetOrAdd(query.Name.ToLowerInvariant(), GetNewCounter).Increment();

                            _totalBlocked++;
                            break;

                        case DnsServerResponseType.UpstreamBlocked:
                            _totalRecursive++;

                            if (query is not null)
                                _queryBlockedDomains.GetOrAdd(query.Name.ToLowerInvariant(), GetNewCounter).Increment();

                            _totalBlocked++;
                            break;

                        case DnsServerResponseType.CacheBlocked:
                            _totalCached++;

                            if (query is not null)
                                _queryBlockedDomains.GetOrAdd(query.Name.ToLowerInvariant(), GetNewCounter).Increment();

                            _totalBlocked++;
                            break;
                    }

                    if (query is not null)
                        _queryTypes.GetOrAdd(query.Type, GetNewCounter).Increment();

                    _clientIpAddresses.GetOrAdd(clientIpAddress, GetNewCounter).Increment();
                    _totalClients = _clientIpAddresses.Count;
                }

                _protocolTypes.GetOrAdd(protocol, GetNewCounter).Increment();
            }

            public void Merge(StatCounter statCounter, bool isDailyStatCounter = false, bool skipLock = false)
            {
                if (!skipLock && (!_locked || !statCounter._locked))
                    throw new DnsServerException("StatCounter must be locked.");

                _totalQueries += statCounter._totalQueries;
                _totalNoError += statCounter._totalNoError;
                _totalServerFailure += statCounter._totalServerFailure;
                _totalNxDomain += statCounter._totalNxDomain;
                _totalRefused += statCounter._totalRefused;

                _totalAuthoritative += statCounter._totalAuthoritative;
                _totalRecursive += statCounter._totalRecursive;
                _totalCached += statCounter._totalCached;
                _totalBlocked += statCounter._totalBlocked;
                _totalDropped += statCounter._totalDropped;

                foreach (KeyValuePair<string, Counter> queryDomain in statCounter._queryDomains)
                    _queryDomains.GetOrAdd(queryDomain.Key, GetNewCounter).Merge(queryDomain.Value);

                foreach (KeyValuePair<string, Counter> queryBlockedDomain in statCounter._queryBlockedDomains)
                    _queryBlockedDomains.GetOrAdd(queryBlockedDomain.Key, GetNewCounter).Merge(queryBlockedDomain.Value);

                foreach (KeyValuePair<DnsResourceRecordType, Counter> queryType in statCounter._queryTypes)
                    _queryTypes.GetOrAdd(queryType.Key, GetNewCounter).Merge(queryType.Value);

                foreach (KeyValuePair<DnsTransportProtocol, Counter> protocolType in statCounter._protocolTypes)
                    _protocolTypes.GetOrAdd(protocolType.Key, GetNewCounter).Merge(protocolType.Value);

                foreach (KeyValuePair<IPAddress, Counter> clientIpAddress in statCounter._clientIpAddresses)
                    _clientIpAddresses.GetOrAdd(clientIpAddress.Key, GetNewCounter).Merge(clientIpAddress.Value);

                foreach (KeyValuePair<IPAddress, Counter> refusedIpAddress in statCounter._errorIpAddresses)
                    _errorIpAddresses.GetOrAdd(refusedIpAddress.Key, GetNewCounter).Merge(refusedIpAddress.Value);

                foreach (KeyValuePair<DnsQuestionRecord, Counter> query in statCounter._queries)
                    _queries.GetOrAdd(query.Key, GetNewCounter).Merge(query.Value);

                _totalClients = _clientIpAddresses.Count;
                _totalClientsDailyStatsSummation += statCounter._totalClients;

                if (isDailyStatCounter && (statCounter._totalClients > statCounter._clientIpAddresses.Count))
                    _truncationFoundDuringMerge = true;
            }

            public bool Truncate(int limit)
            {
                bool truncated = false;

                if (_queryDomains.Count > limit)
                {
                    List<KeyValuePair<string, Counter>> topDomains = new List<KeyValuePair<string, Counter>>(_queryDomains);

                    _queryDomains.Clear();

                    topDomains.Sort(delegate (KeyValuePair<string, Counter> item1, KeyValuePair<string, Counter> item2)
                    {
                        return item2.Value.Count.CompareTo(item1.Value.Count);
                    });

                    if (topDomains.Count > limit)
                        topDomains.RemoveRange(limit, topDomains.Count - limit);

                    foreach (KeyValuePair<string, Counter> item in topDomains)
                        _queryDomains[item.Key] = item.Value;

                    truncated = true;
                }

                if (_queryBlockedDomains.Count > limit)
                {
                    List<KeyValuePair<string, Counter>> topBlockedDomains = new List<KeyValuePair<string, Counter>>(_queryBlockedDomains);

                    _queryBlockedDomains.Clear();

                    topBlockedDomains.Sort(delegate (KeyValuePair<string, Counter> item1, KeyValuePair<string, Counter> item2)
                    {
                        return item2.Value.Count.CompareTo(item1.Value.Count);
                    });

                    if (topBlockedDomains.Count > limit)
                        topBlockedDomains.RemoveRange(limit, topBlockedDomains.Count - limit);

                    foreach (KeyValuePair<string, Counter> item in topBlockedDomains)
                        _queryBlockedDomains[item.Key] = item.Value;

                    truncated = true;
                }

                if (_queryTypes.Count > limit)
                {
                    List<KeyValuePair<DnsResourceRecordType, Counter>> queryTypes = new List<KeyValuePair<DnsResourceRecordType, Counter>>(_queryTypes);

                    _queryTypes.Clear();

                    queryTypes.Sort(delegate (KeyValuePair<DnsResourceRecordType, Counter> item1, KeyValuePair<DnsResourceRecordType, Counter> item2)
                    {
                        return item2.Value.Count.CompareTo(item1.Value.Count);
                    });

                    if (queryTypes.Count > limit)
                    {
                        long othersCount = 0;

                        for (int i = limit; i < queryTypes.Count; i++)
                            othersCount += queryTypes[i].Value.Count;

                        queryTypes.RemoveRange(limit - 1, queryTypes.Count - (limit - 1));
                        queryTypes.Add(new KeyValuePair<DnsResourceRecordType, Counter>(DnsResourceRecordType.Unknown, new Counter(othersCount)));
                    }

                    foreach (KeyValuePair<DnsResourceRecordType, Counter> item in queryTypes)
                        _queryTypes[item.Key] = item.Value;

                    truncated = true;
                }

                if (_clientIpAddresses.Count > limit)
                {
                    List<KeyValuePair<IPAddress, Counter>> topClients = new List<KeyValuePair<IPAddress, Counter>>(_clientIpAddresses);

                    _clientIpAddresses.Clear();

                    topClients.Sort(delegate (KeyValuePair<IPAddress, Counter> item1, KeyValuePair<IPAddress, Counter> item2)
                    {
                        return item2.Value.Count.CompareTo(item1.Value.Count);
                    });

                    if (topClients.Count > limit)
                        topClients.RemoveRange(limit, topClients.Count - limit);

                    foreach (KeyValuePair<IPAddress, Counter> item in topClients)
                        _clientIpAddresses[item.Key] = item.Value;

                    truncated = true;
                }

                if (_errorIpAddresses.Count > limit)
                {
                    List<KeyValuePair<IPAddress, Counter>> topErrorClients = new List<KeyValuePair<IPAddress, Counter>>(_errorIpAddresses);

                    _errorIpAddresses.Clear();

                    topErrorClients.Sort(delegate (KeyValuePair<IPAddress, Counter> item1, KeyValuePair<IPAddress, Counter> item2)
                    {
                        return item2.Value.Count.CompareTo(item1.Value.Count);
                    });

                    if (topErrorClients.Count > limit)
                        topErrorClients.RemoveRange(limit, topErrorClients.Count - limit);

                    foreach (KeyValuePair<IPAddress, Counter> item in topErrorClients)
                        _errorIpAddresses[item.Key] = item.Value;

                    truncated = true;
                }

                if (_queries.Count > limit)
                {
                    //only last hour queries data is required for cache auto prefetching
                    _queries.Clear();

                    truncated = true;
                }

                return truncated;
            }

            public void WriteTo(BinaryWriter bW)
            {
                if (!_locked)
                    throw new DnsServerException("StatCounter must be locked.");

                bW.Write(Encoding.ASCII.GetBytes("SC")); //format
                bW.Write((byte)8); //version

                bW.Write(_totalQueries);
                bW.Write(_totalNoError);
                bW.Write(_totalServerFailure);
                bW.Write(_totalNxDomain);
                bW.Write(_totalRefused);

                bW.Write(_totalAuthoritative);
                bW.Write(_totalRecursive);
                bW.Write(_totalCached);
                bW.Write(_totalBlocked);
                bW.Write(_totalDropped);

                bW.Write(_totalClients);

                {
                    bW.Write(_queryDomains.Count);
                    foreach (KeyValuePair<string, Counter> queryDomain in _queryDomains)
                    {
                        bW.WriteShortString(queryDomain.Key);
                        bW.Write(queryDomain.Value.Count);
                    }
                }

                {
                    bW.Write(_queryBlockedDomains.Count);
                    foreach (KeyValuePair<string, Counter> queryBlockedDomain in _queryBlockedDomains)
                    {
                        bW.WriteShortString(queryBlockedDomain.Key);
                        bW.Write(queryBlockedDomain.Value.Count);
                    }
                }

                {
                    bW.Write(_queryTypes.Count);
                    foreach (KeyValuePair<DnsResourceRecordType, Counter> queryType in _queryTypes)
                    {
                        bW.Write((ushort)queryType.Key);
                        bW.Write(queryType.Value.Count);
                    }
                }

                {
                    bW.Write(_protocolTypes.Count);
                    foreach (KeyValuePair<DnsTransportProtocol, Counter> protocolType in _protocolTypes)
                    {
                        bW.Write((byte)protocolType.Key);
                        bW.Write(protocolType.Value.Count);
                    }
                }

                {
                    bW.Write(_clientIpAddresses.Count);
                    foreach (KeyValuePair<IPAddress, Counter> clientIpAddress in _clientIpAddresses)
                    {
                        clientIpAddress.Key.WriteTo(bW);
                        bW.Write(clientIpAddress.Value.Count);
                    }
                }

                {
                    bW.Write(_queries.Count);
                    foreach (KeyValuePair<DnsQuestionRecord, Counter> query in _queries)
                    {
                        query.Key.WriteTo(bW.BaseStream, null);
                        bW.Write(query.Value.Count);
                    }
                }

                {
                    bW.Write(_errorIpAddresses.Count);
                    foreach (KeyValuePair<IPAddress, Counter> refusedIpAddress in _errorIpAddresses)
                    {
                        refusedIpAddress.Key.WriteTo(bW);
                        bW.Write(refusedIpAddress.Value.Count);
                    }
                }
            }

            public List<KeyValuePair<string, long>> GetTopDomains(int limit)
            {
                List<KeyValuePair<string, long>> topDomains = new List<KeyValuePair<string, long>>(_queryDomains.Count);

                foreach (KeyValuePair<string, Counter> item in _queryDomains)
                    topDomains.Add(new KeyValuePair<string, long>(item.Key, item.Value.Count));

                return GetTopList(topDomains, limit);
            }

            public List<KeyValuePair<string, long>> GetTopBlockedDomains(int limit)
            {
                List<KeyValuePair<string, long>> topBlockedDomains = new List<KeyValuePair<string, long>>(_queryBlockedDomains.Count);

                foreach (KeyValuePair<string, Counter> item in _queryBlockedDomains)
                    topBlockedDomains.Add(new KeyValuePair<string, long>(item.Key, item.Value.Count));

                return GetTopList(topBlockedDomains, limit);
            }

            public List<KeyValuePair<string, long>> GetTopClients(int limit)
            {
                List<KeyValuePair<string, long>> topClients = new List<KeyValuePair<string, long>>(_clientIpAddresses.Count);

                foreach (KeyValuePair<IPAddress, Counter> item in _clientIpAddresses)
                    topClients.Add(new KeyValuePair<string, long>(item.Key.ToString(), item.Value.Count));

                return GetTopList(topClients, limit);
            }

            public List<KeyValuePair<string, long>> GetTopQueryTypes(int limit)
            {
                List<KeyValuePair<string, long>> queryTypes = new List<KeyValuePair<string, long>>(_queryTypes.Count);

                foreach (KeyValuePair<DnsResourceRecordType, Counter> item in _queryTypes)
                    queryTypes.Add(new KeyValuePair<string, long>(item.Key.ToString(), item.Value.Count));

                queryTypes.Sort(delegate (KeyValuePair<string, long> item1, KeyValuePair<string, long> item2)
                {
                    return item2.Value.CompareTo(item1.Value);
                });

                if (queryTypes.Count > limit)
                {
                    long othersCount = 0;

                    for (int i = limit; i < queryTypes.Count; i++)
                        othersCount += queryTypes[i].Value;

                    queryTypes.RemoveRange((limit - 1), queryTypes.Count - (limit - 1));
                    queryTypes.Add(new KeyValuePair<string, long>("Others", othersCount));
                }

                return queryTypes;
            }

            public List<KeyValuePair<string, long>> GetTopProtocolTypes()
            {
                List<KeyValuePair<string, long>> protocolTypes = new List<KeyValuePair<string, long>>(_protocolTypes.Count);

                foreach (KeyValuePair<DnsTransportProtocol, Counter> protocolType in _protocolTypes)
                    protocolTypes.Add(new KeyValuePair<string, long>(protocolType.Key.ToString(), protocolType.Value.Count));

                protocolTypes.Sort(delegate (KeyValuePair<string, long> item1, KeyValuePair<string, long> item2)
                {
                    return item2.Value.CompareTo(item1.Value);
                });

                return protocolTypes;
            }

            public List<KeyValuePair<DnsQuestionRecord, long>> GetEligibleQueries(int minimumHits)
            {
                List<KeyValuePair<DnsQuestionRecord, long>> eligibleQueries = new List<KeyValuePair<DnsQuestionRecord, long>>(Convert.ToInt32(_queries.Count * 0.1));

                foreach (KeyValuePair<DnsQuestionRecord, Counter> item in _queries)
                {
                    if (item.Value.Count >= minimumHits)
                        eligibleQueries.Add(new KeyValuePair<DnsQuestionRecord, long>(item.Key, item.Value.Count));
                }

                return eligibleQueries;
            }

            public Dictionary<IPAddress, long> GetClientSubnetStats(int ipv4PrefixLength, int ipv6PrefixLength)
            {
                Dictionary<IPAddress, long> clientSubnetStats = new Dictionary<IPAddress, long>(_clientIpAddresses.Count);

                foreach (KeyValuePair<IPAddress, Counter> item in _clientIpAddresses)
                {
                    IPAddress clientSubnet;

                    switch (item.Key.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            clientSubnet = item.Key.GetNetworkAddress(ipv4PrefixLength);
                            break;

                        case AddressFamily.InterNetworkV6:
                            clientSubnet = item.Key.GetNetworkAddress(ipv6PrefixLength);
                            break;

                        default:
                            throw new NotSupportedException("AddressFamily not supported.");
                    }

                    if (clientSubnetStats.TryGetValue(clientSubnet, out long existingValue))
                        clientSubnetStats[clientSubnet] = existingValue + item.Value.Count;
                    else
                        clientSubnetStats.Add(clientSubnet, item.Value.Count);
                }

                return clientSubnetStats;
            }

            public Dictionary<IPAddress, long> GetErrorClientSubnetStats(int ipv4PrefixLength, int ipv6PrefixLength)
            {
                Dictionary<IPAddress, long> errorClientSubnetStats = new Dictionary<IPAddress, long>(_errorIpAddresses.Count);

                foreach (KeyValuePair<IPAddress, Counter> item in _errorIpAddresses)
                {
                    IPAddress clientSubnet;

                    switch (item.Key.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            clientSubnet = item.Key.GetNetworkAddress(ipv4PrefixLength);
                            break;

                        case AddressFamily.InterNetworkV6:
                            clientSubnet = item.Key.GetNetworkAddress(ipv6PrefixLength);
                            break;

                        default:
                            throw new NotSupportedException("AddressFamily not supported.");
                    }

                    if (errorClientSubnetStats.TryGetValue(clientSubnet, out long existingValue))
                        errorClientSubnetStats[clientSubnet] = existingValue + item.Value.Count;
                    else
                        errorClientSubnetStats.Add(clientSubnet, item.Value.Count);
                }

                return errorClientSubnetStats;
            }

            #endregion

            #region properties

            public bool IsLocked
            { get { return _locked; } }

            public long TotalQueries
            { get { return _totalQueries; } }

            public long TotalNoError
            { get { return _totalNoError; } }

            public long TotalServerFailure
            { get { return _totalServerFailure; } }

            public long TotalNxDomain
            { get { return _totalNxDomain; } }

            public long TotalRefused
            { get { return _totalRefused; } }

            public long TotalAuthoritative
            { get { return _totalAuthoritative; } }

            public long TotalRecursive
            { get { return _totalRecursive; } }

            public long TotalCached
            { get { return _totalCached; } }

            public long TotalBlocked
            { get { return _totalBlocked; } }

            public long TotalDropped
            { get { return _totalDropped; } }

            public long TotalClients
            {
                get
                {
                    if (_truncationFoundDuringMerge)
                        return _totalClientsDailyStatsSummation;

                    return _totalClients;
                }
            }

            #endregion

            class Counter
            {
                #region variables

                long _count;

                #endregion

                #region constructor

                public Counter()
                { }

                public Counter(long count)
                {
                    _count = count;
                }

                #endregion

                #region public

                public void Increment()
                {
                    _count++;
                }

                public void Merge(Counter counter)
                {
                    _count += counter._count;
                }

                #endregion

                #region properties

                public long Count
                { get { return _count; } }

                #endregion
            }
        }

        class StatsQueueItem
        {
            #region variables

            public readonly DateTime _timestamp;

            public readonly DnsDatagram _request;
            public readonly IPEndPoint _remoteEP;
            public readonly DnsTransportProtocol _protocol;
            public readonly DnsDatagram _response;
            public readonly bool _rateLimited;

            #endregion

            #region constructor

            public StatsQueueItem(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response, bool rateLimited)
            {
                _timestamp = DateTime.UtcNow;

                _request = request;
                _remoteEP = remoteEP;
                _protocol = protocol;
                _response = response;
                _rateLimited = rateLimited;
            }

            #endregion
        }
    }
}
