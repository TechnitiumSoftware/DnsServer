/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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

        readonly DnsServer _dnsServer;
        readonly string _statsFolder;

        readonly StatCounter[] _lastHourStatCounters = new StatCounter[60];
        readonly StatCounter[] _lastHourStatCountersCopy = new StatCounter[60];
        readonly ConcurrentDictionary<DateTime, HourlyStats> _hourlyStatsCache = new ConcurrentDictionary<DateTime, HourlyStats>();
        readonly ConcurrentDictionary<DateTime, StatCounter> _dailyStatsCache = new ConcurrentDictionary<DateTime, StatCounter>();

        readonly Timer _maintenanceTimer;
        const int MAINTENANCE_TIMER_INITIAL_INTERVAL = 10000;
        const int MAINTENANCE_TIMER_INTERVAL = 10000;

        readonly BlockingCollection<StatsQueueItem> _queue = new BlockingCollection<StatsQueueItem>();
        readonly Thread _consumerThread;

        readonly Timer _statsCleanupTimer;
        int _maxStatFileDays = 0;
        const int STATS_CLEANUP_TIMER_INITIAL_INTERVAL = 60 * 1000;
        const int STATS_CLEANUP_TIMER_PERIODIC_INTERVAL = 60 * 60 * 1000;

        #endregion

        #region constructor

        public StatsManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;
            _statsFolder = Path.Combine(dnsServer.ConfigFolder, "stats");

            if (!Directory.Exists(_statsFolder))
                Directory.CreateDirectory(_statsFolder);

            //load stats
            LoadLastHourStats();

            //do first maintenance
            DoMaintenance();

            //start periodic maintenance timer
            _maintenanceTimer = new Timer(delegate (object state)
            {
                try
                {
                    DoMaintenance();
                }
                catch (Exception ex)
                {
                    LogManager log = dnsServer.LogManager;
                    if (log != null)
                        log.Write(ex);
                }
            }, null, MAINTENANCE_TIMER_INITIAL_INTERVAL, MAINTENANCE_TIMER_INTERVAL);

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

                            if (item._request.Question.Count > 0)
                                query = item._request.Question[0];
                            else
                                query = null;

                            DnsServerResponseType responseType;

                            if (item._response.Tag == null)
                                responseType = DnsServerResponseType.Recursive;
                            else
                                responseType = (DnsServerResponseType)item._response.Tag;

                            statCounter.Update(query, item._response.RCODE, responseType, item._remoteEP.Address);
                        }

                        foreach (IDnsQueryLogger logger in _dnsServer.DnsApplicationManager.DnsQueryLoggers)
                        {
                            try
                            {
                                _ = logger.InsertLogAsync(item._timestamp, item._request, item._remoteEP, item._protocol, item._response);
                            }
                            catch (Exception ex)
                            {
                                LogManager log = dnsServer.LogManager;
                                if (log != null)
                                    log.Write(ex);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogManager log = dnsServer.LogManager;
                    if (log != null)
                        log.Write(ex);
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
                    LogManager log = dnsServer.LogManager;
                    if (log != null)
                        log.Write(ex);
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
                    if (_maintenanceTimer != null)
                        _maintenanceTimer.Dispose();

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
                    //load hourly stats data
                    HourlyStats hourlyStats = LoadHourlyStats(lastDateTime);

                    //update hourly stats file
                    lastStatCounter.Lock();
                    hourlyStats.UpdateStat(lastDateTime, lastStatCounter);

                    //save hourly stats
                    SaveHourlyStats(lastDateTime, hourlyStats);

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

        private HourlyStats LoadHourlyStats(DateTime dateTime)
        {
            DateTime hourlyDateTime = new DateTime(dateTime.Year, dateTime.Month, dateTime.Day, dateTime.Hour, 0, 0, 0, DateTimeKind.Utc);

            if (!_hourlyStatsCache.TryGetValue(hourlyDateTime, out HourlyStats hourlyStats))
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
                        LogManager log = _dnsServer.LogManager;
                        if (log != null)
                            log.Write(ex);

                        hourlyStats = new HourlyStats();
                    }
                }
                else
                {
                    hourlyStats = new HourlyStats();
                }

                if (!_hourlyStatsCache.TryAdd(hourlyDateTime, hourlyStats))
                {
                    if (!_hourlyStatsCache.TryGetValue(hourlyDateTime, out hourlyStats))
                        throw new DnsServerException("Unable to load hourly stats.");
                }
            }

            return hourlyStats;
        }

        private StatCounter LoadDailyStats(DateTime dateTime)
        {
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
                        HourlyStats hourlyStats = LoadHourlyStats(dailyDateTime.AddHours(hour));
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

        public void QueueUpdate(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            _queue.Add(new StatsQueueItem(request, remoteEP, protocol, response));
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetLastHourMinuteWiseStats()
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, int>> totalQueriesPerInterval = new List<KeyValuePair<string, int>>(60);
            List<KeyValuePair<string, int>> totalNoErrorPerInterval = new List<KeyValuePair<string, int>>(60);
            List<KeyValuePair<string, int>> totalServerFailurePerInterval = new List<KeyValuePair<string, int>>(60);
            List<KeyValuePair<string, int>> totalNxDomainPerInterval = new List<KeyValuePair<string, int>>(60);
            List<KeyValuePair<string, int>> totalRefusedPerInterval = new List<KeyValuePair<string, int>>(60);

            List<KeyValuePair<string, int>> totalAuthHitPerInterval = new List<KeyValuePair<string, int>>(60);
            List<KeyValuePair<string, int>> totalRecursionsPerInterval = new List<KeyValuePair<string, int>>(60);
            List<KeyValuePair<string, int>> totalCacheHitPerInterval = new List<KeyValuePair<string, int>>(60);
            List<KeyValuePair<string, int>> totalBlockedPerInterval = new List<KeyValuePair<string, int>>(60);

            List<KeyValuePair<string, int>> totalClientsPerInterval = new List<KeyValuePair<string, int>>(60);

            DateTime lastHourDateTime = DateTime.UtcNow.AddMinutes(-60);
            lastHourDateTime = new DateTime(lastHourDateTime.Year, lastHourDateTime.Month, lastHourDateTime.Day, lastHourDateTime.Hour, lastHourDateTime.Minute, 0, DateTimeKind.Utc);

            for (int minute = 0; minute < 60; minute++)
            {
                DateTime lastDateTime = lastHourDateTime.AddMinutes(minute);
                string label = lastDateTime.ToLocalTime().ToString("HH:mm");

                StatCounter statCounter = _lastHourStatCountersCopy[lastDateTime.Minute];
                if ((statCounter != null) && statCounter.IsLocked)
                {
                    totalStatCounter.Merge(statCounter);

                    totalQueriesPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalQueries));
                    totalNoErrorPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalNoError));
                    totalServerFailurePerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalServerFailure));
                    totalNxDomainPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalNxDomain));
                    totalRefusedPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalRefused));

                    totalAuthHitPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalAuthoritative));
                    totalRecursionsPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalRecursive));
                    totalCacheHitPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalCached));
                    totalBlockedPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalBlocked));

                    totalClientsPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalClients));
                }
                else
                {
                    totalQueriesPerInterval.Add(new KeyValuePair<string, int>(label, 0));
                    totalNoErrorPerInterval.Add(new KeyValuePair<string, int>(label, 0));
                    totalServerFailurePerInterval.Add(new KeyValuePair<string, int>(label, 0));
                    totalNxDomainPerInterval.Add(new KeyValuePair<string, int>(label, 0));
                    totalRefusedPerInterval.Add(new KeyValuePair<string, int>(label, 0));

                    totalAuthHitPerInterval.Add(new KeyValuePair<string, int>(label, 0));
                    totalRecursionsPerInterval.Add(new KeyValuePair<string, int>(label, 0));
                    totalCacheHitPerInterval.Add(new KeyValuePair<string, int>(label, 0));
                    totalBlockedPerInterval.Add(new KeyValuePair<string, int>(label, 0));

                    totalClientsPerInterval.Add(new KeyValuePair<string, int>(label, 0));
                }
            }

            Dictionary<string, List<KeyValuePair<string, int>>> data = new Dictionary<string, List<KeyValuePair<string, int>>>();

            {
                List<KeyValuePair<string, int>> stats = new List<KeyValuePair<string, int>>(10);

                stats.Add(new KeyValuePair<string, int>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, int>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, int>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, int>("totalNxDomain", totalStatCounter.TotalNxDomain));
                stats.Add(new KeyValuePair<string, int>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, int>("totalAuthoritative", totalStatCounter.TotalAuthoritative));
                stats.Add(new KeyValuePair<string, int>("totalRecursive", totalStatCounter.TotalRecursive));
                stats.Add(new KeyValuePair<string, int>("totalCached", totalStatCounter.TotalCached));
                stats.Add(new KeyValuePair<string, int>("totalBlocked", totalStatCounter.TotalBlocked));

                stats.Add(new KeyValuePair<string, int>("totalClients", totalStatCounter.TotalClients));

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

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(10));

            return data;
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetLastDayHourWiseStats()
        {
            return GetHourWiseStats(DateTime.UtcNow.AddHours(-24), 24);
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetLastWeekDayWiseStats()
        {
            return GetDayWiseStats(DateTime.UtcNow.AddDays(-7).Date, 7);
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetLastMonthDayWiseStats()
        {
            return GetDayWiseStats(DateTime.UtcNow.AddDays(-31).Date, 31);
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetLastYearMonthWiseStats()
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, int>> totalQueriesPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNoErrorPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalServerFailurePerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNxDomainPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRefusedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalAuthHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRecursionsPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalCacheHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalBlockedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalClientsPerInterval = new List<KeyValuePair<string, int>>();

            DateTime lastYearDateTime = DateTime.UtcNow.AddMonths(-12);
            lastYearDateTime = new DateTime(lastYearDateTime.Year, lastYearDateTime.Month, 1, 0, 0, 0, DateTimeKind.Utc);

            for (int month = 0; month < 12; month++) //months
            {
                StatCounter monthlyStatCounter = new StatCounter();
                monthlyStatCounter.Lock();

                DateTime lastMonthDateTime = lastYearDateTime.AddMonths(month);
                string label = lastMonthDateTime.ToLocalTime().ToString("MM/yyyy");

                int days = DateTime.DaysInMonth(lastMonthDateTime.Year, lastMonthDateTime.Month);

                for (int day = 0; day < days; day++) //days
                {
                    StatCounter dailyStatCounter = LoadDailyStats(lastMonthDateTime.AddDays(day));
                    monthlyStatCounter.Merge(dailyStatCounter, true);
                }

                totalStatCounter.Merge(monthlyStatCounter, true);

                totalQueriesPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalQueries));
                totalNoErrorPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalNoError));
                totalServerFailurePerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalServerFailure));
                totalNxDomainPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalNxDomain));
                totalRefusedPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalRefused));

                totalAuthHitPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalAuthoritative));
                totalRecursionsPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalRecursive));
                totalCacheHitPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalCached));
                totalBlockedPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalBlocked));

                totalClientsPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalClients));
            }

            Dictionary<string, List<KeyValuePair<string, int>>> data = new Dictionary<string, List<KeyValuePair<string, int>>>();

            {
                List<KeyValuePair<string, int>> stats = new List<KeyValuePair<string, int>>(6);

                stats.Add(new KeyValuePair<string, int>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, int>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, int>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, int>("totalNxDomain", totalStatCounter.TotalNxDomain));
                stats.Add(new KeyValuePair<string, int>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, int>("totalAuthoritative", totalStatCounter.TotalAuthoritative));
                stats.Add(new KeyValuePair<string, int>("totalRecursive", totalStatCounter.TotalRecursive));
                stats.Add(new KeyValuePair<string, int>("totalCached", totalStatCounter.TotalCached));
                stats.Add(new KeyValuePair<string, int>("totalBlocked", totalStatCounter.TotalBlocked));

                stats.Add(new KeyValuePair<string, int>("totalClients", totalStatCounter.TotalClients));

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

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(10));

            return data;
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetHourWiseStats(DateTime startDate, DateTime endDate)
        {
            int hours = Convert.ToInt32((endDate - startDate).TotalHours) + 1;
            if (hours < 24)
                hours = 24;

            return GetHourWiseStats(startDate, hours);
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetHourWiseStats(DateTime startDate, int hours)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, int>> totalQueriesPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNoErrorPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalServerFailurePerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNxDomainPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRefusedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalAuthHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRecursionsPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalCacheHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalBlockedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalClientsPerInterval = new List<KeyValuePair<string, int>>();

            for (int hour = 0; hour < hours; hour++)
            {
                DateTime lastDateTime = startDate.AddHours(hour);
                string label = lastDateTime.ToLocalTime().ToString("MM/dd HH") + ":00";

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime);
                StatCounter hourlyStatCounter = hourlyStats.HourStat;

                totalStatCounter.Merge(hourlyStatCounter);

                totalQueriesPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalQueries));
                totalNoErrorPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalNoError));
                totalServerFailurePerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalServerFailure));
                totalNxDomainPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalNxDomain));
                totalRefusedPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalRefused));

                totalAuthHitPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalAuthoritative));
                totalRecursionsPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalRecursive));
                totalCacheHitPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalCached));
                totalBlockedPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalBlocked));

                totalClientsPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalClients));
            }

            Dictionary<string, List<KeyValuePair<string, int>>> data = new Dictionary<string, List<KeyValuePair<string, int>>>();

            {
                List<KeyValuePair<string, int>> stats = new List<KeyValuePair<string, int>>(6);

                stats.Add(new KeyValuePair<string, int>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, int>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, int>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, int>("totalNxDomain", totalStatCounter.TotalNxDomain));
                stats.Add(new KeyValuePair<string, int>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, int>("totalAuthoritative", totalStatCounter.TotalAuthoritative));
                stats.Add(new KeyValuePair<string, int>("totalRecursive", totalStatCounter.TotalRecursive));
                stats.Add(new KeyValuePair<string, int>("totalCached", totalStatCounter.TotalCached));
                stats.Add(new KeyValuePair<string, int>("totalBlocked", totalStatCounter.TotalBlocked));

                stats.Add(new KeyValuePair<string, int>("totalClients", totalStatCounter.TotalClients));

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

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(10));

            return data;
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetDayWiseStats(DateTime startDate, DateTime endDate)
        {
            return GetDayWiseStats(startDate, Convert.ToInt32((endDate - startDate).TotalDays) + 1);
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetDayWiseStats(DateTime startDate, int days)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, int>> totalQueriesPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNoErrorPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalServerFailurePerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNxDomainPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRefusedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalAuthHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRecursionsPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalCacheHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalBlockedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalClientsPerInterval = new List<KeyValuePair<string, int>>();

            for (int day = 0; day < days; day++) //days
            {
                DateTime lastDayDateTime = startDate.AddDays(day);
                string label = lastDayDateTime.ToLocalTime().ToString("MM/dd");

                StatCounter dailyStatCounter = LoadDailyStats(lastDayDateTime);
                totalStatCounter.Merge(dailyStatCounter, true);

                totalQueriesPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalQueries));
                totalNoErrorPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalNoError));
                totalServerFailurePerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalServerFailure));
                totalNxDomainPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalNxDomain));
                totalRefusedPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalRefused));

                totalAuthHitPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalAuthoritative));
                totalRecursionsPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalRecursive));
                totalCacheHitPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalCached));
                totalBlockedPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalBlocked));

                totalClientsPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalClients));
            }

            Dictionary<string, List<KeyValuePair<string, int>>> data = new Dictionary<string, List<KeyValuePair<string, int>>>();

            {
                List<KeyValuePair<string, int>> stats = new List<KeyValuePair<string, int>>(6);

                stats.Add(new KeyValuePair<string, int>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, int>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, int>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, int>("totalNxDomain", totalStatCounter.TotalNxDomain));
                stats.Add(new KeyValuePair<string, int>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, int>("totalAuthoritative", totalStatCounter.TotalAuthoritative));
                stats.Add(new KeyValuePair<string, int>("totalRecursive", totalStatCounter.TotalRecursive));
                stats.Add(new KeyValuePair<string, int>("totalCached", totalStatCounter.TotalCached));
                stats.Add(new KeyValuePair<string, int>("totalBlocked", totalStatCounter.TotalBlocked));

                stats.Add(new KeyValuePair<string, int>("totalClients", totalStatCounter.TotalClients));

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

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(10));

            return data;
        }

        public List<KeyValuePair<string, int>> GetLastHourTopStats(TopStatsType type, int limit)
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

        public List<KeyValuePair<string, int>> GetLastDayTopStats(TopStatsType type, int limit)
        {
            return GetHourWiseTopStats(DateTime.UtcNow.AddHours(-24), 24, type, limit);
        }

        public List<KeyValuePair<string, int>> GetLastWeekTopStats(TopStatsType type, int limit)
        {
            return GetDayWiseTopStats(DateTime.UtcNow.AddDays(-7).Date, 7, type, limit);
        }

        public List<KeyValuePair<string, int>> GetLastMonthTopStats(TopStatsType type, int limit)
        {
            return GetDayWiseTopStats(DateTime.UtcNow.AddDays(-31).Date, 31, type, limit);
        }

        public List<KeyValuePair<string, int>> GetLastYearTopStats(TopStatsType type, int limit)
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

        public List<KeyValuePair<string, int>> GetHourWiseTopStats(DateTime startDate, DateTime endDate, TopStatsType type, int limit)
        {
            int hours = Convert.ToInt32((endDate - startDate).TotalHours) + 1;
            if (hours < 24)
                hours = 24;

            return GetHourWiseTopStats(startDate, hours, type, limit);
        }

        public List<KeyValuePair<string, int>> GetHourWiseTopStats(DateTime startDate, int hours, TopStatsType type, int limit)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            for (int hour = 0; hour < hours; hour++)
            {
                DateTime lastDateTime = startDate.AddHours(hour);

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime);
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

        public List<KeyValuePair<string, int>> GetDayWiseTopStats(DateTime startDate, DateTime endDate, TopStatsType type, int limit)
        {
            return GetDayWiseTopStats(startDate, Convert.ToInt32((endDate - startDate).TotalDays) + 1, type, limit);
        }

        public List<KeyValuePair<string, int>> GetDayWiseTopStats(DateTime startDate, int days, TopStatsType type, int limit)
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

        public List<KeyValuePair<DnsQuestionRecord, int>> GetLastHourEligibleQueries(int minimumHitsPerHour)
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

        public void GetLatestClientSubnetStats(int minutes, int ipv4PrefixLength, int ipv6PrefixLength, out IReadOnlyDictionary<IPAddress, int> clientSubnetStats, out IReadOnlyDictionary<IPAddress, int> errorClientSubnetStats)
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

        public int MaxStatFileDays
        {
            get { return _maxStatFileDays; }
            set { _maxStatFileDays = value; }
        }

        #endregion

        class HourlyStats
        {
            #region variables

            readonly StatCounter _hourStat; //calculated value
            readonly StatCounter[] _minuteStats = new StatCounter[60];

            #endregion

            #region constructor

            public HourlyStats()
            {
                _hourStat = new StatCounter();
                _hourStat.Lock();
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

            int _totalQueries;
            int _totalNoError;
            int _totalServerFailure;
            int _totalNxDomain;
            int _totalRefused;

            int _totalAuthoritative;
            int _totalRecursive;
            int _totalCached;
            int _totalBlocked;

            int _totalClients;

            readonly ConcurrentDictionary<string, Counter> _queryDomains;
            readonly ConcurrentDictionary<string, Counter> _queryBlockedDomains;
            readonly ConcurrentDictionary<DnsResourceRecordType, Counter> _queryTypes;
            readonly ConcurrentDictionary<IPAddress, Counter> _clientIpAddresses; //includes all queries
            readonly ConcurrentDictionary<IPAddress, Counter> _errorIpAddresses; //includes REFUSED, FORMERR and SERVFAIL
            readonly ConcurrentDictionary<DnsQuestionRecord, Counter> _queries;

            bool _truncationFoundDuringMerge;
            int _totalClientsDailyStatsSummation;

            #endregion

            #region constructor

            public StatCounter()
            {
                _queryDomains = new ConcurrentDictionary<string, Counter>();
                _queryBlockedDomains = new ConcurrentDictionary<string, Counter>();
                _queryTypes = new ConcurrentDictionary<DnsResourceRecordType, Counter>();
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

                        {
                            int count = bR.ReadInt32();
                            _clientIpAddresses = new ConcurrentDictionary<IPAddress, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _clientIpAddresses.TryAdd(IPAddressExtension.Parse(bR), new Counter(bR.ReadInt32()));

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
                                _errorIpAddresses.TryAdd(IPAddressExtension.Parse(bR), new Counter(bR.ReadInt32()));
                        }
                        else
                        {
                            _errorIpAddresses = new ConcurrentDictionary<IPAddress, Counter>(1, 0);
                        }

                        break;

                    default:
                        throw new InvalidDataException("StatCounter version not supported.");
                }

                _locked = true;
            }

            #endregion

            #region private

            private static List<KeyValuePair<string, int>> GetTopList(List<KeyValuePair<string, int>> list, int limit)
            {
                list.Sort(delegate (KeyValuePair<string, int> item1, KeyValuePair<string, int> item2)
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

            public void Update(DnsQuestionRecord query, DnsResponseCode responseCode, DnsServerResponseType responseType, IPAddress clientIpAddress)
            {
                if (_locked)
                    return;

                if (clientIpAddress.IsIPv4MappedToIPv6)
                    clientIpAddress = clientIpAddress.MapToIPv4();

                Interlocked.Increment(ref _totalQueries);

                switch (responseCode)
                {
                    case DnsResponseCode.NoError:
                        if ((query is not null) && (responseType != DnsServerResponseType.Blocked)) //skip blocked domains
                        {
                            _queryDomains.GetOrAdd(query.Name.ToLower(), GetNewCounter).Increment();
                            _queries.GetOrAdd(query, GetNewCounter).Increment();
                        }

                        Interlocked.Increment(ref _totalNoError);
                        break;

                    case DnsResponseCode.ServerFailure:
                        _errorIpAddresses.GetOrAdd(clientIpAddress, GetNewCounter).Increment();
                        Interlocked.Increment(ref _totalServerFailure);
                        break;

                    case DnsResponseCode.NxDomain:
                        Interlocked.Increment(ref _totalNxDomain);
                        break;

                    case DnsResponseCode.Refused:
                        _errorIpAddresses.GetOrAdd(clientIpAddress, GetNewCounter).Increment();
                        Interlocked.Increment(ref _totalRefused);
                        break;

                    case DnsResponseCode.FormatError:
                        _errorIpAddresses.GetOrAdd(clientIpAddress, GetNewCounter).Increment();
                        break;
                }

                switch (responseType)
                {
                    case DnsServerResponseType.Authoritative:
                        Interlocked.Increment(ref _totalAuthoritative);
                        break;

                    case DnsServerResponseType.Recursive:
                        Interlocked.Increment(ref _totalRecursive);
                        break;

                    case DnsServerResponseType.Cached:
                        Interlocked.Increment(ref _totalCached);
                        break;

                    case DnsServerResponseType.Blocked:
                        if (query is not null)
                            _queryBlockedDomains.GetOrAdd(query.Name.ToLower(), GetNewCounter).Increment();

                        Interlocked.Increment(ref _totalBlocked);
                        break;
                }

                if (query is not null)
                    _queryTypes.GetOrAdd(query.Type, GetNewCounter).Increment();

                _clientIpAddresses.GetOrAdd(clientIpAddress, GetNewCounter).Increment();
                _totalClients = _clientIpAddresses.Count;
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

                foreach (KeyValuePair<string, Counter> queryDomain in statCounter._queryDomains)
                    _queryDomains.GetOrAdd(queryDomain.Key, GetNewCounter).Merge(queryDomain.Value);

                foreach (KeyValuePair<string, Counter> queryBlockedDomain in statCounter._queryBlockedDomains)
                    _queryBlockedDomains.GetOrAdd(queryBlockedDomain.Key, GetNewCounter).Merge(queryBlockedDomain.Value);

                foreach (KeyValuePair<DnsResourceRecordType, Counter> queryType in statCounter._queryTypes)
                    _queryTypes.GetOrAdd(queryType.Key, GetNewCounter).Merge(queryType.Value);

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
                        int othersCount = 0;

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
                bW.Write((byte)6); //version

                bW.Write(_totalQueries);
                bW.Write(_totalNoError);
                bW.Write(_totalServerFailure);
                bW.Write(_totalNxDomain);
                bW.Write(_totalRefused);

                bW.Write(_totalAuthoritative);
                bW.Write(_totalRecursive);
                bW.Write(_totalCached);
                bW.Write(_totalBlocked);

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

            public List<KeyValuePair<string, int>> GetTopDomains(int limit)
            {
                List<KeyValuePair<string, int>> topDomains = new List<KeyValuePair<string, int>>(_queryDomains.Count);

                foreach (KeyValuePair<string, Counter> item in _queryDomains)
                    topDomains.Add(new KeyValuePair<string, int>(item.Key, item.Value.Count));

                return GetTopList(topDomains, limit);
            }

            public List<KeyValuePair<string, int>> GetTopBlockedDomains(int limit)
            {
                List<KeyValuePair<string, int>> topBlockedDomains = new List<KeyValuePair<string, int>>(_queryBlockedDomains.Count);

                foreach (KeyValuePair<string, Counter> item in _queryBlockedDomains)
                    topBlockedDomains.Add(new KeyValuePair<string, int>(item.Key, item.Value.Count));

                return GetTopList(topBlockedDomains, limit);
            }

            public List<KeyValuePair<string, int>> GetTopClients(int limit)
            {
                List<KeyValuePair<string, int>> topClients = new List<KeyValuePair<string, int>>(_clientIpAddresses.Count);

                foreach (KeyValuePair<IPAddress, Counter> item in _clientIpAddresses)
                    topClients.Add(new KeyValuePair<string, int>(item.Key.ToString(), item.Value.Count));

                return GetTopList(topClients, limit);
            }

            public List<KeyValuePair<string, int>> GetTopQueryTypes(int limit)
            {
                List<KeyValuePair<string, int>> queryTypes = new List<KeyValuePair<string, int>>(_queryTypes.Count);

                foreach (KeyValuePair<DnsResourceRecordType, Counter> item in _queryTypes)
                    queryTypes.Add(new KeyValuePair<string, int>(item.Key.ToString(), item.Value.Count));

                queryTypes.Sort(delegate (KeyValuePair<string, int> item1, KeyValuePair<string, int> item2)
                {
                    return item2.Value.CompareTo(item1.Value);
                });

                if (queryTypes.Count > limit)
                {
                    int othersCount = 0;

                    for (int i = limit; i < queryTypes.Count; i++)
                        othersCount += queryTypes[i].Value;

                    queryTypes.RemoveRange((limit - 1), queryTypes.Count - (limit - 1));
                    queryTypes.Add(new KeyValuePair<string, int>("Others", othersCount));
                }

                return queryTypes;
            }

            public List<KeyValuePair<DnsQuestionRecord, int>> GetEligibleQueries(int minimumHits)
            {
                List<KeyValuePair<DnsQuestionRecord, int>> eligibleQueries = new List<KeyValuePair<DnsQuestionRecord, int>>(Convert.ToInt32(_queries.Count * 0.1));

                foreach (KeyValuePair<DnsQuestionRecord, Counter> item in _queries)
                {
                    if (item.Value.Count >= minimumHits)
                        eligibleQueries.Add(new KeyValuePair<DnsQuestionRecord, int>(item.Key, item.Value.Count));
                }

                return eligibleQueries;
            }

            public IReadOnlyDictionary<IPAddress, int> GetClientSubnetStats(int ipv4PrefixLength, int ipv6PrefixLength)
            {
                Dictionary<IPAddress, int> clientSubnetStats = new Dictionary<IPAddress, int>(_clientIpAddresses.Count);

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

                    if (clientSubnetStats.TryGetValue(clientSubnet, out int existingValue))
                        clientSubnetStats[clientSubnet] = existingValue + item.Value.Count;
                    else
                        clientSubnetStats.Add(clientSubnet, item.Value.Count);
                }

                return clientSubnetStats;
            }

            public IReadOnlyDictionary<IPAddress, int> GetErrorClientSubnetStats(int ipv4PrefixLength, int ipv6PrefixLength)
            {
                Dictionary<IPAddress, int> errorClientSubnetStats = new Dictionary<IPAddress, int>(_errorIpAddresses.Count);

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

                    if (errorClientSubnetStats.TryGetValue(clientSubnet, out int existingValue))
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

            public int TotalQueries
            { get { return _totalQueries; } }

            public int TotalNoError
            { get { return _totalNoError; } }

            public int TotalServerFailure
            { get { return _totalServerFailure; } }

            public int TotalNxDomain
            { get { return _totalNxDomain; } }

            public int TotalRefused
            { get { return _totalRefused; } }

            public int TotalAuthoritative
            { get { return _totalAuthoritative; } }

            public int TotalRecursive
            { get { return _totalRecursive; } }

            public int TotalCached
            { get { return _totalCached; } }

            public int TotalBlocked
            { get { return _totalBlocked; } }

            public int TotalClients
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

                int _count;

                #endregion

                #region constructor

                public Counter()
                { }

                public Counter(int count)
                {
                    _count = count;
                }

                #endregion

                #region public

                public void Increment()
                {
                    Interlocked.Increment(ref _count);
                }

                public void Merge(Counter counter)
                {
                    _count += counter._count;
                }

                #endregion

                #region properties

                public int Count
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

            #endregion

            #region constructor

            public StatsQueueItem(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
            {
                _timestamp = DateTime.UtcNow;

                _request = request;
                _remoteEP = remoteEP;
                _protocol = protocol;
                _response = response;
            }

            #endregion
        }
    }
}
