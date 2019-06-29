/*
Technitium DNS Server
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns
{
    public enum StatsResponseType
    {
        NoError = 1,
        ServerFailure = 2,
        NameError = 3,
        Refused = 4
    }

    public class StatsManager : IDisposable
    {
        #region variables

        readonly string _statsFolder;
        readonly LogManager _log;

        readonly StatCounter[] _lastHourStatCounters = new StatCounter[60];
        readonly StatCounter[] _lastHourStatCountersCopy = new StatCounter[60];
        readonly ConcurrentDictionary<DateTime, HourlyStats> _hourlyStatsCache = new ConcurrentDictionary<DateTime, HourlyStats>();
        readonly ConcurrentDictionary<DateTime, StatCounter> _dailyStatsCache = new ConcurrentDictionary<DateTime, StatCounter>();

        readonly Timer _maintenanceTimer;
        const int MAINTENANCE_TIMER_INITIAL_INTERVAL = 60000;
        const int MAINTENANCE_TIMER_INTERVAL = 60000;

        #endregion

        #region constructor

        public StatsManager(string statsFolder, LogManager log)
        {
            _statsFolder = statsFolder;
            _log = log;

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
                    _log.Write(ex);
                }

            }, null, MAINTENANCE_TIMER_INITIAL_INTERVAL, MAINTENANCE_TIMER_INTERVAL);
        }

        #endregion

        #region IDisposable

        private bool _disposed = false;
        private readonly object _disposeLock = new object();

        protected virtual void Dispose(bool disposing)
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
                    _hourlyStatsCache.TryRemove(key, out HourlyStats hourlyStats);
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
                    _dailyStatsCache.TryRemove(key, out StatCounter dailyStats);
            }
        }

        private HourlyStats LoadHourlyStats(DateTime dateTime)
        {
            HourlyStats hourlyStats;
            DateTime hourlyDateTime = new DateTime(dateTime.Year, dateTime.Month, dateTime.Day, dateTime.Hour, 0, 0, 0, DateTimeKind.Utc);

            if (!_hourlyStatsCache.TryGetValue(hourlyDateTime, out hourlyStats))
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
                        _log.Write(ex);
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
            StatCounter dailyStats;
            DateTime dailyDateTime = new DateTime(dateTime.Year, dateTime.Month, dateTime.Day, 0, 0, 0, 0, DateTimeKind.Utc);

            if (!_dailyStatsCache.TryGetValue(dailyDateTime, out dailyStats))
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
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
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
                        SaveDailyStats(dailyDateTime, dailyStats);
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
                _log.Write(ex);
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
                _log.Write(ex);
            }
        }

        private void Update(DnsQuestionRecord query, StatsResponseType responseType, object responseTag, IPAddress clientIpAddress)
        {
            StatCounter statCounter = _lastHourStatCounters[DateTime.UtcNow.Minute];

            if (statCounter != null)
                statCounter.Update(query, responseType, responseTag, clientIpAddress);
        }

        #endregion

        #region public

        public void Update(DnsDatagram response, IPAddress clientIpAddress)
        {
            StatsResponseType responseType;

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    responseType = StatsResponseType.NoError;
                    break;

                case DnsResponseCode.ServerFailure:
                    responseType = StatsResponseType.ServerFailure;
                    break;

                case DnsResponseCode.NameError:
                    responseType = StatsResponseType.NameError;
                    break;

                case DnsResponseCode.Refused:
                    responseType = StatsResponseType.Refused;
                    break;

                default:
                    return;
            }

            if (response.Header.QDCOUNT > 0)
                Update(response.Question[0], responseType, response.Tag, clientIpAddress);
            else
                Update(new DnsQuestionRecord("", DnsResourceRecordType.ANY, DnsClass.IN), responseType, response.Tag, clientIpAddress);
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetLastHourStats()
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, int>> totalQueriesPerInterval = new List<KeyValuePair<string, int>>(60);
            List<KeyValuePair<string, int>> totalNoErrorPerInterval = new List<KeyValuePair<string, int>>(60);
            List<KeyValuePair<string, int>> totalServerFailurePerInterval = new List<KeyValuePair<string, int>>(60);
            List<KeyValuePair<string, int>> totalNameErrorPerInterval = new List<KeyValuePair<string, int>>(60);
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
                    totalNameErrorPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalNameError));
                    totalRefusedPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalRefused));

                    totalAuthHitPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalAuthHit));
                    totalRecursionsPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalRecursions));
                    totalCacheHitPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalCacheHit));
                    totalBlockedPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalBlocked));

                    totalClientsPerInterval.Add(new KeyValuePair<string, int>(label, statCounter.TotalClients));
                }
                else
                {
                    totalQueriesPerInterval.Add(new KeyValuePair<string, int>(label, 0));
                    totalNoErrorPerInterval.Add(new KeyValuePair<string, int>(label, 0));
                    totalServerFailurePerInterval.Add(new KeyValuePair<string, int>(label, 0));
                    totalNameErrorPerInterval.Add(new KeyValuePair<string, int>(label, 0));
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
                stats.Add(new KeyValuePair<string, int>("totalNameError", totalStatCounter.TotalNameError));
                stats.Add(new KeyValuePair<string, int>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, int>("totalAuthHit", totalStatCounter.TotalAuthHit));
                stats.Add(new KeyValuePair<string, int>("totalRecursions", totalStatCounter.TotalRecursions));
                stats.Add(new KeyValuePair<string, int>("totalCacheHit", totalStatCounter.TotalCacheHit));
                stats.Add(new KeyValuePair<string, int>("totalBlocked", totalStatCounter.TotalBlocked));

                stats.Add(new KeyValuePair<string, int>("totalClients", totalStatCounter.TotalClients));

                data.Add("stats", stats);
            }

            data.Add("totalQueriesPerInterval", totalQueriesPerInterval);
            data.Add("totalNoErrorPerInterval", totalNoErrorPerInterval);
            data.Add("totalServerFailurePerInterval", totalServerFailurePerInterval);
            data.Add("totalNameErrorPerInterval", totalNameErrorPerInterval);
            data.Add("totalRefusedPerInterval", totalRefusedPerInterval);

            data.Add("totalAuthHitPerInterval", totalAuthHitPerInterval);
            data.Add("totalRecursionsPerInterval", totalRecursionsPerInterval);
            data.Add("totalCacheHitPerInterval", totalCacheHitPerInterval);
            data.Add("totalBlockedPerInterval", totalBlockedPerInterval);

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(5));

            return data;
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetLastDayStats()
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, int>> totalQueriesPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNoErrorPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalServerFailurePerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNameErrorPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRefusedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalAuthHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRecursionsPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalCacheHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalBlockedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalClientsPerInterval = new List<KeyValuePair<string, int>>();

            DateTime lastDayDateTime = DateTime.UtcNow.AddHours(-24);
            lastDayDateTime = new DateTime(lastDayDateTime.Year, lastDayDateTime.Month, lastDayDateTime.Day, lastDayDateTime.Hour, 0, 0, DateTimeKind.Utc);

            for (int hour = 0; hour < 24; hour++)
            {
                DateTime lastDateTime = lastDayDateTime.AddHours(hour);
                string label = lastDateTime.ToLocalTime().ToString("MM/dd HH") + ":00";

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime);
                StatCounter hourlyStatCounter = hourlyStats.HourStat;

                totalStatCounter.Merge(hourlyStatCounter);

                totalQueriesPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalQueries));
                totalNoErrorPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalNoError));
                totalServerFailurePerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalServerFailure));
                totalNameErrorPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalNameError));
                totalRefusedPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalRefused));

                totalAuthHitPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalAuthHit));
                totalRecursionsPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalRecursions));
                totalCacheHitPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalCacheHit));
                totalBlockedPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalBlocked));

                totalClientsPerInterval.Add(new KeyValuePair<string, int>(label, hourlyStatCounter.TotalClients));
            }

            Dictionary<string, List<KeyValuePair<string, int>>> data = new Dictionary<string, List<KeyValuePair<string, int>>>();

            {
                List<KeyValuePair<string, int>> stats = new List<KeyValuePair<string, int>>(6);

                stats.Add(new KeyValuePair<string, int>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, int>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, int>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, int>("totalNameError", totalStatCounter.TotalNameError));
                stats.Add(new KeyValuePair<string, int>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, int>("totalAuthHit", totalStatCounter.TotalAuthHit));
                stats.Add(new KeyValuePair<string, int>("totalRecursions", totalStatCounter.TotalRecursions));
                stats.Add(new KeyValuePair<string, int>("totalCacheHit", totalStatCounter.TotalCacheHit));
                stats.Add(new KeyValuePair<string, int>("totalBlocked", totalStatCounter.TotalBlocked));

                stats.Add(new KeyValuePair<string, int>("totalClients", totalStatCounter.TotalClients));

                data.Add("stats", stats);
            }

            data.Add("totalQueriesPerInterval", totalQueriesPerInterval);
            data.Add("totalNoErrorPerInterval", totalNoErrorPerInterval);
            data.Add("totalServerFailurePerInterval", totalServerFailurePerInterval);
            data.Add("totalNameErrorPerInterval", totalNameErrorPerInterval);
            data.Add("totalRefusedPerInterval", totalRefusedPerInterval);

            data.Add("totalAuthHitPerInterval", totalAuthHitPerInterval);
            data.Add("totalRecursionsPerInterval", totalRecursionsPerInterval);
            data.Add("totalCacheHitPerInterval", totalCacheHitPerInterval);
            data.Add("totalBlockedPerInterval", totalBlockedPerInterval);

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(5));

            return data;
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetLastWeekStats()
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, int>> totalQueriesPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNoErrorPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalServerFailurePerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNameErrorPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRefusedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalAuthHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRecursionsPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalCacheHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalBlockedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalClientsPerInterval = new List<KeyValuePair<string, int>>();

            DateTime lastWeekDateTime = DateTime.UtcNow.AddDays(-7);
            lastWeekDateTime = new DateTime(lastWeekDateTime.Year, lastWeekDateTime.Month, lastWeekDateTime.Day, 0, 0, 0, DateTimeKind.Utc);

            for (int day = 0; day < 7; day++) //days
            {
                DateTime lastDayDateTime = lastWeekDateTime.AddDays(day);
                string label = lastDayDateTime.ToLocalTime().ToString("MM/dd");

                StatCounter dailyStatCounter = LoadDailyStats(lastDayDateTime);
                totalStatCounter.Merge(dailyStatCounter);

                totalQueriesPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalQueries));
                totalNoErrorPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalNoError));
                totalServerFailurePerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalServerFailure));
                totalNameErrorPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalNameError));
                totalRefusedPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalRefused));

                totalAuthHitPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalAuthHit));
                totalRecursionsPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalRecursions));
                totalCacheHitPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalCacheHit));
                totalBlockedPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalBlocked));

                totalClientsPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalClients));
            }

            Dictionary<string, List<KeyValuePair<string, int>>> data = new Dictionary<string, List<KeyValuePair<string, int>>>();

            {
                List<KeyValuePair<string, int>> stats = new List<KeyValuePair<string, int>>(6);

                stats.Add(new KeyValuePair<string, int>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, int>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, int>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, int>("totalNameError", totalStatCounter.TotalNameError));
                stats.Add(new KeyValuePair<string, int>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, int>("totalAuthHit", totalStatCounter.TotalAuthHit));
                stats.Add(new KeyValuePair<string, int>("totalRecursions", totalStatCounter.TotalRecursions));
                stats.Add(new KeyValuePair<string, int>("totalCacheHit", totalStatCounter.TotalCacheHit));
                stats.Add(new KeyValuePair<string, int>("totalBlocked", totalStatCounter.TotalBlocked));

                stats.Add(new KeyValuePair<string, int>("totalClients", totalStatCounter.TotalClients));

                data.Add("stats", stats);
            }

            data.Add("totalQueriesPerInterval", totalQueriesPerInterval);
            data.Add("totalNoErrorPerInterval", totalNoErrorPerInterval);
            data.Add("totalServerFailurePerInterval", totalServerFailurePerInterval);
            data.Add("totalNameErrorPerInterval", totalNameErrorPerInterval);
            data.Add("totalRefusedPerInterval", totalRefusedPerInterval);

            data.Add("totalAuthHitPerInterval", totalAuthHitPerInterval);
            data.Add("totalRecursionsPerInterval", totalRecursionsPerInterval);
            data.Add("totalCacheHitPerInterval", totalCacheHitPerInterval);
            data.Add("totalBlockedPerInterval", totalBlockedPerInterval);

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(5));

            return data;
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetLastMonthStats()
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, int>> totalQueriesPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNoErrorPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalServerFailurePerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNameErrorPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRefusedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalAuthHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalRecursionsPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalCacheHitPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalBlockedPerInterval = new List<KeyValuePair<string, int>>();

            List<KeyValuePair<string, int>> totalClientsPerInterval = new List<KeyValuePair<string, int>>();

            DateTime lastMonthDateTime = DateTime.UtcNow.AddDays(-31);
            lastMonthDateTime = new DateTime(lastMonthDateTime.Year, lastMonthDateTime.Month, lastMonthDateTime.Day, 0, 0, 0, DateTimeKind.Utc);

            for (int day = 0; day < 31; day++) //days
            {
                DateTime lastDayDateTime = lastMonthDateTime.AddDays(day);
                string label = lastDayDateTime.ToLocalTime().ToString("MM/dd");

                StatCounter dailyStatCounter = LoadDailyStats(lastDayDateTime);
                totalStatCounter.Merge(dailyStatCounter);

                totalQueriesPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalQueries));
                totalNoErrorPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalNoError));
                totalServerFailurePerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalServerFailure));
                totalNameErrorPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalNameError));
                totalRefusedPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalRefused));

                totalAuthHitPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalAuthHit));
                totalRecursionsPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalRecursions));
                totalCacheHitPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalCacheHit));
                totalBlockedPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalBlocked));

                totalClientsPerInterval.Add(new KeyValuePair<string, int>(label, dailyStatCounter.TotalClients));
            }

            Dictionary<string, List<KeyValuePair<string, int>>> data = new Dictionary<string, List<KeyValuePair<string, int>>>();

            {
                List<KeyValuePair<string, int>> stats = new List<KeyValuePair<string, int>>(6);

                stats.Add(new KeyValuePair<string, int>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, int>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, int>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, int>("totalNameError", totalStatCounter.TotalNameError));
                stats.Add(new KeyValuePair<string, int>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, int>("totalAuthHit", totalStatCounter.TotalAuthHit));
                stats.Add(new KeyValuePair<string, int>("totalRecursions", totalStatCounter.TotalRecursions));
                stats.Add(new KeyValuePair<string, int>("totalCacheHit", totalStatCounter.TotalCacheHit));
                stats.Add(new KeyValuePair<string, int>("totalBlocked", totalStatCounter.TotalBlocked));

                stats.Add(new KeyValuePair<string, int>("totalClients", totalStatCounter.TotalClients));

                data.Add("stats", stats);
            }

            data.Add("totalQueriesPerInterval", totalQueriesPerInterval);
            data.Add("totalNoErrorPerInterval", totalNoErrorPerInterval);
            data.Add("totalServerFailurePerInterval", totalServerFailurePerInterval);
            data.Add("totalNameErrorPerInterval", totalNameErrorPerInterval);
            data.Add("totalRefusedPerInterval", totalRefusedPerInterval);

            data.Add("totalAuthHitPerInterval", totalAuthHitPerInterval);
            data.Add("totalRecursionsPerInterval", totalRecursionsPerInterval);
            data.Add("totalCacheHitPerInterval", totalCacheHitPerInterval);
            data.Add("totalBlockedPerInterval", totalBlockedPerInterval);

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(5));

            return data;
        }

        public Dictionary<string, List<KeyValuePair<string, int>>> GetLastYearStats()
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            List<KeyValuePair<string, int>> totalQueriesPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNoErrorPerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalServerFailurePerInterval = new List<KeyValuePair<string, int>>();
            List<KeyValuePair<string, int>> totalNameErrorPerInterval = new List<KeyValuePair<string, int>>();
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
                    monthlyStatCounter.Merge(dailyStatCounter);
                }

                totalStatCounter.Merge(monthlyStatCounter);

                totalQueriesPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalQueries));
                totalNoErrorPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalNoError));
                totalServerFailurePerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalServerFailure));
                totalNameErrorPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalNameError));
                totalRefusedPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalRefused));

                totalAuthHitPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalAuthHit));
                totalRecursionsPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalRecursions));
                totalCacheHitPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalCacheHit));
                totalBlockedPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalBlocked));

                totalClientsPerInterval.Add(new KeyValuePair<string, int>(label, monthlyStatCounter.TotalClients));
            }

            Dictionary<string, List<KeyValuePair<string, int>>> data = new Dictionary<string, List<KeyValuePair<string, int>>>();

            {
                List<KeyValuePair<string, int>> stats = new List<KeyValuePair<string, int>>(6);

                stats.Add(new KeyValuePair<string, int>("totalQueries", totalStatCounter.TotalQueries));
                stats.Add(new KeyValuePair<string, int>("totalNoError", totalStatCounter.TotalNoError));
                stats.Add(new KeyValuePair<string, int>("totalServerFailure", totalStatCounter.TotalServerFailure));
                stats.Add(new KeyValuePair<string, int>("totalNameError", totalStatCounter.TotalNameError));
                stats.Add(new KeyValuePair<string, int>("totalRefused", totalStatCounter.TotalRefused));

                stats.Add(new KeyValuePair<string, int>("totalAuthHit", totalStatCounter.TotalAuthHit));
                stats.Add(new KeyValuePair<string, int>("totalRecursions", totalStatCounter.TotalRecursions));
                stats.Add(new KeyValuePair<string, int>("totalCacheHit", totalStatCounter.TotalCacheHit));
                stats.Add(new KeyValuePair<string, int>("totalBlocked", totalStatCounter.TotalBlocked));

                stats.Add(new KeyValuePair<string, int>("totalClients", totalStatCounter.TotalClients));

                data.Add("stats", stats);
            }

            data.Add("totalQueriesPerInterval", totalQueriesPerInterval);
            data.Add("totalNoErrorPerInterval", totalNoErrorPerInterval);
            data.Add("totalServerFailurePerInterval", totalServerFailurePerInterval);
            data.Add("totalNameErrorPerInterval", totalNameErrorPerInterval);
            data.Add("totalRefusedPerInterval", totalRefusedPerInterval);

            data.Add("totalAuthHitPerInterval", totalAuthHitPerInterval);
            data.Add("totalRecursionsPerInterval", totalRecursionsPerInterval);
            data.Add("totalCacheHitPerInterval", totalCacheHitPerInterval);
            data.Add("totalBlockedPerInterval", totalBlockedPerInterval);

            data.Add("totalClientsPerInterval", totalClientsPerInterval);

            data.Add("topDomains", totalStatCounter.GetTopDomains(10));
            data.Add("topBlockedDomains", totalStatCounter.GetTopBlockedDomains(10));
            data.Add("topClients", totalStatCounter.GetTopClients(10));
            data.Add("queryTypes", totalStatCounter.GetTopQueryTypes(5));

            return data;
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
            int _totalNameError;
            int _totalRefused;

            int _totalAuthHit;
            int _totalRecursions;
            int _totalCacheHit;
            int _totalBlocked;

            readonly ConcurrentDictionary<string, Counter> _queryDomains = new ConcurrentDictionary<string, Counter>(100, 100);
            readonly ConcurrentDictionary<string, Counter> _queryBlockedDomains = new ConcurrentDictionary<string, Counter>(100, 100);
            readonly ConcurrentDictionary<DnsResourceRecordType, Counter> _queryTypes = new ConcurrentDictionary<DnsResourceRecordType, Counter>(100, 10);
            readonly ConcurrentDictionary<IPAddress, Counter> _clientIpAddresses = new ConcurrentDictionary<IPAddress, Counter>(100, 100);
            readonly ConcurrentDictionary<DnsQuestionRecord, Counter> _queries = new ConcurrentDictionary<DnsQuestionRecord, Counter>(100, 100);

            #endregion

            #region constructor

            public StatCounter()
            { }

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
                        _totalQueries = bR.ReadInt32();
                        _totalNoError = bR.ReadInt32();
                        _totalServerFailure = bR.ReadInt32();
                        _totalNameError = bR.ReadInt32();
                        _totalRefused = bR.ReadInt32();

                        if (version >= 3)
                        {
                            _totalAuthHit = bR.ReadInt32();
                            _totalRecursions = bR.ReadInt32();
                            _totalCacheHit = bR.ReadInt32();
                            _totalBlocked = bR.ReadInt32();
                        }
                        else
                        {
                            _totalBlocked = bR.ReadInt32();

                            if (version >= 2)
                                _totalCacheHit = bR.ReadInt32();
                        }

                        {
                            int count = bR.ReadInt32();
                            for (int i = 0; i < count; i++)
                                _queryDomains.TryAdd(bR.ReadShortString(), new Counter(bR.ReadInt32()));
                        }

                        {
                            int count = bR.ReadInt32();
                            for (int i = 0; i < count; i++)
                                _queryBlockedDomains.TryAdd(bR.ReadShortString(), new Counter(bR.ReadInt32()));
                        }

                        {
                            int count = bR.ReadInt32();
                            for (int i = 0; i < count; i++)
                                _queryTypes.TryAdd((DnsResourceRecordType)bR.ReadUInt16(), new Counter(bR.ReadInt32()));
                        }

                        {
                            int count = bR.ReadInt32();
                            for (int i = 0; i < count; i++)
                                _clientIpAddresses.TryAdd(IPAddressExtension.Parse(bR), new Counter(bR.ReadInt32()));
                        }
                        break;

                    default:
                        throw new InvalidDataException("StatCounter version not supported.");
                }

                _locked = true;
            }

            #endregion

            #region private

            private List<KeyValuePair<string, int>> GetTopList(List<KeyValuePair<string, int>> list, int limit)
            {
                list.Sort(delegate (KeyValuePair<string, int> item1, KeyValuePair<string, int> item2)
                {
                    return item2.Value.CompareTo(item1.Value);
                });

                if (list.Count > limit)
                    list.RemoveRange(limit, list.Count - limit);

                return list;
            }

            #endregion

            #region public

            public void Lock()
            {
                _locked = true;
            }

            public void Update(DnsQuestionRecord query, StatsResponseType responseType, object responseTag, IPAddress clientIpAddress)
            {
                if (_locked)
                    return;

                if (clientIpAddress.IsIPv4MappedToIPv6)
                    clientIpAddress = clientIpAddress.MapToIPv4();

                Interlocked.Increment(ref _totalQueries);

                switch (responseType)
                {
                    case StatsResponseType.NoError:
                        if (!"blocked".Equals(responseTag)) //skip blocked domains
                        {
                            _queryDomains.GetOrAdd(query.Name, new Counter()).Increment();
                            _queries.GetOrAdd(query, new Counter()).Increment();
                        }

                        Interlocked.Increment(ref _totalNoError);
                        break;

                    case StatsResponseType.ServerFailure:
                        Interlocked.Increment(ref _totalServerFailure);
                        break;

                    case StatsResponseType.NameError:
                        Interlocked.Increment(ref _totalNameError);
                        break;

                    case StatsResponseType.Refused:
                        Interlocked.Increment(ref _totalRefused);
                        break;
                }

                switch (responseTag)
                {
                    case "authHit":
                        Interlocked.Increment(ref _totalAuthHit);
                        break;

                    case null: //recursion
                        Interlocked.Increment(ref _totalRecursions);
                        break;

                    case "cacheHit":
                        Interlocked.Increment(ref _totalCacheHit);
                        break;

                    case "blocked":
                        _queryBlockedDomains.GetOrAdd(query.Name, new Counter()).Increment();
                        Interlocked.Increment(ref _totalBlocked);
                        break;
                }

                _queryTypes.GetOrAdd(query.Type, new Counter()).Increment();
                _clientIpAddresses.GetOrAdd(clientIpAddress, new Counter()).Increment();
            }

            public void Merge(StatCounter statCounter)
            {
                if (!_locked || !statCounter._locked)
                    throw new DnsServerException("StatCounter must be locked.");

                _totalQueries += statCounter._totalQueries;
                _totalNoError += statCounter._totalNoError;
                _totalServerFailure += statCounter._totalServerFailure;
                _totalNameError += statCounter._totalNameError;
                _totalRefused += statCounter._totalRefused;

                _totalAuthHit += statCounter._totalAuthHit;
                _totalRecursions += statCounter._totalRecursions;
                _totalCacheHit += statCounter._totalCacheHit;
                _totalBlocked += statCounter._totalBlocked;

                foreach (KeyValuePair<string, Counter> queryDomain in statCounter._queryDomains)
                    _queryDomains.GetOrAdd(queryDomain.Key, new Counter()).Merge(queryDomain.Value);

                foreach (KeyValuePair<string, Counter> queryBlockedDomain in statCounter._queryBlockedDomains)
                    _queryBlockedDomains.GetOrAdd(queryBlockedDomain.Key, new Counter()).Merge(queryBlockedDomain.Value);

                foreach (KeyValuePair<DnsResourceRecordType, Counter> queryType in statCounter._queryTypes)
                    _queryTypes.GetOrAdd(queryType.Key, new Counter()).Merge(queryType.Value);

                foreach (KeyValuePair<IPAddress, Counter> clientIpAddress in statCounter._clientIpAddresses)
                    _clientIpAddresses.GetOrAdd(clientIpAddress.Key, new Counter()).Merge(clientIpAddress.Value);

                foreach (KeyValuePair<DnsQuestionRecord, Counter> query in statCounter._queries)
                    _queries.GetOrAdd(query.Key, new Counter()).Merge(query.Value);
            }

            public void WriteTo(BinaryWriter bW)
            {
                if (!_locked)
                    throw new DnsServerException("StatCounter must be locked.");

                bW.Write(Encoding.ASCII.GetBytes("SC")); //format
                bW.Write((byte)3); //version

                bW.Write(_totalQueries);
                bW.Write(_totalNoError);
                bW.Write(_totalServerFailure);
                bW.Write(_totalNameError);
                bW.Write(_totalRefused);

                bW.Write(_totalAuthHit);
                bW.Write(_totalRecursions);
                bW.Write(_totalCacheHit);
                bW.Write(_totalBlocked);

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
            }

            public List<KeyValuePair<string, int>> GetTopDomains(int limit)
            {
                List<KeyValuePair<string, int>> topDomains = new List<KeyValuePair<string, int>>(10);

                foreach (KeyValuePair<string, Counter> item in _queryDomains)
                    topDomains.Add(new KeyValuePair<string, int>(item.Key, item.Value.Count));

                return GetTopList(topDomains, limit);
            }

            public List<KeyValuePair<string, int>> GetTopBlockedDomains(int limit)
            {
                List<KeyValuePair<string, int>> topBlockedDomains = new List<KeyValuePair<string, int>>(10);

                foreach (KeyValuePair<string, Counter> item in _queryBlockedDomains)
                    topBlockedDomains.Add(new KeyValuePair<string, int>(item.Key, item.Value.Count));

                return GetTopList(topBlockedDomains, limit);
            }

            public List<KeyValuePair<string, int>> GetTopClients(int limit)
            {
                List<KeyValuePair<string, int>> topClients = new List<KeyValuePair<string, int>>(10);

                foreach (KeyValuePair<IPAddress, Counter> item in _clientIpAddresses)
                    topClients.Add(new KeyValuePair<string, int>(item.Key.ToString(), item.Value.Count));

                return GetTopList(topClients, limit);
            }

            public List<KeyValuePair<string, int>> GetTopQueryTypes(int limit)
            {
                List<KeyValuePair<string, int>> queryTypes = new List<KeyValuePair<string, int>>(10);

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
                List<KeyValuePair<DnsQuestionRecord, int>> eligibleQueries = new List<KeyValuePair<DnsQuestionRecord, int>>(100);

                foreach (KeyValuePair<DnsQuestionRecord, Counter> item in _queries)
                {
                    if (item.Value.Count >= minimumHits)
                        eligibleQueries.Add(new KeyValuePair<DnsQuestionRecord, int>(item.Key, item.Value.Count));
                }

                return eligibleQueries;
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

            public int TotalNameError
            { get { return _totalNameError; } }

            public int TotalRefused
            { get { return _totalRefused; } }

            public int TotalAuthHit
            { get { return _totalAuthHit; } }

            public int TotalRecursions
            { get { return _totalRecursions; } }

            public int TotalCacheHit
            { get { return _totalCacheHit; } }

            public int TotalBlocked
            { get { return _totalBlocked; } }

            public int TotalClients
            { get { return _clientIpAddresses.Count; } }

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
    }
}
