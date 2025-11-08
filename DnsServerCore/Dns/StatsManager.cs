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
using DnsServerCore.HttpApi.Models;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns
{
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

        readonly Channel<StatsQueueItem> _channel;
        readonly ChannelWriter<StatsQueueItem> _channelWriter;
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

            UnboundedChannelOptions options = new UnboundedChannelOptions();
            options.SingleReader = true;

            _channel = Channel.CreateUnbounded<StatsQueueItem>(options);
            _channelWriter = _channel.Writer;

            //load stats
            LoadLastHourStats();

            try
            {
                //do first maintenance
                DoMaintenance();
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
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
                    _dnsServer.LogManager.Write(ex);
                }
            }, null, MAINTENANCE_TIMER_INITIAL_INTERVAL, MAINTENANCE_TIMER_PERIODIC_INTERVAL);

            //stats consumer thread
            _consumerThread = new Thread(async delegate ()
            {
                try
                {
                    await foreach (StatsQueueItem item in _channel.Reader.ReadAllAsync())
                    {
                        if (_disposed)
                            break;

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
                            continue; //skip dropped requests for apps to prevent DoS

                        foreach (IDnsQueryLogger logger in _dnsServer.DnsApplicationManager.DnsQueryLoggers)
                        {
                            try
                            {
                                _ = logger.InsertLogAsync(item._timestamp, item._request, item._remoteEP, item._protocol, item._response);
                            }
                            catch (Exception ex)
                            {
                                dnsServer.LogManager.Write(ex);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
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
                                    dnsServer.LogManager.Write("StatsManager cleanup deleted the hourly stats file: " + hourlyStatsFile);
                                }
                                catch (Exception ex)
                                {
                                    dnsServer.LogManager.Write(ex);
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
                                    dnsServer.LogManager.Write("StatsManager cleanup deleted the daily stats file: " + dailyStatsFile);
                                }
                                catch (Exception ex)
                                {
                                    dnsServer.LogManager.Write(ex);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            });

            _statsCleanupTimer.Change(STATS_CLEANUP_TIMER_INITIAL_INTERVAL, STATS_CLEANUP_TIMER_PERIODIC_INTERVAL);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _maintenanceTimer?.Dispose();
            _statsCleanupTimer?.Dispose();

            _channelWriter?.TryComplete();

            DoMaintenance(); //do last maintenance

            _disposed = true;
            GC.SuppressFinalize(this);
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
                _dnsServer.LogManager.Write(ex);
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
                        _dnsServer.LogManager.Write(ex);

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
                        {
                            SaveDailyStats(dailyDateTime, dailyStats); //save truncated file
                            GC.Collect();
                        }
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                }

                if (dailyStats is null)
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
                        GC.Collect();
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
                _dnsServer.LogManager.Write(ex);
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
                _dnsServer.LogManager.Write(ex);
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
            _channelWriter.TryWrite(new StatsQueueItem(request, remoteEP, protocol, response, rateLimited));
        }

        public DashboardStats GetLastHourMinuteWiseStats(bool utcFormat)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            string[] labels = new string[60];

            long[] totalQueriesPerInterval = new long[60];
            long[] totalNoErrorPerInterval = new long[60];
            long[] totalServerFailurePerInterval = new long[60];
            long[] totalNxDomainPerInterval = new long[60];
            long[] totalRefusedPerInterval = new long[60];

            long[] totalAuthHitPerInterval = new long[60];
            long[] totalRecursionsPerInterval = new long[60];
            long[] totalCacheHitPerInterval = new long[60];
            long[] totalBlockedPerInterval = new long[60];
            long[] totalDroppedPerInterval = new long[60];

            long[] totalClientsPerInterval = new long[60];

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

                labels[minute] = label;

                StatCounter statCounter = _lastHourStatCountersCopy[lastDateTime.Minute];
                if ((statCounter != null) && statCounter.IsLocked)
                {
                    totalStatCounter.Merge(statCounter);

                    totalQueriesPerInterval[minute] = statCounter.TotalQueries;

                    totalNoErrorPerInterval[minute] = statCounter.TotalNoError;
                    totalServerFailurePerInterval[minute] = statCounter.TotalServerFailure;
                    totalNxDomainPerInterval[minute] = statCounter.TotalNxDomain;
                    totalRefusedPerInterval[minute] = statCounter.TotalRefused;

                    totalAuthHitPerInterval[minute] = statCounter.TotalAuthoritative;
                    totalRecursionsPerInterval[minute] = statCounter.TotalRecursive;
                    totalCacheHitPerInterval[minute] = statCounter.TotalCached;
                    totalBlockedPerInterval[minute] = statCounter.TotalBlocked;
                    totalDroppedPerInterval[minute] = statCounter.TotalDropped;

                    totalClientsPerInterval[minute] = statCounter.TotalClients;
                }
            }

            DashboardStats.ChartData mainChartData = new DashboardStats.ChartData()
            {
                Labels = labels,
                DataSets =
                [
                    new DashboardStats.DataSet()
                    {
                        Label = "Total",
                        Data = totalQueriesPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "No Error",
                        Data = totalNoErrorPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Server Failure",
                        Data = totalServerFailurePerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "NX Domain",
                        Data = totalNxDomainPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Refused",
                        Data = totalRefusedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Authoritative",
                        Data = totalAuthHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Recursive",
                        Data = totalRecursionsPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Cached",
                        Data = totalCacheHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Blocked",
                        Data = totalBlockedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Dropped",
                        Data = totalDroppedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Clients",
                        Data = totalClientsPerInterval
                    }
                ]
            };

            return new DashboardStats()
            {
                Stats = totalStatCounter.GetStatsData(),
                MainChartData = mainChartData,
                QueryResponseChartData = totalStatCounter.GetQueryResponseChartData(),
                QueryTypeChartData = totalStatCounter.GetTopQueryTypesChartData(),
                ProtocolTypeChartData = totalStatCounter.GetTopProtocolTypesChartData(),
                TopClients = totalStatCounter.GetTopClientStats(10),
                TopDomains = totalStatCounter.GetTopDomainStats(10),
                TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(10)
            };
        }

        public DashboardStats GetLastDayHourWiseStats(bool utcFormat)
        {
            return GetHourWiseStats(DateTime.UtcNow.AddHours(-24), 24, utcFormat);
        }

        public DashboardStats GetLastWeekDayWiseStats(bool utcFormat)
        {
            return GetDayWiseStats(DateTime.UtcNow.AddDays(-7).Date, 7, utcFormat);
        }

        public DashboardStats GetLastMonthDayWiseStats(bool utcFormat)
        {
            return GetDayWiseStats(DateTime.UtcNow.AddDays(-31).Date, 31, utcFormat);
        }

        public DashboardStats GetLastYearMonthWiseStats(bool utcFormat)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            string[] labels = new string[12];

            long[] totalQueriesPerInterval = new long[12];
            long[] totalNoErrorPerInterval = new long[12];
            long[] totalServerFailurePerInterval = new long[12];
            long[] totalNxDomainPerInterval = new long[12];
            long[] totalRefusedPerInterval = new long[12];

            long[] totalAuthHitPerInterval = new long[12];
            long[] totalRecursionsPerInterval = new long[12];
            long[] totalCacheHitPerInterval = new long[12];
            long[] totalBlockedPerInterval = new long[12];
            long[] totalDroppedPerInterval = new long[12];

            long[] totalClientsPerInterval = new long[12];

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

                labels[month] = label;

                int days = DateTime.DaysInMonth(lastMonthDateTime.Year, lastMonthDateTime.Month);

                for (int day = 0; day < days; day++) //days
                {
                    StatCounter dailyStatCounter = LoadDailyStats(lastMonthDateTime.AddDays(day));
                    monthlyStatCounter.Merge(dailyStatCounter, true);
                }

                totalStatCounter.Merge(monthlyStatCounter, true);

                totalQueriesPerInterval[month] = monthlyStatCounter.TotalQueries;

                totalNoErrorPerInterval[month] = monthlyStatCounter.TotalNoError;
                totalServerFailurePerInterval[month] = monthlyStatCounter.TotalServerFailure;
                totalNxDomainPerInterval[month] = monthlyStatCounter.TotalNxDomain;
                totalRefusedPerInterval[month] = monthlyStatCounter.TotalRefused;

                totalAuthHitPerInterval[month] = monthlyStatCounter.TotalAuthoritative;
                totalRecursionsPerInterval[month] = monthlyStatCounter.TotalRecursive;
                totalCacheHitPerInterval[month] = monthlyStatCounter.TotalCached;
                totalBlockedPerInterval[month] = monthlyStatCounter.TotalBlocked;
                totalDroppedPerInterval[month] = monthlyStatCounter.TotalDropped;

                totalClientsPerInterval[month] = monthlyStatCounter.TotalClients;
            }

            DashboardStats.ChartData mainChartData = new DashboardStats.ChartData()
            {
                Labels = labels,
                DataSets =
                [
                    new DashboardStats.DataSet()
                    {
                        Label = "Total",
                        Data = totalQueriesPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "No Error",
                        Data = totalNoErrorPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Server Failure",
                        Data = totalServerFailurePerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "NX Domain",
                        Data = totalNxDomainPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Refused",
                        Data = totalRefusedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Authoritative",
                        Data = totalAuthHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Recursive",
                        Data = totalRecursionsPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Cached",
                        Data = totalCacheHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Blocked",
                        Data = totalBlockedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Dropped",
                        Data = totalDroppedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Clients",
                        Data = totalClientsPerInterval
                    }
                ]
            };

            return new DashboardStats()
            {
                Stats = totalStatCounter.GetStatsData(),
                MainChartData = mainChartData,
                QueryResponseChartData = totalStatCounter.GetQueryResponseChartData(),
                QueryTypeChartData = totalStatCounter.GetTopQueryTypesChartData(),
                ProtocolTypeChartData = totalStatCounter.GetTopProtocolTypesChartData(),
                TopClients = totalStatCounter.GetTopClientStats(10),
                TopDomains = totalStatCounter.GetTopDomainStats(10),
                TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(10)
            };
        }

        public DashboardStats GetMinuteWiseStats(DateTime startDate, DateTime endDate, bool utcFormat)
        {
            return GetMinuteWiseStats(startDate, Convert.ToInt32((endDate - startDate).TotalMinutes) + 1, utcFormat);
        }

        public DashboardStats GetMinuteWiseStats(DateTime startDate, int minutes, bool utcFormat)
        {
            startDate = startDate.AddMinutes(-1);

            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            string[] labels = new string[minutes];

            long[] totalQueriesPerInterval = new long[minutes];
            long[] totalNoErrorPerInterval = new long[minutes];
            long[] totalServerFailurePerInterval = new long[minutes];
            long[] totalNxDomainPerInterval = new long[minutes];
            long[] totalRefusedPerInterval = new long[minutes];

            long[] totalAuthHitPerInterval = new long[minutes];
            long[] totalRecursionsPerInterval = new long[minutes];
            long[] totalCacheHitPerInterval = new long[minutes];
            long[] totalBlockedPerInterval = new long[minutes];
            long[] totalDroppedPerInterval = new long[minutes];

            long[] totalClientsPerInterval = new long[minutes];

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

                labels[minute] = label;

                totalStatCounter.Merge(minuteStatCounter);

                totalQueriesPerInterval[minute] = minuteStatCounter.TotalQueries;

                totalNoErrorPerInterval[minute] = minuteStatCounter.TotalNoError;
                totalServerFailurePerInterval[minute] = minuteStatCounter.TotalServerFailure;
                totalNxDomainPerInterval[minute] = minuteStatCounter.TotalNxDomain;
                totalRefusedPerInterval[minute] = minuteStatCounter.TotalRefused;

                totalAuthHitPerInterval[minute] = minuteStatCounter.TotalAuthoritative;
                totalRecursionsPerInterval[minute] = minuteStatCounter.TotalRecursive;
                totalCacheHitPerInterval[minute] = minuteStatCounter.TotalCached;
                totalBlockedPerInterval[minute] = minuteStatCounter.TotalBlocked;
                totalDroppedPerInterval[minute] = minuteStatCounter.TotalDropped;

                totalClientsPerInterval[minute] = minuteStatCounter.TotalClients;
            }

            DashboardStats.ChartData mainChartData = new DashboardStats.ChartData()
            {
                Labels = labels,
                DataSets =
                [
                    new DashboardStats.DataSet()
                    {
                        Label = "Total",
                        Data = totalQueriesPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "No Error",
                        Data = totalNoErrorPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Server Failure",
                        Data = totalServerFailurePerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "NX Domain",
                        Data = totalNxDomainPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Refused",
                        Data = totalRefusedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Authoritative",
                        Data = totalAuthHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Recursive",
                        Data = totalRecursionsPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Cached",
                        Data = totalCacheHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Blocked",
                        Data = totalBlockedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Dropped",
                        Data = totalDroppedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Clients",
                        Data = totalClientsPerInterval
                    }
                ]
            };

            return new DashboardStats()
            {
                Stats = totalStatCounter.GetStatsData(),
                MainChartData = mainChartData,
                QueryResponseChartData = totalStatCounter.GetQueryResponseChartData(),
                QueryTypeChartData = totalStatCounter.GetTopQueryTypesChartData(),
                ProtocolTypeChartData = totalStatCounter.GetTopProtocolTypesChartData(),
                TopClients = totalStatCounter.GetTopClientStats(10),
                TopDomains = totalStatCounter.GetTopDomainStats(10),
                TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(10)
            };
        }

        public DashboardStats GetHourWiseStats(DateTime startDate, DateTime endDate, bool utcFormat)
        {
            return GetHourWiseStats(startDate, Convert.ToInt32((endDate - startDate).TotalHours) + 1, utcFormat);
        }

        public DashboardStats GetHourWiseStats(DateTime startDate, int hours, bool utcFormat)
        {
            startDate = new DateTime(startDate.Year, startDate.Month, startDate.Day, startDate.Hour, 0, 0, 0, DateTimeKind.Utc);

            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            string[] labels = new string[hours];

            long[] totalQueriesPerInterval = new long[hours];
            long[] totalNoErrorPerInterval = new long[hours];
            long[] totalServerFailurePerInterval = new long[hours];
            long[] totalNxDomainPerInterval = new long[hours];
            long[] totalRefusedPerInterval = new long[hours];

            long[] totalAuthHitPerInterval = new long[hours];
            long[] totalRecursionsPerInterval = new long[hours];
            long[] totalCacheHitPerInterval = new long[hours];
            long[] totalBlockedPerInterval = new long[hours];
            long[] totalDroppedPerInterval = new long[hours];

            long[] totalClientsPerInterval = new long[hours];

            for (int hour = 0; hour < hours; hour++)
            {
                DateTime lastDateTime = startDate.AddHours(hour);
                string label;

                if (utcFormat)
                    label = lastDateTime.AddHours(1).ToString("O");
                else
                    label = lastDateTime.AddHours(1).ToLocalTime().ToString("MM/dd HH") + ":00";

                labels[hour] = label;

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime, ifNotExistsReturnEmptyHourlyStats: true);
                StatCounter hourlyStatCounter = hourlyStats.HourStat;

                totalStatCounter.Merge(hourlyStatCounter);

                totalQueriesPerInterval[hour] = hourlyStatCounter.TotalQueries;

                totalNoErrorPerInterval[hour] = hourlyStatCounter.TotalNoError;
                totalServerFailurePerInterval[hour] = hourlyStatCounter.TotalServerFailure;
                totalNxDomainPerInterval[hour] = hourlyStatCounter.TotalNxDomain;
                totalRefusedPerInterval[hour] = hourlyStatCounter.TotalRefused;

                totalAuthHitPerInterval[hour] = hourlyStatCounter.TotalAuthoritative;
                totalRecursionsPerInterval[hour] = hourlyStatCounter.TotalRecursive;
                totalCacheHitPerInterval[hour] = hourlyStatCounter.TotalCached;
                totalBlockedPerInterval[hour] = hourlyStatCounter.TotalBlocked;
                totalDroppedPerInterval[hour] = hourlyStatCounter.TotalDropped;

                totalClientsPerInterval[hour] = hourlyStatCounter.TotalClients;
            }

            DashboardStats.ChartData mainChartData = new DashboardStats.ChartData()
            {
                Labels = labels,
                DataSets =
                [
                    new DashboardStats.DataSet()
                    {
                        Label = "Total",
                        Data = totalQueriesPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "No Error",
                        Data = totalNoErrorPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Server Failure",
                        Data = totalServerFailurePerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "NX Domain",
                        Data = totalNxDomainPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Refused",
                        Data = totalRefusedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Authoritative",
                        Data = totalAuthHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Recursive",
                        Data = totalRecursionsPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Cached",
                        Data = totalCacheHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Blocked",
                        Data = totalBlockedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Dropped",
                        Data = totalDroppedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Clients",
                        Data = totalClientsPerInterval
                    }
                ]
            };

            return new DashboardStats()
            {
                Stats = totalStatCounter.GetStatsData(),
                MainChartData = mainChartData,
                QueryResponseChartData = totalStatCounter.GetQueryResponseChartData(),
                QueryTypeChartData = totalStatCounter.GetTopQueryTypesChartData(),
                ProtocolTypeChartData = totalStatCounter.GetTopProtocolTypesChartData(),
                TopClients = totalStatCounter.GetTopClientStats(10),
                TopDomains = totalStatCounter.GetTopDomainStats(10),
                TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(10)
            };
        }

        public DashboardStats GetDayWiseStats(DateTime startDate, DateTime endDate, bool utcFormat)
        {
            return GetDayWiseStats(startDate, Convert.ToInt32((endDate - startDate).TotalDays) + 1, utcFormat);
        }

        public DashboardStats GetDayWiseStats(DateTime startDate, int days, bool utcFormat)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            string[] labels = new string[days];

            long[] totalQueriesPerInterval = new long[days];
            long[] totalNoErrorPerInterval = new long[days];
            long[] totalServerFailurePerInterval = new long[days];
            long[] totalNxDomainPerInterval = new long[days];
            long[] totalRefusedPerInterval = new long[days];

            long[] totalAuthHitPerInterval = new long[days];
            long[] totalRecursionsPerInterval = new long[days];
            long[] totalCacheHitPerInterval = new long[days];
            long[] totalBlockedPerInterval = new long[days];
            long[] totalDroppedPerInterval = new long[days];

            long[] totalClientsPerInterval = new long[days];

            for (int day = 0; day < days; day++) //days
            {
                DateTime lastDayDateTime = startDate.AddDays(day);
                string label;

                if (utcFormat)
                    label = lastDayDateTime.ToString("O");
                else
                    label = lastDayDateTime.ToLocalTime().ToString("MM/dd");

                labels[day] = label;

                StatCounter dailyStatCounter = LoadDailyStats(lastDayDateTime);
                totalStatCounter.Merge(dailyStatCounter, true);

                totalQueriesPerInterval[day] = dailyStatCounter.TotalQueries;

                totalNoErrorPerInterval[day] = dailyStatCounter.TotalNoError;
                totalServerFailurePerInterval[day] = dailyStatCounter.TotalServerFailure;
                totalNxDomainPerInterval[day] = dailyStatCounter.TotalNxDomain;
                totalRefusedPerInterval[day] = dailyStatCounter.TotalRefused;

                totalAuthHitPerInterval[day] = dailyStatCounter.TotalAuthoritative;
                totalRecursionsPerInterval[day] = dailyStatCounter.TotalRecursive;
                totalCacheHitPerInterval[day] = dailyStatCounter.TotalCached;
                totalBlockedPerInterval[day] = dailyStatCounter.TotalBlocked;
                totalDroppedPerInterval[day] = dailyStatCounter.TotalDropped;

                totalClientsPerInterval[day] = dailyStatCounter.TotalClients;
            }

            DashboardStats.ChartData mainChartData = new DashboardStats.ChartData()
            {
                Labels = labels,
                DataSets =
                [
                    new DashboardStats.DataSet()
                    {
                        Label = "Total",
                        Data = totalQueriesPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "No Error",
                        Data = totalNoErrorPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Server Failure",
                        Data = totalServerFailurePerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "NX Domain",
                        Data = totalNxDomainPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Refused",
                        Data = totalRefusedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Authoritative",
                        Data = totalAuthHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Recursive",
                        Data = totalRecursionsPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Cached",
                        Data = totalCacheHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Blocked",
                        Data = totalBlockedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Dropped",
                        Data = totalDroppedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Clients",
                        Data = totalClientsPerInterval
                    }
                ]
            };

            return new DashboardStats()
            {
                Stats = totalStatCounter.GetStatsData(),
                MainChartData = mainChartData,
                QueryResponseChartData = totalStatCounter.GetQueryResponseChartData(),
                QueryTypeChartData = totalStatCounter.GetTopQueryTypesChartData(),
                ProtocolTypeChartData = totalStatCounter.GetTopProtocolTypesChartData(),
                TopClients = totalStatCounter.GetTopClientStats(10),
                TopDomains = totalStatCounter.GetTopDomainStats(10),
                TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(10)
            };
        }

        public DashboardStats GetLastHourTopStats(DashboardTopStatsType type, int limit)
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
                case DashboardTopStatsType.TopClients:
                    return new DashboardStats()
                    {
                        TopClients = totalStatCounter.GetTopClientStats(limit),
                    };

                case DashboardTopStatsType.TopDomains:
                    return new DashboardStats()
                    {
                        TopDomains = totalStatCounter.GetTopDomainStats(limit),
                    };

                case DashboardTopStatsType.TopBlockedDomains:
                    return new DashboardStats()
                    {
                        TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(limit)
                    };

                default:
                    throw new NotSupportedException();
            }
        }

        public DashboardStats GetLastDayTopStats(DashboardTopStatsType type, int limit)
        {
            return GetHourWiseTopStats(DateTime.UtcNow.AddHours(-24), 24, type, limit);
        }

        public DashboardStats GetLastWeekTopStats(DashboardTopStatsType type, int limit)
        {
            return GetDayWiseTopStats(DateTime.UtcNow.AddDays(-7).Date, 7, type, limit);
        }

        public DashboardStats GetLastMonthTopStats(DashboardTopStatsType type, int limit)
        {
            return GetDayWiseTopStats(DateTime.UtcNow.AddDays(-31).Date, 31, type, limit);
        }

        public DashboardStats GetLastYearTopStats(DashboardTopStatsType type, int limit)
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
                case DashboardTopStatsType.TopClients:
                    return new DashboardStats()
                    {
                        TopClients = totalStatCounter.GetTopClientStats(limit),
                    };

                case DashboardTopStatsType.TopDomains:
                    return new DashboardStats()
                    {
                        TopDomains = totalStatCounter.GetTopDomainStats(limit),
                    };

                case DashboardTopStatsType.TopBlockedDomains:
                    return new DashboardStats()
                    {
                        TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(limit)
                    };

                default:
                    throw new NotSupportedException();
            }
        }

        public DashboardStats GetMinuteWiseTopStats(DateTime startDate, DateTime endDate, DashboardTopStatsType type, int limit)
        {
            return GetMinuteWiseTopStats(startDate, Convert.ToInt32((endDate - startDate).TotalMinutes) + 1, type, limit);
        }

        public DashboardStats GetMinuteWiseTopStats(DateTime startDate, int minutes, DashboardTopStatsType type, int limit)
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
                case DashboardTopStatsType.TopClients:
                    return new DashboardStats()
                    {
                        TopClients = totalStatCounter.GetTopClientStats(limit),
                    };

                case DashboardTopStatsType.TopDomains:
                    return new DashboardStats()
                    {
                        TopDomains = totalStatCounter.GetTopDomainStats(limit),
                    };

                case DashboardTopStatsType.TopBlockedDomains:
                    return new DashboardStats()
                    {
                        TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(limit)
                    };

                default:
                    throw new NotSupportedException();
            }
        }

        public DashboardStats GetHourWiseTopStats(DateTime startDate, DateTime endDate, DashboardTopStatsType type, int limit)
        {
            return GetHourWiseTopStats(startDate, Convert.ToInt32((endDate - startDate).TotalHours) + 1, type, limit);
        }

        public DashboardStats GetHourWiseTopStats(DateTime startDate, int hours, DashboardTopStatsType type, int limit)
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
                case DashboardTopStatsType.TopClients:
                    return new DashboardStats()
                    {
                        TopClients = totalStatCounter.GetTopClientStats(limit),
                    };

                case DashboardTopStatsType.TopDomains:
                    return new DashboardStats()
                    {
                        TopDomains = totalStatCounter.GetTopDomainStats(limit),
                    };

                case DashboardTopStatsType.TopBlockedDomains:
                    return new DashboardStats()
                    {
                        TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(limit)
                    };

                default:
                    throw new NotSupportedException();
            }
        }

        public DashboardStats GetDayWiseTopStats(DateTime startDate, DateTime endDate, DashboardTopStatsType type, int limit)
        {
            return GetDayWiseTopStats(startDate, Convert.ToInt32((endDate - startDate).TotalDays) + 1, type, limit);
        }

        public DashboardStats GetDayWiseTopStats(DateTime startDate, int days, DashboardTopStatsType type, int limit)
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
                case DashboardTopStatsType.TopClients:
                    return new DashboardStats()
                    {
                        TopClients = totalStatCounter.GetTopClientStats(limit),
                    };

                case DashboardTopStatsType.TopDomains:
                    return new DashboardStats()
                    {
                        TopDomains = totalStatCounter.GetTopDomainStats(limit),
                    };

                case DashboardTopStatsType.TopBlockedDomains:
                    return new DashboardStats()
                    {
                        TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(limit)
                    };

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

        public Dictionary<NetworkAddress, ValueTuple<long, long>> GetLatestClientSubnetStats(int minutes, IEnumerable<int> ipv4Prefixes, IEnumerable<int> ipv6Prefixes)
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

            return totalStatCounter.GetClientSubnetStats(ipv4Prefixes, ipv6Prefixes);
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
            { get { return _minuteStats; } }

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
            readonly ConcurrentDictionary<IPAddress, (Counter, Counter)> _clientIpAddressesUdpTcp;
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
                _clientIpAddressesUdpTcp = new ConcurrentDictionary<IPAddress, (Counter, Counter)>();
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
                            _clientIpAddressesUdpTcp = new ConcurrentDictionary<IPAddress, (Counter, Counter)>(1, count);

                            for (int i = 0; i < count; i++)
                                _clientIpAddressesUdpTcp.TryAdd(IPAddressExtensions.ReadFrom(bR), (new Counter(bR.ReadInt32()), new Counter()));

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
                            ConcurrentDictionary<IPAddress, Counter> errorIpAddresses = new ConcurrentDictionary<IPAddress, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                errorIpAddresses.TryAdd(IPAddressExtensions.ReadFrom(bR), new Counter(bR.ReadInt32()));
                        }

                        break;

                    case 7:
                    case 8:
                    case 9:
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

                        if (version >= 9)
                        {
                            int count = bR.ReadInt32();
                            _clientIpAddressesUdpTcp = new ConcurrentDictionary<IPAddress, (Counter, Counter)>(1, count);

                            for (int i = 0; i < count; i++)
                                _clientIpAddressesUdpTcp.TryAdd(IPAddressExtensions.ReadFrom(bR), (new Counter(bR.ReadInt64()), new Counter(bR.ReadInt64())));
                        }
                        else
                        {
                            int count = bR.ReadInt32();
                            _clientIpAddressesUdpTcp = new ConcurrentDictionary<IPAddress, (Counter, Counter)>(1, count);

                            for (int i = 0; i < count; i++)
                                _clientIpAddressesUdpTcp.TryAdd(IPAddressExtensions.ReadFrom(bR), (new Counter(bR.ReadInt64()), new Counter()));
                        }

                        {
                            int count = bR.ReadInt32();
                            _queries = new ConcurrentDictionary<DnsQuestionRecord, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queries.TryAdd(new DnsQuestionRecord(bR.BaseStream), new Counter(bR.ReadInt64()));
                        }

                        if (version <= 8)
                        {
                            int count = bR.ReadInt32();
                            ConcurrentDictionary<IPAddress, Counter> errorIpAddresses = new ConcurrentDictionary<IPAddress, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                errorIpAddresses.TryAdd(IPAddressExtensions.ReadFrom(bR), new Counter(bR.ReadInt64()));
                        }

                        break;

                    default:
                        throw new InvalidDataException("StatCounter version not supported.");
                }

                _locked = true;
            }

            #endregion

            #region private

            private static List<KeyValuePair<string, T>> GetTopList<T>(List<KeyValuePair<string, T>> list, int limit) where T : DashboardStats.TopStats
            {
                list.Sort(delegate (KeyValuePair<string, T> item1, KeyValuePair<string, T> item2)
                {
                    return item2.Value.Hits.CompareTo(item1.Value.Hits);
                });

                if (list.Count > limit)
                    list.RemoveRange(limit, list.Count - limit);

                return list;
            }

            private static Counter GetNewCounter<T>(T key)
            {
                return new Counter();
            }

            private static (Counter, Counter) GetNewCounterTuple<T>(T key)
            {
                return (new Counter(), new Counter());
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
                        if (protocol == DnsTransportProtocol.Udp)
                            _clientIpAddressesUdpTcp.GetOrAdd(clientIpAddress, GetNewCounterTuple).Item1.Increment();
                        else
                            _clientIpAddressesUdpTcp.GetOrAdd(clientIpAddress, GetNewCounterTuple).Item2.Increment();

                        _totalClients = _clientIpAddressesUdpTcp.Count;
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
                                    case DnsServerResponseType.UpstreamBlockedCached:
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
                            _totalServerFailure++;
                            break;

                        case DnsResponseCode.NxDomain:
                            _totalNxDomain++;
                            break;

                        case DnsResponseCode.Refused:
                            _totalRefused++;
                            break;

                        case DnsResponseCode.FormatError:
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

                        case DnsServerResponseType.UpstreamBlockedCached:
                            _totalCached++;

                            if (query is not null)
                                _queryBlockedDomains.GetOrAdd(query.Name.ToLowerInvariant(), GetNewCounter).Increment();

                            _totalBlocked++;
                            break;
                    }

                    if (query is not null)
                        _queryTypes.GetOrAdd(query.Type, GetNewCounter).Increment();

                    if (protocol == DnsTransportProtocol.Udp)
                        _clientIpAddressesUdpTcp.GetOrAdd(clientIpAddress, GetNewCounterTuple).Item1.Increment();
                    else
                        _clientIpAddressesUdpTcp.GetOrAdd(clientIpAddress, GetNewCounterTuple).Item2.Increment();

                    _totalClients = _clientIpAddressesUdpTcp.Count;
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

                foreach (KeyValuePair<IPAddress, (Counter, Counter)> clientIpAddress in statCounter._clientIpAddressesUdpTcp)
                {
                    (Counter, Counter) counterTuple = _clientIpAddressesUdpTcp.GetOrAdd(clientIpAddress.Key, GetNewCounterTuple);
                    counterTuple.Item1.Merge(clientIpAddress.Value.Item1);
                    counterTuple.Item2.Merge(clientIpAddress.Value.Item2);
                }

                foreach (KeyValuePair<DnsQuestionRecord, Counter> query in statCounter._queries)
                    _queries.GetOrAdd(query.Key, GetNewCounter).Merge(query.Value);

                _totalClients = _clientIpAddressesUdpTcp.Count;
                _totalClientsDailyStatsSummation += statCounter._totalClients;

                if (isDailyStatCounter && (statCounter._totalClients > statCounter._clientIpAddressesUdpTcp.Count))
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

                if (_clientIpAddressesUdpTcp.Count > limit)
                {
                    List<KeyValuePair<IPAddress, (Counter, Counter)>> topClients = new List<KeyValuePair<IPAddress, (Counter, Counter)>>(_clientIpAddressesUdpTcp);

                    _clientIpAddressesUdpTcp.Clear();

                    topClients.Sort(delegate (KeyValuePair<IPAddress, (Counter, Counter)> x, KeyValuePair<IPAddress, (Counter, Counter)> y)
                    {
                        long x1 = x.Value.Item1.Count + x.Value.Item2.Count;
                        long y1 = y.Value.Item1.Count + y.Value.Item2.Count;

                        return y1.CompareTo(x1);
                    });

                    if (topClients.Count > limit)
                        topClients.RemoveRange(limit, topClients.Count - limit);

                    foreach (KeyValuePair<IPAddress, (Counter, Counter)> item in topClients)
                        _clientIpAddressesUdpTcp[item.Key] = item.Value;

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
                bW.Write((byte)9); //version

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
                    bW.Write(_clientIpAddressesUdpTcp.Count);
                    foreach (KeyValuePair<IPAddress, (Counter, Counter)> clientIpAddress in _clientIpAddressesUdpTcp)
                    {
                        clientIpAddress.Key.WriteTo(bW);
                        bW.Write(clientIpAddress.Value.Item1.Count);
                        bW.Write(clientIpAddress.Value.Item2.Count);
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
            }

            public DashboardStats.StatsData GetStatsData()
            {
                return new DashboardStats.StatsData
                {
                    TotalQueries = _totalQueries,
                    TotalNoError = _totalNoError,
                    TotalServerFailure = _totalServerFailure,
                    TotalNxDomain = _totalNxDomain,
                    TotalRefused = _totalRefused,

                    TotalAuthoritative = _totalAuthoritative,
                    TotalRecursive = _totalRecursive,
                    TotalCached = _totalCached,
                    TotalBlocked = _totalBlocked,
                    TotalDropped = _totalDropped,

                    TotalClients = _totalClients
                };
            }

            public DashboardStats.ChartData GetQueryResponseChartData()
            {
                return new DashboardStats.ChartData()
                {
                    Labels =
                    [
                        "Authoritative",
                        "Recursive",
                        "Cached",
                        "Blocked",
                        "Dropped"
                    ],
                    DataSets =
                    [
                        new DashboardStats.DataSet()
                        {
                            Data =
                            [
                                _totalAuthoritative,
                                _totalRecursive,
                                _totalCached,
                                _totalBlocked,
                                _totalDropped
                            ]
                        }
                    ]
                };
            }

            public DashboardStats.TopStats[] GetTopDomainStats(int limit)
            {
                List<KeyValuePair<string, DashboardStats.TopStats>> topDomainsList = new List<KeyValuePair<string, DashboardStats.TopStats>>(_queryDomains.Count);

                foreach (KeyValuePair<string, Counter> item in _queryDomains)
                    topDomainsList.Add(new KeyValuePair<string, DashboardStats.TopStats>(item.Key, new DashboardStats.TopStats { Name = item.Key, Hits = item.Value.Count }));

                List<KeyValuePair<string, DashboardStats.TopStats>> topDomainsData = GetTopList(topDomainsList, limit);
                DashboardStats.TopStats[] topDomains = new DashboardStats.TopStats[topDomainsData.Count];

                for (int i = 0; i < topDomainsData.Count; i++)
                    topDomains[i] = topDomainsData[i].Value;

                return topDomains;
            }

            public DashboardStats.TopStats[] GetTopBlockedDomainStats(int limit)
            {
                List<KeyValuePair<string, DashboardStats.TopStats>> topBlockedDomainsList = new List<KeyValuePair<string, DashboardStats.TopStats>>(_queryBlockedDomains.Count);

                foreach (KeyValuePair<string, Counter> item in _queryBlockedDomains)
                    topBlockedDomainsList.Add(new KeyValuePair<string, DashboardStats.TopStats>(item.Key, new DashboardStats.TopStats { Name = item.Key, Hits = item.Value.Count }));

                List<KeyValuePair<string, DashboardStats.TopStats>> topBlockedDomainsData = GetTopList(topBlockedDomainsList, limit);
                DashboardStats.TopStats[] topBlockedDomains = new DashboardStats.TopStats[topBlockedDomainsData.Count];

                for (int i = 0; i < topBlockedDomainsData.Count; i++)
                    topBlockedDomains[i] = topBlockedDomainsData[i].Value;

                return topBlockedDomains;
            }

            public DashboardStats.TopClientStats[] GetTopClientStats(int limit)
            {
                List<KeyValuePair<string, DashboardStats.TopClientStats>> topClientsList = new List<KeyValuePair<string, DashboardStats.TopClientStats>>(_clientIpAddressesUdpTcp.Count);

                foreach (KeyValuePair<IPAddress, (Counter, Counter)> item in _clientIpAddressesUdpTcp)
                    topClientsList.Add(new KeyValuePair<string, DashboardStats.TopClientStats>(item.Key.ToString(), new DashboardStats.TopClientStats { Name = item.Key.ToString(), Hits = item.Value.Item1.Count + item.Value.Item2.Count }));

                List<KeyValuePair<string, DashboardStats.TopClientStats>> topClientsData = GetTopList(topClientsList, limit);
                DashboardStats.TopClientStats[] topClients = new DashboardStats.TopClientStats[topClientsData.Count];

                for (int i = 0; i < topClientsData.Count; i++)
                    topClients[i] = topClientsData[i].Value;

                return topClients;
            }

            public DashboardStats.ChartData GetTopQueryTypesChartData()
            {
                List<KeyValuePair<string, long>> queryTypes = new List<KeyValuePair<string, long>>(_queryTypes.Count);

                foreach (KeyValuePair<DnsResourceRecordType, Counter> item in _queryTypes)
                    queryTypes.Add(new KeyValuePair<string, long>(item.Key.ToString(), item.Value.Count));

                queryTypes.Sort(delegate (KeyValuePair<string, long> item1, KeyValuePair<string, long> item2)
                {
                    return item2.Value.CompareTo(item1.Value);
                });

                string[] queryTypeLabels = new string[queryTypes.Count];
                long[] queryTypeData = new long[queryTypes.Count];

                for (int i = 0; i < queryTypes.Count; i++)
                {
                    KeyValuePair<string, long> topQueryTypeData = queryTypes[i];

                    queryTypeLabels[i] = topQueryTypeData.Key;
                    queryTypeData[i] = topQueryTypeData.Value;
                }

                return new DashboardStats.ChartData()
                {
                    Labels = queryTypeLabels,
                    DataSets =
                    [
                        new DashboardStats.DataSet()
                        {
                            Data = queryTypeData
                        }
                    ]
                };
            }

            public DashboardStats.ChartData GetTopProtocolTypesChartData()
            {
                List<KeyValuePair<string, long>> protocolTypes = new List<KeyValuePair<string, long>>(_protocolTypes.Count);

                foreach (KeyValuePair<DnsTransportProtocol, Counter> protocolType in _protocolTypes)
                    protocolTypes.Add(new KeyValuePair<string, long>(protocolType.Key.ToString(), protocolType.Value.Count));

                protocolTypes.Sort(delegate (KeyValuePair<string, long> item1, KeyValuePair<string, long> item2)
                {
                    return item2.Value.CompareTo(item1.Value);
                });

                string[] topProtocolLabels = new string[protocolTypes.Count];
                long[] topProtocolData = new long[protocolTypes.Count];

                for (int i = 0; i < protocolTypes.Count; i++)
                {
                    KeyValuePair<string, long> topProtocolTypeData = protocolTypes[i];

                    topProtocolLabels[i] = topProtocolTypeData.Key;
                    topProtocolData[i] = topProtocolTypeData.Value;
                }

                return new DashboardStats.ChartData()
                {
                    Labels = topProtocolLabels,
                    DataSets =
                    [
                        new DashboardStats.DataSet()
                        {
                            Data = topProtocolData
                        }
                    ]
                };
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

            public Dictionary<NetworkAddress, (long, long)> GetClientSubnetStats(IEnumerable<int> ipv4Prefixes, IEnumerable<int> ipv6Prefixes)
            {
                Dictionary<NetworkAddress, (long, long)> clientSubnetStats = new Dictionary<NetworkAddress, (long, long)>(_clientIpAddressesUdpTcp.Count);

                void UpdateClientSubnetStats(NetworkAddress clientSubnet, (Counter, Counter) value)
                {
                    if (clientSubnetStats.TryGetValue(clientSubnet, out ValueTuple<long, long> existingValue))
                    {
                        existingValue.Item1 += value.Item1.Count;
                        existingValue.Item2 += value.Item2.Count;
                    }
                    else
                    {
                        clientSubnetStats.Add(clientSubnet, (value.Item1.Count, value.Item2.Count));
                    }
                }

                foreach (KeyValuePair<IPAddress, (Counter, Counter)> item in _clientIpAddressesUdpTcp)
                {
                    switch (item.Key.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            IPAddress clientIPv4 = item.Key;

                            foreach (int ipv4Prefix in ipv4Prefixes)
                                UpdateClientSubnetStats(new NetworkAddress(clientIPv4, (byte)ipv4Prefix), item.Value);

                            break;

                        case AddressFamily.InterNetworkV6:
                            IPAddress clientIPv6 = item.Key;

                            foreach (int ipv6Prefix in ipv6Prefixes)
                                UpdateClientSubnetStats(new NetworkAddress(clientIPv6, (byte)ipv6Prefix), item.Value);

                            break;

                        default:
                            throw new NotSupportedException("AddressFamily not supported.");
                    }
                }

                return clientSubnetStats;
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

        readonly struct StatsQueueItem
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
