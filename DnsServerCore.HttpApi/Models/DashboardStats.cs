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

using System.Collections.Generic;
using System.Linq;

namespace DnsServerCore.HttpApi.Models
{
    public enum DashboardStatsType
    {
        Unknown = 0,
        LastHour = 1,
        LastDay = 2,
        LastWeek = 3,
        LastMonth = 4,
        LastYear = 5,
        Custom = 6
    }

    public enum DashboardTopStatsType
    {
        Unknown = 0,
        TopClients = 1,
        TopDomains = 2,
        TopBlockedDomains = 3
    }

    public class DashboardStats
    {
        public StatsData? Stats { get; set; }
        public ChartData? MainChartData { get; set; }
        public ChartData? QueryResponseChartData { get; set; }
        public ChartData? QueryTypeChartData { get; set; }
        public ChartData? ProtocolTypeChartData { get; set; }
        public TopClientStats[]? TopClients { get; set; }
        public TopStats[]? TopDomains { get; set; }
        public TopStats[]? TopBlockedDomains { get; set; }

        public void Merge(DashboardStats other, int limit)
        {
            if ((Stats is not null) && (other.Stats is not null))
                Stats.Merge(other.Stats);

            if ((MainChartData is not null) && (other.MainChartData is not null))
                MainChartData = ChartData.Merge(MainChartData, other.MainChartData, false);

            if ((QueryResponseChartData is not null) && (other.QueryResponseChartData is not null))
                QueryResponseChartData = ChartData.Merge(QueryResponseChartData, other.QueryResponseChartData, false);

            if ((QueryTypeChartData is not null) && (other.QueryTypeChartData is not null))
                QueryTypeChartData = ChartData.Merge(QueryTypeChartData, other.QueryTypeChartData, true);

            if ((ProtocolTypeChartData is not null) && (other.ProtocolTypeChartData is not null))
                ProtocolTypeChartData = ChartData.Merge(ProtocolTypeChartData, other.ProtocolTypeChartData, true);

            if ((TopClients is not null) && (other.TopClients is not null))
                TopClients = TopStats.Merge(TopClients, other.TopClients, limit);

            if ((TopDomains is not null) && (other.TopDomains is not null))
                TopDomains = TopStats.Merge(TopDomains, other.TopDomains, limit);

            if ((TopBlockedDomains is not null) && (other.TopBlockedDomains is not null))
                TopBlockedDomains = TopStats.Merge(TopBlockedDomains, other.TopBlockedDomains, limit);
        }

        public class StatsData
        {
            public long TotalQueries { get; set; }
            public long TotalNoError { get; set; }
            public long TotalServerFailure { get; set; }
            public long TotalNxDomain { get; set; }
            public long TotalRefused { get; set; }
            public long TotalAuthoritative { get; set; }
            public long TotalRecursive { get; set; }
            public long TotalCached { get; set; }
            public long TotalBlocked { get; set; }
            public long TotalDropped { get; set; }
            public long TotalClients { get; set; }
            public int Zones { get; set; }
            public long CachedEntries { get; set; }
            public int AllowedZones { get; set; }
            public int BlockedZones { get; set; }
            public int AllowListZones { get; set; }
            public int BlockListZones { get; set; }

            public void Merge(StatsData statsData)
            {
                TotalQueries += statsData.TotalQueries;
                TotalNoError += statsData.TotalNoError;
                TotalServerFailure += statsData.TotalServerFailure;
                TotalNxDomain += statsData.TotalNxDomain;
                TotalRefused += statsData.TotalRefused;

                TotalAuthoritative += statsData.TotalAuthoritative;
                TotalRecursive += statsData.TotalRecursive;
                TotalCached += statsData.TotalCached;
                TotalBlocked += statsData.TotalBlocked;
                TotalDropped += statsData.TotalDropped;

                if (statsData.TotalClients > TotalClients)
                    TotalClients = statsData.TotalClients;

                if (statsData.Zones > Zones)
                    Zones = statsData.Zones;

                if (statsData.CachedEntries > CachedEntries)
                    CachedEntries = statsData.CachedEntries;

                if (statsData.AllowedZones > AllowedZones)
                    AllowedZones = statsData.AllowedZones;

                if (statsData.BlockedZones > BlockedZones)
                    BlockedZones = statsData.BlockedZones;

                if (statsData.AllowListZones > AllowListZones)
                    AllowListZones = statsData.AllowListZones;

                if (statsData.BlockListZones > BlockListZones)
                    BlockListZones = statsData.BlockListZones;
            }
        }

        public class ChartData
        {
            public required string[] Labels { get; set; }
            public required DataSet[] DataSets { get; set; }

            internal static ChartData Merge(ChartData x, ChartData y, bool sortByData)
            {
                Dictionary<string, Dictionary<string, long>> aggregateDataSet = new Dictionary<string, Dictionary<string, long>>(x.Labels.Length + y.Labels.Length);

                foreach (DataSet dataSet in x.DataSets)
                {
                    Dictionary<string, long> data = new Dictionary<string, long>(dataSet.Data.Length);

                    for (int i = 0; i < dataSet.Data.Length; i++)
                        data[x.Labels[i]] = dataSet.Data[i];

                    aggregateDataSet[dataSet.Label ?? ""] = data;
                }

                foreach (DataSet dataSet in y.DataSets)
                {
                    if (!aggregateDataSet.TryGetValue(dataSet.Label ?? "", out Dictionary<string, long>? data))
                    {
                        data = new Dictionary<string, long>(dataSet.Data.Length);
                        aggregateDataSet[dataSet.Label ?? ""] = data;
                    }

                    for (int i = 0; i < dataSet.Data.Length; i++)
                    {
                        string label = y.Labels[i];

                        if (data.TryGetValue(label, out long value))
                            data[label] = value + dataSet.Data[i];
                        else
                            data[label] = dataSet.Data[i];
                    }
                }

                if (sortByData && (aggregateDataSet.Count == 1))
                {
                    //prepare single dataset with sorted data
                    KeyValuePair<string, Dictionary<string, long>> firstDataSet = aggregateDataSet.First();
                    Dictionary<string, long> dataSet = firstDataSet.Value;
                    List<KeyValuePair<string, long>> sortedData = [.. dataSet];

                    sortedData.Sort(delegate (KeyValuePair<string, long> item1, KeyValuePair<string, long> item2)
                    {
                        return item2.Value.CompareTo(item1.Value);
                    });

                    string[] labels = new string[sortedData.Count];
                    long[] data = new long[sortedData.Count];

                    for (int i = 0; i < sortedData.Count; i++)
                    {
                        labels[i] = sortedData[i].Key;
                        data[i] = sortedData[i].Value;
                    }

                    return new ChartData
                    {
                        Labels = labels,
                        DataSets =
                        [
                            new DataSet
                            {
                                Label = firstDataSet.Key == "" ? null : aggregateDataSet.First().Key,
                                Data = data
                            }
                        ]
                    };
                }
                else
                {
                    //prepare merged labels
                    List<string> mergedLabels = new List<string>(x.Labels.Length + y.Labels.Length);

                    mergedLabels.AddRange(x.Labels);

                    foreach (string label in y.Labels)
                    {
                        if (!mergedLabels.Contains(label))
                            mergedLabels.Add(label);
                    }

                    //prepare merged datasets with ordered data
                    List<DataSet> mergedDataSets = new List<DataSet>(aggregateDataSet.Count);

                    foreach (KeyValuePair<string, Dictionary<string, long>> dataSetEntry in aggregateDataSet)
                    {
                        long[] data = new long[mergedLabels.Count];

                        for (int i = 0; i < mergedLabels.Count; i++)
                        {
                            string label = mergedLabels[i];

                            if (dataSetEntry.Value.TryGetValue(label, out long value))
                                data[i] = value;
                        }

                        mergedDataSets.Add(new DataSet
                        {
                            Label = dataSetEntry.Key == "" ? null : dataSetEntry.Key,
                            Data = data
                        });
                    }

                    return new ChartData
                    {
                        Labels = [.. mergedLabels],
                        DataSets = [.. mergedDataSets]
                    };
                }
            }

            public void Trim(int limit)
            {
                if (Labels.Length > limit)
                {
                    string[] newLabels = new string[limit];

                    for (int i = 0; i < limit - 1; i++)
                        newLabels[i] = Labels[i];

                    newLabels[limit - 1] = "Others";

                    Labels = newLabels;

                    foreach (DataSet dataSet in DataSets)
                        dataSet.Trim(limit);
                }
            }
        }

        public class DataSet
        {
            public string? Label { get; set; }
            public required long[] Data { get; set; }

            public void Trim(int limit)
            {
                if (Data.Length > limit)
                {
                    long[] newData = new long[limit];

                    for (int i = 0; i < newData.Length - 1; i++)
                        newData[i] = Data[i];

                    long othersCount = 0;

                    for (int i = limit; i < Data.Length; i++)
                        othersCount += Data[i];

                    newData[limit - 1] = othersCount;

                    Data = newData;
                }
            }
        }

        public class TopStats
        {
            public required string Name { get; set; }
            public required long Hits { get; set; }

            private static List<KeyValuePair<string, T>> GetTopList<T>(List<KeyValuePair<string, T>> list, int limit) where T : TopStats
            {
                list.Sort(delegate (KeyValuePair<string, T> item1, KeyValuePair<string, T> item2)
                {
                    return item2.Value.Hits.CompareTo(item1.Value.Hits);
                });

                if (list.Count > limit)
                    list.RemoveRange(limit, list.Count - limit);

                return list;
            }

            internal static T[] Merge<T>(T[] x, T[] y, int limit) where T : TopStats
            {
                Dictionary<string, T> aggregateData = new Dictionary<string, T>(x.Length + y.Length);

                foreach (T item in x)
                    aggregateData[item.Name] = item;

                foreach (T item in y)
                {
                    if (aggregateData.TryGetValue(item.Name, out T? entry))
                    {
                        entry.Hits += item.Hits;

                        if ((entry is TopClientStats topClientEntry) && (item is TopClientStats topClientItem))
                        {
                            topClientEntry.Domain ??= topClientItem.Domain;
                            topClientEntry.RateLimited |= topClientItem.RateLimited;
                        }
                    }
                    else
                    {
                        aggregateData[item.Name] = item;
                    }
                }

                List<KeyValuePair<string, T>> topList = GetTopList([.. aggregateData], limit);

                T[] z = new T[topList.Count];

                for (int i = 0; i < topList.Count; i++)
                    z[i] = topList[i].Value;

                return z;
            }
        }

        public class TopClientStats : TopStats
        {
            public string? Domain { get; set; }
            public bool RateLimited { get; set; }
        }
    }
}
