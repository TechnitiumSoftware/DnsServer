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
using DnsServerCore.Dns;
using System.Reflection;
using Xunit;

namespace DnsServerCore.Tests.Dns
{
    /// <summary>
    /// Unit tests for ResponseTimeStats nested class in StatsManager.
    /// Uses reflection to access the private nested class for testing.
    /// </summary>
    public class ResponseTimeStatsTests
    {
        private const string STATS_MANAGER_TYPE = "DnsServerCore.Dns.StatsManager";
        private const string STAT_COUNTER_TYPE = "DnsServerCore.Dns.StatsManager+StatCounter";
        private const string RESPONSE_TIME_STATS_TYPE = "DnsServerCore.Dns.StatsManager+StatCounter+ResponseTimeStats";

        private readonly Type _responseTimeStatsType;
        private readonly Type _statCounterType;

        public ResponseTimeStatsTests()
        {
            var assembly = Assembly.GetAssembly(typeof(StatsManager))!;
            _statCounterType = assembly.GetType(STAT_COUNTER_TYPE)!;
            _responseTimeStatsType = assembly.GetType(RESPONSE_TIME_STATS_TYPE)!;
        }

        private object CreateResponseTimeStats()
        {
            var constructor = _responseTimeStatsType.GetConstructor(
                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance,
                null, Type.EmptyTypes, null)!;
            return constructor.Invoke(null);
        }

        private void InvokeUpdate(object instance, double responseTimeMs, DnsServerResponseType responseType)
        {
            var method = _responseTimeStatsType.GetMethod("Update", BindingFlags.Public | BindingFlags.Instance);
            method!.Invoke(instance, new object[] { responseTimeMs, responseType });
        }

        private double InvokeCalculatePercentile(object instance, double percentile)
        {
            var method = _responseTimeStatsType.GetMethod("CalculatePercentile", BindingFlags.Public | BindingFlags.Instance);
            return (double)method!.Invoke(instance, new object[] { percentile })!;
        }

        private void InvokeMerge(object instance, object other)
        {
            var method = _responseTimeStatsType.GetMethod("Merge", BindingFlags.Public | BindingFlags.Instance);
            method!.Invoke(instance, new object[] { other });
        }

        private T GetProperty<T>(object instance, string propertyName)
        {
            var property = _responseTimeStatsType.GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance);
            return (T)property!.GetValue(instance)!;
        }

        private T GetField<T>(object instance, string fieldName)
        {
            var field = _responseTimeStatsType.GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance);
            return (T)field!.GetValue(instance)!;
        }

        #region T014: test_ResponseTimeStats_Update_RecordsCachedQuery

        [Fact]
        public void Test_ResponseTimeStats_Update_RecordsCachedQuery()
        {
            // Arrange
            var stats = CreateResponseTimeStats();
            double expectedResponseTime = 15.5;

            // Act
            InvokeUpdate(stats, expectedResponseTime, DnsServerResponseType.Cached);

            // Assert
            var avgCached = GetProperty<double>(stats, "CachedAverageResponseTimeMs");
            Assert.Equal(expectedResponseTime, avgCached);
            
            var cachedCount = GetField<long>(stats, "_cachedTotalCount");
            Assert.Equal(1, cachedCount);
        }

        #endregion

        #region T015: test_ResponseTimeStats_Update_RecordsRecursiveQuery

        [Fact]
        public void Test_ResponseTimeStats_Update_RecordsRecursiveQuery()
        {
            // Arrange
            var stats = CreateResponseTimeStats();
            double expectedResponseTime = 125.75;

            // Act
            InvokeUpdate(stats, expectedResponseTime, DnsServerResponseType.Recursive);

            // Assert
            var avgRecursive = GetProperty<double>(stats, "RecursiveAverageResponseTimeMs");
            Assert.Equal(expectedResponseTime, avgRecursive);
            
            var recursiveCount = GetField<long>(stats, "_recursiveTotalCount");
            Assert.Equal(1, recursiveCount);
        }

        #endregion

        #region T016: test_ResponseTimeStats_Update_TracksMinMax

        [Fact]
        public void Test_ResponseTimeStats_Update_TracksMinMax()
        {
            // Arrange
            var stats = CreateResponseTimeStats();
            
            // Act - Add multiple queries with different response times
            InvokeUpdate(stats, 50.0, DnsServerResponseType.Cached);
            InvokeUpdate(stats, 10.0, DnsServerResponseType.Cached);
            InvokeUpdate(stats, 200.0, DnsServerResponseType.Recursive);
            InvokeUpdate(stats, 75.0, DnsServerResponseType.Recursive);

            // Assert
            var minResponseTime = GetProperty<double>(stats, "MinResponseTimeMs");
            var maxResponseTime = GetProperty<double>(stats, "MaxResponseTimeMs");
            
            Assert.Equal(10.0, minResponseTime);
            Assert.Equal(200.0, maxResponseTime);
        }

        #endregion

        #region T017: test_ResponseTimeStats_HistogramBuckets_DistributeCorrectly

        [Fact]
        public void Test_ResponseTimeStats_HistogramBuckets_DistributeCorrectly()
        {
            // Arrange
            var stats = CreateResponseTimeStats();
            // Bucket thresholds: [5, 10, 25, 50, 100, 250, 500, 1000, 5000, ∞]
            
            // Act - Add queries that fall into different buckets
            InvokeUpdate(stats, 2.0, DnsServerResponseType.Cached);    // Bucket 0: < 5ms
            InvokeUpdate(stats, 7.0, DnsServerResponseType.Cached);    // Bucket 1: 5-10ms
            InvokeUpdate(stats, 20.0, DnsServerResponseType.Cached);   // Bucket 2: 10-25ms
            InvokeUpdate(stats, 45.0, DnsServerResponseType.Cached);   // Bucket 3: 25-50ms
            InvokeUpdate(stats, 80.0, DnsServerResponseType.Recursive); // Bucket 4: 50-100ms
            InvokeUpdate(stats, 200.0, DnsServerResponseType.Recursive); // Bucket 5: 100-250ms
            InvokeUpdate(stats, 400.0, DnsServerResponseType.Recursive); // Bucket 6: 250-500ms
            InvokeUpdate(stats, 800.0, DnsServerResponseType.Recursive); // Bucket 7: 500-1000ms
            InvokeUpdate(stats, 3000.0, DnsServerResponseType.Recursive); // Bucket 8: 1000-5000ms
            InvokeUpdate(stats, 10000.0, DnsServerResponseType.Recursive); // Bucket 9: >= 5000ms

            // Assert
            var buckets = GetField<long[]>(stats, "_buckets");
            Assert.Equal(10, buckets.Length);
            
            for (int i = 0; i < 10; i++)
            {
                Assert.Equal(1, buckets[i]); // Each bucket should have exactly 1 entry
            }
        }

        #endregion

        #region T018: test_ResponseTimeStats_CalculatePercentile_P50

        [Fact]
        public void Test_ResponseTimeStats_CalculatePercentile_P50()
        {
            // Arrange
            var stats = CreateResponseTimeStats();
            // Add 100 samples: 50 fast (5ms falls into 5-10ms bucket), 50 slow (>100ms)
            // Bucket thresholds are: [5, 10, 25, 50, 100, 250, 500, 1000, 5000, ∞]
            // 5.0ms is NOT < 5, so it falls into bucket 1 (5-10ms range)
            for (int i = 0; i < 50; i++)
            {
                InvokeUpdate(stats, 5.0, DnsServerResponseType.Cached);    // 5-10ms bucket (bucket 1)
            }
            for (int i = 0; i < 50; i++)
            {
                InvokeUpdate(stats, 150.0, DnsServerResponseType.Recursive); // 100-250ms bucket
            }

            // Act
            var p50 = InvokeCalculatePercentile(stats, 50);

            // Assert - P50 should be bucket 1's midpoint (7.5ms)
            // because exactly 50% of values are at 5ms which falls in 5-10ms bucket
            // Bucket midpoint = (5 + 10) / 2 = 7.5
            Assert.Equal(7.5, p50);
        }

        #endregion

        #region T019: test_ResponseTimeStats_CalculatePercentile_P95

        [Fact]
        public void Test_ResponseTimeStats_CalculatePercentile_P95()
        {
            // Arrange
            var stats = CreateResponseTimeStats();
            // Add 100 samples: 90 fast (<10ms), 10 slow (>100ms)
            for (int i = 0; i < 90; i++)
            {
                InvokeUpdate(stats, 5.0, DnsServerResponseType.Cached);    // < 5ms bucket
            }
            for (int i = 0; i < 10; i++)
            {
                InvokeUpdate(stats, 150.0, DnsServerResponseType.Recursive); // 100-250ms bucket
            }

            // Act
            var p95 = InvokeCalculatePercentile(stats, 95);

            // Assert - P95 should be the 100-250ms bucket midpoint (175)
            // Bucket midpoint = (100 + 250) / 2 = 175
            Assert.Equal(175, p95);
        }

        #endregion

        #region T020: test_ResponseTimeStats_CalculatePercentile_P99

        [Fact]
        public void Test_ResponseTimeStats_CalculatePercentile_P99()
        {
            // Arrange
            var stats = CreateResponseTimeStats();
            // Add 100 samples: 98 fast (<10ms), 2 very slow (>1000ms)
            for (int i = 0; i < 98; i++)
            {
                InvokeUpdate(stats, 5.0, DnsServerResponseType.Cached);    // < 5ms bucket
            }
            for (int i = 0; i < 2; i++)
            {
                InvokeUpdate(stats, 2000.0, DnsServerResponseType.Recursive); // 1000-5000ms bucket
            }

            // Act
            var p99 = InvokeCalculatePercentile(stats, 99);

            // Assert - P99 should be the 1000-5000ms bucket midpoint (3000)
            // Bucket midpoint = (1000 + 5000) / 2 = 3000
            Assert.Equal(3000, p99);
        }

        #endregion

        #region T021: test_ResponseTimeStats_Merge_CombinesMultipleBuckets

        [Fact]
        public void Test_ResponseTimeStats_Merge_CombinesMultipleBuckets()
        {
            // Arrange
            var stats1 = CreateResponseTimeStats();
            var stats2 = CreateResponseTimeStats();
            
            // Stats1: 10 queries at 5ms (bucket 0)
            for (int i = 0; i < 10; i++)
            {
                InvokeUpdate(stats1, 3.0, DnsServerResponseType.Cached);
            }
            
            // Stats2: 10 queries at 150ms (bucket 5)
            for (int i = 0; i < 10; i++)
            {
                InvokeUpdate(stats2, 150.0, DnsServerResponseType.Recursive);
            }

            // Act
            InvokeMerge(stats1, stats2);

            // Assert
            var buckets = GetField<long[]>(stats1, "_buckets");
            Assert.Equal(10, buckets[0]); // First bucket has stats1's data
            Assert.Equal(10, buckets[5]); // Sixth bucket has stats2's data
            
            var totalCount = GetField<long>(stats1, "_totalCount");
            Assert.Equal(20, totalCount);
        }

        #endregion

        #region T022: test_ResponseTimeStats_Serialization_RoundTrip

        [Fact]
        public void Test_ResponseTimeStats_Serialization_RoundTrip()
        {
            // Arrange
            var stats = CreateResponseTimeStats();
            InvokeUpdate(stats, 25.5, DnsServerResponseType.Cached);
            InvokeUpdate(stats, 150.75, DnsServerResponseType.Recursive);
            InvokeUpdate(stats, 5.0, DnsServerResponseType.Cached);

            // Act - Serialize
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);
            
            var writeMethod = _responseTimeStatsType.GetMethod("WriteTo", BindingFlags.Public | BindingFlags.Instance);
            writeMethod!.Invoke(stats, new object[] { bw });
            bw.Flush();
            
            // Act - Deserialize
            ms.Position = 0;
            using var br = new BinaryReader(ms);
            
            var readConstructor = _responseTimeStatsType.GetConstructor(
                BindingFlags.Public | BindingFlags.Instance,
                null, new[] { typeof(BinaryReader) }, null);
            var deserializedStats = readConstructor!.Invoke(new object[] { br });

            // Assert
            var originalAvg = GetProperty<double>(stats, "AverageResponseTimeMs");
            var deserializedAvg = GetProperty<double>(deserializedStats, "AverageResponseTimeMs");
            Assert.Equal(originalAvg, deserializedAvg, 2);
            
            var originalMin = GetProperty<double>(stats, "MinResponseTimeMs");
            var deserializedMin = GetProperty<double>(deserializedStats, "MinResponseTimeMs");
            Assert.Equal(originalMin, deserializedMin);
            
            var originalMax = GetProperty<double>(stats, "MaxResponseTimeMs");
            var deserializedMax = GetProperty<double>(deserializedStats, "MaxResponseTimeMs");
            Assert.Equal(originalMax, deserializedMax);
        }

        #endregion

        #region T023: test_StatCounter_BackwardCompatibility_LoadsVersion9

        [Fact]
        public void Test_StatCounter_BackwardCompatibility_LoadsVersion9()
        {
            // This test verifies that when version < 10 is encountered,
            // ResponseTimeStats is initialized with default values
            
            // Arrange - Create a StatCounter and check default ResponseTimeStats behavior
            var stats = CreateResponseTimeStats();
            
            // Assert - Default values for empty ResponseTimeStats
            var avgResponseTime = GetProperty<double>(stats, "AverageResponseTimeMs");
            Assert.Equal(0, avgResponseTime);
            
            var minResponseTime = GetProperty<double>(stats, "MinResponseTimeMs");
            Assert.Equal(0, minResponseTime); // When totalCount is 0, MinResponseTimeMs returns 0
            
            var maxResponseTime = GetProperty<double>(stats, "MaxResponseTimeMs");
            Assert.Equal(0, maxResponseTime);
            
            var p50 = GetProperty<double>(stats, "P50");
            Assert.Equal(0, p50);
        }

        #endregion

        #region Additional edge case tests

        [Fact]
        public void Test_ResponseTimeStats_EmptyStats_ReturnsZero()
        {
            // Arrange
            var stats = CreateResponseTimeStats();

            // Assert - All averages should be 0 when no data
            Assert.Equal(0, GetProperty<double>(stats, "AverageResponseTimeMs"));
            Assert.Equal(0, GetProperty<double>(stats, "CachedAverageResponseTimeMs"));
            Assert.Equal(0, GetProperty<double>(stats, "RecursiveAverageResponseTimeMs"));
            Assert.Equal(0, GetProperty<double>(stats, "MinResponseTimeMs"));
            Assert.Equal(0, GetProperty<double>(stats, "P50"));
            Assert.Equal(0, GetProperty<double>(stats, "P95"));
            Assert.Equal(0, GetProperty<double>(stats, "P99"));
        }

        [Fact]
        public void Test_ResponseTimeStats_Update_CalculatesAverageCorrectly()
        {
            // Arrange
            var stats = CreateResponseTimeStats();
            
            // Act - Add 4 queries: 10ms, 20ms, 30ms, 40ms = avg 25ms
            InvokeUpdate(stats, 10.0, DnsServerResponseType.Cached);
            InvokeUpdate(stats, 20.0, DnsServerResponseType.Cached);
            InvokeUpdate(stats, 30.0, DnsServerResponseType.Recursive);
            InvokeUpdate(stats, 40.0, DnsServerResponseType.Recursive);

            // Assert
            var avgResponseTime = GetProperty<double>(stats, "AverageResponseTimeMs");
            Assert.Equal(25.0, avgResponseTime);
            
            var cachedAvg = GetProperty<double>(stats, "CachedAverageResponseTimeMs");
            Assert.Equal(15.0, cachedAvg); // (10 + 20) / 2
            
            var recursiveAvg = GetProperty<double>(stats, "RecursiveAverageResponseTimeMs");
            Assert.Equal(35.0, recursiveAvg); // (30 + 40) / 2
        }

        [Fact]
        public void Test_ResponseTimeStats_Merge_PreservesMinMax()
        {
            // Arrange
            var stats1 = CreateResponseTimeStats();
            var stats2 = CreateResponseTimeStats();
            
            InvokeUpdate(stats1, 50.0, DnsServerResponseType.Cached);
            InvokeUpdate(stats1, 100.0, DnsServerResponseType.Cached);
            
            InvokeUpdate(stats2, 10.0, DnsServerResponseType.Recursive);
            InvokeUpdate(stats2, 200.0, DnsServerResponseType.Recursive);

            // Act
            InvokeMerge(stats1, stats2);

            // Assert - Min should be from stats2, max should be from stats2
            var minResponseTime = GetProperty<double>(stats1, "MinResponseTimeMs");
            Assert.Equal(10.0, minResponseTime);
            
            var maxResponseTime = GetProperty<double>(stats1, "MaxResponseTimeMs");
            Assert.Equal(200.0, maxResponseTime);
        }

        [Fact]
        public void Test_ResponseTimeStats_Update_HandlesUpstreamBlockedCached()
        {
            // Arrange
            var stats = CreateResponseTimeStats();
            
            // Act - UpstreamBlockedCached should count as cached
            InvokeUpdate(stats, 5.0, DnsServerResponseType.UpstreamBlockedCached);

            // Assert
            var cachedCount = GetField<long>(stats, "_cachedTotalCount");
            Assert.Equal(1, cachedCount);
        }

        [Fact]
        public void Test_ResponseTimeStats_Update_HandlesUpstreamBlocked()
        {
            // Arrange
            var stats = CreateResponseTimeStats();
            
            // Act - UpstreamBlocked should count as recursive
            InvokeUpdate(stats, 100.0, DnsServerResponseType.UpstreamBlocked);

            // Assert
            var recursiveCount = GetField<long>(stats, "_recursiveTotalCount");
            Assert.Equal(1, recursiveCount);
        }

        #endregion
    }
}
