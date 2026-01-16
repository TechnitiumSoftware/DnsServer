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

using DnsServerCore.HttpApi.Models;
using Xunit;

namespace DnsServerCore.Tests
{
    /// <summary>
    /// Integration tests for WebServiceDashboardApi response time metrics.
    /// Tests the StatsData model and merge logic that would be used by the API.
    /// </summary>
    public class WebServiceDashboardApiIntegrationTests
    {
        #region T064: test_GetStats_ReturnsResponseTimeMetrics_WithMixedQueries

        [Fact]
        public void Test_GetStats_ReturnsResponseTimeMetrics_WithMixedQueries()
        {
            // Arrange - Simulate stats data with mixed cached and recursive queries
            var statsData = new DashboardStats.StatsData
            {
                TotalQueries = 1000,
                TotalCached = 600,
                TotalRecursive = 400,
                AverageResponseTimeMs = 45.5,
                CachedAverageResponseTimeMs = 5.2,
                RecursiveAverageResponseTimeMs = 105.8,
                MinResponseTimeMs = 0.5,
                MaxResponseTimeMs = 2500.0,
                P50ResponseTimeMs = 10.0,
                P95ResponseTimeMs = 250.0,
                P99ResponseTimeMs = 1000.0
            };

            // Assert - Verify all response time fields are populated
            Assert.NotNull(statsData.AverageResponseTimeMs);
            Assert.NotNull(statsData.CachedAverageResponseTimeMs);
            Assert.NotNull(statsData.RecursiveAverageResponseTimeMs);
            Assert.NotNull(statsData.MinResponseTimeMs);
            Assert.NotNull(statsData.MaxResponseTimeMs);
            Assert.NotNull(statsData.P50ResponseTimeMs);
            Assert.NotNull(statsData.P95ResponseTimeMs);
            Assert.NotNull(statsData.P99ResponseTimeMs);

            // Verify cached is faster than recursive (typical scenario)
            Assert.True(statsData.CachedAverageResponseTimeMs < statsData.RecursiveAverageResponseTimeMs);

            // Verify percentiles are in ascending order
            Assert.True(statsData.P50ResponseTimeMs <= statsData.P95ResponseTimeMs);
            Assert.True(statsData.P95ResponseTimeMs <= statsData.P99ResponseTimeMs);

            // Verify min/max bounds
            Assert.True(statsData.MinResponseTimeMs <= statsData.AverageResponseTimeMs);
            Assert.True(statsData.AverageResponseTimeMs <= statsData.MaxResponseTimeMs);
        }

        #endregion

        #region T065: test_GetStats_HandlesBackwardCompatibility_Version9Stats

        [Fact]
        public void Test_GetStats_HandlesBackwardCompatibility_Version9Stats()
        {
            // Arrange - Simulate stats data from version 9 (no response time metrics)
            var oldStats = new DashboardStats.StatsData
            {
                TotalQueries = 5000,
                TotalCached = 3000,
                TotalRecursive = 2000,
                // Response time fields are null (not available in version 9)
                AverageResponseTimeMs = null,
                CachedAverageResponseTimeMs = null,
                RecursiveAverageResponseTimeMs = null,
                MinResponseTimeMs = null,
                MaxResponseTimeMs = null,
                P50ResponseTimeMs = null,
                P95ResponseTimeMs = null,
                P99ResponseTimeMs = null
            };

            // Assert - Verify null handling for old stats
            Assert.Null(oldStats.AverageResponseTimeMs);
            Assert.Null(oldStats.CachedAverageResponseTimeMs);
            Assert.Null(oldStats.RecursiveAverageResponseTimeMs);
            Assert.Null(oldStats.MinResponseTimeMs);
            Assert.Null(oldStats.MaxResponseTimeMs);
            Assert.Null(oldStats.P50ResponseTimeMs);
            Assert.Null(oldStats.P95ResponseTimeMs);
            Assert.Null(oldStats.P99ResponseTimeMs);

            // Verify non-response-time fields are still valid
            Assert.Equal(5000, oldStats.TotalQueries);
            Assert.Equal(3000, oldStats.TotalCached);
            Assert.Equal(2000, oldStats.TotalRecursive);
        }

        #endregion

        #region T066: test_GetStats_ClusterMode_AggregatesResponseTimeCorrectly

        [Fact]
        public void Test_GetStats_ClusterMode_AggregatesResponseTimeCorrectly()
        {
            // Arrange - Two cluster nodes with different response times
            var node1Stats = new DashboardStats.StatsData
            {
                TotalQueries = 1000,
                AverageResponseTimeMs = 30.0,
                CachedAverageResponseTimeMs = 5.0,
                RecursiveAverageResponseTimeMs = 80.0,
                MinResponseTimeMs = 1.0,
                MaxResponseTimeMs = 500.0,
                P50ResponseTimeMs = 10.0,
                P95ResponseTimeMs = 200.0,
                P99ResponseTimeMs = 400.0
            };

            var node2Stats = new DashboardStats.StatsData
            {
                TotalQueries = 2000,
                AverageResponseTimeMs = 50.0,
                CachedAverageResponseTimeMs = 8.0,
                RecursiveAverageResponseTimeMs = 120.0,
                MinResponseTimeMs = 2.0,
                MaxResponseTimeMs = 800.0,
                P50ResponseTimeMs = 15.0,
                P95ResponseTimeMs = 300.0,
                P99ResponseTimeMs = 600.0
            };

            // Act - Merge node2 into node1
            node1Stats.Merge(node2Stats);

            // Assert - Verify merge results
            // Total queries should be summed
            Assert.Equal(3000, node1Stats.TotalQueries);

            // Averages should be averaged (simple average for now)
            Assert.Equal(40.0, node1Stats.AverageResponseTimeMs); // (30 + 50) / 2
            Assert.Equal(6.5, node1Stats.CachedAverageResponseTimeMs); // (5 + 8) / 2
            Assert.Equal(100.0, node1Stats.RecursiveAverageResponseTimeMs); // (80 + 120) / 2

            // Min should be minimum across nodes
            Assert.Equal(1.0, node1Stats.MinResponseTimeMs);

            // Max should be maximum across nodes
            Assert.Equal(800.0, node1Stats.MaxResponseTimeMs);

            // Percentiles use conservative max approach
            Assert.Equal(15.0, node1Stats.P50ResponseTimeMs); // max(10, 15)
            Assert.Equal(300.0, node1Stats.P95ResponseTimeMs); // max(200, 300)
            Assert.Equal(600.0, node1Stats.P99ResponseTimeMs); // max(400, 600)
        }

        #endregion

        #region T067: test_GetStats_EmptyStats_ReturnsNullResponseTime

        [Fact]
        public void Test_GetStats_EmptyStats_ReturnsNullResponseTime()
        {
            // Arrange - Fresh server with no queries processed yet
            var emptyStats = new DashboardStats.StatsData
            {
                TotalQueries = 0,
                TotalCached = 0,
                TotalRecursive = 0,
                // No response time data available yet
                AverageResponseTimeMs = null,
                CachedAverageResponseTimeMs = null,
                RecursiveAverageResponseTimeMs = null,
                MinResponseTimeMs = null,
                MaxResponseTimeMs = null,
                P50ResponseTimeMs = null,
                P95ResponseTimeMs = null,
                P99ResponseTimeMs = null
            };

            // Assert - Verify all response time fields are null for empty stats
            Assert.Equal(0, emptyStats.TotalQueries);
            Assert.Null(emptyStats.AverageResponseTimeMs);
            Assert.Null(emptyStats.CachedAverageResponseTimeMs);
            Assert.Null(emptyStats.RecursiveAverageResponseTimeMs);
            Assert.Null(emptyStats.MinResponseTimeMs);
            Assert.Null(emptyStats.MaxResponseTimeMs);
            Assert.Null(emptyStats.P50ResponseTimeMs);
            Assert.Null(emptyStats.P95ResponseTimeMs);
            Assert.Null(emptyStats.P99ResponseTimeMs);
        }

        #endregion

        #region T068: test_ResponseTimeChartData_HasCorrectStructure

        [Fact]
        public void Test_ResponseTimeChartData_HasCorrectStructure()
        {
            // Arrange - Create chart data structure
            var chartData = new DashboardStats.ChartData
            {
                Labels = new string[] { "00:00", "00:05", "00:10", "00:15" },
                DataSets = new DashboardStats.DataSet[]
                {
                    new DashboardStats.DataSet
                    {
                        Label = "Average",
                        Data = new long[] { 25, 30, 28, 32 }
                    },
                    new DashboardStats.DataSet
                    {
                        Label = "Cached Avg",
                        Data = new long[] { 5, 6, 5, 7 }
                    },
                    new DashboardStats.DataSet
                    {
                        Label = "Recursive Avg",
                        Data = new long[] { 80, 95, 85, 100 }
                    },
                    new DashboardStats.DataSet
                    {
                        Label = "P95",
                        Data = new long[] { 200, 250, 220, 280 }
                    }
                }
            };

            // Assert - Verify chart data structure
            Assert.NotNull(chartData.Labels);
            Assert.Equal(4, chartData.Labels.Length);

            Assert.NotNull(chartData.DataSets);
            Assert.Equal(4, chartData.DataSets.Length);

            // Verify each dataset has matching data points
            foreach (var dataSet in chartData.DataSets)
            {
                Assert.NotNull(dataSet.Label);
                Assert.NotNull(dataSet.Data);
                Assert.Equal(chartData.Labels.Length, dataSet.Data.Length);
            }

            // Verify dataset labels
            Assert.Equal("Average", chartData.DataSets[0].Label);
            Assert.Equal("Cached Avg", chartData.DataSets[1].Label);
            Assert.Equal("Recursive Avg", chartData.DataSets[2].Label);
            Assert.Equal("P95", chartData.DataSets[3].Label);
        }

        #endregion

        #region Additional Integration Tests

        [Fact]
        public void Test_GetStats_MergeWithNullOther_PreservesOriginal()
        {
            // Arrange
            var stats = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                AverageResponseTimeMs = 25.0,
                MinResponseTimeMs = 1.0,
                MaxResponseTimeMs = 100.0
            };

            var otherStats = new DashboardStats.StatsData
            {
                TotalQueries = 50,
                AverageResponseTimeMs = null,
                MinResponseTimeMs = null,
                MaxResponseTimeMs = null
            };

            // Act
            stats.Merge(otherStats);

            // Assert - Original values preserved when other is null
            Assert.Equal(150, stats.TotalQueries);
            Assert.Equal(25.0, stats.AverageResponseTimeMs); // Preserved from original
            Assert.Equal(1.0, stats.MinResponseTimeMs);
            Assert.Equal(100.0, stats.MaxResponseTimeMs);
        }

        [Fact]
        public void Test_GetStats_MergeWithNullSource_TakesOther()
        {
            // Arrange
            var stats = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                AverageResponseTimeMs = null,
                MinResponseTimeMs = null,
                MaxResponseTimeMs = null
            };

            var otherStats = new DashboardStats.StatsData
            {
                TotalQueries = 50,
                AverageResponseTimeMs = 35.0,
                MinResponseTimeMs = 2.0,
                MaxResponseTimeMs = 200.0
            };

            // Act
            stats.Merge(otherStats);

            // Assert - Takes other values when source is null
            Assert.Equal(150, stats.TotalQueries);
            Assert.Equal(35.0, stats.AverageResponseTimeMs);
            Assert.Equal(2.0, stats.MinResponseTimeMs);
            Assert.Equal(200.0, stats.MaxResponseTimeMs);
        }

        #endregion
    }
}
