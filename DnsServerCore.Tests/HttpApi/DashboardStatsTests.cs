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

namespace DnsServerCore.Tests.HttpApi
{
    /// <summary>
    /// Unit tests for StatsData class response time merge logic.
    /// Tests T025-T027 from tasks.md.
    /// </summary>
    public class DashboardStatsTests
    {
        #region T025: test_StatsData_Merge_WeightedAverageResponseTime

        [Fact]
        public void Test_StatsData_Merge_WeightedAverageResponseTime()
        {
            // Arrange
            var stats1 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                AverageResponseTimeMs = 20.0,
                CachedAverageResponseTimeMs = 10.0,
                RecursiveAverageResponseTimeMs = 50.0
            };

            var stats2 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                AverageResponseTimeMs = 40.0,
                CachedAverageResponseTimeMs = 20.0,
                RecursiveAverageResponseTimeMs = 100.0
            };

            // Act
            stats1.Merge(stats2);

            // Assert - Simple average (weighted equally)
            Assert.Equal(30.0, stats1.AverageResponseTimeMs);
            Assert.Equal(15.0, stats1.CachedAverageResponseTimeMs);
            Assert.Equal(75.0, stats1.RecursiveAverageResponseTimeMs);
        }

        [Fact]
        public void Test_StatsData_Merge_AverageWithNullSource()
        {
            // Arrange - stats1 has null response time
            var stats1 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                AverageResponseTimeMs = null
            };

            var stats2 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                AverageResponseTimeMs = 40.0
            };

            // Act
            stats1.Merge(stats2);

            // Assert - Should take stats2's value
            Assert.Equal(40.0, stats1.AverageResponseTimeMs);
        }

        [Fact]
        public void Test_StatsData_Merge_AverageWithNullOther()
        {
            // Arrange - stats2 has null response time
            var stats1 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                AverageResponseTimeMs = 20.0
            };

            var stats2 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                AverageResponseTimeMs = null
            };

            // Act
            stats1.Merge(stats2);

            // Assert - Should keep stats1's value
            Assert.Equal(20.0, stats1.AverageResponseTimeMs);
        }

        #endregion

        #region T026: test_StatsData_Merge_MinMaxAcrossNodes

        [Fact]
        public void Test_StatsData_Merge_MinMaxAcrossNodes()
        {
            // Arrange
            var stats1 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                MinResponseTimeMs = 5.0,
                MaxResponseTimeMs = 150.0
            };

            var stats2 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                MinResponseTimeMs = 2.0,  // Lower min
                MaxResponseTimeMs = 300.0 // Higher max
            };

            // Act
            stats1.Merge(stats2);

            // Assert - Min takes the lowest, Max takes the highest
            Assert.Equal(2.0, stats1.MinResponseTimeMs);
            Assert.Equal(300.0, stats1.MaxResponseTimeMs);
        }

        [Fact]
        public void Test_StatsData_Merge_MinMaxKeepsOriginalWhenBetter()
        {
            // Arrange
            var stats1 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                MinResponseTimeMs = 1.0,   // Lower min
                MaxResponseTimeMs = 500.0  // Higher max
            };

            var stats2 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                MinResponseTimeMs = 5.0,
                MaxResponseTimeMs = 200.0
            };

            // Act
            stats1.Merge(stats2);

            // Assert - Original values preserved
            Assert.Equal(1.0, stats1.MinResponseTimeMs);
            Assert.Equal(500.0, stats1.MaxResponseTimeMs);
        }

        [Fact]
        public void Test_StatsData_Merge_MinMaxWithNulls()
        {
            // Arrange
            var stats1 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                MinResponseTimeMs = null,
                MaxResponseTimeMs = null
            };

            var stats2 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                MinResponseTimeMs = 5.0,
                MaxResponseTimeMs = 200.0
            };

            // Act
            stats1.Merge(stats2);

            // Assert - Takes stats2's values
            Assert.Equal(5.0, stats1.MinResponseTimeMs);
            Assert.Equal(200.0, stats1.MaxResponseTimeMs);
        }

        #endregion

        #region T027: test_StatsData_NullHandling_OldStatsWithoutResponseTime

        [Fact]
        public void Test_StatsData_NullHandling_OldStatsWithoutResponseTime()
        {
            // Arrange - Simulate old stats (version 9) without response time data
            var oldStats = new DashboardStats.StatsData
            {
                TotalQueries = 1000,
                TotalNoError = 950,
                TotalServerFailure = 10,
                TotalNxDomain = 30,
                TotalRefused = 10,
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

            // Assert - All response time fields should be null
            Assert.Null(oldStats.AverageResponseTimeMs);
            Assert.Null(oldStats.CachedAverageResponseTimeMs);
            Assert.Null(oldStats.RecursiveAverageResponseTimeMs);
            Assert.Null(oldStats.MinResponseTimeMs);
            Assert.Null(oldStats.MaxResponseTimeMs);
            Assert.Null(oldStats.P50ResponseTimeMs);
            Assert.Null(oldStats.P95ResponseTimeMs);
            Assert.Null(oldStats.P99ResponseTimeMs);
        }

        [Fact]
        public void Test_StatsData_Merge_OldStatsWithNewStats()
        {
            // Arrange - Old stats (no response time) merged with new stats (has response time)
            var oldStats = new DashboardStats.StatsData
            {
                TotalQueries = 1000,
                AverageResponseTimeMs = null,
                MinResponseTimeMs = null,
                MaxResponseTimeMs = null
            };

            var newStats = new DashboardStats.StatsData
            {
                TotalQueries = 500,
                AverageResponseTimeMs = 25.0,
                MinResponseTimeMs = 5.0,
                MaxResponseTimeMs = 150.0
            };

            // Act
            oldStats.Merge(newStats);

            // Assert - New stats' response time values should be adopted
            Assert.Equal(25.0, oldStats.AverageResponseTimeMs);
            Assert.Equal(5.0, oldStats.MinResponseTimeMs);
            Assert.Equal(150.0, oldStats.MaxResponseTimeMs);
            Assert.Equal(1500, oldStats.TotalQueries); // Queries merged
        }

        [Fact]
        public void Test_StatsData_Merge_NewStatsWithOldStats()
        {
            // Arrange - New stats (has response time) merged with old stats (no response time)
            var newStats = new DashboardStats.StatsData
            {
                TotalQueries = 500,
                AverageResponseTimeMs = 25.0,
                MinResponseTimeMs = 5.0,
                MaxResponseTimeMs = 150.0
            };

            var oldStats = new DashboardStats.StatsData
            {
                TotalQueries = 1000,
                AverageResponseTimeMs = null,
                MinResponseTimeMs = null,
                MaxResponseTimeMs = null
            };

            // Act
            newStats.Merge(oldStats);

            // Assert - New stats' response time values should be preserved
            Assert.Equal(25.0, newStats.AverageResponseTimeMs);
            Assert.Equal(5.0, newStats.MinResponseTimeMs);
            Assert.Equal(150.0, newStats.MaxResponseTimeMs);
            Assert.Equal(1500, newStats.TotalQueries);
        }

        #endregion

        #region Percentile merge tests (conservative approach)

        [Fact]
        public void Test_StatsData_Merge_PercentilesUseConservativeMax()
        {
            // Arrange
            var stats1 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                P50ResponseTimeMs = 10.0,
                P95ResponseTimeMs = 100.0,
                P99ResponseTimeMs = 200.0
            };

            var stats2 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                P50ResponseTimeMs = 15.0,   // Higher
                P95ResponseTimeMs = 80.0,   // Lower
                P99ResponseTimeMs = 250.0   // Higher
            };

            // Act
            stats1.Merge(stats2);

            // Assert - Conservative: takes max across nodes
            Assert.Equal(15.0, stats1.P50ResponseTimeMs);  // Max of 10 and 15
            Assert.Equal(100.0, stats1.P95ResponseTimeMs); // Max of 100 and 80
            Assert.Equal(250.0, stats1.P99ResponseTimeMs); // Max of 200 and 250
        }

        [Fact]
        public void Test_StatsData_Merge_PercentilesWithNullSource()
        {
            // Arrange
            var stats1 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                P50ResponseTimeMs = null,
                P95ResponseTimeMs = null,
                P99ResponseTimeMs = null
            };

            var stats2 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                P50ResponseTimeMs = 15.0,
                P95ResponseTimeMs = 100.0,
                P99ResponseTimeMs = 250.0
            };

            // Act
            stats1.Merge(stats2);

            // Assert - Takes stats2's values
            Assert.Equal(15.0, stats1.P50ResponseTimeMs);
            Assert.Equal(100.0, stats1.P95ResponseTimeMs);
            Assert.Equal(250.0, stats1.P99ResponseTimeMs);
        }

        #endregion

        #region Edge cases

        [Fact]
        public void Test_StatsData_Merge_BothNull()
        {
            // Arrange
            var stats1 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                AverageResponseTimeMs = null
            };

            var stats2 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                AverageResponseTimeMs = null
            };

            // Act
            stats1.Merge(stats2);

            // Assert - Stays null
            Assert.Null(stats1.AverageResponseTimeMs);
        }

        [Fact]
        public void Test_StatsData_Merge_PreservesNonResponseTimeFields()
        {
            // Arrange
            var stats1 = new DashboardStats.StatsData
            {
                TotalQueries = 100,
                TotalNoError = 90,
                TotalServerFailure = 5,
                TotalNxDomain = 3,
                TotalRefused = 2,
                Zones = 10,
                CachedEntries = 5000
            };

            var stats2 = new DashboardStats.StatsData
            {
                TotalQueries = 200,
                TotalNoError = 180,
                TotalServerFailure = 10,
                TotalNxDomain = 5,
                TotalRefused = 5,
                Zones = 15,
                CachedEntries = 8000
            };

            // Act
            stats1.Merge(stats2);

            // Assert - Non-response-time fields merged correctly
            Assert.Equal(300, stats1.TotalQueries);
            Assert.Equal(270, stats1.TotalNoError);
            Assert.Equal(15, stats1.TotalServerFailure);
            Assert.Equal(8, stats1.TotalNxDomain);
            Assert.Equal(7, stats1.TotalRefused);
            Assert.Equal(15, stats1.Zones);  // Max
            Assert.Equal(8000, stats1.CachedEntries);  // Max
        }

        #endregion
    }
}
