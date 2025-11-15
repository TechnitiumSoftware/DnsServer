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

using DnsServerCore.Auth;
using DnsServerCore.HttpApi.Models;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        class WebServiceDashboardApi
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            const int CLUSTER_NODE_DASHBOARD_STATS_API_TIMEOUT = 10000;

            #endregion

            #region constructor

            public WebServiceDashboardApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            private static void WriteChartDataSet(Utf8JsonWriter jsonWriter, DashboardStats.DataSet dataSet, string backgroundColor, string borderColor)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WriteString("label", dataSet.Label);
                jsonWriter.WriteString("backgroundColor", backgroundColor);
                jsonWriter.WriteString("borderColor", borderColor);
                jsonWriter.WriteNumber("borderWidth", 2);
                jsonWriter.WriteBoolean("fill", true);

                jsonWriter.WritePropertyName("data");
                jsonWriter.WriteStartArray();

                foreach (long value in dataSet.Data)
                    jsonWriter.WriteNumberValue(value);

                jsonWriter.WriteEndArray();

                jsonWriter.WriteEndObject();
            }

            private async Task ResolvePtrTopClientsAsync(DashboardStats.TopClientStats[] topClients)
            {
                IDictionary<string, string> dhcpClientIpMap = _dnsWebService._dhcpServer.GetAddressHostNameMap();

                async Task ResolvePtrAsync(DashboardStats.TopClientStats item)
                {
                    string ip = item.Name;

                    if (dhcpClientIpMap.TryGetValue(ip, out string dhcpDomain))
                    {
                        item.Domain = dhcpDomain;
                        return;
                    }

                    IPAddress address = IPAddress.Parse(ip);

                    if (IPAddress.IsLoopback(address))
                    {
                        item.Domain = "localhost";
                        return;
                    }

                    DnsDatagram ptrResponse = await _dnsWebService._dnsServer.DirectQueryAsync(new DnsQuestionRecord(address, DnsClass.IN), 500);
                    if (ptrResponse.Answer.Count > 0)
                    {
                        IReadOnlyList<string> ptrDomains = DnsClient.ParseResponsePTR(ptrResponse);
                        if (ptrDomains.Count > 0)
                        {
                            item.Domain = ptrDomains[0];
                            return;
                        }
                    }
                }

                List<Task> resolverTasks = new List<Task>(topClients.Length);

                foreach (DashboardStats.TopClientStats item in topClients)
                {
                    if (string.IsNullOrEmpty(item.Domain))
                        resolverTasks.Add(ResolvePtrAsync(item));
                }

                foreach (Task resolverTask in resolverTasks)
                {
                    try
                    {
                        await resolverTask;
                    }
                    catch
                    { }
                }
            }

            #endregion

            #region public

            public async Task GetStats(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Dashboard, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                DashboardStatsType type = request.GetQueryOrFormEnum("type", DashboardStatsType.LastHour);
                bool utcFormat = request.GetQueryOrForm("utc", bool.Parse, false);

                bool isLanguageEnUs = true;
                string acceptLanguage = request.Headers.AcceptLanguage;
                if (!string.IsNullOrEmpty(acceptLanguage))
                    isLanguageEnUs = acceptLanguage.StartsWith("en-us", StringComparison.OrdinalIgnoreCase);

                bool dontTrimQueryTypeData = request.GetQueryOrForm("dontTrimQueryTypeData", bool.Parse, false);

                DateTime startDate = default;
                DateTime endDate = default;

                if (type == DashboardStatsType.Custom)
                {
                    string strStartDate = request.GetQueryOrForm("start");
                    string strEndDate = request.GetQueryOrForm("end");

                    if (!DateTime.TryParse(strStartDate, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out startDate))
                        throw new DnsWebServiceException("Invalid start date format.");

                    if (!DateTime.TryParse(strEndDate, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out endDate))
                        throw new DnsWebServiceException("Invalid end date format.");

                    if (startDate > endDate)
                        throw new DnsWebServiceException("Start date must be less than or equal to end date.");
                }

                List<Task<DashboardStats>> tasks = null;

                if (_dnsWebService._clusterManager.ClusterInitialized)
                {
                    string node = request.GetQueryOrForm("node", null);
                    if ("cluster".Equals(node, StringComparison.OrdinalIgnoreCase))
                    {
                        IReadOnlyDictionary<int, Cluster.ClusterNode> clusterNodes = _dnsWebService._clusterManager.ClusterNodes;
                        tasks = new List<Task<DashboardStats>>(clusterNodes.Count);

                        foreach (KeyValuePair<int, Cluster.ClusterNode> clusterNode in clusterNodes)
                        {
                            if (clusterNode.Value.State == Cluster.ClusterNodeState.Self)
                                continue;

                            tasks.Add(TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                            {
                                return clusterNode.Value.GetDashboardStatsAsync(type, utcFormat, acceptLanguage, true, startDate, endDate, cancellationToken1);
                            }, CLUSTER_NODE_DASHBOARD_STATS_API_TIMEOUT));
                        }
                    }
                }

                DashboardStats dashboardStats;
                string labelFormat;

                switch (type)
                {
                    case DashboardStatsType.LastHour:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetLastHourMinuteWiseStats(utcFormat);
                        labelFormat = "HH:mm";
                        break;

                    case DashboardStatsType.LastDay:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetLastDayHourWiseStats(utcFormat);

                        if (isLanguageEnUs)
                            labelFormat = "MM/DD HH:00";
                        else
                            labelFormat = "DD/MM HH:00";

                        break;

                    case DashboardStatsType.LastWeek:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetLastWeekDayWiseStats(utcFormat);

                        if (isLanguageEnUs)
                            labelFormat = "MM/DD";
                        else
                            labelFormat = "DD/MM";

                        break;

                    case DashboardStatsType.LastMonth:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetLastMonthDayWiseStats(utcFormat);

                        if (isLanguageEnUs)
                            labelFormat = "MM/DD";
                        else
                            labelFormat = "DD/MM";

                        break;

                    case DashboardStatsType.LastYear:
                        labelFormat = "MM/YYYY";
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetLastYearMonthWiseStats(utcFormat);
                        break;

                    case DashboardStatsType.Custom:
                        TimeSpan duration = endDate - startDate;

                        if ((Convert.ToInt32(duration.TotalDays) + 1) > 7)
                        {
                            dashboardStats = _dnsWebService._dnsServer.StatsManager.GetDayWiseStats(startDate, endDate, utcFormat);

                            if (isLanguageEnUs)
                                labelFormat = "MM/DD";
                            else
                                labelFormat = "DD/MM";
                        }
                        else if ((Convert.ToInt32(duration.TotalHours) + 1) > 3)
                        {
                            dashboardStats = _dnsWebService._dnsServer.StatsManager.GetHourWiseStats(startDate, endDate, utcFormat);

                            if (isLanguageEnUs)
                                labelFormat = "MM/DD HH:00";
                            else
                                labelFormat = "DD/MM HH:00";
                        }
                        else
                        {
                            dashboardStats = _dnsWebService._dnsServer.StatsManager.GetMinuteWiseStats(startDate, endDate, utcFormat);

                            if (isLanguageEnUs)
                                labelFormat = "MM/DD HH:mm";
                            else
                                labelFormat = "DD/MM HH:mm";
                        }

                        break;

                    default:
                        throw new DnsWebServiceException("Unknown stats type requested: " + type.ToString());
                }

                //add extra stats
                {
                    dashboardStats.Stats.Zones = _dnsWebService._dnsServer.AuthZoneManager.TotalZones;
                    dashboardStats.Stats.CachedEntries = _dnsWebService._dnsServer.CacheZoneManager.TotalEntries;
                    dashboardStats.Stats.AllowedZones = _dnsWebService._dnsServer.AllowedZoneManager.TotalZonesAllowed;
                    dashboardStats.Stats.BlockedZones = _dnsWebService._dnsServer.BlockedZoneManager.TotalZonesBlocked;
                    dashboardStats.Stats.AllowListZones = _dnsWebService._dnsServer.BlockListZoneManager.TotalZonesAllowed;
                    dashboardStats.Stats.BlockListZones = _dnsWebService._dnsServer.BlockListZoneManager.TotalZonesBlocked;
                }

                if (tasks is not null)
                {
                    foreach (Task<DashboardStats> task in tasks)
                    {
                        try
                        {
                            dashboardStats.Merge(await task, 10);
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    }
                }

                if (!dontTrimQueryTypeData)
                    dashboardStats.QueryTypeChartData.Trim(10); //trim query type data

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                //stats
                {
                    jsonWriter.WritePropertyName("stats");
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteNumber("totalQueries", dashboardStats.Stats.TotalQueries);
                    jsonWriter.WriteNumber("totalNoError", dashboardStats.Stats.TotalNoError);
                    jsonWriter.WriteNumber("totalServerFailure", dashboardStats.Stats.TotalServerFailure);
                    jsonWriter.WriteNumber("totalNxDomain", dashboardStats.Stats.TotalNxDomain);
                    jsonWriter.WriteNumber("totalRefused", dashboardStats.Stats.TotalRefused);

                    jsonWriter.WriteNumber("totalAuthoritative", dashboardStats.Stats.TotalAuthoritative);
                    jsonWriter.WriteNumber("totalRecursive", dashboardStats.Stats.TotalRecursive);
                    jsonWriter.WriteNumber("totalCached", dashboardStats.Stats.TotalCached);
                    jsonWriter.WriteNumber("totalBlocked", dashboardStats.Stats.TotalBlocked);
                    jsonWriter.WriteNumber("totalDropped", dashboardStats.Stats.TotalDropped);

                    jsonWriter.WriteNumber("totalClients", dashboardStats.Stats.TotalClients);

                    jsonWriter.WriteNumber("zones", dashboardStats.Stats.Zones);
                    jsonWriter.WriteNumber("cachedEntries", dashboardStats.Stats.CachedEntries);
                    jsonWriter.WriteNumber("allowedZones", dashboardStats.Stats.AllowedZones);
                    jsonWriter.WriteNumber("blockedZones", dashboardStats.Stats.BlockedZones);
                    jsonWriter.WriteNumber("allowListZones", dashboardStats.Stats.AllowListZones);
                    jsonWriter.WriteNumber("blockListZones", dashboardStats.Stats.BlockListZones);

                    jsonWriter.WriteEndObject();
                }

                //main chart
                {
                    jsonWriter.WritePropertyName("mainChartData");
                    jsonWriter.WriteStartObject();

                    //label format
                    {
                        jsonWriter.WriteString("labelFormat", labelFormat);
                    }

                    //label
                    {
                        jsonWriter.WritePropertyName("labels");
                        jsonWriter.WriteStartArray();

                        foreach (string label in dashboardStats.MainChartData.Labels)
                            jsonWriter.WriteStringValue(label);

                        jsonWriter.WriteEndArray();
                    }

                    //datasets
                    {
                        jsonWriter.WritePropertyName("datasets");
                        jsonWriter.WriteStartArray();

                        foreach (DashboardStats.DataSet dataSet in dashboardStats.MainChartData.DataSets)
                        {
                            string backgroundColor;
                            string borderColor;

                            switch (dataSet.Label)
                            {
                                case "Total":
                                    backgroundColor = "rgba(102, 153, 255, 0.1)";
                                    borderColor = "rgb(102, 153, 255)";
                                    break;

                                case "No Error":
                                    backgroundColor = "rgba(92, 184, 92, 0.1)";
                                    borderColor = "rgb(92, 184, 92)";
                                    break;

                                case "Server Failure":
                                    backgroundColor = "rgba(217, 83, 79, 0.1)";
                                    borderColor = "rgb(217, 83, 79)";
                                    break;

                                case "NX Domain":
                                    backgroundColor = "rgba(120, 120, 120, 0.1)";
                                    borderColor = "rgb(120, 120, 120)";
                                    break;

                                case "Refused":
                                    backgroundColor = "rgba(91, 192, 222, 0.1)";
                                    borderColor = "rgb(91, 192, 222)";
                                    break;

                                case "Authoritative":
                                    backgroundColor = "rgba(150, 150, 0, 0.1)";
                                    borderColor = "rgb(150, 150, 0)";
                                    break;

                                case "Recursive":
                                    backgroundColor = "rgba(23, 162, 184, 0.1)";
                                    borderColor = "rgb(23, 162, 184)";
                                    break;

                                case "Cached":
                                    backgroundColor = "rgba(111, 84, 153, 0.1)";
                                    borderColor = "rgb(111, 84, 153)";
                                    break;

                                case "Blocked":
                                    backgroundColor = "rgba(255, 165, 0, 0.1)";
                                    borderColor = "rgb(255, 165, 0)";
                                    break;

                                case "Dropped":
                                    backgroundColor = "rgba(30, 30, 30, 0.1)";
                                    borderColor = "rgb(30, 30, 30)";
                                    break;

                                case "Clients":
                                    backgroundColor = "rgba(51, 122, 183, 0.1)";
                                    borderColor = "rgb(51, 122, 183)";
                                    break;

                                default:
                                    throw new InvalidOperationException();
                            }

                            WriteChartDataSet(jsonWriter, dataSet, backgroundColor, borderColor);
                        }

                        jsonWriter.WriteEndArray();
                    }

                    jsonWriter.WriteEndObject();
                }

                //query response chart
                {
                    jsonWriter.WritePropertyName("queryResponseChartData");
                    jsonWriter.WriteStartObject();

                    //labels
                    {
                        jsonWriter.WritePropertyName("labels");
                        jsonWriter.WriteStartArray();

                        foreach (string label in dashboardStats.QueryResponseChartData.Labels)
                            jsonWriter.WriteStringValue(label);

                        jsonWriter.WriteEndArray();
                    }

                    //datasets
                    {
                        jsonWriter.WritePropertyName("datasets");
                        jsonWriter.WriteStartArray();

                        jsonWriter.WriteStartObject();

                        jsonWriter.WritePropertyName("data");
                        jsonWriter.WriteStartArray();

                        foreach (long value in dashboardStats.QueryResponseChartData.DataSets[0].Data)
                            jsonWriter.WriteNumberValue(value);

                        jsonWriter.WriteEndArray();

                        jsonWriter.WritePropertyName("backgroundColor");
                        jsonWriter.WriteStartArray();
                        jsonWriter.WriteStringValue("rgba(150, 150, 0, 0.5)");
                        jsonWriter.WriteStringValue("rgba(23, 162, 184, 0.5)");
                        jsonWriter.WriteStringValue("rgba(111, 84, 153, 0.5)");
                        jsonWriter.WriteStringValue("rgba(255, 165, 0, 0.5)");
                        jsonWriter.WriteStringValue("rgba(7, 7, 7, 0.5)");
                        jsonWriter.WriteEndArray();

                        jsonWriter.WriteEndObject();

                        jsonWriter.WriteEndArray();
                    }

                    jsonWriter.WriteEndObject();
                }

                //query type chart
                {
                    jsonWriter.WritePropertyName("queryTypeChartData");
                    jsonWriter.WriteStartObject();

                    //labels
                    {
                        jsonWriter.WritePropertyName("labels");
                        jsonWriter.WriteStartArray();

                        foreach (string label in dashboardStats.QueryTypeChartData.Labels)
                            jsonWriter.WriteStringValue(label);

                        jsonWriter.WriteEndArray();
                    }

                    //datasets
                    {
                        jsonWriter.WritePropertyName("datasets");
                        jsonWriter.WriteStartArray();

                        jsonWriter.WriteStartObject();

                        jsonWriter.WritePropertyName("data");
                        jsonWriter.WriteStartArray();

                        foreach (long value in dashboardStats.QueryTypeChartData.DataSets[0].Data)
                            jsonWriter.WriteNumberValue(value);

                        jsonWriter.WriteEndArray();

                        jsonWriter.WritePropertyName("backgroundColor");
                        jsonWriter.WriteStartArray();
                        jsonWriter.WriteStringValue("rgba(102, 153, 255, 0.5)");
                        jsonWriter.WriteStringValue("rgba(92, 184, 92, 0.5)");
                        jsonWriter.WriteStringValue("rgba(7, 7, 7, 0.5)");
                        jsonWriter.WriteStringValue("rgba(91, 192, 222, 0.5)");
                        jsonWriter.WriteStringValue("rgba(150, 150, 0, 0.5)");
                        jsonWriter.WriteStringValue("rgba(23, 162, 184, 0.5)");
                        jsonWriter.WriteStringValue("rgba(111, 84, 153, 0.5)");
                        jsonWriter.WriteStringValue("rgba(255, 165, 0, 0.5)");
                        jsonWriter.WriteStringValue("rgba(51, 122, 183, 0.5)");
                        jsonWriter.WriteStringValue("rgba(150, 150, 150, 0.5)");
                        jsonWriter.WriteEndArray();

                        jsonWriter.WriteEndObject();

                        jsonWriter.WriteEndArray();
                    }

                    jsonWriter.WriteEndObject();
                }

                //protocol type chart
                {
                    jsonWriter.WritePropertyName("protocolTypeChartData");
                    jsonWriter.WriteStartObject();

                    //labels
                    {
                        jsonWriter.WritePropertyName("labels");
                        jsonWriter.WriteStartArray();

                        foreach (string label in dashboardStats.ProtocolTypeChartData.Labels)
                            jsonWriter.WriteStringValue(label);

                        jsonWriter.WriteEndArray();
                    }

                    //datasets
                    {
                        jsonWriter.WritePropertyName("datasets");
                        jsonWriter.WriteStartArray();

                        jsonWriter.WriteStartObject();

                        jsonWriter.WritePropertyName("data");
                        jsonWriter.WriteStartArray();

                        foreach (long value in dashboardStats.ProtocolTypeChartData.DataSets[0].Data)
                            jsonWriter.WriteNumberValue(value);

                        jsonWriter.WriteEndArray();

                        jsonWriter.WritePropertyName("backgroundColor");
                        jsonWriter.WriteStartArray();
                        jsonWriter.WriteStringValue("rgba(111, 84, 153, 0.5)");
                        jsonWriter.WriteStringValue("rgba(150, 150, 0, 0.5)");
                        jsonWriter.WriteStringValue("rgba(23, 162, 184, 0.5)"); ;
                        jsonWriter.WriteStringValue("rgba(255, 165, 0, 0.5)");
                        jsonWriter.WriteStringValue("rgba(91, 192, 222, 0.5)");
                        jsonWriter.WriteEndArray();

                        jsonWriter.WriteEndObject();

                        jsonWriter.WriteEndArray();
                    }

                    jsonWriter.WriteEndObject();
                }

                //top clients
                {
                    await ResolvePtrTopClientsAsync(dashboardStats.TopClients);

                    jsonWriter.WritePropertyName("topClients");
                    jsonWriter.WriteStartArray();

                    foreach (DashboardStats.TopClientStats item in dashboardStats.TopClients)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("name", item.Name);

                        if (!string.IsNullOrEmpty(item.Domain))
                            jsonWriter.WriteString("domain", item.Domain);

                        jsonWriter.WriteNumber("hits", item.Hits);

                        IPAddress ip = IPAddress.Parse(item.Name);
                        jsonWriter.WriteBoolean("rateLimited", item.RateLimited || _dnsWebService._dnsServer.HasQpmLimitExceeded(ip, DnsTransportProtocol.Udp) || _dnsWebService._dnsServer.HasQpmLimitExceeded(ip, DnsTransportProtocol.Tcp));

                        jsonWriter.WriteEndObject();
                    }

                    jsonWriter.WriteEndArray();
                }

                //top domains
                {
                    jsonWriter.WritePropertyName("topDomains");
                    jsonWriter.WriteStartArray();

                    foreach (DashboardStats.TopStats item in dashboardStats.TopDomains)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("name", item.Name);

                        if (DnsClient.TryConvertDomainNameToUnicode(item.Name, out string idn))
                            jsonWriter.WriteString("nameIdn", idn);

                        jsonWriter.WriteNumber("hits", item.Hits);

                        jsonWriter.WriteEndObject();
                    }

                    jsonWriter.WriteEndArray();
                }

                //top blocked domains
                {
                    jsonWriter.WritePropertyName("topBlockedDomains");
                    jsonWriter.WriteStartArray();

                    foreach (DashboardStats.TopStats item in dashboardStats.TopBlockedDomains)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("name", item.Name);

                        if (DnsClient.TryConvertDomainNameToUnicode(item.Name, out string idn))
                            jsonWriter.WriteString("nameIdn", idn);

                        jsonWriter.WriteNumber("hits", item.Hits);

                        jsonWriter.WriteEndObject();
                    }

                    jsonWriter.WriteEndArray();
                }
            }

            public async Task GetTopStats(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Dashboard, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                DashboardStatsType type = request.GetQueryOrFormEnum("type", DashboardStatsType.LastHour);
                DashboardTopStatsType statsType = request.GetQueryOrFormEnum<DashboardTopStatsType>("statsType");
                int limit = request.GetQueryOrForm("limit", int.Parse, 1000);

                DateTime startDate = default;
                DateTime endDate = default;

                if (type == DashboardStatsType.Custom)
                {
                    string strStartDate = request.GetQueryOrForm("start");
                    string strEndDate = request.GetQueryOrForm("end");

                    if (!DateTime.TryParse(strStartDate, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out startDate))
                        throw new DnsWebServiceException("Invalid start date format.");

                    if (!DateTime.TryParse(strEndDate, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out endDate))
                        throw new DnsWebServiceException("Invalid end date format.");

                    if (startDate > endDate)
                        throw new DnsWebServiceException("Start date must be less than or equal to end date.");
                }

                List<Task<DashboardStats>> tasks = null;

                if (_dnsWebService._clusterManager.ClusterInitialized)
                {
                    string node = request.GetQueryOrForm("node", null);
                    if ("cluster".Equals(node, StringComparison.OrdinalIgnoreCase))
                    {
                        IReadOnlyDictionary<int, Cluster.ClusterNode> clusterNodes = _dnsWebService._clusterManager.ClusterNodes;
                        tasks = new List<Task<DashboardStats>>(clusterNodes.Count);

                        foreach (KeyValuePair<int, Cluster.ClusterNode> clusterNode in clusterNodes)
                        {
                            if (clusterNode.Value.State == Cluster.ClusterNodeState.Self)
                                continue;

                            tasks.Add(TechnitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                            {
                                return clusterNode.Value.GetDashboardTopStatsAsync(statsType, limit, type, startDate, endDate, cancellationToken1);
                            }, CLUSTER_NODE_DASHBOARD_STATS_API_TIMEOUT));
                        }
                    }
                }

                DashboardStats topStatsData;

                switch (type)
                {
                    case DashboardStatsType.LastHour:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetLastHourTopStats(statsType, limit);
                        break;

                    case DashboardStatsType.LastDay:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetLastDayTopStats(statsType, limit);
                        break;

                    case DashboardStatsType.LastWeek:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetLastWeekTopStats(statsType, limit);
                        break;

                    case DashboardStatsType.LastMonth:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetLastMonthTopStats(statsType, limit);
                        break;

                    case DashboardStatsType.LastYear:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetLastYearTopStats(statsType, limit);
                        break;

                    case DashboardStatsType.Custom:
                        TimeSpan duration = endDate - startDate;

                        if ((Convert.ToInt32(duration.TotalDays) + 1) > 7)
                            topStatsData = _dnsWebService._dnsServer.StatsManager.GetDayWiseTopStats(startDate, endDate, statsType, limit);
                        else if ((Convert.ToInt32(duration.TotalHours) + 1) > 3)
                            topStatsData = _dnsWebService._dnsServer.StatsManager.GetHourWiseTopStats(startDate, endDate, statsType, limit);
                        else
                            topStatsData = _dnsWebService._dnsServer.StatsManager.GetMinuteWiseTopStats(startDate, endDate, statsType, limit);

                        break;

                    default:
                        throw new DnsWebServiceException("Unknown stats type requested: " + type.ToString());
                }

                if (tasks is not null)
                {
                    foreach (Task<DashboardStats> task in tasks)
                    {
                        try
                        {
                            topStatsData.Merge(await task, limit);
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    }
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                switch (statsType)
                {
                    case DashboardTopStatsType.TopClients:
                        {
                            bool noReverseLookup = request.GetQueryOrForm("noReverseLookup", bool.Parse, false);
                            bool onlyRateLimitedClients = request.GetQueryOrForm("onlyRateLimitedClients", bool.Parse, false);

                            if (!noReverseLookup)
                                await ResolvePtrTopClientsAsync(topStatsData.TopClients);

                            jsonWriter.WritePropertyName("topClients");
                            jsonWriter.WriteStartArray();

                            foreach (DashboardStats.TopClientStats item in topStatsData.TopClients)
                            {
                                IPAddress ip = IPAddress.Parse(item.Name);
                                bool rateLimited = item.RateLimited || _dnsWebService._dnsServer.HasQpmLimitExceeded(ip, DnsTransportProtocol.Udp) || _dnsWebService._dnsServer.HasQpmLimitExceeded(ip, DnsTransportProtocol.Tcp);

                                if (onlyRateLimitedClients && !rateLimited)
                                    continue;

                                jsonWriter.WriteStartObject();

                                jsonWriter.WriteString("name", item.Name);

                                if (!string.IsNullOrEmpty(item.Domain))
                                    jsonWriter.WriteString("domain", item.Domain);

                                jsonWriter.WriteNumber("hits", item.Hits);
                                jsonWriter.WriteBoolean("rateLimited", rateLimited);

                                jsonWriter.WriteEndObject();
                            }

                            jsonWriter.WriteEndArray();
                        }
                        break;

                    case DashboardTopStatsType.TopDomains:
                        {
                            jsonWriter.WritePropertyName("topDomains");
                            jsonWriter.WriteStartArray();

                            foreach (DashboardStats.TopStats item in topStatsData.TopDomains)
                            {
                                jsonWriter.WriteStartObject();

                                jsonWriter.WriteString("name", item.Name);

                                if (DnsClient.TryConvertDomainNameToUnicode(item.Name, out string idn))
                                    jsonWriter.WriteString("nameIdn", idn);

                                jsonWriter.WriteNumber("hits", item.Hits);

                                jsonWriter.WriteEndObject();
                            }

                            jsonWriter.WriteEndArray();
                        }
                        break;

                    case DashboardTopStatsType.TopBlockedDomains:
                        {
                            jsonWriter.WritePropertyName("topBlockedDomains");
                            jsonWriter.WriteStartArray();

                            foreach (DashboardStats.TopStats item in topStatsData.TopBlockedDomains)
                            {
                                jsonWriter.WriteStartObject();

                                jsonWriter.WriteString("name", item.Name);

                                if (DnsClient.TryConvertDomainNameToUnicode(item.Name, out string idn))
                                    jsonWriter.WriteString("nameIdn", idn);

                                jsonWriter.WriteNumber("hits", item.Hits);

                                jsonWriter.WriteEndObject();
                            }

                            jsonWriter.WriteEndArray();
                        }
                        break;

                    default:
                        throw new NotSupportedException();
                }
            }

            #endregion
        }
    }
}
