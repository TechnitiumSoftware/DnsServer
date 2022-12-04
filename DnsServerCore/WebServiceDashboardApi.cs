/*
Technitium DNS Server
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.Dns;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore
{
    class WebServiceDashboardApi
    {
        #region variables

        readonly DnsWebService _dnsWebService;

        #endregion

        #region constructor

        public WebServiceDashboardApi(DnsWebService dnsWebService)
        {
            _dnsWebService = dnsWebService;
        }

        #endregion

        #region private

        private static void WriteChartDataSet(JsonTextWriter jsonWriter, string label, string backgroundColor, string borderColor, List<KeyValuePair<string, long>> statsPerInterval)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WritePropertyName("label");
            jsonWriter.WriteValue(label);

            jsonWriter.WritePropertyName("backgroundColor");
            jsonWriter.WriteValue(backgroundColor);

            jsonWriter.WritePropertyName("borderColor");
            jsonWriter.WriteValue(borderColor);

            jsonWriter.WritePropertyName("borderWidth");
            jsonWriter.WriteValue(2);

            jsonWriter.WritePropertyName("fill");
            jsonWriter.WriteValue(true);

            jsonWriter.WritePropertyName("data");
            jsonWriter.WriteStartArray();
            foreach (KeyValuePair<string, long> item in statsPerInterval)
                jsonWriter.WriteValue(item.Value);
            jsonWriter.WriteEndArray();

            jsonWriter.WriteEndObject();
        }

        private async Task<IDictionary<string, string>> ResolvePtrTopClientsAsync(List<KeyValuePair<string, long>> topClients)
        {
            IDictionary<string, string> dhcpClientIpMap = _dnsWebService.DhcpServer.GetAddressHostNameMap();

            async Task<KeyValuePair<string, string>> ResolvePtrAsync(string ip)
            {
                if (dhcpClientIpMap.TryGetValue(ip, out string dhcpDomain))
                    return new KeyValuePair<string, string>(ip, dhcpDomain);

                IPAddress address = IPAddress.Parse(ip);

                if (IPAddress.IsLoopback(address))
                    return new KeyValuePair<string, string>(ip, "localhost");

                DnsDatagram ptrResponse = await _dnsWebService.DnsServer.DirectQueryAsync(new DnsQuestionRecord(address, DnsClass.IN), 500);
                if (ptrResponse.Answer.Count > 0)
                {
                    IReadOnlyList<string> ptrDomains = DnsClient.ParseResponsePTR(ptrResponse);
                    if (ptrDomains.Count > 0)
                        return new KeyValuePair<string, string>(ip, ptrDomains[0]);
                }

                return new KeyValuePair<string, string>(ip, null);
            }

            List<Task<KeyValuePair<string, string>>> resolverTasks = new List<Task<KeyValuePair<string, string>>>();

            foreach (KeyValuePair<string, long> item in topClients)
            {
                resolverTasks.Add(ResolvePtrAsync(item.Key));
            }

            Dictionary<string, string> result = new Dictionary<string, string>();

            foreach (Task<KeyValuePair<string, string>> resolverTask in resolverTasks)
            {
                try
                {
                    KeyValuePair<string, string> ptrResult = await resolverTask;
                    result[ptrResult.Key] = ptrResult.Value;
                }
                catch
                { }
            }

            return result;
        }

        #endregion

        #region public

        public async Task GetStats(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                strType = "lastHour";

            bool utcFormat;
            string strUtcFormat = request.QueryString["utc"];
            if (string.IsNullOrEmpty(strUtcFormat))
                utcFormat = false;
            else
                utcFormat = bool.Parse(strUtcFormat);

            Dictionary<string, List<KeyValuePair<string, long>>> data;
            string labelFormat;
            bool isLanguageEnUs;

            string acceptLanguage = request.Headers["Accept-Language"];
            if (string.IsNullOrEmpty(acceptLanguage))
                isLanguageEnUs = true;
            else
                isLanguageEnUs = acceptLanguage.StartsWith("en-us", StringComparison.OrdinalIgnoreCase);

            switch (strType.ToLower())
            {
                case "lasthour":
                    data = _dnsWebService.DnsServer.StatsManager.GetLastHourMinuteWiseStats(utcFormat);
                    labelFormat = "HH:mm";
                    break;

                case "lastday":
                    data = _dnsWebService.DnsServer.StatsManager.GetLastDayHourWiseStats(utcFormat);

                    if (isLanguageEnUs)
                        labelFormat = "MM/DD HH:00";
                    else
                        labelFormat = "DD/MM HH:00";

                    break;

                case "lastweek":
                    data = _dnsWebService.DnsServer.StatsManager.GetLastWeekDayWiseStats(utcFormat);

                    if (isLanguageEnUs)
                        labelFormat = "MM/DD";
                    else
                        labelFormat = "DD/MM";

                    break;

                case "lastmonth":
                    data = _dnsWebService.DnsServer.StatsManager.GetLastMonthDayWiseStats(utcFormat);

                    if (isLanguageEnUs)
                        labelFormat = "MM/DD";
                    else
                        labelFormat = "DD/MM";

                    break;

                case "lastyear":
                    labelFormat = "MM/YYYY";
                    data = _dnsWebService.DnsServer.StatsManager.GetLastYearMonthWiseStats(utcFormat);
                    break;

                case "custom":
                    string strStartDate = request.QueryString["start"];
                    if (string.IsNullOrEmpty(strStartDate))
                        throw new DnsWebServiceException("Parameter 'start' missing.");

                    string strEndDate = request.QueryString["end"];
                    if (string.IsNullOrEmpty(strEndDate))
                        throw new DnsWebServiceException("Parameter 'end' missing.");

                    if (!DateTime.TryParse(strStartDate, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime startDate))
                        throw new DnsWebServiceException("Invalid start date format.");

                    if (!DateTime.TryParse(strEndDate, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime endDate))
                        throw new DnsWebServiceException("Invalid end date format.");

                    if (startDate > endDate)
                        throw new DnsWebServiceException("Start date must be less than or equal to end date.");

                    if ((Convert.ToInt32((endDate - startDate).TotalDays) + 1) > 7)
                    {
                        data = _dnsWebService.DnsServer.StatsManager.GetDayWiseStats(startDate, endDate, utcFormat);

                        if (isLanguageEnUs)
                            labelFormat = "MM/DD";
                        else
                            labelFormat = "DD/MM";
                    }
                    else
                    {
                        data = _dnsWebService.DnsServer.StatsManager.GetHourWiseStats(startDate, endDate, utcFormat);

                        if (isLanguageEnUs)
                            labelFormat = "MM/DD HH:00";
                        else
                            labelFormat = "DD/MM HH:00";
                    }

                    break;

                default:
                    throw new DnsWebServiceException("Unknown stats type requested: " + strType);
            }

            //stats
            {
                List<KeyValuePair<string, long>> stats = data["stats"];

                jsonWriter.WritePropertyName("stats");
                jsonWriter.WriteStartObject();

                foreach (KeyValuePair<string, long> item in stats)
                {
                    jsonWriter.WritePropertyName(item.Key);
                    jsonWriter.WriteValue(item.Value);
                }

                jsonWriter.WritePropertyName("zones");
                jsonWriter.WriteValue(_dnsWebService.DnsServer.AuthZoneManager.TotalZones);

                jsonWriter.WritePropertyName("cachedEntries");
                jsonWriter.WriteValue(_dnsWebService.DnsServer.CacheZoneManager.TotalEntries);

                jsonWriter.WritePropertyName("allowedZones");
                jsonWriter.WriteValue(_dnsWebService.DnsServer.AllowedZoneManager.TotalZonesAllowed);

                jsonWriter.WritePropertyName("blockedZones");
                jsonWriter.WriteValue(_dnsWebService.DnsServer.BlockedZoneManager.TotalZonesBlocked);

                jsonWriter.WritePropertyName("blockListZones");
                jsonWriter.WriteValue(_dnsWebService.DnsServer.BlockListZoneManager.TotalZonesBlocked);

                jsonWriter.WriteEndObject();
            }

            //main chart
            {
                jsonWriter.WritePropertyName("mainChartData");
                jsonWriter.WriteStartObject();

                //label format
                {
                    jsonWriter.WritePropertyName("labelFormat");
                    jsonWriter.WriteValue(labelFormat);
                }

                //label
                {
                    List<KeyValuePair<string, long>> statsPerInterval = data["totalQueriesPerInterval"];

                    jsonWriter.WritePropertyName("labels");
                    jsonWriter.WriteStartArray();

                    foreach (KeyValuePair<string, long> item in statsPerInterval)
                        jsonWriter.WriteValue(item.Key);

                    jsonWriter.WriteEndArray();
                }

                //datasets
                {
                    jsonWriter.WritePropertyName("datasets");
                    jsonWriter.WriteStartArray();

                    WriteChartDataSet(jsonWriter, "Total", "rgba(102, 153, 255, 0.1)", "rgb(102, 153, 255)", data["totalQueriesPerInterval"]);
                    WriteChartDataSet(jsonWriter, "No Error", "rgba(92, 184, 92, 0.1)", "rgb(92, 184, 92)", data["totalNoErrorPerInterval"]);
                    WriteChartDataSet(jsonWriter, "Server Failure", "rgba(217, 83, 79, 0.1)", "rgb(217, 83, 79)", data["totalServerFailurePerInterval"]);
                    WriteChartDataSet(jsonWriter, "NX Domain", "rgba(7, 7, 7, 0.1)", "rgb(7, 7, 7)", data["totalNxDomainPerInterval"]);
                    WriteChartDataSet(jsonWriter, "Refused", "rgba(91, 192, 222, 0.1)", "rgb(91, 192, 222)", data["totalRefusedPerInterval"]);

                    WriteChartDataSet(jsonWriter, "Authoritative", "rgba(150, 150, 0, 0.1)", "rgb(150, 150, 0)", data["totalAuthHitPerInterval"]);
                    WriteChartDataSet(jsonWriter, "Recursive", "rgba(23, 162, 184, 0.1)", "rgb(23, 162, 184)", data["totalRecursionsPerInterval"]);
                    WriteChartDataSet(jsonWriter, "Cached", "rgba(111, 84, 153, 0.1)", "rgb(111, 84, 153)", data["totalCacheHitPerInterval"]);
                    WriteChartDataSet(jsonWriter, "Blocked", "rgba(255, 165, 0, 0.1)", "rgb(255, 165, 0)", data["totalBlockedPerInterval"]);

                    WriteChartDataSet(jsonWriter, "Clients", "rgba(51, 122, 183, 0.1)", "rgb(51, 122, 183)", data["totalClientsPerInterval"]);

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteEndObject();
            }

            //query response chart
            {
                jsonWriter.WritePropertyName("queryResponseChartData");
                jsonWriter.WriteStartObject();

                List<KeyValuePair<string, long>> stats = data["stats"];

                //labels
                {
                    jsonWriter.WritePropertyName("labels");
                    jsonWriter.WriteStartArray();

                    foreach (KeyValuePair<string, long> item in stats)
                    {
                        switch (item.Key)
                        {
                            case "totalAuthoritative":
                                jsonWriter.WriteValue("Authoritative");
                                break;

                            case "totalRecursive":
                                jsonWriter.WriteValue("Recursive");
                                break;

                            case "totalCached":
                                jsonWriter.WriteValue("Cached");
                                break;

                            case "totalBlocked":
                                jsonWriter.WriteValue("Blocked");
                                break;
                        }
                    }

                    jsonWriter.WriteEndArray();
                }

                //datasets
                {
                    jsonWriter.WritePropertyName("datasets");
                    jsonWriter.WriteStartArray();

                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("data");
                    jsonWriter.WriteStartArray();

                    foreach (KeyValuePair<string, long> item in stats)
                    {
                        switch (item.Key)
                        {
                            case "totalAuthoritative":
                            case "totalRecursive":
                            case "totalCached":
                            case "totalBlocked":
                                jsonWriter.WriteValue(item.Value);
                                break;
                        }
                    }

                    jsonWriter.WriteEndArray();

                    jsonWriter.WritePropertyName("backgroundColor");
                    jsonWriter.WriteStartArray();
                    jsonWriter.WriteValue("rgba(150, 150, 0, 0.5)");
                    jsonWriter.WriteValue("rgba(23, 162, 184, 0.5)");
                    jsonWriter.WriteValue("rgba(111, 84, 153, 0.5)");
                    jsonWriter.WriteValue("rgba(255, 165, 0, 0.5)");
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

                List<KeyValuePair<string, long>> queryTypes = data["queryTypes"];

                //labels
                {
                    jsonWriter.WritePropertyName("labels");
                    jsonWriter.WriteStartArray();

                    foreach (KeyValuePair<string, long> item in queryTypes)
                        jsonWriter.WriteValue(item.Key);

                    jsonWriter.WriteEndArray();
                }

                //datasets
                {
                    jsonWriter.WritePropertyName("datasets");
                    jsonWriter.WriteStartArray();

                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("data");
                    jsonWriter.WriteStartArray();
                    foreach (KeyValuePair<string, long> item in queryTypes)
                        jsonWriter.WriteValue(item.Value);
                    jsonWriter.WriteEndArray();

                    jsonWriter.WritePropertyName("backgroundColor");
                    jsonWriter.WriteStartArray();
                    jsonWriter.WriteValue("rgba(102, 153, 255, 0.5)");
                    jsonWriter.WriteValue("rgba(92, 184, 92, 0.5)");
                    jsonWriter.WriteValue("rgba(7, 7, 7, 0.5)");
                    jsonWriter.WriteValue("rgba(91, 192, 222, 0.5)");
                    jsonWriter.WriteValue("rgba(150, 150, 0, 0.5)");
                    jsonWriter.WriteValue("rgba(23, 162, 184, 0.5)");
                    jsonWriter.WriteValue("rgba(111, 84, 153, 0.5)");
                    jsonWriter.WriteValue("rgba(255, 165, 0, 0.5)");
                    jsonWriter.WriteValue("rgba(51, 122, 183, 0.5)");
                    jsonWriter.WriteValue("rgba(150, 150, 150, 0.5)");
                    jsonWriter.WriteEndArray();

                    jsonWriter.WriteEndObject();

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteEndObject();
            }

            //top clients
            {
                List<KeyValuePair<string, long>> topClients = data["topClients"];

                IDictionary<string, string> clientIpMap = await ResolvePtrTopClientsAsync(topClients);

                jsonWriter.WritePropertyName("topClients");
                jsonWriter.WriteStartArray();

                foreach (KeyValuePair<string, long> item in topClients)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("name");
                    jsonWriter.WriteValue(item.Key);

                    if (clientIpMap.TryGetValue(item.Key, out string clientDomain) && !string.IsNullOrEmpty(clientDomain))
                    {
                        jsonWriter.WritePropertyName("domain");
                        jsonWriter.WriteValue(clientDomain);
                    }

                    jsonWriter.WritePropertyName("hits");
                    jsonWriter.WriteValue(item.Value);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            //top domains
            {
                List<KeyValuePair<string, long>> topDomains = data["topDomains"];

                jsonWriter.WritePropertyName("topDomains");
                jsonWriter.WriteStartArray();

                foreach (KeyValuePair<string, long> item in topDomains)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("name");
                    jsonWriter.WriteValue(item.Key);

                    jsonWriter.WritePropertyName("hits");
                    jsonWriter.WriteValue(item.Value);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            //top blocked domains
            {
                List<KeyValuePair<string, long>> topBlockedDomains = data["topBlockedDomains"];

                jsonWriter.WritePropertyName("topBlockedDomains");
                jsonWriter.WriteStartArray();

                foreach (KeyValuePair<string, long> item in topBlockedDomains)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("name");
                    jsonWriter.WriteValue(item.Key);

                    jsonWriter.WritePropertyName("hits");
                    jsonWriter.WriteValue(item.Value);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }
        }

        public async Task GetTopStats(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                strType = "lastHour";

            string strStatsType = request.QueryString["statsType"];
            if (string.IsNullOrEmpty(strStatsType))
                throw new DnsWebServiceException("Parameter 'statsType' missing.");

            string strLimit = request.QueryString["limit"];
            if (string.IsNullOrEmpty(strLimit))
                strLimit = "1000";

            TopStatsType statsType = Enum.Parse<TopStatsType>(strStatsType, true);
            int limit = int.Parse(strLimit);

            List<KeyValuePair<string, long>> topStatsData;

            switch (strType.ToLower())
            {
                case "lasthour":
                    topStatsData = _dnsWebService.DnsServer.StatsManager.GetLastHourTopStats(statsType, limit);
                    break;

                case "lastday":
                    topStatsData = _dnsWebService.DnsServer.StatsManager.GetLastDayTopStats(statsType, limit);
                    break;

                case "lastweek":
                    topStatsData = _dnsWebService.DnsServer.StatsManager.GetLastWeekTopStats(statsType, limit);
                    break;

                case "lastmonth":
                    topStatsData = _dnsWebService.DnsServer.StatsManager.GetLastMonthTopStats(statsType, limit);
                    break;

                case "lastyear":
                    topStatsData = _dnsWebService.DnsServer.StatsManager.GetLastYearTopStats(statsType, limit);
                    break;

                case "custom":
                    string strStartDate = request.QueryString["start"];
                    if (string.IsNullOrEmpty(strStartDate))
                        throw new DnsWebServiceException("Parameter 'start' missing.");

                    string strEndDate = request.QueryString["end"];
                    if (string.IsNullOrEmpty(strEndDate))
                        throw new DnsWebServiceException("Parameter 'end' missing.");

                    if (!DateTime.TryParseExact(strStartDate, "yyyy-M-d", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime startDate))
                        throw new DnsWebServiceException("Invalid start date format.");

                    if (!DateTime.TryParseExact(strEndDate, "yyyy-M-d", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime endDate))
                        throw new DnsWebServiceException("Invalid end date format.");

                    if (startDate > endDate)
                        throw new DnsWebServiceException("Start date must be less than or equal to end date.");

                    if ((Convert.ToInt32((endDate - startDate).TotalDays) + 1) > 7)
                        topStatsData = _dnsWebService.DnsServer.StatsManager.GetDayWiseTopStats(startDate, endDate, statsType, limit);
                    else
                        topStatsData = _dnsWebService.DnsServer.StatsManager.GetHourWiseTopStats(startDate, endDate, statsType, limit);

                    break;

                default:
                    throw new DnsWebServiceException("Unknown stats type requested: " + strType);
            }

            switch (statsType)
            {
                case TopStatsType.TopClients:
                    {
                        IDictionary<string, string> clientIpMap = await ResolvePtrTopClientsAsync(topStatsData);

                        jsonWriter.WritePropertyName("topClients");
                        jsonWriter.WriteStartArray();

                        foreach (KeyValuePair<string, long> item in topStatsData)
                        {
                            jsonWriter.WriteStartObject();

                            jsonWriter.WritePropertyName("name");
                            jsonWriter.WriteValue(item.Key);

                            if (clientIpMap.TryGetValue(item.Key, out string clientDomain) && !string.IsNullOrEmpty(clientDomain))
                            {
                                jsonWriter.WritePropertyName("domain");
                                jsonWriter.WriteValue(clientDomain);
                            }

                            jsonWriter.WritePropertyName("hits");
                            jsonWriter.WriteValue(item.Value);

                            jsonWriter.WriteEndObject();
                        }

                        jsonWriter.WriteEndArray();
                    }
                    break;

                case TopStatsType.TopDomains:
                    {
                        jsonWriter.WritePropertyName("topDomains");
                        jsonWriter.WriteStartArray();

                        foreach (KeyValuePair<string, long> item in topStatsData)
                        {
                            jsonWriter.WriteStartObject();

                            jsonWriter.WritePropertyName("name");
                            jsonWriter.WriteValue(item.Key);

                            jsonWriter.WritePropertyName("hits");
                            jsonWriter.WriteValue(item.Value);

                            jsonWriter.WriteEndObject();
                        }

                        jsonWriter.WriteEndArray();
                    }
                    break;

                case TopStatsType.TopBlockedDomains:
                    {
                        jsonWriter.WritePropertyName("topBlockedDomains");
                        jsonWriter.WriteStartArray();

                        foreach (KeyValuePair<string, long> item in topStatsData)
                        {
                            jsonWriter.WriteStartObject();

                            jsonWriter.WritePropertyName("name");
                            jsonWriter.WriteValue(item.Key);

                            jsonWriter.WritePropertyName("hits");
                            jsonWriter.WriteValue(item.Value);

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
