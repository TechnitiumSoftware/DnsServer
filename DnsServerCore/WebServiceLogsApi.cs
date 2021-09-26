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
using DnsServerCore.Dns.Applications;
using Newtonsoft.Json;
using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore
{
    class WebServiceLogsApi
    {
        #region variables

        readonly DnsWebService _dnsWebService;

        #endregion

        #region constructor

        public WebServiceLogsApi(DnsWebService dnsWebService)
        {
            _dnsWebService = dnsWebService;
        }

        #endregion

        #region public

        public void ListLogs(JsonTextWriter jsonWriter)
        {
            string[] logFiles = _dnsWebService.Log.ListLogFiles();

            Array.Sort(logFiles);
            Array.Reverse(logFiles);

            jsonWriter.WritePropertyName("logFiles");
            jsonWriter.WriteStartArray();

            foreach (string logFile in logFiles)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("fileName");
                jsonWriter.WriteValue(Path.GetFileNameWithoutExtension(logFile));

                jsonWriter.WritePropertyName("size");
                jsonWriter.WriteValue(WebUtilities.GetFormattedSize(new FileInfo(logFile).Length));

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        public void DeleteLog(HttpListenerRequest request)
        {
            string log = request.QueryString["log"];
            if (string.IsNullOrEmpty(log))
                throw new DnsWebServiceException("Parameter 'log' missing.");

            _dnsWebService.Log.DeleteLog(log);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Log file was deleted: " + log);
        }

        public void DeleteAllLogs(HttpListenerRequest request)
        {
            _dnsWebService.Log.DeleteAllLogs();

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] All log files were deleted.");
        }

        public void DeleteAllStats(HttpListenerRequest request)
        {
            _dnsWebService.DnsServer.StatsManager.DeleteAllStats();

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] All stats files were deleted.");
        }

        public async Task QueryLogsAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string name = request.QueryString["name"];
            if (string.IsNullOrEmpty(name))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            string classPath = request.QueryString["classPath"];
            if (string.IsNullOrEmpty(classPath))
                throw new DnsWebServiceException("Parameter 'classPath' missing.");

            if (!_dnsWebService.DnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication application))
                throw new DnsWebServiceException("DNS application was not found: " + name);

            if (!application.DnsQueryLoggers.TryGetValue(classPath, out IDnsQueryLogger logger))
                throw new DnsWebServiceException("DNS application '" + classPath + "' class path was not found: " + name);

            long pageNumber;
            string strPageNumber = request.QueryString["pageNumber"];
            if (string.IsNullOrEmpty(strPageNumber))
                pageNumber = 1;
            else
                pageNumber = long.Parse(strPageNumber);

            int entriesPerPage;
            string strEntriesPerPage = request.QueryString["entriesPerPage"];
            if (string.IsNullOrEmpty(strEntriesPerPage))
                entriesPerPage = 25;
            else
                entriesPerPage = int.Parse(strEntriesPerPage);

            bool descendingOrder;
            string strDescendingOrder = request.QueryString["descendingOrder"];
            if (string.IsNullOrEmpty(strDescendingOrder))
                descendingOrder = true;
            else
                descendingOrder = bool.Parse(strDescendingOrder);

            DateTime? start;
            string strStart = request.QueryString["start"];
            if (string.IsNullOrEmpty(strStart))
                start = null;
            else
                start = DateTime.ParseExact(strStart, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal);

            DateTime? end;
            string strEnd = request.QueryString["end"];
            if (string.IsNullOrEmpty(strEnd))
                end = null;
            else
                end = DateTime.ParseExact(strEnd, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal);

            IPAddress clientIpAddress;
            string strClientIpAddress = request.QueryString["clientIpAddress"];
            if (string.IsNullOrEmpty(strClientIpAddress))
                clientIpAddress = null;
            else
                clientIpAddress = IPAddress.Parse(strClientIpAddress);

            DnsTransportProtocol? protocol;
            string strProtocol = request.QueryString["protocol"];
            if (string.IsNullOrEmpty(strProtocol))
                protocol = null;
            else
                protocol = Enum.Parse<DnsTransportProtocol>(strProtocol, true);

            DnsServerResponseType? responseType;
            string strResponseType = request.QueryString["responseType"];
            if (string.IsNullOrEmpty(strResponseType))
                responseType = null;
            else
                responseType = Enum.Parse<DnsServerResponseType>(strResponseType, true);

            DnsResponseCode? rcode;
            string strRcode = request.QueryString["rcode"];
            if (string.IsNullOrEmpty(strRcode))
                rcode = null;
            else
                rcode = Enum.Parse<DnsResponseCode>(strRcode, true);

            string qname = request.QueryString["qname"];
            if (string.IsNullOrEmpty(qname))
                qname = null;

            DnsResourceRecordType? qtype;
            string strQtype = request.QueryString["qtype"];
            if (string.IsNullOrEmpty(strQtype))
                qtype = null;
            else
                qtype = Enum.Parse<DnsResourceRecordType>(strQtype, true);

            DnsClass? qclass;
            string strQclass = request.QueryString["qclass"];
            if (string.IsNullOrEmpty(strQclass))
                qclass = null;
            else
                qclass = Enum.Parse<DnsClass>(strQclass, true);

            DnsLogPage page = await logger.QueryLogsAsync(pageNumber, entriesPerPage, descendingOrder, start, end, clientIpAddress, protocol, responseType, rcode, qname, qtype, qclass);

            jsonWriter.WritePropertyName("pageNumber");
            jsonWriter.WriteValue(page.PageNumber);

            jsonWriter.WritePropertyName("totalPages");
            jsonWriter.WriteValue(page.TotalPages);

            jsonWriter.WritePropertyName("totalEntries");
            jsonWriter.WriteValue(page.TotalEntries);

            jsonWriter.WritePropertyName("entries");
            jsonWriter.WriteStartArray();

            foreach (DnsLogEntry entry in page.Entries)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("rowNumber");
                jsonWriter.WriteValue(entry.RowNumber);

                jsonWriter.WritePropertyName("timestamp");
                jsonWriter.WriteValue(entry.Timestamp);

                jsonWriter.WritePropertyName("clientIpAddress");
                jsonWriter.WriteValue(entry.ClientIpAddress.ToString());

                jsonWriter.WritePropertyName("protocol");
                jsonWriter.WriteValue(entry.Protocol.ToString());

                jsonWriter.WritePropertyName("responseType");
                jsonWriter.WriteValue(entry.ResponseType.ToString());

                jsonWriter.WritePropertyName("rcode");
                jsonWriter.WriteValue(entry.RCODE.ToString());

                jsonWriter.WritePropertyName("qname");
                jsonWriter.WriteValue(entry.Question?.Name);

                jsonWriter.WritePropertyName("qtype");
                jsonWriter.WriteValue(entry.Question?.Type.ToString());

                jsonWriter.WritePropertyName("qclass");
                jsonWriter.WriteValue(entry.Question?.Class.ToString());

                jsonWriter.WritePropertyName("answer");
                jsonWriter.WriteValue(entry.Answer);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        #endregion
    }
}
