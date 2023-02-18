/*
Technitium DNS Server
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using DnsServerCore.Auth;
using DnsServerCore.Dns.Applications;
using Microsoft.AspNetCore.Http;
using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

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

        public void ListLogs(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            string[] logFiles = _dnsWebService._log.ListLogFiles();

            Array.Sort(logFiles);
            Array.Reverse(logFiles);

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WritePropertyName("logFiles");
            jsonWriter.WriteStartArray();

            foreach (string logFile in logFiles)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WriteString("fileName", Path.GetFileNameWithoutExtension(logFile));
                jsonWriter.WriteString("size", WebUtilities.GetFormattedSize(new FileInfo(logFile).Length));

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        public Task DownloadLogAsync(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string fileName = request.GetQueryOrForm("fileName");
            int limit = request.GetQueryOrForm("limit", int.Parse, 0);

            return _dnsWebService._log.DownloadLogAsync(context, fileName, limit * 1024 * 1024);
        }

        public void DeleteLog(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string log = request.GetQueryOrForm("log");

            _dnsWebService._log.DeleteLog(log);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Log file was deleted: " + log);
        }

        public void DeleteAllLogs(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService._log.DeleteAllLogs();

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] All log files were deleted.");
        }

        public void DeleteAllStats(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Dashboard, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService.DnsServer.StatsManager.DeleteAllStats();

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] All stats files were deleted.");
        }

        public async Task QueryLogsAsync(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string name = request.GetQueryOrForm("name");
            string classPath = request.GetQueryOrForm("classPath");

            if (!_dnsWebService.DnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication application))
                throw new DnsWebServiceException("DNS application was not found: " + name);

            if (!application.DnsQueryLoggers.TryGetValue(classPath, out IDnsQueryLogger logger))
                throw new DnsWebServiceException("DNS application '" + classPath + "' class path was not found: " + name);

            long pageNumber = request.GetQueryOrForm("pageNumber", long.Parse, 1);
            int entriesPerPage = request.GetQueryOrForm("entriesPerPage", int.Parse, 25);
            bool descendingOrder = request.GetQueryOrForm("descendingOrder", bool.Parse, true);

            DateTime? start = null;
            string strStart = request.QueryOrForm("start");
            if (!string.IsNullOrEmpty(strStart))
                start = DateTime.Parse(strStart, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

            DateTime? end = null;
            string strEnd = request.QueryOrForm("end");
            if (!string.IsNullOrEmpty(strEnd))
                end = DateTime.Parse(strEnd, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

            IPAddress clientIpAddress = request.GetQueryOrForm("clientIpAddress", IPAddress.Parse, null);

            DnsTransportProtocol? protocol = null;
            string strProtocol = request.QueryOrForm("protocol");
            if (!string.IsNullOrEmpty(strProtocol))
                protocol = Enum.Parse<DnsTransportProtocol>(strProtocol, true);

            DnsServerResponseType? responseType = null;
            string strResponseType = request.QueryOrForm("responseType");
            if (!string.IsNullOrEmpty(strResponseType))
                responseType = Enum.Parse<DnsServerResponseType>(strResponseType, true);

            DnsResponseCode? rcode = null;
            string strRcode = request.QueryOrForm("rcode");
            if (!string.IsNullOrEmpty(strRcode))
                rcode = Enum.Parse<DnsResponseCode>(strRcode, true);

            string qname = request.GetQueryOrForm("qname", null);

            DnsResourceRecordType? qtype = null;
            string strQtype = request.QueryOrForm("qtype");
            if (!string.IsNullOrEmpty(strQtype))
                qtype = Enum.Parse<DnsResourceRecordType>(strQtype, true);

            DnsClass? qclass = null;
            string strQclass = request.QueryOrForm("qclass");
            if (!string.IsNullOrEmpty(strQclass))
                qclass = Enum.Parse<DnsClass>(strQclass, true);

            DnsLogPage page = await logger.QueryLogsAsync(pageNumber, entriesPerPage, descendingOrder, start, end, clientIpAddress, protocol, responseType, rcode, qname, qtype, qclass);

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WriteNumber("pageNumber", page.PageNumber);
            jsonWriter.WriteNumber("totalPages", page.TotalPages);
            jsonWriter.WriteNumber("totalEntries", page.TotalEntries);

            jsonWriter.WritePropertyName("entries");
            jsonWriter.WriteStartArray();

            foreach (DnsLogEntry entry in page.Entries)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WriteNumber("rowNumber", entry.RowNumber);
                jsonWriter.WriteString("timestamp", entry.Timestamp);
                jsonWriter.WriteString("clientIpAddress", entry.ClientIpAddress.ToString());
                jsonWriter.WriteString("protocol", entry.Protocol.ToString());
                jsonWriter.WriteString("responseType", entry.ResponseType.ToString());
                jsonWriter.WriteString("rcode", entry.RCODE.ToString());
                jsonWriter.WriteString("qname", entry.Question?.Name);
                jsonWriter.WriteString("qtype", entry.Question?.Type.ToString());
                jsonWriter.WriteString("qclass", entry.Question?.Class.ToString());
                jsonWriter.WriteString("answer", entry.Answer);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        #endregion
    }
}
