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
using DnsServerCore.Auth;
using DnsServerCore.Dns.Applications;
using Microsoft.AspNetCore.Http;
using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore
{
    public partial class DnsWebService
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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, sessionUser, PermissionFlag.View))
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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string fileName = request.GetQueryOrForm("fileName");
                int limit = request.GetQueryOrForm("limit", int.Parse, 0);

                return _dnsWebService._log.DownloadLogFileAsync(context, fileName, limit * 1024 * 1024);
            }

            public void DeleteLog(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string log = request.GetQueryOrForm("log");

                _dnsWebService._log.DeleteLogFile(log);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Log file was deleted: " + log);
            }

            public void DeleteAllLogs(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._log.DeleteAllLogFiles();

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] All log files were deleted.");
            }

            public void DeleteAllStats(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Dashboard, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._dnsServer.StatsManager.DeleteAllStats();

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] All stats files were deleted.");
            }

            public async Task QueryLogsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name");
                string classPath = request.GetQueryOrForm("classPath");

                if (!_dnsWebService._dnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication application))
                    throw new DnsWebServiceException("DNS application was not found: " + name);

                if (!application.DnsQueryLogs.TryGetValue(classPath, out IDnsQueryLogs queryLogs))
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
                if (qname is not null)
                    qname = qname.TrimEnd('.');

                DnsResourceRecordType? qtype = null;
                string strQtype = request.QueryOrForm("qtype");
                if (!string.IsNullOrEmpty(strQtype))
                    qtype = Enum.Parse<DnsResourceRecordType>(strQtype, true);

                DnsClass? qclass = null;
                string strQclass = request.QueryOrForm("qclass");
                if (!string.IsNullOrEmpty(strQclass))
                    qclass = Enum.Parse<DnsClass>(strQclass, true);

                DnsLogPage page = await queryLogs.QueryLogsAsync(pageNumber, entriesPerPage, descendingOrder, start, end, clientIpAddress, protocol, responseType, rcode, qname, qtype, qclass);

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

                    if (entry.ResponseRtt.HasValue)
                        jsonWriter.WriteNumber("responseRtt", entry.ResponseRtt.Value);

                    jsonWriter.WriteString("rcode", entry.RCODE.ToString());
                    jsonWriter.WriteString("qname", entry.Question?.Name);
                    jsonWriter.WriteString("qtype", entry.Question?.Type.ToString());
                    jsonWriter.WriteString("qclass", entry.Question?.Class.ToString());
                    jsonWriter.WriteString("answer", entry.Answer);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            public async Task ExportLogsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Logs, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string name = request.GetQueryOrForm("name");
                string classPath = request.GetQueryOrForm("classPath");

                if (!_dnsWebService._dnsServer.DnsApplicationManager.Applications.TryGetValue(name, out DnsApplication application))
                    throw new DnsWebServiceException("DNS application was not found: " + name);

                if (!application.DnsQueryLogs.TryGetValue(classPath, out IDnsQueryLogs queryLogs))
                    throw new DnsWebServiceException("DNS application '" + classPath + "' class path was not found: " + name);

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

                static async Task WriteCsvFieldAsync(StreamWriter sW, string data)
                {
                    if ((data is null) || (data.Length == 0))
                        return;

                    if (data.Contains('"', StringComparison.OrdinalIgnoreCase))
                    {
                        await sW.WriteAsync('"');
                        await sW.WriteAsync(data.Replace("\"", "\"\""));
                        await sW.WriteAsync('"');
                    }
                    else if (data.Contains(',', StringComparison.OrdinalIgnoreCase) || data.Contains(' ', StringComparison.OrdinalIgnoreCase))
                    {
                        await sW.WriteAsync('"');
                        await sW.WriteAsync(data);
                        await sW.WriteAsync('"');
                    }
                    else
                    {
                        await sW.WriteAsync(data);
                    }
                }

                DnsLogPage page;
                long pageNumber = 1;
                string tmpFile = Path.GetTempFileName();

                try
                {
                    using (FileStream csvFileStream = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        StreamWriter sW = new StreamWriter(csvFileStream, Encoding.UTF8);

                        await sW.WriteLineAsync("RowNumber,Timestamp,ClientIpAddress,Protocol,ResponseType,ResponseRtt,RCODE,Domain,Type,Class,Answer");

                        do
                        {
                            page = await queryLogs.QueryLogsAsync(pageNumber, 10000, false, start, end, clientIpAddress, protocol, responseType, rcode, qname, qtype, qclass);

                            foreach (DnsLogEntry entry in page.Entries)
                            {
                                await WriteCsvFieldAsync(sW, entry.RowNumber.ToString());
                                await sW.WriteAsync(',');
                                await WriteCsvFieldAsync(sW, entry.Timestamp.ToString("O"));
                                await sW.WriteAsync(',');
                                await WriteCsvFieldAsync(sW, entry.ClientIpAddress.ToString());
                                await sW.WriteAsync(',');
                                await WriteCsvFieldAsync(sW, entry.Protocol.ToString());
                                await sW.WriteAsync(',');
                                await WriteCsvFieldAsync(sW, entry.ResponseType.ToString());
                                await sW.WriteAsync(',');

                                if (entry.ResponseRtt.HasValue)
                                    await WriteCsvFieldAsync(sW, entry.ResponseRtt.Value.ToString());

                                await sW.WriteAsync(',');
                                await WriteCsvFieldAsync(sW, entry.RCODE.ToString());
                                await sW.WriteAsync(',');
                                await WriteCsvFieldAsync(sW, entry.Question?.Name.ToString());
                                await sW.WriteAsync(',');
                                await WriteCsvFieldAsync(sW, entry.Question?.Type.ToString());
                                await sW.WriteAsync(',');
                                await WriteCsvFieldAsync(sW, entry.Question?.Class.ToString());
                                await sW.WriteAsync(',');
                                await WriteCsvFieldAsync(sW, entry.Answer);

                                await sW.WriteLineAsync();
                            }
                        }
                        while (pageNumber++ < page.TotalPages);

                        await sW.FlushAsync();

                        //send csv file
                        csvFileStream.Position = 0;

                        HttpResponse response = context.Response;

                        response.ContentType = "text/csv";
                        response.ContentLength = csvFileStream.Length;
                        response.Headers.ContentDisposition = "attachment;filename=" + _dnsWebService._dnsServer.ServerDomain + DateTime.UtcNow.ToString("_yyyy-MM-dd_HH-mm-ss") + "_query_logs.csv";

                        using (Stream output = response.Body)
                        {
                            await csvFileStream.CopyToAsync(output);
                        }
                    }
                }
                finally
                {
                    try
                    {
                        File.Delete(tmpFile);
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService._log.Write(ex);
                    }
                }
            }

            #endregion
        }
    }
}
