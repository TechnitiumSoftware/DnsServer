/*
Technitium Library
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore
{
    public class DnsWebService
    {
        #region variables

        readonly string _serverDomain;
        readonly DnsServer _dnsServer;

        readonly HttpListener _webService;
        readonly Thread _webServiceThread;

        #endregion

        #region constructor

        public DnsWebService(string serverDomain)
        {
            _serverDomain = serverDomain;
            _dnsServer = new DnsServer();

            _webService = new HttpListener();
            _webService.Prefixes.Add("http://localhost:5380/");
            _webService.Start();

            _webServiceThread = new Thread(AcceptWebRequestAsync);
            _webServiceThread.IsBackground = true;
            _webServiceThread.Start();

            CreateZone("technitium.com");
        }

        #endregion

        #region private

        private void AcceptWebRequestAsync(object state)
        {
            while (true)
            {
                HttpListenerContext context = _webService.GetContext();
                ThreadPool.QueueUserWorkItem(ProcessRequestAsync, new object[] { context.Request, context.Response });
            }
        }

        private void ProcessRequestAsync(object state)
        {
            object[] parameters = state as object[];
            HttpListenerRequest request = parameters[0] as HttpListenerRequest;
            HttpListenerResponse response = parameters[1] as HttpListenerResponse;

            try
            {
                Uri url = request.Url;
                string path = url.AbsolutePath;

                if (!path.StartsWith("/"))
                {
                    Send404(response);
                    return;
                }

                if (path.StartsWith("/api/"))
                {
                    response.ContentType = "application/json; charset=utf-8";
                    response.ContentEncoding = Encoding.UTF8;

                    using (JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(response.OutputStream)))
                    {
                        jsonWriter.WriteStartObject();

                        try
                        {
                            jsonWriter.WritePropertyName("response");
                            jsonWriter.WriteStartObject();

                            switch (path)
                            {
                                case "/api/listZones":
                                    ListZones(jsonWriter);
                                    break;

                                case "/api/createZone":
                                    CreateZone(request.QueryString["domain"]);
                                    break;

                                case "/api/deleteZone":
                                    DeleteZone(request.QueryString["domain"]);
                                    break;

                                case "/api/setRecords":
                                    SetRecords(request);
                                    break;

                                case "/api/getRecords":
                                    GetRecords(request.QueryString["domain"], jsonWriter);
                                    break;

                                default:
                                    throw new Exception("Invalid command: " + path);
                            }

                            jsonWriter.WriteEndObject();

                            jsonWriter.WritePropertyName("status");
                            jsonWriter.WriteValue("ok");
                        }
                        catch (Exception ex)
                        {
                            jsonWriter.WritePropertyName("status");
                            jsonWriter.WriteValue("error");

                            jsonWriter.WritePropertyName("errorMessage");
                            jsonWriter.WriteValue(ex.Message);

                            jsonWriter.WritePropertyName("stackTrace");
                            jsonWriter.WriteValue(ex.StackTrace);
                        }

                        jsonWriter.WriteEndObject();
                    }
                }
                else
                {
                    if (path.Contains("/../"))
                    {
                        Send404(response);
                        return;
                    }

                    if (path == "/")
                        path = "/index.html";

                    path = "www" + path;

                    if (!File.Exists(path))
                    {
                        Send404(response);
                        return;
                    }

                    SendFile(response, path);
                }
            }
            catch (Exception ex)
            {
                Send500(response, ex);
            }
        }

        private void Send500(HttpListenerResponse response, Exception ex)
        {
            Send500(response, ex.ToString());
        }

        private void Send500(HttpListenerResponse response, string message)
        {
            byte[] buffer = Encoding.UTF8.GetBytes("<h1>500 Internal Server Error</h1><p>" + message + "</p>");

            response.StatusCode = 500;
            response.ContentType = "text/html";
            response.ContentLength64 = buffer.Length;

            using (Stream stream = response.OutputStream)
            {
                stream.Write(buffer, 0, buffer.Length);
            }
        }

        private void Send404(HttpListenerResponse response)
        {
            byte[] buffer = Encoding.UTF8.GetBytes("<h1>404 Not Found</h1>");

            response.StatusCode = 404;
            response.ContentType = "text/html";
            response.ContentLength64 = buffer.Length;

            using (Stream stream = response.OutputStream)
            {
                stream.Write(buffer, 0, buffer.Length);
            }
        }

        private void SendFile(HttpListenerResponse response, string path)
        {
            using (FileStream fS = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                response.ContentType = WebUtilities.GetContentType(path).MediaType;
                response.ContentLength64 = fS.Length;

                using (Stream stream = response.OutputStream)
                {
                    OffsetStream.StreamCopy(fS, stream);
                }
            }
        }

        private void ListZones(JsonTextWriter jsonWriter)
        {
            string[] zones = _dnsServer.AuthoritativeZoneRoot.ListAuthoritativeZones();

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            foreach (string zone in zones)
            {
                jsonWriter.WriteValue(zone);
            }

            jsonWriter.WriteEndArray();
        }

        private void CreateZone(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                throw new Exception("Parameter 'domain' missing.");

            _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord(_serverDomain, "admin." + _serverDomain, uint.Parse(DateTime.UtcNow.ToString("yyyymmddHH")), 28800, 7200, 604800, 600) });
        }

        private void DeleteZone(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                throw new Exception("Parameter 'domain' missing.");

            _dnsServer.AuthoritativeZoneRoot.DeleteZone(domain);
        }

        private void SetRecords(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new Exception("Parameter 'domain' missing.");

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new Exception("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

            uint ttl;
            string strTtl = request.QueryString["ttl"];
            if (string.IsNullOrEmpty(strTtl))
                ttl = 3600;
            else
                ttl = uint.Parse(strTtl);

            switch (type)
            {
                case DnsResourceRecordType.A:
                    {
                        string ip = request.QueryString["ip"];
                        if (string.IsNullOrEmpty(ip))
                            throw new Exception("Parameter 'ip' missing.");

                        string[] strIPs = ip.Split(',');
                        DnsARecord[] records = new DnsARecord[strIPs.Length];

                        for (int i = 0; i < strIPs.Length; i++)
                            records[i] = new DnsARecord(IPAddress.Parse(strIPs[i]));

                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, records);
                    }
                    break;

                case DnsResourceRecordType.AAAA:
                    {
                        string ip = request.QueryString["ip"];
                        if (string.IsNullOrEmpty(ip))
                            throw new Exception("Parameter 'ip' missing.");

                        string[] strIPs = ip.Split(',');
                        DnsAAAARecord[] records = new DnsAAAARecord[strIPs.Length];

                        for (int i = 0; i < strIPs.Length; i++)
                            records[i] = new DnsAAAARecord(IPAddress.Parse(strIPs[i]));

                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, records);
                    }
                    break;

                case DnsResourceRecordType.SOA:
                    {
                        string masterNameServer = request.QueryString["masterNameServer"];
                        if (string.IsNullOrEmpty(masterNameServer))
                            throw new Exception("Parameter 'masterNameServer' missing.");

                        string responsiblePerson = request.QueryString["responsiblePerson"];
                        if (string.IsNullOrEmpty(responsiblePerson))
                            throw new Exception("Parameter 'responsiblePerson' missing.");

                        string serial = request.QueryString["serial"];
                        if (string.IsNullOrEmpty(serial))
                            throw new Exception("Parameter 'serial' missing.");

                        string refresh = request.QueryString["refresh"];
                        if (string.IsNullOrEmpty(refresh))
                            throw new Exception("Parameter 'refresh' missing.");

                        string retry = request.QueryString["retry"];
                        if (string.IsNullOrEmpty(retry))
                            throw new Exception("Parameter 'retry' missing.");

                        string expire = request.QueryString["expire"];
                        if (string.IsNullOrEmpty(expire))
                            throw new Exception("Parameter 'expire' missing.");

                        string minimum = request.QueryString["minimum"];
                        if (string.IsNullOrEmpty(minimum))
                            throw new Exception("Parameter 'minimum' missing.");

                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsSOARecord(masterNameServer, responsiblePerson, uint.Parse(serial), uint.Parse(refresh), uint.Parse(retry), uint.Parse(expire), uint.Parse(minimum)) });
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        string ptrDomain = request.QueryString["ptrDomain"];
                        if (string.IsNullOrEmpty(ptrDomain))
                            throw new Exception("Parameter 'ptrDomain' missing.");

                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsPTRRecord(ptrDomain) });
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        string mxDomain = request.QueryString["mxDomain"];
                        if (string.IsNullOrEmpty(mxDomain))
                            throw new Exception("Parameter 'mxDomain' missing.");

                        string[] mxDomainList = mxDomain.Split(',');
                        DnsMXRecord[] records = new DnsMXRecord[mxDomain.Length];

                        for (int i = 0; i < mxDomainList.Length; i++)
                        {
                            string[] strMxData = mxDomainList[i].Split(':');

                            records[i] = new DnsMXRecord(ushort.Parse(strMxData[0]), strMxData[1]);
                        }

                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, records);
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string txtData = request.QueryString["txtData"];
                        if (string.IsNullOrEmpty(txtData))
                            throw new Exception("Parameter 'txtData' missing.");

                        string[] txtDataList = txtData.Split(',');
                        DnsTXTRecord[] records = new DnsTXTRecord[txtData.Length];

                        for (int i = 0; i < txtDataList.Length; i++)
                            records[i] = new DnsTXTRecord(txtDataList[i]);

                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, records);
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nsDomain = request.QueryString["nsDomain"];
                        if (string.IsNullOrEmpty(nsDomain))
                            throw new Exception("Parameter 'nsDomain' missing.");

                        string[] nsDomains = nsDomain.Split(',');
                        DnsNSRecord[] records = new DnsNSRecord[nsDomain.Length];

                        for (int i = 0; i < nsDomains.Length; i++)
                            records[i] = new DnsNSRecord(nsDomains[i]);

                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, records);
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        string cnameDomain = request.QueryString["cnameDomain"];
                        if (string.IsNullOrEmpty(cnameDomain))
                            throw new Exception("Parameter 'cnameDomain' missing.");

                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsCNAMERecord(cnameDomain) });
                    }
                    break;
            }
        }

        private void GetRecords(string domain, JsonTextWriter jsonWriter)
        {
            if (string.IsNullOrEmpty(domain))
                throw new Exception("Parameter 'domain' missing.");

            DnsResourceRecord[] records = _dnsServer.AuthoritativeZoneRoot.GetRecords(domain);

            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = Zone.GroupRecords(records);

            jsonWriter.WritePropertyName("records");
            jsonWriter.WriteStartArray();

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByTypeRecords in groupedByDomainRecords)
            {
                string recordName = groupedByTypeRecords.Key;

                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                {
                    DnsResourceRecordType type = groupedRecords.Key;
                    DnsResourceRecord[] resourceRecords = groupedRecords.Value.ToArray();

                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("name");
                    jsonWriter.WriteValue(recordName);

                    jsonWriter.WritePropertyName("type");
                    jsonWriter.WriteValue(type.ToString());

                    jsonWriter.WritePropertyName("ttl");
                    jsonWriter.WriteValue(resourceRecords[0].TTLValue);

                    jsonWriter.WritePropertyName("rData");
                    jsonWriter.WriteStartObject();

                    switch (type)
                    {
                        case DnsResourceRecordType.A:
                            {
                                jsonWriter.WritePropertyName("ipAddress");
                                jsonWriter.WriteStartArray();

                                foreach (DnsResourceRecord record in resourceRecords)
                                    jsonWriter.WriteValue((record.RDATA as DnsARecord).IPAddress);

                                jsonWriter.WriteEndArray();
                            }
                            break;

                        case DnsResourceRecordType.AAAA:
                            {
                                jsonWriter.WritePropertyName("ipAddress");
                                jsonWriter.WriteStartArray();

                                foreach (DnsResourceRecord record in resourceRecords)
                                    jsonWriter.WriteValue((record.RDATA as DnsAAAARecord).IPAddress);

                                jsonWriter.WriteEndArray();
                            }
                            break;

                        case DnsResourceRecordType.SOA:
                            {
                                DnsSOARecord rdata = resourceRecords[0].RDATA as DnsSOARecord;

                                jsonWriter.WritePropertyName("masterNameServer");
                                jsonWriter.WriteValue(rdata.MasterNameServer);

                                jsonWriter.WritePropertyName("responsiblePerson");
                                jsonWriter.WriteValue(rdata.ResponsiblePerson);

                                jsonWriter.WritePropertyName("serial");
                                jsonWriter.WriteValue(rdata.Serial);

                                jsonWriter.WritePropertyName("refresh");
                                jsonWriter.WriteValue(rdata.Refresh);

                                jsonWriter.WritePropertyName("retry");
                                jsonWriter.WriteValue(rdata.Retry);

                                jsonWriter.WritePropertyName("expire");
                                jsonWriter.WriteValue(rdata.Expire);

                                jsonWriter.WritePropertyName("minimum");
                                jsonWriter.WriteValue(rdata.Minimum);
                            }
                            break;

                        case DnsResourceRecordType.PTR:
                            {
                                DnsPTRRecord rdata = resourceRecords[0].RDATA as DnsPTRRecord;

                                jsonWriter.WritePropertyName("domain");
                                jsonWriter.WriteValue(rdata.PTRDomainName);
                            }
                            break;

                        case DnsResourceRecordType.MX:
                            {
                                jsonWriter.WritePropertyName("mxData");
                                jsonWriter.WriteStartArray();

                                foreach (DnsResourceRecord record in resourceRecords)
                                {
                                    DnsMXRecord rdata = record.RDATA as DnsMXRecord;

                                    jsonWriter.WriteStartObject();

                                    jsonWriter.WritePropertyName("preference");
                                    jsonWriter.WriteValue(rdata.Preference);

                                    jsonWriter.WritePropertyName("exchange");
                                    jsonWriter.WriteValue(rdata.Exchange);

                                    jsonWriter.WriteEndObject();
                                }

                                jsonWriter.WriteEndArray();
                            }
                            break;

                        case DnsResourceRecordType.TXT:
                            {
                                jsonWriter.WritePropertyName("txtData");
                                jsonWriter.WriteStartArray();

                                foreach (DnsResourceRecord record in resourceRecords)
                                    jsonWriter.WriteValue((record.RDATA as DnsTXTRecord).TXTData);

                                jsonWriter.WriteEndArray();
                            }
                            break;

                        case DnsResourceRecordType.NS:
                            {
                                jsonWriter.WritePropertyName("txtData");
                                jsonWriter.WriteStartArray();

                                foreach (DnsResourceRecord record in resourceRecords)
                                    jsonWriter.WriteValue((record.RDATA as DnsNSRecord).NSDomainName);

                                jsonWriter.WriteEndArray();
                            }
                            break;

                        case DnsResourceRecordType.CNAME:
                            {
                                DnsCNAMERecord rdata = resourceRecords[0].RDATA as DnsCNAMERecord;

                                jsonWriter.WritePropertyName("domain");
                                jsonWriter.WriteValue(rdata.CNAMEDomainName);
                            }
                            break;

                        default:
                            {
                                jsonWriter.WritePropertyName("unknownData");
                                jsonWriter.WriteStartArray();

                                foreach (DnsResourceRecord record in resourceRecords)
                                {
                                    using (MemoryStream mS = new MemoryStream())
                                    {
                                        record.RDATA.WriteTo(mS, new List<DnsDomainOffset>());

                                        jsonWriter.WriteValue(Convert.ToBase64String(mS.ToArray()));
                                    }
                                }

                                jsonWriter.WriteEndArray();
                            }
                            break;
                    }

                    jsonWriter.WriteEndObject();

                    jsonWriter.WriteEndObject();
                }
            }

            jsonWriter.WriteEndArray();
        }

        #endregion
    }
}
