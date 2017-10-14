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
using System.Collections.Concurrent;
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

        const int SESSION_TIMEOUT = 30 * 60 * 1000; //30 mins

        string _serverDomain = "localhost";
        readonly DnsServer _dnsServer;

        readonly HttpListener _webService;
        readonly Thread _webServiceThread;

        readonly ConcurrentDictionary<string, string> _credentials = new ConcurrentDictionary<string, string>();
        readonly ConcurrentDictionary<string, DateTime> _sessions = new ConcurrentDictionary<string, DateTime>();

        #endregion

        #region constructor

        public DnsWebService()
        {
            _dnsServer = new DnsServer();

            _webService = new HttpListener();
            _webService.Prefixes.Add("http://localhost:5380/");
            _webService.Start();

            _webServiceThread = new Thread(AcceptWebRequestAsync);
            _webServiceThread.IsBackground = true;
            _webServiceThread.Start();

            _credentials.TryAdd("admin", "admin");
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
                            switch (path)
                            {
                                case "/api/login":
                                    Login(request, jsonWriter);
                                    break;

                                case "/api/logout":
                                    Logout(request);
                                    break;

                                default:
                                    if (!IsSessionValid(request))
                                        throw new Exception("Invalid token or session expired.");

                                    jsonWriter.WritePropertyName("response");
                                    jsonWriter.WriteStartObject();

                                    try
                                    {
                                        switch (path)
                                        {
                                            case "/api/getDnsSettings":
                                                GetDnsSettings(jsonWriter);
                                                break;

                                            case "/api/setDnsSettings":
                                                SetDnsSettings(request);
                                                break;

                                            case "/api/listZones":
                                                ListZones(jsonWriter);
                                                break;

                                            case "/api/createZone":
                                                CreateZone(request);
                                                break;

                                            case "/api/deleteZone":
                                                DeleteZone(request);
                                                break;

                                            case "/api/setRecords":
                                                SetRecords(request);
                                                break;

                                            case "/api/addRecord":
                                                AddRecord(request);
                                                break;

                                            case "/api/getRecords":
                                                GetRecords(request, jsonWriter);
                                                break;

                                            case "/api/deleteRecord":
                                                DeleteRecord(request);
                                                break;

                                            default:
                                                throw new Exception("Invalid command: " + path);
                                        }
                                    }
                                    finally
                                    {
                                        jsonWriter.WriteEndObject();
                                    }
                                    break;
                            }

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

        private void Login(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strUsername = request.QueryString["user"];
            if (string.IsNullOrEmpty(strUsername))
                throw new Exception("Parameter 'user' missing.");

            string strPassword = request.QueryString["pass"];
            if (string.IsNullOrEmpty(strPassword))
                throw new Exception("Parameter 'pass' missing.");

            if (!_credentials.TryGetValue(strUsername, out string password) || (password != strPassword))
                throw new Exception("Invalid username or password.");

            string token = BinaryNumber.GenerateRandomNumber256().ToString();
            if (!_sessions.TryAdd(token, DateTime.UtcNow))
                throw new Exception("Error while creating session. Please try again.");

            jsonWriter.WritePropertyName("token");
            jsonWriter.WriteValue(token);
        }

        private bool IsSessionValid(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new Exception("Parameter 'token' missing.");

            if (_sessions.TryGetValue(strToken, out DateTime sessionTime))
            {
                if (sessionTime.AddMilliseconds(SESSION_TIMEOUT) < DateTime.UtcNow)
                {
                    _sessions.TryRemove(strToken, out DateTime value);
                    return false;
                }

                _sessions.TryUpdate(strToken, DateTime.UtcNow, sessionTime);
                return true;
            }

            return false;
        }

        private void Logout(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new Exception("Parameter 'token' missing.");

            _sessions.TryRemove(strToken, out DateTime value);
        }

        private void GetDnsSettings(JsonTextWriter jsonWriter)
        {
            jsonWriter.WritePropertyName("serverDomain");
            jsonWriter.WriteValue(_serverDomain);

            jsonWriter.WritePropertyName("preferIPv6");
            jsonWriter.WriteValue(_dnsServer.PreferIPv6);

            jsonWriter.WritePropertyName("allowRecursion");
            jsonWriter.WriteValue(_dnsServer.AllowRecursion);

            jsonWriter.WritePropertyName("forwarders");

            if (_dnsServer.Forwarders == null)
            {
                jsonWriter.WriteNull();
            }
            else
            {
                jsonWriter.WriteStartArray();

                foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                    jsonWriter.WriteValue(forwarder.EndPoint.Address.ToString());

                jsonWriter.WriteEndArray();
            }
        }

        private void SetDnsSettings(HttpListenerRequest request)
        {
            string strServerDomain = request.QueryString["serverDomain"];
            if (!string.IsNullOrEmpty(strServerDomain))
                _serverDomain = strServerDomain;

            string strPreferIPv6 = request.QueryString["preferIPv6"];
            if (!string.IsNullOrEmpty(strPreferIPv6))
                _dnsServer.PreferIPv6 = bool.Parse(strPreferIPv6);

            string strAllowRecursion = request.QueryString["allowRecursion"];
            if (!string.IsNullOrEmpty(strAllowRecursion))
                _dnsServer.AllowRecursion = bool.Parse(strAllowRecursion);

            string strForwarders = request.QueryString["forwarders"];
            if (!string.IsNullOrEmpty(strForwarders))
            {
                if (strForwarders == "false")
                {
                    _dnsServer.Forwarders = null;
                }
                else
                {
                    string[] strForwardersList = strForwarders.Split(',');
                    NameServerAddress[] forwarders = new NameServerAddress[strForwardersList.Length];

                    for (int i = 0; i < strForwardersList.Length; i++)
                        forwarders[i] = new NameServerAddress(IPAddress.Parse(strForwardersList[i]));

                    _dnsServer.Forwarders = forwarders;
                }
            }
        }

        private void ListZones(JsonTextWriter jsonWriter)
        {
            string[] zones = _dnsServer.AuthoritativeZoneRoot.ListAuthoritativeZones();

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            foreach (string zone in zones)
                jsonWriter.WriteValue(zone);

            jsonWriter.WriteEndArray();
        }

        private void CreateZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new Exception("Parameter 'domain' missing.");

            _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord(_serverDomain, "admin." + _serverDomain, uint.Parse(DateTime.UtcNow.ToString("yyyymmddHH")), 28800, 7200, 604800, 600) });
        }

        private void DeleteZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
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

                default:
                    throw new Exception("Type not supported for SetRecords().");
            }
        }

        private void AddRecord(HttpListenerRequest request)
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
                        string strIP = request.QueryString["ip"];
                        if (string.IsNullOrEmpty(strIP))
                            throw new Exception("Parameter 'ip' missing.");

                        _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsARecord(IPAddress.Parse(strIP)));
                    }
                    break;

                case DnsResourceRecordType.AAAA:
                    {
                        string strIP = request.QueryString["ip"];
                        if (string.IsNullOrEmpty(strIP))
                            throw new Exception("Parameter 'ip' missing.");

                        _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsAAAARecord(IPAddress.Parse(strIP)));
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        string preference = request.QueryString["preference"];
                        if (string.IsNullOrEmpty(preference))
                            throw new Exception("Parameter 'preference' missing.");

                        string exchange = request.QueryString["exchange"];
                        if (string.IsNullOrEmpty(exchange))
                            throw new Exception("Parameter 'exchange' missing.");

                        _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsMXRecord(ushort.Parse(preference), exchange));
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string txtData = request.QueryString["txtData"];
                        if (string.IsNullOrEmpty(txtData))
                            throw new Exception("Parameter 'txtData' missing.");

                        _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsTXTRecord(txtData));
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nsDomain = request.QueryString["nsDomain"];
                        if (string.IsNullOrEmpty(nsDomain))
                            throw new Exception("Parameter 'nsDomain' missing.");

                        _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsNSRecord(nsDomain));
                    }
                    break;

                default:
                    throw new Exception("Type not supported for AddRecords().");
            }
        }

        private void GetRecords(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new Exception("Parameter 'domain' missing.");

            DnsResourceRecord[] records = _dnsServer.AuthoritativeZoneRoot.GetRecords(domain);
            if (records == null)
            {
                jsonWriter.WritePropertyName("records");
                jsonWriter.WriteStartArray();
                jsonWriter.WriteEndArray();

                return;
            }

            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = Zone.GroupRecords(records);

            jsonWriter.WritePropertyName("records");
            jsonWriter.WriteStartArray();

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByTypeRecords in groupedByDomainRecords)
            {
                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                {
                    foreach (DnsResourceRecord resourceRecord in groupedRecords.Value)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WritePropertyName("name");
                        jsonWriter.WriteValue(resourceRecord.Name);

                        jsonWriter.WritePropertyName("type");
                        jsonWriter.WriteValue(resourceRecord.Type.ToString());

                        jsonWriter.WritePropertyName("ttl");
                        jsonWriter.WriteValue(resourceRecord.TTLValue);

                        jsonWriter.WritePropertyName("rData");
                        jsonWriter.WriteStartObject();

                        switch (resourceRecord.Type)
                        {
                            case DnsResourceRecordType.A:
                                {
                                    jsonWriter.WritePropertyName("ipAddress");
                                    jsonWriter.WriteValue((resourceRecord.RDATA as DnsARecord).IPAddress);
                                }
                                break;

                            case DnsResourceRecordType.AAAA:
                                {
                                    jsonWriter.WritePropertyName("ipAddress");
                                    jsonWriter.WriteValue((resourceRecord.RDATA as DnsAAAARecord).IPAddress);
                                }
                                break;

                            case DnsResourceRecordType.SOA:
                                {
                                    DnsSOARecord rdata = resourceRecord.RDATA as DnsSOARecord;

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
                                    DnsPTRRecord rdata = resourceRecord.RDATA as DnsPTRRecord;

                                    jsonWriter.WritePropertyName("domain");
                                    jsonWriter.WriteValue(rdata.PTRDomainName);
                                }
                                break;

                            case DnsResourceRecordType.MX:
                                {
                                    DnsMXRecord rdata = resourceRecord.RDATA as DnsMXRecord;

                                    jsonWriter.WritePropertyName("preference");
                                    jsonWriter.WriteValue(rdata.Preference);

                                    jsonWriter.WritePropertyName("exchange");
                                    jsonWriter.WriteValue(rdata.Exchange);
                                }
                                break;

                            case DnsResourceRecordType.TXT:
                                {
                                    jsonWriter.WritePropertyName("txtData");
                                    jsonWriter.WriteValue((resourceRecord.RDATA as DnsTXTRecord).TXTData);
                                }
                                break;

                            case DnsResourceRecordType.NS:
                                {
                                    jsonWriter.WritePropertyName("domain");
                                    jsonWriter.WriteValue((resourceRecord.RDATA as DnsNSRecord).NSDomainName);
                                }
                                break;

                            case DnsResourceRecordType.CNAME:
                                {
                                    DnsCNAMERecord rdata = resourceRecord.RDATA as DnsCNAMERecord;

                                    jsonWriter.WritePropertyName("domain");
                                    jsonWriter.WriteValue(rdata.CNAMEDomainName);
                                }
                                break;

                            default:
                                {
                                    jsonWriter.WritePropertyName("binaryData");

                                    using (MemoryStream mS = new MemoryStream())
                                    {
                                        resourceRecord.RDATA.WriteTo(mS, new List<DnsDomainOffset>());

                                        jsonWriter.WriteValue(Convert.ToBase64String(mS.ToArray()));
                                    }
                                }
                                break;
                        }

                        jsonWriter.WriteEndObject();

                        jsonWriter.WriteEndObject();
                    }
                }
            }

            jsonWriter.WriteEndArray();
        }

        private void DeleteRecord(HttpListenerRequest request)
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
                        string strIP = request.QueryString["ip"];
                        if (string.IsNullOrEmpty(strIP))
                            throw new Exception("Parameter 'ip' missing.");

                        _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, ttl, new DnsARecord(IPAddress.Parse(strIP)));
                    }
                    break;

                case DnsResourceRecordType.AAAA:
                    {
                        string strIP = request.QueryString["ip"];
                        if (string.IsNullOrEmpty(strIP))
                            throw new Exception("Parameter 'ip' missing.");

                        _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, ttl, new DnsAAAARecord(IPAddress.Parse(strIP)));
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        _dnsServer.AuthoritativeZoneRoot.DeleteRecords(domain, type);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        string preference = request.QueryString["preference"];
                        if (string.IsNullOrEmpty(preference))
                            throw new Exception("Parameter 'preference' missing.");

                        string exchange = request.QueryString["exchange"];
                        if (string.IsNullOrEmpty(exchange))
                            throw new Exception("Parameter 'exchange' missing.");

                        _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, ttl, new DnsMXRecord(ushort.Parse(preference), exchange));
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string txtData = request.QueryString["txtData"];
                        if (string.IsNullOrEmpty(txtData))
                            throw new Exception("Parameter 'txtData' missing.");

                        _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, ttl, new DnsTXTRecord(txtData));
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nsDomain = request.QueryString["nsDomain"];
                        if (string.IsNullOrEmpty(nsDomain))
                            throw new Exception("Parameter 'nsDomain' missing.");

                        _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, ttl, new DnsNSRecord(nsDomain));
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        _dnsServer.AuthoritativeZoneRoot.DeleteRecords(domain, type);
                    }
                    break;

                default:
                    throw new Exception("Type not supported for DeleteRecord().");
            }
        }

        #endregion
    }
}
