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
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore
{
    public class DnsWebService
    {
        #region enum

        enum ServiceState
        {
            Stopped = 0,
            Running = 1,
            Stopping = 2
        }

        #endregion

        #region variables

        readonly string _appFolder;
        readonly string _configFolder;

        string _serverDomain;
        int _webServicePort;

        DnsServer _dnsServer;

        HttpListener _webService;
        Thread _webServiceThread;

        readonly ConcurrentDictionary<string, string> _credentials = new ConcurrentDictionary<string, string>();
        readonly ConcurrentDictionary<string, UserSession> _sessions = new ConcurrentDictionary<string, UserSession>();

        volatile ServiceState _state = ServiceState.Stopped;

        #endregion

        #region constructor

        public DnsWebService(string configFolder = null)
        {
            _appFolder = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);

            if (configFolder == null)
                _configFolder = Path.Combine(_appFolder, "config");
            else
                _configFolder = configFolder;

            if (!Directory.Exists(_configFolder))
                Directory.CreateDirectory(_configFolder);
        }

        #endregion

        #region private

        private void AcceptWebRequestAsync(object state)
        {
            try
            {
                while (true)
                {
                    HttpListenerContext context = _webService.GetContext();
                    ThreadPool.QueueUserWorkItem(ProcessRequestAsync, new object[] { context.Request, context.Response });
                }
            }
            catch
            {
                if (_state == ServiceState.Running)
                    throw;
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
                                        throw new InvalidTokenDnsWebServiceException("Invalid token or session expired.");

                                    jsonWriter.WritePropertyName("response");
                                    jsonWriter.WriteStartObject();

                                    try
                                    {
                                        switch (path)
                                        {
                                            case "/api/changePassword":
                                                ChangePassword(request);
                                                break;

                                            case "/api/getDnsSettings":
                                                GetDnsSettings(jsonWriter);
                                                break;

                                            case "/api/setDnsSettings":
                                                SetDnsSettings(request);
                                                break;

                                            case "/api/flushDnsCache":
                                                _dnsServer.CacheZoneRoot.Flush();
                                                break;

                                            case "/api/listCachedZones":
                                                ListCachedZones(request, jsonWriter);
                                                break;

                                            case "/api/deleteCachedZone":
                                                DeleteCachedZone(request);
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

                                            case "/api/enableZone":
                                                EnableZone(request);
                                                break;

                                            case "/api/disableZone":
                                                DisableZone(request);
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

                                            case "/api/updateRecord":
                                                UpdateRecord(request);
                                                break;

                                            case "/api/resolveQuery":
                                                ResolveQuery(request, jsonWriter);
                                                break;

                                            default:
                                                throw new DnsWebServiceException("Invalid command: " + path);
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
                        catch (InvalidTokenDnsWebServiceException ex)
                        {
                            jsonWriter.WritePropertyName("status");
                            jsonWriter.WriteValue("invalid-token");

                            jsonWriter.WritePropertyName("errorMessage");
                            jsonWriter.WriteValue(ex.Message);
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

                    path = Path.Combine(_appFolder, "www" + path.Replace('/', Path.DirectorySeparatorChar));

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
                response.AddHeader("Cache-Control", "private, max-age=300");

                using (Stream stream = response.OutputStream)
                {
                    OffsetStream.StreamCopy(fS, stream);
                }
            }
        }

        private string CreateSession(string username)
        {
            string token = BinaryNumber.GenerateRandomNumber256().ToString();

            if (!_sessions.TryAdd(token, new UserSession(username)))
                throw new DnsWebServiceException("Error while creating session. Please try again.");

            return token;
        }

        private UserSession GetSession(string token)
        {
            if (_sessions.TryGetValue(token, out UserSession session))
                return session;

            return null;
        }

        private UserSession DeleteSession(string token)
        {
            if (_sessions.TryRemove(token, out UserSession session))
                return session;

            return null;
        }

        private void Login(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strUsername = request.QueryString["user"];
            if (string.IsNullOrEmpty(strUsername))
                throw new DnsWebServiceException("Parameter 'user' missing.");

            string strPassword = request.QueryString["pass"];
            if (string.IsNullOrEmpty(strPassword))
                throw new DnsWebServiceException("Parameter 'pass' missing.");

            strUsername = strUsername.ToLower();

            if (!_credentials.TryGetValue(strUsername, out string password) || (password != strPassword))
                throw new DnsWebServiceException("Invalid username or password.");

            string token = CreateSession(strUsername);

            jsonWriter.WritePropertyName("token");
            jsonWriter.WriteValue(token);
        }

        private bool IsSessionValid(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new DnsWebServiceException("Parameter 'token' missing.");

            UserSession session = GetSession(strToken);
            if (session == null)
                return false;

            if (session.HasExpired())
            {
                _sessions.TryRemove(strToken, out UserSession x);
                return false;
            }

            session.UpdateLastSeen();
            return true;
        }

        private void ChangePassword(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new DnsWebServiceException("Parameter 'token' missing.");

            string strPassword = request.QueryString["pass"];
            if (string.IsNullOrEmpty(strPassword))
                throw new DnsWebServiceException("Parameter 'pass' missing.");

            UserSession session = GetSession(strToken);
            if (session == null)
                throw new DnsWebServiceException("User session does not exists.");

            SetCredentials(session.Username, strPassword);
            SaveConfigFile();
        }

        private void Logout(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new DnsWebServiceException("Parameter 'token' missing.");

            DeleteSession(strToken);
        }

        private void GetDnsSettings(JsonTextWriter jsonWriter)
        {
            jsonWriter.WritePropertyName("serverDomain");
            jsonWriter.WriteValue(_serverDomain);

            jsonWriter.WritePropertyName("webServicePort");
            jsonWriter.WriteValue(_webServicePort);

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

            string strWebServicePort = request.QueryString["webServicePort"];
            if (!string.IsNullOrEmpty(strWebServicePort))
                _webServicePort = int.Parse(strWebServicePort);

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

            SaveConfigFile();
        }

        private void ListCachedZones(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (domain == null)
                domain = "";

            string[] subZones = _dnsServer.CacheZoneRoot.ListSubZones(domain);
            DnsResourceRecord[] records = _dnsServer.CacheZoneRoot.GetAllRecords(domain, false);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain != "")
                domain = "." + domain;

            foreach (string subZone in subZones)
                jsonWriter.WriteValue(subZone + domain);

            jsonWriter.WriteEndArray();

            WriteRecordsAsJson(records, jsonWriter);
        }

        private void DeleteCachedZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            _dnsServer.CacheZoneRoot.DeleteZone(domain);
        }

        private void ListZones(JsonTextWriter jsonWriter)
        {
            Zone.ZoneInfo[] zones = _dnsServer.AuthoritativeZoneRoot.ListAuthoritativeZones();

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            foreach (Zone.ZoneInfo zone in zones)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("zoneName");
                jsonWriter.WriteValue(zone.ZoneName);

                jsonWriter.WritePropertyName("disabled");
                jsonWriter.WriteValue(zone.Disabled);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        private void CreateZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord(_serverDomain, "hostmaster." + _serverDomain, uint.Parse(DateTime.UtcNow.ToString("yyyymmddHH")), 28800, 7200, 604800, 600) });
            SaveZoneFile(domain);
        }

        private void DeleteZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            string[] deletedZones = _dnsServer.AuthoritativeZoneRoot.DeleteZone(domain);

            foreach (string deletedZone in deletedZones)
                DeleteZoneFile(deletedZone);
        }

        private void EnableZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            _dnsServer.AuthoritativeZoneRoot.EnableZone(domain);
            SaveConfigFile();
        }

        private void DisableZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            _dnsServer.AuthoritativeZoneRoot.DisableZone(domain);
            SaveConfigFile();
        }

        private void AddRecord(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

            string value = request.QueryString["value"];
            if (string.IsNullOrEmpty(value))
                throw new DnsWebServiceException("Parameter 'value' missing.");

            uint ttl;
            string strTtl = request.QueryString["ttl"];
            if (string.IsNullOrEmpty(strTtl))
                ttl = 3600;
            else
                ttl = uint.Parse(strTtl);

            switch (type)
            {
                case DnsResourceRecordType.A:
                    _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsARecord(IPAddress.Parse(value)));
                    break;

                case DnsResourceRecordType.AAAA:
                    _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsAAAARecord(IPAddress.Parse(value)));
                    break;

                case DnsResourceRecordType.MX:
                    string preference = request.QueryString["preference"];
                    if (string.IsNullOrEmpty(preference))
                        throw new DnsWebServiceException("Parameter 'preference' missing.");

                    _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsMXRecord(ushort.Parse(preference), value));
                    break;

                case DnsResourceRecordType.TXT:
                    _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsTXTRecord(value));
                    break;

                case DnsResourceRecordType.NS:
                    _dnsServer.AuthoritativeZoneRoot.AddRecord(domain, type, ttl, new DnsNSRecord(value));
                    break;

                case DnsResourceRecordType.PTR:
                    _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsPTRRecord(value) });
                    break;

                case DnsResourceRecordType.CNAME:
                    _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsCNAMERecord(value) });
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for AddRecords().");
            }

            SaveZoneFile(domain);
        }

        private void GetRecords(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            DnsResourceRecord[] records = _dnsServer.AuthoritativeZoneRoot.GetAllRecords(domain);

            WriteRecordsAsJson(records, jsonWriter);
        }

        private void WriteRecordsAsJson(DnsResourceRecord[] records, JsonTextWriter jsonWriter)
        {
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
                                    DnsARecord rdata = (resourceRecord.RDATA as DnsARecord);
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.IPAddress);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.AAAA:
                                {
                                    DnsAAAARecord rdata = (resourceRecord.RDATA as DnsAAAARecord);
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.IPAddress);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.SOA:
                                {
                                    DnsSOARecord rdata = resourceRecord.RDATA as DnsSOARecord;
                                    if (rdata != null)
                                    {
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
                                }
                                break;

                            case DnsResourceRecordType.PTR:
                                {
                                    DnsPTRRecord rdata = resourceRecord.RDATA as DnsPTRRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.PTRDomainName);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.MX:
                                {
                                    DnsMXRecord rdata = resourceRecord.RDATA as DnsMXRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("preference");
                                        jsonWriter.WriteValue(rdata.Preference);

                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Exchange);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.TXT:
                                {
                                    DnsTXTRecord rdata = resourceRecord.RDATA as DnsTXTRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.TXTData);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.NS:
                                {
                                    DnsNSRecord rdata = resourceRecord.RDATA as DnsNSRecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.NSDomainName);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.CNAME:
                                {
                                    DnsCNAMERecord rdata = resourceRecord.RDATA as DnsCNAMERecord;
                                    if (rdata != null)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.CNAMEDomainName);
                                    }
                                }
                                break;

                            default:
                                {
                                    jsonWriter.WritePropertyName("value");

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
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

            string value = request.QueryString["value"];
            if (string.IsNullOrEmpty(value))
                throw new DnsWebServiceException("Parameter 'value' missing.");

            switch (type)
            {
                case DnsResourceRecordType.A:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsARecord(IPAddress.Parse(value)));
                    break;

                case DnsResourceRecordType.AAAA:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsAAAARecord(IPAddress.Parse(value)));
                    break;

                case DnsResourceRecordType.MX:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsMXRecord(0, value));
                    break;

                case DnsResourceRecordType.TXT:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsTXTRecord(value));
                    break;

                case DnsResourceRecordType.NS:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecord(domain, type, new DnsNSRecord(value));
                    break;

                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.PTR:
                    _dnsServer.AuthoritativeZoneRoot.DeleteRecords(domain, type);
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for DeleteRecord().");
            }

            SaveZoneFile(domain);
        }

        private void UpdateRecord(HttpListenerRequest request)
        {
            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            string oldDomain = request.QueryString["oldDomain"];
            if (string.IsNullOrEmpty(oldDomain))
                oldDomain = domain;

            string value = request.QueryString["value"];
            string oldValue = request.QueryString["oldValue"];

            uint ttl;
            string strTtl = request.QueryString["ttl"];
            if (string.IsNullOrEmpty(strTtl))
                ttl = 3600;
            else
                ttl = uint.Parse(strTtl);

            switch (type)
            {
                case DnsResourceRecordType.A:
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(oldDomain, type, DnsClass.IN, 0, new DnsARecord(IPAddress.Parse(oldValue))), new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsARecord(IPAddress.Parse(value))));
                    break;

                case DnsResourceRecordType.AAAA:
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(oldDomain, type, DnsClass.IN, 0, new DnsAAAARecord(IPAddress.Parse(oldValue))), new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsAAAARecord(IPAddress.Parse(value))));
                    break;

                case DnsResourceRecordType.MX:
                    string preference = request.QueryString["preference"];
                    if (string.IsNullOrEmpty(preference))
                        throw new DnsWebServiceException("Parameter 'preference' missing.");

                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(oldDomain, type, DnsClass.IN, 0, new DnsMXRecord(0, oldValue)), new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsMXRecord(ushort.Parse(preference), value)));
                    break;

                case DnsResourceRecordType.TXT:
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(oldDomain, type, DnsClass.IN, 0, new DnsTXTRecord(oldValue)), new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsTXTRecord(value)));
                    break;

                case DnsResourceRecordType.NS:
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(oldDomain, type, DnsClass.IN, 0, new DnsNSRecord(oldValue)), new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsNSRecord(value)));
                    break;

                case DnsResourceRecordType.SOA:
                    {
                        string masterNameServer = request.QueryString["masterNameServer"];
                        if (string.IsNullOrEmpty(masterNameServer))
                            throw new DnsWebServiceException("Parameter 'masterNameServer' missing.");

                        string responsiblePerson = request.QueryString["responsiblePerson"];
                        if (string.IsNullOrEmpty(responsiblePerson))
                            throw new DnsWebServiceException("Parameter 'responsiblePerson' missing.");

                        string serial = request.QueryString["serial"];
                        if (string.IsNullOrEmpty(serial))
                            throw new DnsWebServiceException("Parameter 'serial' missing.");

                        string refresh = request.QueryString["refresh"];
                        if (string.IsNullOrEmpty(refresh))
                            throw new DnsWebServiceException("Parameter 'refresh' missing.");

                        string retry = request.QueryString["retry"];
                        if (string.IsNullOrEmpty(retry))
                            throw new DnsWebServiceException("Parameter 'retry' missing.");

                        string expire = request.QueryString["expire"];
                        if (string.IsNullOrEmpty(expire))
                            throw new DnsWebServiceException("Parameter 'expire' missing.");

                        string minimum = request.QueryString["minimum"];
                        if (string.IsNullOrEmpty(minimum))
                            throw new DnsWebServiceException("Parameter 'minimum' missing.");

                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, type, ttl, new DnsResourceRecordData[] { new DnsSOARecord(masterNameServer, responsiblePerson, uint.Parse(serial), uint.Parse(refresh), uint.Parse(retry), uint.Parse(expire), uint.Parse(minimum)) });
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(oldDomain, type, DnsClass.IN, 0, new DnsPTRRecord(oldValue)), new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsPTRRecord(value)));
                    break;

                case DnsResourceRecordType.CNAME:
                    _dnsServer.AuthoritativeZoneRoot.UpdateRecord(new DnsResourceRecord(oldDomain, type, DnsClass.IN, 0, new DnsCNAMERecord(oldValue)), new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCNAMERecord(value)));
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for UpdateRecords().");
            }

            SaveZoneFile(domain);
        }

        private void ResolveQuery(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string server = request.QueryString["server"];
            if (string.IsNullOrEmpty(server))
                throw new DnsWebServiceException("Parameter 'server' missing.");

            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

            string protocol = request.QueryString["protocol"];
            if (string.IsNullOrEmpty(protocol))
                protocol = "UDP";

            bool importRecords = false;
            string strImport = request.QueryString["import"];
            if (!string.IsNullOrEmpty(strImport))
                importRecords = bool.Parse(strImport);

            bool PREFER_IPv6 = _dnsServer.PreferIPv6;
            bool TCP = (protocol.Equals("TCP", StringComparison.CurrentCultureIgnoreCase));
            const int RETRIES = 2;

            DnsDatagram dnsResponse;

            if (server == "root-servers")
            {
                dnsResponse = DnsClient.ResolveViaRootNameServers(domain, type, null, null, PREFER_IPv6, TCP, RETRIES);
            }
            else
            {
                NameServerAddress[] nameServers;

                if (server == "this-server")
                {
                    nameServers = new NameServerAddress[] { new NameServerAddress(_serverDomain, IPAddress.Parse("127.0.0.1")) };
                }
                else if (IPAddress.TryParse(server, out IPAddress serverIP))
                {
                    string serverDomain = null;

                    try
                    {
                        DnsClient client;

                        if (_dnsServer.AllowRecursion)
                            client = new DnsClient(IPAddress.Parse("127.0.0.1"));
                        else
                            client = new DnsClient();

                        client.PreferIPv6 = PREFER_IPv6;
                        client.Tcp = TCP;
                        client.Retries = RETRIES;

                        serverDomain = client.ResolvePTR(serverIP);
                    }
                    catch
                    { }

                    nameServers = new NameServerAddress[] { new NameServerAddress(serverDomain, serverIP) };
                }
                else
                {
                    IPAddress[] serverIPs = (new DnsClient() { PreferIPv6 = PREFER_IPv6, Tcp = TCP, Retries = RETRIES }).ResolveIP(server, PREFER_IPv6);

                    nameServers = new NameServerAddress[serverIPs.Length];

                    for (int i = 0; i < serverIPs.Length; i++)
                        nameServers[i] = new NameServerAddress(server, serverIPs[i]);
                }

                dnsResponse = (new DnsClient(nameServers) { PreferIPv6 = PREFER_IPv6, Tcp = TCP, Retries = RETRIES }).Resolve(domain, type);
            }

            if (importRecords)
            {
                List<DnsResourceRecord> recordsToSet = new List<DnsResourceRecord>();
                bool containsSOARecord = false;

                foreach (DnsResourceRecord record in dnsResponse.Answer)
                {
                    if (record.Name.Equals(domain, StringComparison.CurrentCultureIgnoreCase))
                    {
                        recordsToSet.Add(record);

                        if (record.Type == DnsResourceRecordType.SOA)
                            containsSOARecord = true;
                    }
                }

                if (!containsSOARecord)
                {
                    bool SOARecordExists = false;

                    foreach (Zone.ZoneInfo zone in _dnsServer.AuthoritativeZoneRoot.ListAuthoritativeZones())
                    {
                        if (domain.EndsWith(zone.ZoneName, StringComparison.CurrentCultureIgnoreCase))
                        {
                            SOARecordExists = true;
                            break;
                        }
                    }

                    if (!SOARecordExists)
                        _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord(_serverDomain, "hostmaster." + _serverDomain, uint.Parse(DateTime.UtcNow.ToString("yyyymmddHH")), 28800, 7200, 604800, 600) });
                }

                _dnsServer.AuthoritativeZoneRoot.SetRecords(recordsToSet);
                SaveZoneFile(domain);
            }

            jsonWriter.WritePropertyName("result");
            jsonWriter.WriteRawValue(JsonConvert.SerializeObject(dnsResponse, new StringEnumConverter()));
        }

        private void SetCredentials(string username, string password)
        {
            username = username.ToLower();

            _credentials.AddOrUpdate(username, password, delegate (string key, string oldValue)
            {
                return password;
            });
        }

        private void LoadZoneFiles()
        {
            string[] zoneFiles = Directory.GetFiles(_configFolder, "*.zone");

            if (zoneFiles.Length == 0)
            {
                {
                    _dnsServer.AuthoritativeZoneRoot.SetRecords("localhost", DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord("localhost", "hostmaster.localhost", uint.Parse(DateTime.UtcNow.ToString("yyyymmddHH")), 28800, 7200, 604800, 600) });
                    _dnsServer.AuthoritativeZoneRoot.SetRecords("localhost", DnsResourceRecordType.A, 3600, new DnsResourceRecordData[] { new DnsARecord(IPAddress.Loopback) });
                    _dnsServer.AuthoritativeZoneRoot.SetRecords("localhost", DnsResourceRecordType.AAAA, 3600, new DnsResourceRecordData[] { new DnsAAAARecord(IPAddress.IPv6Loopback) });

                    SaveZoneFile("localhost");
                }

                {
                    string prtDomain = new DnsQuestionRecord(IPAddress.Loopback, DnsClass.IN).Name;

                    _dnsServer.AuthoritativeZoneRoot.SetRecords(prtDomain, DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord("localhost", "hostmaster.localhost", uint.Parse(DateTime.UtcNow.ToString("yyyymmddHH")), 28800, 7200, 604800, 600) });
                    _dnsServer.AuthoritativeZoneRoot.SetRecords(prtDomain, DnsResourceRecordType.PTR, 3600, new DnsResourceRecordData[] { new DnsPTRRecord("localhost") });

                    SaveZoneFile(prtDomain);
                }

                {
                    string prtDomain = new DnsQuestionRecord(IPAddress.IPv6Loopback, DnsClass.IN).Name;

                    _dnsServer.AuthoritativeZoneRoot.SetRecords(prtDomain, DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord("localhost", "hostmaster.localhost", uint.Parse(DateTime.UtcNow.ToString("yyyymmddHH")), 28800, 7200, 604800, 600) });
                    _dnsServer.AuthoritativeZoneRoot.SetRecords(prtDomain, DnsResourceRecordType.PTR, 3600, new DnsResourceRecordData[] { new DnsPTRRecord("localhost") });

                    SaveZoneFile(prtDomain);
                }
            }
            else
            {
                foreach (string zoneFile in zoneFiles)
                    LoadZoneFile(zoneFile);
            }
        }

        private void LoadZoneFile(string zoneFile)
        {
            using (FileStream fS = new FileStream(zoneFile, FileMode.Open, FileAccess.Read))
            {
                BincodingDecoder decoder = new BincodingDecoder(fS, "DZ");

                switch (decoder.Version)
                {
                    case 1:
                        List<Bincoding> entries = decoder.DecodeNext().GetList();
                        DnsResourceRecord[] records = new DnsResourceRecord[entries.Count];

                        for (int i = 0; i < entries.Count; i++)
                            records[i] = new DnsResourceRecord(entries[i].GetValueStream());

                        _dnsServer.AuthoritativeZoneRoot.SetRecords(records);
                        break;

                    default:
                        throw new IOException("Dns Zone file version not supported: " + decoder.Version);
                }
            }
        }

        private void SaveZoneFile(string domain)
        {
            domain = domain.ToLower();
            DnsResourceRecord[] records = _dnsServer.AuthoritativeZoneRoot.GetAllRecords(domain, false);

            if ((records == null) || (records.Length == 0))
            {
                DeleteZoneFile(domain);
            }
            else
            {
                using (FileStream fS = new FileStream(Path.Combine(_configFolder, domain + ".zone"), FileMode.Create, FileAccess.Write))
                {
                    BincodingEncoder encoder = new BincodingEncoder(fS, "DZ", 1);

                    encoder.Encode(records);
                }
            }
        }

        private void DeleteZoneFile(string domain)
        {
            domain = domain.ToLower();
            File.Delete(Path.Combine(_configFolder, domain + ".zone"));
        }

        private void LoadConfigFile()
        {
            try
            {
                using (FileStream fS = new FileStream(Path.Combine(_configFolder, "dns.config"), FileMode.Open, FileAccess.Read))
                {
                    BincodingDecoder decoder = new BincodingDecoder(fS, "DS");

                    switch (decoder.Version)
                    {
                        case 1:
                            while (true)
                            {
                                Bincoding item = decoder.DecodeNext();
                                if (item.Type == BincodingType.NULL)
                                    break;

                                if (item.Type == BincodingType.KEY_VALUE_PAIR)
                                {
                                    KeyValuePair<string, Bincoding> entry = item.GetKeyValuePair();

                                    switch (entry.Key)
                                    {
                                        case "serverDomain":
                                            _serverDomain = entry.Value.GetStringValue();
                                            break;

                                        case "webServicePort":
                                            _webServicePort = entry.Value.GetIntegerValue();
                                            break;

                                        case "dnsPreferIPv6":
                                            _dnsServer.PreferIPv6 = entry.Value.GetBooleanValue();
                                            break;

                                        case "dnsAllowRecursion":
                                            _dnsServer.AllowRecursion = entry.Value.GetBooleanValue();
                                            break;

                                        case "dnsForwarders":
                                            List<Bincoding> entries = entry.Value.GetList();
                                            NameServerAddress[] forwarders = new NameServerAddress[entries.Count];

                                            for (int i = 0; i < entries.Count; i++)
                                                forwarders[i] = new NameServerAddress(IPAddress.Parse(entries[i].GetStringValue()));

                                            _dnsServer.Forwarders = forwarders;
                                            break;

                                        case "credentials":
                                            foreach (KeyValuePair<string, Bincoding> credential in entry.Value.GetDictionary())
                                                SetCredentials(credential.Key, credential.Value.GetStringValue());

                                            break;

                                        case "disabledZones":
                                            foreach (Bincoding disabledZone in entry.Value.GetList())
                                                _dnsServer.AuthoritativeZoneRoot.DisableZone(disabledZone.GetStringValue());

                                            break;
                                    }
                                }
                            }
                            break;

                        default:
                            throw new IOException("Dns Config file version not supported: " + decoder.Version);
                    }
                }
            }
            catch (IOException)
            {
                _serverDomain = System.Environment.MachineName;
                _webServicePort = 5380;

                SetCredentials("admin", "admin");

                _dnsServer.AllowRecursion = true;

                SaveConfigFile();
            }
        }

        private void SaveConfigFile()
        {
            using (FileStream fS = new FileStream(Path.Combine(_configFolder, "dns.config"), FileMode.Create, FileAccess.Write))
            {
                BincodingEncoder encoder = new BincodingEncoder(fS, "DS", 1);

                encoder.Encode("serverDomain", _serverDomain);
                encoder.Encode("webServicePort", _webServicePort);

                encoder.Encode("dnsPreferIPv6", _dnsServer.PreferIPv6);
                encoder.Encode("dnsAllowRecursion", _dnsServer.AllowRecursion);

                if (_dnsServer.Forwarders != null)
                {
                    List<Bincoding> forwarders = new List<Bincoding>();

                    foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                        forwarders.Add(Bincoding.GetValue(forwarder.EndPoint.Address.ToString()));

                    encoder.Encode("dnsForwarders", forwarders);
                }

                {
                    Dictionary<string, Bincoding> credentials = new Dictionary<string, Bincoding>();

                    foreach (KeyValuePair<string, string> credential in _credentials)
                        credentials.Add(credential.Key, Bincoding.GetValue(credential.Value));

                    encoder.Encode("credentials", credentials);
                }

                {
                    List<Bincoding> disabledZones = new List<Bincoding>();

                    foreach (Zone.ZoneInfo zone in _dnsServer.AuthoritativeZoneRoot.ListAuthoritativeZones())
                    {
                        if (zone.Disabled)
                            disabledZones.Add(Bincoding.GetValue(zone.ZoneName));
                    }

                    encoder.Encode("disabledZones", disabledZones);
                }

                encoder.EncodeNull();
            }
        }

        #endregion

        #region public

        public void Start()
        {
            if (_state != ServiceState.Stopped)
                return;

            _dnsServer = new DnsServer();

            LoadZoneFiles();
            LoadConfigFile();

            _dnsServer.Start();

            try
            {
                _webService = new HttpListener();
                _webService.Prefixes.Add("http://localhost:" + _webServicePort + "/");
                _webService.Prefixes.Add("http://127.0.0.1:" + _webServicePort + "/");
                _webService.Prefixes.Add("http://*:" + _webServicePort + "/");
                _webService.Start();
            }
            catch
            {
                _webService = new HttpListener();
                _webService.Prefixes.Add("http://localhost:" + _webServicePort + "/");
                _webService.Prefixes.Add("http://127.0.0.1:" + _webServicePort + "/");
                _webService.Start();
            }

            _webServiceThread = new Thread(AcceptWebRequestAsync);
            _webServiceThread.IsBackground = true;
            _webServiceThread.Start();
        }

        public void Stop()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            _webService.Stop();
            _dnsServer.Stop();

            _state = ServiceState.Stopped;
        }

        #endregion
    }

    public class UserSession
    {
        #region variables

        const int SESSION_TIMEOUT = 30 * 60 * 1000; //30 mins

        readonly string _username;
        DateTime _lastSeen;

        #endregion

        #region constructor

        public UserSession(string username)
        {
            _username = username;
            _lastSeen = DateTime.UtcNow;
        }

        #endregion

        #region public

        public void UpdateLastSeen()
        {
            _lastSeen = DateTime.UtcNow;
        }

        public bool HasExpired()
        {
            return _lastSeen.AddMilliseconds(SESSION_TIMEOUT) < DateTime.UtcNow;
        }

        #endregion

        #region properties

        public string Username
        { get { return _username; } }

        #endregion
    }

    public class DnsWebServiceException : Exception
    {
        #region constructors

        public DnsWebServiceException()
            : base()
        { }

        public DnsWebServiceException(string message)
            : base(message)
        { }

        public DnsWebServiceException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected DnsWebServiceException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }

    public class InvalidTokenDnsWebServiceException : Exception
    {
        #region constructors

        public InvalidTokenDnsWebServiceException()
            : base()
        { }

        public InvalidTokenDnsWebServiceException(string message)
            : base(message)
        { }

        public InvalidTokenDnsWebServiceException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected InvalidTokenDnsWebServiceException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }
}
