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

using DnsServerCore.Dns.Zones;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore
{
    class WebServiceOtherZonesApi
    {
        #region variables

        readonly DnsWebService _dnsWebService;

        #endregion

        #region constructor

        public WebServiceOtherZonesApi(DnsWebService dnsWebService)
        {
            _dnsWebService = dnsWebService;
        }

        #endregion

        #region public

        #region cache api

        public void FlushCache(HttpListenerRequest request)
        {
            _dnsWebService.DnsServer.CacheZoneManager.Flush();

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Cache was flushed.");
        }

        public void ListCachedZones(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (domain == null)
                domain = "";

            string direction = request.QueryString["direction"];
            if (direction is not null)
                direction = direction.ToLower();

            List<string> subZones = new List<string>();
            List<DnsResourceRecord> records = new List<DnsResourceRecord>();

            while (true)
            {
                subZones.Clear();
                records.Clear();

                _dnsWebService.DnsServer.CacheZoneManager.ListSubDomains(domain, subZones);
                _dnsWebService.DnsServer.CacheZoneManager.ListAllRecords(domain, records);

                if (records.Count > 0)
                    break;

                if (subZones.Count != 1)
                    break;

                if (direction == "up")
                {
                    if (domain.Length == 0)
                        break;

                    int i = domain.IndexOf('.');
                    if (i < 0)
                        domain = "";
                    else
                        domain = domain.Substring(i + 1);
                }
                else if (domain.Length == 0)
                {
                    domain = subZones[0];
                }
                else
                {
                    domain = subZones[0] + "." + domain;
                }
            }

            subZones.Sort();

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(domain);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain.Length != 0)
                domain = "." + domain;

            foreach (string subZone in subZones)
                jsonWriter.WriteValue(subZone + domain);

            jsonWriter.WriteEndArray();

            WebServiceZonesApi.WriteRecordsAsJson(records, jsonWriter, false);
        }

        public void DeleteCachedZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            if (_dnsWebService.DnsServer.CacheZoneManager.DeleteZone(domain))
                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Cached zone was deleted: " + domain);
        }

        #endregion

        #region allowed zones api

        public void ListAllowedZones(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (domain == null)
                domain = "";

            string direction = request.QueryString["direction"];
            if (direction is not null)
                direction = direction.ToLower();

            List<string> subZones = new List<string>();
            List<DnsResourceRecord> records = new List<DnsResourceRecord>();

            while (true)
            {
                subZones.Clear();
                records.Clear();

                _dnsWebService.DnsServer.AllowedZoneManager.ListSubDomains(domain, subZones);
                _dnsWebService.DnsServer.AllowedZoneManager.ListAllRecords(domain, records);

                if (records.Count > 0)
                    break;

                if (subZones.Count != 1)
                    break;

                if (direction == "up")
                {
                    if (domain.Length == 0)
                        break;

                    int i = domain.IndexOf('.');
                    if (i < 0)
                        domain = "";
                    else
                        domain = domain.Substring(i + 1);
                }
                else if (domain.Length == 0)
                {
                    domain = subZones[0];
                }
                else
                {
                    domain = subZones[0] + "." + domain;
                }
            }

            subZones.Sort();

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(domain);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain.Length != 0)
                domain = "." + domain;

            foreach (string subZone in subZones)
                jsonWriter.WriteValue(subZone + domain);

            jsonWriter.WriteEndArray();

            WebServiceZonesApi.WriteRecordsAsJson(new List<DnsResourceRecord>(records), jsonWriter, false);
        }

        public async Task ImportAllowedZonesAsync(HttpListenerRequest request)
        {
            if (!request.ContentType.StartsWith("application/x-www-form-urlencoded"))
                throw new DnsWebServiceException("Invalid content type. Expected application/x-www-form-urlencoded.");

            string formRequest;
            using (StreamReader sR = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                formRequest = await sR.ReadToEndAsync();
            }

            string[] formParts = formRequest.Split('&');

            foreach (string formPart in formParts)
            {
                if (formPart.StartsWith("allowedZones="))
                {
                    string value = Uri.UnescapeDataString(formPart.Substring(13));
                    string[] allowedZones = value.Split(',');
                    bool added = false;

                    foreach (string allowedZone in allowedZones)
                    {
                        if (_dnsWebService.DnsServer.AllowedZoneManager.AllowZone(allowedZone))
                            added = true;
                    }

                    if (added)
                    {
                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Total " + allowedZones.Length + " zones were imported into allowed zone successfully.");
                        _dnsWebService.DnsServer.AllowedZoneManager.SaveZoneFile();
                    }

                    return;
                }
            }

            throw new DnsWebServiceException("Parameter 'allowedZones' missing.");
        }

        public void ExportAllowedZones(HttpListenerResponse response)
        {
            IReadOnlyList<AuthZoneInfo> zoneInfoList = _dnsWebService.DnsServer.AllowedZoneManager.ListZones();

            response.ContentType = "text/plain";
            response.AddHeader("Content-Disposition", "attachment;filename=AllowedZones.txt");

            using (StreamWriter sW = new StreamWriter(new BufferedStream(response.OutputStream)))
            {
                foreach (AuthZoneInfo zoneInfo in zoneInfoList)
                    sW.WriteLine(zoneInfo.Name);
            }
        }

        public void DeleteAllowedZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            if (_dnsWebService.DnsServer.AllowedZoneManager.DeleteZone(domain))
            {
                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Allowed zone was deleted: " + domain);
                _dnsWebService.DnsServer.AllowedZoneManager.SaveZoneFile();
            }
        }

        public void FlushAllowedZone(HttpListenerRequest request)
        {
            _dnsWebService.DnsServer.AllowedZoneManager.Flush();

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Allowed zone was flushed successfully.");
            _dnsWebService.DnsServer.AllowedZoneManager.SaveZoneFile();
        }

        public void AllowZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                domain = ipAddress.GetReverseDomain();

            if (_dnsWebService.DnsServer.AllowedZoneManager.AllowZone(domain))
            {
                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Zone was allowed: " + domain);
                _dnsWebService.DnsServer.AllowedZoneManager.SaveZoneFile();
            }
        }

        #endregion

        #region blocked zones api

        public void ListBlockedZones(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (domain == null)
                domain = "";

            string direction = request.QueryString["direction"];
            if (direction is not null)
                direction = direction.ToLower();

            List<string> subZones = new List<string>();
            List<DnsResourceRecord> records = new List<DnsResourceRecord>();

            while (true)
            {
                subZones.Clear();
                records.Clear();

                _dnsWebService.DnsServer.BlockedZoneManager.ListSubDomains(domain, subZones);
                _dnsWebService.DnsServer.BlockedZoneManager.ListAllRecords(domain, records);

                if (records.Count > 0)
                    break;

                if (subZones.Count != 1)
                    break;

                if (direction == "up")
                {
                    if (domain.Length == 0)
                        break;

                    int i = domain.IndexOf('.');
                    if (i < 0)
                        domain = "";
                    else
                        domain = domain.Substring(i + 1);
                }
                else if (domain.Length == 0)
                {
                    domain = subZones[0];
                }
                else
                {
                    domain = subZones[0] + "." + domain;
                }
            }

            subZones.Sort();

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(domain);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain.Length != 0)
                domain = "." + domain;

            foreach (string subZone in subZones)
                jsonWriter.WriteValue(subZone + domain);

            jsonWriter.WriteEndArray();

            WebServiceZonesApi.WriteRecordsAsJson(new List<DnsResourceRecord>(records), jsonWriter, false);
        }

        public async Task ImportBlockedZonesAsync(HttpListenerRequest request)
        {
            if (!request.ContentType.StartsWith("application/x-www-form-urlencoded"))
                throw new DnsWebServiceException("Invalid content type. Expected application/x-www-form-urlencoded.");

            string formRequest;
            using (StreamReader sR = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                formRequest = await sR.ReadToEndAsync();
            }

            string[] formParts = formRequest.Split('&');

            foreach (string formPart in formParts)
            {
                if (formPart.StartsWith("blockedZones="))
                {
                    string value = Uri.UnescapeDataString(formPart.Substring(13));
                    string[] blockedZones = value.Split(',');
                    bool added = false;

                    foreach (string blockedZone in blockedZones)
                    {
                        if (_dnsWebService.DnsServer.BlockedZoneManager.BlockZone(blockedZone))
                            added = true;
                    }

                    if (added)
                    {
                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Total " + blockedZones.Length + " zones were imported into blocked zone successfully.");
                        _dnsWebService.DnsServer.BlockedZoneManager.SaveZoneFile();
                    }

                    return;
                }
            }

            throw new DnsWebServiceException("Parameter 'blockedZones' missing.");
        }

        public void ExportBlockedZones(HttpListenerResponse response)
        {
            IReadOnlyList<AuthZoneInfo> zoneInfoList = _dnsWebService.DnsServer.BlockedZoneManager.ListZones();

            response.ContentType = "text/plain";
            response.AddHeader("Content-Disposition", "attachment;filename=BlockedZones.txt");

            using (StreamWriter sW = new StreamWriter(new BufferedStream(response.OutputStream)))
            {
                foreach (AuthZoneInfo zoneInfo in zoneInfoList)
                    sW.WriteLine(zoneInfo.Name);
            }
        }

        public void DeleteBlockedZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            if (_dnsWebService.DnsServer.BlockedZoneManager.DeleteZone(domain))
            {
                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Blocked zone was deleted: " + domain);
                _dnsWebService.DnsServer.BlockedZoneManager.SaveZoneFile();
            }
        }

        public void FlushBlockedZone(HttpListenerRequest request)
        {
            _dnsWebService.DnsServer.BlockedZoneManager.Flush();

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Blocked zone was flushed successfully.");
            _dnsWebService.DnsServer.BlockedZoneManager.SaveZoneFile();
        }

        public void BlockZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                domain = ipAddress.GetReverseDomain();

            if (_dnsWebService.DnsServer.BlockedZoneManager.BlockZone(domain))
            {
                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] Domain was added to blocked zone: " + domain);
                _dnsWebService.DnsServer.BlockedZoneManager.SaveZoneFile();
            }
        }

        #endregion

        #endregion
    }
}
