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

using DnsServerCore.Auth;
using DnsServerCore.Dns.Zones;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
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

        public void FlushCache(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Cache, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService.DnsServer.CacheZoneManager.Flush();

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Cache was flushed.");
        }

        public void ListCachedZones(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Cache, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string domain = request.GetQueryOrForm("domain", "");

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            string direction = request.QueryOrForm("direction");
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

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WriteString("domain", domain);

            if (DnsClient.TryConvertDomainNameToUnicode(domain, out string idn))
                jsonWriter.WriteString("domainIdn", idn);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain.Length != 0)
                domain = "." + domain;

            foreach (string subZone in subZones)
            {
                string zone = subZone + domain;

                if (DnsClient.TryConvertDomainNameToUnicode(zone, out string zoneIdn))
                    zone = zoneIdn;

                jsonWriter.WriteStringValue(zone);
            }

            jsonWriter.WriteEndArray();

            WebServiceZonesApi.WriteRecordsAsJson(records, jsonWriter, false);
        }

        public void DeleteCachedZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Cache, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string domain = context.Request.GetQueryOrForm("domain");

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            if (_dnsWebService.DnsServer.CacheZoneManager.DeleteZone(domain))
                _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Cached zone was deleted: " + domain);
        }

        #endregion

        #region allowed zones api

        public void ListAllowedZones(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string domain = request.GetQueryOrForm("domain", "");

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            string direction = request.QueryOrForm("direction");
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

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WriteString("domain", domain);

            if (DnsClient.TryConvertDomainNameToUnicode(domain, out string idn))
                jsonWriter.WriteString("domainIdn", idn);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain.Length != 0)
                domain = "." + domain;

            foreach (string subZone in subZones)
            {
                string zone = subZone + domain;

                if (DnsClient.TryConvertDomainNameToUnicode(zone, out string zoneIdn))
                    zone = zoneIdn;

                jsonWriter.WriteStringValue(zone);
            }

            jsonWriter.WriteEndArray();

            WebServiceZonesApi.WriteRecordsAsJson(records, jsonWriter, true);
        }

        public void ImportAllowedZones(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string allowedZones = request.GetQueryOrForm("allowedZones");
            string[] allowedZonesList = allowedZones.Split(',');

            for (int i = 0; i < allowedZonesList.Length; i++)
            {
                if (DnsClient.IsDomainNameUnicode(allowedZonesList[i]))
                    allowedZonesList[i] = DnsClient.ConvertDomainNameToAscii(allowedZonesList[i]);
            }

            _dnsWebService.DnsServer.AllowedZoneManager.ImportZones(allowedZonesList);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Total " + allowedZonesList.Length + " zones were imported into allowed zone successfully.");
            _dnsWebService.DnsServer.AllowedZoneManager.SaveZoneFile();
        }

        public async Task ExportAllowedZonesAsync(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            IReadOnlyList<AuthZoneInfo> zoneInfoList = _dnsWebService.DnsServer.AllowedZoneManager.GetAllZones();

            HttpResponse response = context.Response;

            response.ContentType = "text/plain";
            response.Headers.ContentDisposition = "attachment;filename=AllowedZones.txt";

            await using (StreamWriter sW = new StreamWriter(response.Body))
            {
                foreach (AuthZoneInfo zoneInfo in zoneInfoList)
                    await sW.WriteLineAsync(zoneInfo.Name);
            }
        }

        public void DeleteAllowedZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string domain = context.Request.GetQueryOrForm("domain");

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            if (_dnsWebService.DnsServer.AllowedZoneManager.DeleteZone(domain))
            {
                _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Allowed zone was deleted: " + domain);
                _dnsWebService.DnsServer.AllowedZoneManager.SaveZoneFile();
            }
        }

        public void FlushAllowedZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService.DnsServer.AllowedZoneManager.Flush();

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Allowed zone was flushed successfully.");
            _dnsWebService.DnsServer.AllowedZoneManager.SaveZoneFile();
        }

        public void AllowZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string domain = context.Request.GetQueryOrForm("domain");

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                domain = ipAddress.GetReverseDomain();

            if (_dnsWebService.DnsServer.AllowedZoneManager.AllowZone(domain))
            {
                _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Zone was allowed: " + domain);
                _dnsWebService.DnsServer.AllowedZoneManager.SaveZoneFile();
            }
        }

        #endregion

        #region blocked zones api

        public void ListBlockedZones(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string domain = request.GetQueryOrForm("domain", "");

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            string direction = request.QueryOrForm("direction");
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

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WriteString("domain", domain);

            if (DnsClient.TryConvertDomainNameToUnicode(domain, out string idn))
                jsonWriter.WriteString("domainIdn", idn);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            if (domain.Length != 0)
                domain = "." + domain;

            foreach (string subZone in subZones)
            {
                string zone = subZone + domain;

                if (DnsClient.TryConvertDomainNameToUnicode(zone, out string zoneIdn))
                    zone = zoneIdn;

                jsonWriter.WriteStringValue(zone);
            }

            jsonWriter.WriteEndArray();

            WebServiceZonesApi.WriteRecordsAsJson(records, jsonWriter, true);
        }

        public void ImportBlockedZones(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string blockedZones = request.GetQueryOrForm("blockedZones");
            string[] blockedZonesList = blockedZones.Split(',');

            for (int i = 0; i < blockedZonesList.Length; i++)
            {
                if (DnsClient.IsDomainNameUnicode(blockedZonesList[i]))
                    blockedZonesList[i] = DnsClient.ConvertDomainNameToAscii(blockedZonesList[i]);
            }

            _dnsWebService.DnsServer.BlockedZoneManager.ImportZones(blockedZonesList);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Total " + blockedZonesList.Length + " zones were imported into blocked zone successfully.");
            _dnsWebService.DnsServer.BlockedZoneManager.SaveZoneFile();
        }

        public async Task ExportBlockedZonesAsync(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            IReadOnlyList<AuthZoneInfo> zoneInfoList = _dnsWebService.DnsServer.BlockedZoneManager.GetAllZones();

            HttpResponse response = context.Response;

            response.ContentType = "text/plain";
            response.Headers.ContentDisposition = "attachment;filename=BlockedZones.txt";

            await using (StreamWriter sW = new StreamWriter(response.Body))
            {
                foreach (AuthZoneInfo zoneInfo in zoneInfoList)
                    await sW.WriteLineAsync(zoneInfo.Name);
            }
        }

        public void DeleteBlockedZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string domain = context.Request.GetQueryOrForm("domain");

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            if (_dnsWebService.DnsServer.BlockedZoneManager.DeleteZone(domain))
            {
                _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Blocked zone was deleted: " + domain);
                _dnsWebService.DnsServer.BlockedZoneManager.SaveZoneFile();
            }
        }

        public void FlushBlockedZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService.DnsServer.BlockedZoneManager.Flush();

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Blocked zone was flushed successfully.");
            _dnsWebService.DnsServer.BlockedZoneManager.SaveZoneFile();
        }

        public void BlockZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string domain = context.Request.GetQueryOrForm("domain");

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                domain = ipAddress.GetReverseDomain();

            if (_dnsWebService.DnsServer.BlockedZoneManager.BlockZone(domain))
            {
                _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Domain was added to blocked zone: " + domain);
                _dnsWebService.DnsServer.BlockedZoneManager.SaveZoneFile();
            }
        }

        #endregion

        #endregion
    }
}
