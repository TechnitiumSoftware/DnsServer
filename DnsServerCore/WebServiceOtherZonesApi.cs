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
using DnsServerCore.Dns.Zones;
using Microsoft.AspNetCore.Http;
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
    public partial class DnsWebService
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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Cache, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._dnsServer.CacheZoneManager.Flush();

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Cache was flushed.");
            }

            public void ListCachedZones(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Cache, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string domain = request.GetQueryOrForm("domain", "");

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                string direction = request.QueryOrForm("direction");
                if (direction is not null)
                    direction = direction.ToLowerInvariant();

                List<string> subZones = new List<string>();
                List<DnsResourceRecord> records = new List<DnsResourceRecord>();

                while (true)
                {
                    subZones.Clear();
                    records.Clear();

                    _dnsWebService._dnsServer.CacheZoneManager.ListSubDomains(domain, subZones);
                    _dnsWebService._dnsServer.CacheZoneManager.ListAllRecords(domain, records);

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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Cache, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                string domain = context.Request.GetQueryOrForm("domain");

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                if (_dnsWebService._dnsServer.CacheZoneManager.DeleteZone(domain))
                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Cached zone was deleted: " + domain);
            }

            #endregion

            #region allowed zones api

            public void ListAllowedZones(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string domain = request.GetQueryOrForm("domain", "");

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                string direction = request.QueryOrForm("direction");
                if (direction is not null)
                    direction = direction.ToLowerInvariant();

                List<string> subZones = new List<string>();
                List<DnsResourceRecord> records = new List<DnsResourceRecord>();

                while (true)
                {
                    subZones.Clear();
                    records.Clear();

                    _dnsWebService._dnsServer.AllowedZoneManager.ListSubDomains(domain, subZones);
                    _dnsWebService._dnsServer.AllowedZoneManager.ListAllRecords(domain, records);

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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string allowedZones = request.GetQueryOrForm("allowedZones");
                string[] allowedZonesList = allowedZones.Split(',');

                for (int i = 0; i < allowedZonesList.Length; i++)
                {
                    if (DnsClient.IsDomainNameUnicode(allowedZonesList[i]))
                        allowedZonesList[i] = DnsClient.ConvertDomainNameToAscii(allowedZonesList[i]);
                }

                _dnsWebService._dnsServer.AllowedZoneManager.ImportZones(allowedZonesList);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Total " + allowedZonesList.Length + " zones were imported into allowed zone successfully.");
                _dnsWebService._dnsServer.AllowedZoneManager.SaveZoneFile();

                //trigger cluster update
                if (_dnsWebService._clusterManager.ClusterInitialized)
                    _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
            }

            public async Task ExportAllowedZonesAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                IReadOnlyList<AuthZoneInfo> zoneInfoList = _dnsWebService._dnsServer.AllowedZoneManager.GetAllZones();

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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                string domain = context.Request.GetQueryOrForm("domain");

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                if (_dnsWebService._dnsServer.AllowedZoneManager.DeleteZone(domain))
                {
                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Allowed zone was deleted: " + domain);
                    _dnsWebService._dnsServer.AllowedZoneManager.SaveZoneFile();

                    //trigger cluster update
                    if (_dnsWebService._clusterManager.ClusterInitialized)
                        _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
                }
            }

            public void FlushAllowedZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._dnsServer.AllowedZoneManager.Flush();

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Allowed zone was flushed successfully.");
                _dnsWebService._dnsServer.AllowedZoneManager.SaveZoneFile();

                //trigger cluster update
                if (_dnsWebService._clusterManager.ClusterInitialized)
                    _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
            }

            public void AllowZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string domain = context.Request.GetQueryOrForm("domain");

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                    domain = ipAddress.GetReverseDomain();

                if (_dnsWebService._dnsServer.AllowedZoneManager.AllowZone(domain))
                {
                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Zone was allowed: " + domain);
                    _dnsWebService._dnsServer.AllowedZoneManager.SaveZoneFile();

                    //trigger cluster update
                    if (_dnsWebService._clusterManager.ClusterInitialized)
                        _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
                }
            }

            #endregion

            #region blocked zones api

            public void ListBlockedZones(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string domain = request.GetQueryOrForm("domain", "");

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                string direction = request.QueryOrForm("direction");
                if (direction is not null)
                    direction = direction.ToLowerInvariant();

                List<string> subZones = new List<string>();
                List<DnsResourceRecord> records = new List<DnsResourceRecord>();

                while (true)
                {
                    subZones.Clear();
                    records.Clear();

                    _dnsWebService._dnsServer.BlockedZoneManager.ListSubDomains(domain, subZones);
                    _dnsWebService._dnsServer.BlockedZoneManager.ListAllRecords(domain, records);

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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string blockedZones = request.GetQueryOrForm("blockedZones");
                string[] blockedZonesList = blockedZones.Split(',');

                for (int i = 0; i < blockedZonesList.Length; i++)
                {
                    if (DnsClient.IsDomainNameUnicode(blockedZonesList[i]))
                        blockedZonesList[i] = DnsClient.ConvertDomainNameToAscii(blockedZonesList[i]);
                }

                _dnsWebService._dnsServer.BlockedZoneManager.ImportZones(blockedZonesList);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Total " + blockedZonesList.Length + " zones were imported into blocked zone successfully.");
                _dnsWebService._dnsServer.BlockedZoneManager.SaveZoneFile();

                //trigger cluster update
                if (_dnsWebService._clusterManager.ClusterInitialized)
                    _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
            }

            public async Task ExportBlockedZonesAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                IReadOnlyList<AuthZoneInfo> zoneInfoList = _dnsWebService._dnsServer.BlockedZoneManager.GetAllZones();

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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                string domain = context.Request.GetQueryOrForm("domain");

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                if (_dnsWebService._dnsServer.BlockedZoneManager.DeleteZone(domain))
                {
                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Blocked zone was deleted: " + domain);
                    _dnsWebService._dnsServer.BlockedZoneManager.SaveZoneFile();

                    //trigger cluster update
                    if (_dnsWebService._clusterManager.ClusterInitialized)
                        _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
                }
            }

            public void FlushBlockedZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._dnsServer.BlockedZoneManager.Flush();

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Blocked zone was flushed successfully.");
                _dnsWebService._dnsServer.BlockedZoneManager.SaveZoneFile();

                //trigger cluster update
                if (_dnsWebService._clusterManager.ClusterInitialized)
                    _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
            }

            public void BlockZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string domain = context.Request.GetQueryOrForm("domain");

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                if (IPAddress.TryParse(domain, out IPAddress ipAddress))
                    domain = ipAddress.GetReverseDomain();

                if (_dnsWebService._dnsServer.BlockedZoneManager.BlockZone(domain))
                {
                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Domain was added to blocked zone: " + domain);
                    _dnsWebService._dnsServer.BlockedZoneManager.SaveZoneFile();

                    //trigger cluster update
                    if (_dnsWebService._clusterManager.ClusterInitialized)
                        _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();
                }
            }

            #endregion

            #endregion
        }
    }
}
