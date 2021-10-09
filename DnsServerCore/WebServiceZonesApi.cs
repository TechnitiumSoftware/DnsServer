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

using DnsServerCore.Dns;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore
{
    class WebServiceZonesApi
    {
        #region variables

        readonly DnsWebService _dnsWebService;

        uint _defaultRecordTtl = 3600;

        #endregion

        #region constructor

        public WebServiceZonesApi(DnsWebService dnsWebService)
        {
            _dnsWebService = dnsWebService;
        }

        #endregion

        #region public

        public void ListZones(JsonTextWriter jsonWriter)
        {
            List<AuthZoneInfo> zones = _dnsWebService.DnsServer.AuthZoneManager.ListZones();

            zones.Sort();

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            foreach (AuthZoneInfo zone in zones)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("name");
                jsonWriter.WriteValue(zone.Name);

                jsonWriter.WritePropertyName("type");
                jsonWriter.WriteValue(zone.Type.ToString());

                switch (zone.Type)
                {
                    case AuthZoneType.Primary:
                        jsonWriter.WritePropertyName("internal");
                        jsonWriter.WriteValue(zone.Internal);
                        break;

                    case AuthZoneType.Secondary:
                    case AuthZoneType.Stub:
                        jsonWriter.WritePropertyName("expiry");
                        jsonWriter.WriteValue(zone.Expiry);

                        jsonWriter.WritePropertyName("isExpired");
                        jsonWriter.WriteValue(zone.IsExpired);
                        break;
                }

                jsonWriter.WritePropertyName("disabled");
                jsonWriter.WriteValue(zone.Disabled);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        public async Task CreateZoneAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            if (domain.Contains("*"))
                throw new DnsWebServiceException("Domain name for a zone cannot contain wildcard character.");

            if (IPAddress.TryParse(domain, out IPAddress ipAddress))
            {
                domain = new DnsQuestionRecord(ipAddress, DnsClass.IN).Name.ToLower();
            }
            else if (domain.Contains("/"))
            {
                string[] parts = domain.Split('/');
                if ((parts.Length == 2) && IPAddress.TryParse(parts[0], out ipAddress) && int.TryParse(parts[1], out int subnetMaskWidth))
                    domain = Zone.GetReverseZone(ipAddress, subnetMaskWidth);
            }
            else if (domain.EndsWith("."))
            {
                domain = domain.Substring(0, domain.Length - 1);
            }

            AuthZoneType type = AuthZoneType.Primary;
            string strType = request.QueryString["type"];
            if (!string.IsNullOrEmpty(strType))
                type = (AuthZoneType)Enum.Parse(typeof(AuthZoneType), strType, true);

            switch (type)
            {
                case AuthZoneType.Primary:
                    if (_dnsWebService.DnsServer.AuthZoneManager.CreatePrimaryZone(domain, _dnsWebService.DnsServer.ServerDomain, false) == null)
                        throw new DnsWebServiceException("Zone already exists: " + domain);

                    _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Authoritative primary zone was created: " + domain);
                    _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(domain);
                    break;

                case AuthZoneType.Secondary:
                    {
                        string primaryNameServerAddresses = request.QueryString["primaryNameServerAddresses"];
                        if (string.IsNullOrEmpty(primaryNameServerAddresses))
                            primaryNameServerAddresses = null;

                        DnsTransportProtocol zoneTransferProtocol;

                        string strZoneTransferProtocol = request.QueryString["zoneTransferProtocol"];
                        if (string.IsNullOrEmpty(strZoneTransferProtocol))
                            zoneTransferProtocol = DnsTransportProtocol.Tcp;
                        else
                            zoneTransferProtocol = Enum.Parse<DnsTransportProtocol>(strZoneTransferProtocol, true);

                        string tsigKeyName = request.QueryString["tsigKeyName"];
                        if (string.IsNullOrEmpty(tsigKeyName))
                            tsigKeyName = null;

                        if (await _dnsWebService.DnsServer.AuthZoneManager.CreateSecondaryZoneAsync(domain, primaryNameServerAddresses, zoneTransferProtocol, tsigKeyName) == null)
                            throw new DnsWebServiceException("Zone already exists: " + domain);

                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Authoritative secondary zone was created: " + domain);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(domain);
                    }
                    break;

                case AuthZoneType.Stub:
                    {
                        string strPrimaryNameServerAddresses = request.QueryString["primaryNameServerAddresses"];
                        if (string.IsNullOrEmpty(strPrimaryNameServerAddresses))
                            strPrimaryNameServerAddresses = null;

                        if (await _dnsWebService.DnsServer.AuthZoneManager.CreateStubZoneAsync(domain, strPrimaryNameServerAddresses) == null)
                            throw new DnsWebServiceException("Zone already exists: " + domain);

                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Stub zone was created: " + domain);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(domain);
                    }
                    break;

                case AuthZoneType.Forwarder:
                    {
                        DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;
                        string strForwarderProtocol = request.QueryString["protocol"];
                        if (!string.IsNullOrEmpty(strForwarderProtocol))
                            forwarderProtocol = (DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), strForwarderProtocol, true);

                        string strForwarder = request.QueryString["forwarder"];
                        if (string.IsNullOrEmpty(strForwarder))
                            throw new DnsWebServiceException("Parameter 'forwarder' missing.");

                        if (_dnsWebService.DnsServer.AuthZoneManager.CreateForwarderZone(domain, forwarderProtocol, strForwarder) == null)
                            throw new DnsWebServiceException("Zone already exists: " + domain);

                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Forwarder zone was created: " + domain);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(domain);
                    }
                    break;

                default:
                    throw new NotSupportedException("Zone type not supported.");
            }

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
            _dnsWebService.DnsServer.CacheZoneManager.DeleteZone(domain);

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(string.IsNullOrEmpty(domain) ? "." : domain);
        }

        public void DeleteZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new DnsWebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService.DnsServer.AuthZoneManager.DeleteZone(domain))
                throw new DnsWebServiceException("Zone '" + domain + "' was not found.");

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] " + zoneInfo.Type.ToString() + " zone was deleted: " + domain);

            _dnsWebService.DnsServer.AuthZoneManager.DeleteZoneFile(zoneInfo.Name);
        }

        public void EnableZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new DnsWebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            zoneInfo.Disabled = false;

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] " + zoneInfo.Type.ToString() + " zone was enabled: " + zoneInfo.Name);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
            _dnsWebService.DnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);
        }

        public void DisableZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new DnsWebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            zoneInfo.Disabled = true;

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] " + zoneInfo.Type.ToString() + " zone was disabled: " + zoneInfo.Name);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void GetZoneOptions(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new DnsWebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            jsonWriter.WritePropertyName("name");
            jsonWriter.WriteValue(zoneInfo.Name);

            jsonWriter.WritePropertyName("type");
            jsonWriter.WriteValue(zoneInfo.Type.ToString());

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    jsonWriter.WritePropertyName("internal");
                    jsonWriter.WriteValue(zoneInfo.Internal);
                    break;
            }

            jsonWriter.WritePropertyName("disabled");
            jsonWriter.WriteValue(zoneInfo.Disabled);

            jsonWriter.WritePropertyName("zoneTransfer");
            jsonWriter.WriteValue(zoneInfo.ZoneTransfer.ToString());

            jsonWriter.WritePropertyName("zoneTransferNameServers");
            {
                jsonWriter.WriteStartArray();

                if (zoneInfo.ZoneTransferNameServers is not null)
                {
                    foreach (IPAddress nameServer in zoneInfo.ZoneTransferNameServers)
                        jsonWriter.WriteValue(nameServer.ToString());
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("notify");
            jsonWriter.WriteValue(zoneInfo.Notify.ToString());

            jsonWriter.WritePropertyName("notifyNameServers");
            {
                jsonWriter.WriteStartArray();

                if (zoneInfo.NotifyNameServers is not null)
                {
                    foreach (IPAddress nameServer in zoneInfo.NotifyNameServers)
                        jsonWriter.WriteValue(nameServer.ToString());
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("zoneTransferTsigKeyNames");
            {
                jsonWriter.WriteStartArray();

                if (zoneInfo.TsigKeyNames is not null)
                {
                    foreach (KeyValuePair<string, object> tsigKeyName in zoneInfo.TsigKeyNames)
                        jsonWriter.WriteValue(tsigKeyName.Key);
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("availableTsigKeyNames");
            {
                jsonWriter.WriteStartArray();

                if (_dnsWebService.DnsServer.TsigKeys is not null)
                {
                    foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsWebService.DnsServer.TsigKeys)
                        jsonWriter.WriteValue(tsigKey.Key);
                }

                jsonWriter.WriteEndArray();
            }
        }

        public void SetZoneOptions(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new DnsWebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            string strDisabled = request.QueryString["disabled"];
            if (!string.IsNullOrEmpty(strDisabled))
                zoneInfo.Disabled = bool.Parse(strDisabled);

            string strZoneTransfer = request.QueryString["zoneTransfer"];
            if (!string.IsNullOrEmpty(strZoneTransfer))
                zoneInfo.ZoneTransfer = Enum.Parse<AuthZoneTransfer>(strZoneTransfer, true);

            string strZoneTransferNameServers = request.QueryString["zoneTransferNameServers"];
            if (!string.IsNullOrEmpty(strZoneTransferNameServers))
            {
                if (strZoneTransferNameServers == "false")
                {
                    zoneInfo.ZoneTransferNameServers = null;
                }
                else
                {
                    string[] strNameServers = strZoneTransferNameServers.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    IPAddress[] nameServers = new IPAddress[strNameServers.Length];

                    for (int i = 0; i < strNameServers.Length; i++)
                        nameServers[i] = IPAddress.Parse(strNameServers[i]);

                    zoneInfo.ZoneTransferNameServers = nameServers;
                }
            }

            string strNotify = request.QueryString["notify"];
            if (!string.IsNullOrEmpty(strNotify))
                zoneInfo.Notify = Enum.Parse<AuthZoneNotify>(strNotify, true);

            string strNotifyNameServers = request.QueryString["notifyNameServers"];
            if (!string.IsNullOrEmpty(strNotifyNameServers))
            {
                if (strNotifyNameServers == "false")
                {
                    zoneInfo.NotifyNameServers = null;
                }
                else
                {
                    string[] strNameServers = strNotifyNameServers.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    IPAddress[] nameServers = new IPAddress[strNameServers.Length];

                    for (int i = 0; i < strNameServers.Length; i++)
                        nameServers[i] = IPAddress.Parse(strNameServers[i]);

                    zoneInfo.NotifyNameServers = nameServers;
                }
            }

            string strZoneTransferTsigKeyNames = request.QueryString["zoneTransferTsigKeyNames"];
            if (!string.IsNullOrEmpty(strZoneTransferTsigKeyNames))
            {
                if (strZoneTransferTsigKeyNames == "false")
                {
                    zoneInfo.TsigKeyNames = null;
                }
                else
                {
                    string[] strZoneTransferTsigKeyNamesParts = strZoneTransferTsigKeyNames.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    Dictionary<string, object> zoneTransferTsigKeyNames = new Dictionary<string, object>(strZoneTransferTsigKeyNamesParts.Length);

                    for (int i = 0; i < strZoneTransferTsigKeyNamesParts.Length; i++)
                        zoneTransferTsigKeyNames.Add(strZoneTransferTsigKeyNamesParts[i].ToLower(), null);

                    zoneInfo.TsigKeyNames = zoneTransferTsigKeyNames;
                }
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] " + zoneInfo.Type.ToString() + " zone options were updated successfully: " + zoneInfo.Name);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void ResyncZone(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new DnsWebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Secondary:
                case AuthZoneType.Stub:
                    zoneInfo.TriggerResync();
                    break;

                default:
                    throw new DnsWebServiceException("Only Secondary and Stub zones support resync.");
            }
        }

        public void AddRecord(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new DnsWebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

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
                ttl = _defaultRecordTtl;
            else
                ttl = uint.Parse(strTtl);

            bool overwrite = false;
            string strOverwrite = request.QueryString["overwrite"];
            if (!string.IsNullOrEmpty(strOverwrite))
                overwrite = bool.Parse(strOverwrite);

            string comments = request.QueryString["comments"];

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        IPAddress ipAddress = IPAddress.Parse(value);

                        bool ptr = false;
                        string strPtr = request.QueryString["ptr"];
                        if (!string.IsNullOrEmpty(strPtr))
                            ptr = bool.Parse(strPtr);

                        if (ptr)
                        {
                            string ptrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(ptrDomain);
                            if (reverseZoneInfo == null)
                            {
                                bool createPtrZone = false;
                                string strCreatePtrZone = request.QueryString["createPtrZone"];
                                if (!string.IsNullOrEmpty(strCreatePtrZone))
                                    createPtrZone = bool.Parse(strCreatePtrZone);

                                if (!createPtrZone)
                                    throw new DnsServerException("No reverse zone available to add PTR record.");

                                string ptrZone = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 24 : 64);

                                reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreatePrimaryZone(ptrZone, _dnsWebService.DnsServer.ServerDomain, false);
                                if (reverseZoneInfo == null)
                                    throw new DnsServerException("Failed to create reverse zone to add PTR record: " + ptrZone);
                            }

                            if (reverseZoneInfo.Internal)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is an internal zone.");

                            if (reverseZoneInfo.Type != AuthZoneType.Primary)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is not a primary zone.");

                            _dnsWebService.DnsServer.AuthZoneManager.SetRecords(ptrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecord[] { new DnsPTRRecord(domain) });
                            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                        }

                        DnsResourceRecord newRecord;

                        if (type == DnsResourceRecordType.A)
                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsARecord(ipAddress));
                        else
                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsAAAARecord(ipAddress));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(newRecord);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        string preference = request.QueryString["preference"];
                        if (string.IsNullOrEmpty(preference))
                            throw new DnsWebServiceException("Parameter 'preference' missing.");

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsMXRecord(ushort.Parse(preference), value.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(newRecord);
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsTXTRecord(value));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(newRecord);
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string glueAddresses = request.QueryString["glue"];
                        if (string.IsNullOrEmpty(glueAddresses))
                            glueAddresses = null;

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsNSRecord(value.TrimEnd('.')));

                        if (glueAddresses != null)
                            newRecord.SetGlueRecords(glueAddresses);

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(newRecord);
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsPTRRecord(value.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCNAMERecord(value.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        string priority = request.QueryString["priority"];
                        if (string.IsNullOrEmpty(priority))
                            throw new DnsWebServiceException("Parameter 'priority' missing.");

                        string weight = request.QueryString["weight"];
                        if (string.IsNullOrEmpty(weight))
                            throw new DnsWebServiceException("Parameter 'weight' missing.");

                        string port = request.QueryString["port"];
                        if (string.IsNullOrEmpty(port))
                            throw new DnsWebServiceException("Parameter 'port' missing.");

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSRVRecord(ushort.Parse(priority), ushort.Parse(weight), ushort.Parse(port), value.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(newRecord);
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    {
                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsDNAMERecord(value.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        string flags = request.QueryString["flags"];
                        if (string.IsNullOrEmpty(flags))
                            throw new DnsWebServiceException("Parameter 'flags' missing.");

                        string tag = request.QueryString["tag"];
                        if (string.IsNullOrEmpty(tag))
                            throw new DnsWebServiceException("Parameter 'tag' missing.");

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCAARecord(byte.Parse(flags), tag, value));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(newRecord);
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsANAMERecord(value.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(newRecord);
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        string protocol = request.QueryString["protocol"];
                        if (string.IsNullOrEmpty(protocol))
                            protocol = "Udp";

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecord((DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), protocol, true), value));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(newRecord);
                    }
                    break;

                case DnsResourceRecordType.APP:
                    {
                        string classPath = request.QueryString["classPath"];
                        if (string.IsNullOrEmpty(classPath))
                            throw new DnsWebServiceException("Parameter 'classPath' missing.");

                        string recordData = request.QueryString["recordData"];
                        if (string.IsNullOrEmpty(recordData))
                            recordData = "";

                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsApplicationRecord(value, classPath, recordData));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newRecord);
                    }
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for AddRecords().");
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] New record was added to authoritative zone {domain: " + domain + "; type: " + type + "; value: " + value + "; ttl: " + ttl + ";}");

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void GetRecords(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new DnsWebServiceException("Zone '" + domain + "' was not found.");

            jsonWriter.WritePropertyName("zone");
            jsonWriter.WriteStartObject();

            jsonWriter.WritePropertyName("name");
            jsonWriter.WriteValue(zoneInfo.Name);

            jsonWriter.WritePropertyName("type");
            jsonWriter.WriteValue(zoneInfo.Type.ToString());

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    jsonWriter.WritePropertyName("internal");
                    jsonWriter.WriteValue(zoneInfo.Internal);
                    break;

                case AuthZoneType.Secondary:
                case AuthZoneType.Stub:
                    jsonWriter.WritePropertyName("expiry");
                    jsonWriter.WriteValue(zoneInfo.Expiry);

                    jsonWriter.WritePropertyName("isExpired");
                    jsonWriter.WriteValue(zoneInfo.IsExpired);
                    break;
            }

            jsonWriter.WritePropertyName("disabled");
            jsonWriter.WriteValue(zoneInfo.Disabled);

            jsonWriter.WriteEndObject();

            List<DnsResourceRecord> records = new List<DnsResourceRecord>();
            _dnsWebService.DnsServer.AuthZoneManager.ListAllRecords(domain, records);

            WriteRecordsAsJson(records, jsonWriter, true);
        }

        public static void WriteRecordsAsJson(List<DnsResourceRecord> records, JsonTextWriter jsonWriter, bool authoritativeZoneRecords)
        {
            if (records == null)
            {
                jsonWriter.WritePropertyName("records");
                jsonWriter.WriteStartArray();
                jsonWriter.WriteEndArray();

                return;
            }

            records.Sort();

            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = DnsResourceRecord.GroupRecords(records);

            jsonWriter.WritePropertyName("records");
            jsonWriter.WriteStartArray();

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByTypeRecords in groupedByDomainRecords)
            {
                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                {
                    foreach (DnsResourceRecord record in groupedRecords.Value)
                    {
                        jsonWriter.WriteStartObject();

                        if (authoritativeZoneRecords)
                        {
                            jsonWriter.WritePropertyName("disabled");
                            jsonWriter.WriteValue(record.IsDisabled());
                        }

                        jsonWriter.WritePropertyName("name");
                        jsonWriter.WriteValue(record.Name);

                        jsonWriter.WritePropertyName("type");
                        jsonWriter.WriteValue(record.Type.ToString());

                        jsonWriter.WritePropertyName("ttl");
                        if (authoritativeZoneRecords)
                            jsonWriter.WriteValue(record.TtlValue);
                        else
                            jsonWriter.WriteValue(record.TTL);

                        if (authoritativeZoneRecords)
                        {
                            string comments = record.GetComments();
                            if (!string.IsNullOrEmpty(comments))
                            {
                                jsonWriter.WritePropertyName("comments");
                                jsonWriter.WriteValue(comments);
                            }
                        }

                        jsonWriter.WritePropertyName("rData");
                        jsonWriter.WriteStartObject();

                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                                {
                                    if (record.RDATA is DnsARecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.IPAddress);
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }
                                }
                                break;

                            case DnsResourceRecordType.AAAA:
                                {
                                    if (record.RDATA is DnsAAAARecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.IPAddress);
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }
                                }
                                break;

                            case DnsResourceRecordType.SOA:
                                {
                                    if (record.RDATA is DnsSOARecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("primaryNameServer");
                                        jsonWriter.WriteValue(rdata.PrimaryNameServer);

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
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }

                                    if (authoritativeZoneRecords)
                                    {
                                        IReadOnlyList<NameServerAddress> primaryNameServers = record.GetPrimaryNameServers();
                                        if (primaryNameServers.Count > 0)
                                        {
                                            string primaryAddresses = null;

                                            foreach (NameServerAddress primaryNameServer in primaryNameServers)
                                            {
                                                if (primaryAddresses == null)
                                                    primaryAddresses = primaryNameServer.OriginalAddress;
                                                else
                                                    primaryAddresses = primaryAddresses + ", " + primaryNameServer.OriginalAddress;
                                            }

                                            jsonWriter.WritePropertyName("primaryAddresses");
                                            jsonWriter.WriteValue(primaryAddresses);
                                        }

                                        DnsResourceRecordInfo recordInfo = record.GetRecordInfo();

                                        if (recordInfo.ZoneTransferProtocol != DnsTransportProtocol.Udp)
                                        {
                                            jsonWriter.WritePropertyName("zoneTransferProtocol");
                                            jsonWriter.WriteValue(recordInfo.ZoneTransferProtocol.ToString());
                                        }

                                        if (!string.IsNullOrEmpty(recordInfo.TsigKeyName))
                                        {
                                            jsonWriter.WritePropertyName("tsigKeyName");
                                            jsonWriter.WriteValue(recordInfo.TsigKeyName);
                                        }
                                    }
                                }
                                break;

                            case DnsResourceRecordType.PTR:
                                {
                                    if (record.RDATA is DnsPTRRecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Domain.Length == 0 ? "." : rdata.Domain);
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }
                                }
                                break;

                            case DnsResourceRecordType.MX:
                                {
                                    if (record.RDATA is DnsMXRecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("preference");
                                        jsonWriter.WriteValue(rdata.Preference);

                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Exchange.Length == 0 ? "." : rdata.Exchange);

                                        IReadOnlyList<DnsResourceRecord> glueRecords = record.GetGlueRecords();
                                        if (glueRecords.Count > 0)
                                        {
                                            string glue = null;

                                            foreach (DnsResourceRecord glueRecord in glueRecords)
                                            {
                                                if (glue == null)
                                                    glue = glueRecord.RDATA.ToString();
                                                else
                                                    glue = glue + ", " + glueRecord.RDATA.ToString();
                                            }

                                            jsonWriter.WritePropertyName("glue");
                                            jsonWriter.WriteValue(glue);
                                        }
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }
                                }
                                break;

                            case DnsResourceRecordType.TXT:
                                {
                                    if (record.RDATA is DnsTXTRecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Text);
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }
                                }
                                break;

                            case DnsResourceRecordType.NS:
                                {
                                    if (record.RDATA is DnsNSRecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.NameServer.Length == 0 ? "." : rdata.NameServer);

                                        IReadOnlyList<DnsResourceRecord> glueRecords = record.GetGlueRecords();
                                        if (glueRecords.Count > 0)
                                        {
                                            string glue = null;

                                            foreach (DnsResourceRecord glueRecord in glueRecords)
                                            {
                                                if (glue == null)
                                                    glue = glueRecord.RDATA.ToString();
                                                else
                                                    glue = glue + ", " + glueRecord.RDATA.ToString();
                                            }

                                            jsonWriter.WritePropertyName("glue");
                                            jsonWriter.WriteValue(glue);
                                        }
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }
                                }
                                break;

                            case DnsResourceRecordType.CNAME:
                                {
                                    if (record.RDATA is DnsCNAMERecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Domain.Length == 0 ? "." : rdata.Domain);
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }
                                }
                                break;

                            case DnsResourceRecordType.SRV:
                                {
                                    if (record.RDATA is DnsSRVRecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("priority");
                                        jsonWriter.WriteValue(rdata.Priority);

                                        jsonWriter.WritePropertyName("weight");
                                        jsonWriter.WriteValue(rdata.Weight);

                                        jsonWriter.WritePropertyName("port");
                                        jsonWriter.WriteValue(rdata.Port);

                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Target.Length == 0 ? "." : rdata.Target);

                                        IReadOnlyList<DnsResourceRecord> glueRecords = record.GetGlueRecords();
                                        if (glueRecords.Count > 0)
                                        {
                                            string glue = null;

                                            foreach (DnsResourceRecord glueRecord in glueRecords)
                                            {
                                                if (glue == null)
                                                    glue = glueRecord.RDATA.ToString();
                                                else
                                                    glue = glue + ", " + glueRecord.RDATA.ToString();
                                            }

                                            jsonWriter.WritePropertyName("glue");
                                            jsonWriter.WriteValue(glue);
                                        }
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }
                                }
                                break;

                            case DnsResourceRecordType.DNAME:
                                {
                                    if (record.RDATA is DnsDNAMERecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Domain.Length == 0 ? "." : rdata.Domain);
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }
                                }
                                break;

                            case DnsResourceRecordType.CAA:
                                {
                                    if (record.RDATA is DnsCAARecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("flags");
                                        jsonWriter.WriteValue(rdata.Flags);

                                        jsonWriter.WritePropertyName("tag");
                                        jsonWriter.WriteValue(rdata.Tag);

                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Value);
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }
                                }
                                break;

                            case DnsResourceRecordType.ANAME:
                                {
                                    if (record.RDATA is DnsANAMERecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Domain.Length == 0 ? "." : rdata.Domain);
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
                                    }
                                }
                                break;

                            case DnsResourceRecordType.FWD:
                                {
                                    if (record.RDATA is DnsForwarderRecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("protocol");
                                        jsonWriter.WriteValue(rdata.Protocol.ToString());

                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.Forwarder);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.APP:
                                {
                                    if (record.RDATA is DnsApplicationRecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("value");
                                        jsonWriter.WriteValue(rdata.AppName);

                                        jsonWriter.WritePropertyName("classPath");
                                        jsonWriter.WriteValue(rdata.ClassPath);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(rdata.Data);
                                    }
                                }
                                break;

                            default:
                                {
                                    if (record.RDATA is DnsUnknownRecord)
                                    {
                                        jsonWriter.WritePropertyName("value");

                                        using (MemoryStream mS = new MemoryStream())
                                        {
                                            record.RDATA.WriteTo(mS, new List<DnsDomainOffset>());

                                            jsonWriter.WriteValue(Convert.ToBase64String(mS.ToArray()));
                                        }
                                    }
                                    else
                                    {
                                        jsonWriter.WritePropertyName("dataType");
                                        jsonWriter.WriteValue(record.RDATA.GetType().Name);

                                        jsonWriter.WritePropertyName("data");
                                        jsonWriter.WriteValue(record.RDATA.ToString());
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

        public void DeleteRecord(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new DnsWebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

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
                case DnsResourceRecordType.AAAA:
                    {
                        IPAddress address = IPAddress.Parse(value);

                        if (type == DnsResourceRecordType.A)
                            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsARecord(address));
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsAAAARecord(address));

                        string ptrDomain = Zone.GetReverseZone(address, type == DnsResourceRecordType.A ? 32 : 128);
                        AuthZoneInfo reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(ptrDomain);
                        if ((reverseZoneInfo != null) && !reverseZoneInfo.Internal && (reverseZoneInfo.Type == AuthZoneType.Primary))
                        {
                            IReadOnlyList<DnsResourceRecord> ptrRecords = _dnsWebService.DnsServer.AuthZoneManager.QueryRecords(ptrDomain, DnsResourceRecordType.PTR);
                            if (ptrRecords.Count > 0)
                            {
                                foreach (DnsResourceRecord ptrRecord in ptrRecords)
                                {
                                    if ((ptrRecord.RDATA as DnsPTRRecord).Domain.Equals(domain, StringComparison.OrdinalIgnoreCase))
                                    {
                                        //delete PTR record and save reverse zone
                                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(ptrDomain, DnsResourceRecordType.PTR, ptrRecord.RDATA);
                                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    break;

                case DnsResourceRecordType.MX:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsMXRecord(0, value));
                    break;

                case DnsResourceRecordType.TXT:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsTXTRecord(value));
                    break;

                case DnsResourceRecordType.NS:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsNSRecord(value));
                    break;

                case DnsResourceRecordType.ANAME:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsANAMERecord(value));
                    break;

                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.DNAME:
                case DnsResourceRecordType.PTR:
                case DnsResourceRecordType.APP:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(domain, type);
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        string port = request.QueryString["port"];
                        if (string.IsNullOrEmpty(port))
                            throw new DnsWebServiceException("Parameter 'port' missing.");

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsSRVRecord(0, 0, ushort.Parse(port), value));
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        string flags = request.QueryString["flags"];
                        if (string.IsNullOrEmpty(flags))
                            throw new DnsWebServiceException("Parameter 'flags' missing.");

                        string tag = request.QueryString["tag"];
                        if (string.IsNullOrEmpty(tag))
                            throw new DnsWebServiceException("Parameter 'tag' missing.");

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsCAARecord(byte.Parse(flags), tag, value));
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        string strProtocol = request.QueryString["protocol"];
                        if (string.IsNullOrEmpty(strProtocol))
                            strProtocol = "Udp";

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(domain, type, new DnsForwarderRecord((DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), strProtocol, true), value));
                    }
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for DeleteRecord().");
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Record was deleted from authoritative zone {domain: " + domain + "; type: " + type + "; value: " + value + ";}");

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void UpdateRecord(HttpListenerRequest request)
        {
            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
            if (zoneInfo == null)
                throw new DnsWebServiceException("Zone '" + domain + "' was not found.");

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            string newDomain = request.QueryString["newDomain"];
            if (string.IsNullOrEmpty(newDomain))
                newDomain = domain;

            newDomain = newDomain.TrimEnd('.');

            uint ttl;
            string strTtl = request.QueryString["ttl"];
            if (string.IsNullOrEmpty(strTtl))
                ttl = _defaultRecordTtl;
            else
                ttl = uint.Parse(strTtl);

            string value = request.QueryString["value"];

            string newValue = request.QueryString["newValue"];
            if (string.IsNullOrEmpty(newValue))
                newValue = value;

            bool disable = false;
            string strDisable = request.QueryString["disable"];
            if (!string.IsNullOrEmpty(strDisable))
                disable = bool.Parse(strDisable);

            string comments = request.QueryString["comments"];

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        IPAddress oldIpAddress = IPAddress.Parse(value);
                        IPAddress newIpAddress = IPAddress.Parse(newValue);

                        bool ptr = false;
                        string strPtr = request.QueryString["ptr"];
                        if (!string.IsNullOrEmpty(strPtr))
                            ptr = bool.Parse(strPtr);

                        if (ptr)
                        {
                            string ptrDomain = Zone.GetReverseZone(newIpAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(ptrDomain);
                            if (reverseZoneInfo == null)
                            {
                                bool createPtrZone = false;
                                string strCreatePtrZone = request.QueryString["createPtrZone"];
                                if (!string.IsNullOrEmpty(strCreatePtrZone))
                                    createPtrZone = bool.Parse(strCreatePtrZone);

                                if (!createPtrZone)
                                    throw new DnsServerException("No reverse zone available to add PTR record.");

                                string ptrZone = Zone.GetReverseZone(newIpAddress, type == DnsResourceRecordType.A ? 24 : 64);

                                reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreatePrimaryZone(ptrZone, _dnsWebService.DnsServer.ServerDomain, false);
                                if (reverseZoneInfo == null)
                                    throw new DnsServerException("Failed to create reverse zone to add PTR record: " + ptrZone);
                            }

                            if (reverseZoneInfo.Internal)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is an internal zone.");

                            if (reverseZoneInfo.Type != AuthZoneType.Primary)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is not a primary zone.");


                            string oldPtrDomain = Zone.GetReverseZone(oldIpAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo oldReverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(oldPtrDomain);
                            if ((oldReverseZoneInfo != null) && !oldReverseZoneInfo.Internal && (oldReverseZoneInfo.Type == AuthZoneType.Primary))
                            {
                                //delete old PTR record if any and save old reverse zone
                                _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(oldPtrDomain, DnsResourceRecordType.PTR);
                                _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(oldReverseZoneInfo.Name);
                            }

                            //add new PTR record and save reverse zone
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecords(ptrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecord[] { new DnsPTRRecord(domain) });
                            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                        }

                        DnsResourceRecord oldRecord;
                        DnsResourceRecord newRecord;

                        if (type == DnsResourceRecordType.A)
                        {
                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsARecord(oldIpAddress));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsARecord(newIpAddress));
                        }
                        else
                        {
                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsAAAARecord(oldIpAddress));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsAAAARecord(newIpAddress));
                        }

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        string preference = request.QueryString["preference"];
                        if (string.IsNullOrEmpty(preference))
                            preference = "1";

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsMXRecord(0, value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsMXRecord(ushort.Parse(preference), newValue.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsTXTRecord(value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsTXTRecord(newValue));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsNSRecord(value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsNSRecord(newValue.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        string glueAddresses = request.QueryString["glue"];
                        if (!string.IsNullOrEmpty(glueAddresses))
                            newRecord.SetGlueRecords(glueAddresses);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SOA:
                    {
                        string primaryNameServer = request.QueryString["primaryNameServer"];
                        if (string.IsNullOrEmpty(primaryNameServer))
                            throw new DnsWebServiceException("Parameter 'primaryNameServer' missing.");

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

                        DnsResourceRecord newSoaRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSOARecord(primaryNameServer, responsiblePerson, uint.Parse(serial), uint.Parse(refresh), uint.Parse(retry), uint.Parse(expire), uint.Parse(minimum)));

                        switch (zoneInfo.Type)
                        {
                            case AuthZoneType.Secondary:
                            case AuthZoneType.Stub:
                                string primaryAddresses = request.QueryString["primaryAddresses"];
                                if (!string.IsNullOrEmpty(primaryAddresses))
                                    newSoaRecord.SetPrimaryNameServers(primaryAddresses);

                                break;
                        }

                        if (zoneInfo.Type == AuthZoneType.Secondary)
                        {
                            DnsResourceRecordInfo recordInfo = newSoaRecord.GetRecordInfo();

                            string zoneTransferProtocol = request.QueryString["zoneTransferProtocol"];
                            if (string.IsNullOrEmpty(zoneTransferProtocol))
                                recordInfo.ZoneTransferProtocol = DnsTransportProtocol.Tcp;
                            else
                                recordInfo.ZoneTransferProtocol = Enum.Parse<DnsTransportProtocol>(zoneTransferProtocol, true);

                            string tsigKeyName = request.QueryString["tsigKeyName"];
                            if (!string.IsNullOrEmpty(tsigKeyName))
                                recordInfo.TsigKeyName = tsigKeyName;
                        }

                        if (!string.IsNullOrEmpty(comments))
                            newSoaRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(newSoaRecord);
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsPTRRecord(value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsPTRRecord(newValue.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCNAMERecord(value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCNAMERecord(newValue.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        string port = request.QueryString["port"];
                        if (string.IsNullOrEmpty(port))
                            throw new DnsWebServiceException("Parameter 'port' missing.");

                        string priority = request.QueryString["priority"];
                        if (string.IsNullOrEmpty(priority))
                            throw new DnsWebServiceException("Parameter 'priority' missing.");

                        string weight = request.QueryString["weight"];
                        if (string.IsNullOrEmpty(weight))
                            throw new DnsWebServiceException("Parameter 'weight' missing.");

                        string newPort = request.QueryString["newPort"];
                        if (string.IsNullOrEmpty(newPort))
                            newPort = port;

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSRVRecord(0, 0, ushort.Parse(port), value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSRVRecord(ushort.Parse(priority), ushort.Parse(weight), ushort.Parse(newPort), newValue.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsDNAMERecord(value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsDNAMERecord(newValue.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        string flags = request.QueryString["flags"];
                        if (string.IsNullOrEmpty(flags))
                            throw new DnsWebServiceException("Parameter 'flags' missing.");

                        string tag = request.QueryString["tag"];
                        if (string.IsNullOrEmpty(tag))
                            throw new DnsWebServiceException("Parameter 'tag' missing.");

                        string newFlags = request.QueryString["newFlags"];
                        if (string.IsNullOrEmpty(newFlags))
                            newFlags = flags;

                        string newTag = request.QueryString["newTag"];
                        if (string.IsNullOrEmpty(newTag))
                            newTag = tag;

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCAARecord(byte.Parse(flags), tag, value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCAARecord(byte.Parse(newFlags), newTag, newValue));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsANAMERecord(value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsANAMERecord(newValue.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        string strProtocol = request.QueryString["protocol"];
                        if (string.IsNullOrEmpty(strProtocol))
                            strProtocol = "Udp";

                        DnsTransportProtocol protocol = (DnsTransportProtocol)Enum.Parse(typeof(DnsTransportProtocol), strProtocol, true);

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecord(protocol, value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsForwarderRecord(protocol, newValue));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.APP:
                    {
                        string classPath = request.QueryString["classPath"];
                        if (string.IsNullOrEmpty(classPath))
                            throw new DnsWebServiceException("Parameter 'classPath' missing.");

                        string recordData = request.QueryString["recordData"];
                        if (string.IsNullOrEmpty(recordData))
                            recordData = "";

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsApplicationRecord(value, classPath, recordData));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsApplicationRecord(newValue, classPath, recordData));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(oldRecord, newRecord);
                    }
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for UpdateRecords().");
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Record was updated for authoritative zone {oldDomain: " + domain + "; domain: " + newDomain + "; type: " + type + "; oldValue: " + value + "; value: " + newValue + "; ttl: " + ttl + "; disabled: " + disable + ";}");

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        #endregion

        #region properties

        public uint DefaultRecordTtl
        {
            get { return _defaultRecordTtl; }
            set { _defaultRecordTtl = value; }
        }

        #endregion
    }
}
