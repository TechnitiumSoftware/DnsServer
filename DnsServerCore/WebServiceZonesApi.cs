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
using DnsServerCore.Dns;
using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

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

        #region static

        public static void WriteRecordsAsJson(List<DnsResourceRecord> records, Utf8JsonWriter jsonWriter, bool authoritativeZoneRecords, AuthZoneInfo zoneInfo = null)
        {
            if (records is null)
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
                        WriteRecordAsJson(record, jsonWriter, authoritativeZoneRecords, zoneInfo);
                }
            }

            jsonWriter.WriteEndArray();
        }

        #endregion

        #region private

        private static void WriteRecordAsJson(DnsResourceRecord record, Utf8JsonWriter jsonWriter, bool authoritativeZoneRecords, AuthZoneInfo zoneInfo = null)
        {
            jsonWriter.WriteStartObject();

            if (authoritativeZoneRecords)
                jsonWriter.WriteBoolean("disabled", record.IsDisabled());

            jsonWriter.WriteString("name", record.Name);

            jsonWriter.WriteString("type", record.Type.ToString());

            jsonWriter.WritePropertyName("ttl");
            if (authoritativeZoneRecords)
                jsonWriter.WriteNumberValue(record.TTL);
            else
                jsonWriter.WriteStringValue(record.TTL + " (" + WebUtilities.GetFormattedTime((int)record.TTL) + ")");

            if (authoritativeZoneRecords)
            {
                string comments = record.GetComments();
                if (!string.IsNullOrEmpty(comments))
                    jsonWriter.WriteString("comments", comments);
            }

            jsonWriter.WritePropertyName("rData");
            jsonWriter.WriteStartObject();

            DnsResourceRecordInfo recordInfo = record.GetRecordInfo();

            switch (record.Type)
            {
                case DnsResourceRecordType.A:
                    {
                        if (record.RDATA is DnsARecordData rdata)
                        {
                            jsonWriter.WriteString("ipAddress", rdata.Address.ToString());
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        if (record.RDATA is DnsNSRecordData rdata)
                        {
                            jsonWriter.WriteString("nameServer", rdata.NameServer.Length == 0 ? "." : rdata.NameServer);

                            if (!authoritativeZoneRecords)
                            {
                                if (rdata.IsParentSideTtlSet)
                                    jsonWriter.WriteString("parentSideTtl", rdata.ParentSideTtl + " (" + WebUtilities.GetFormattedTime((int)rdata.ParentSideTtl) + ")");
                            }
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        if (record.RDATA is DnsCNAMERecordData rdata)
                        {
                            jsonWriter.WriteString("cname", rdata.Domain.Length == 0 ? "." : rdata.Domain);
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.SOA:
                    {
                        if (record.RDATA is DnsSOARecordData rdata)
                        {
                            jsonWriter.WriteString("primaryNameServer", rdata.PrimaryNameServer);
                            jsonWriter.WriteString("responsiblePerson", rdata.ResponsiblePerson);
                            jsonWriter.WriteNumber("serial", rdata.Serial);
                            jsonWriter.WriteNumber("refresh", rdata.Refresh);
                            jsonWriter.WriteNumber("retry", rdata.Retry);
                            jsonWriter.WriteNumber("expire", rdata.Expire);
                            jsonWriter.WriteNumber("minimum", rdata.Minimum);
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
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

                                jsonWriter.WriteString("primaryAddresses", primaryAddresses);
                            }

                            if (recordInfo.ZoneTransferProtocol != DnsTransportProtocol.Udp)
                                jsonWriter.WriteString("zoneTransferProtocol", recordInfo.ZoneTransferProtocol.ToString());

                            if (!string.IsNullOrEmpty(recordInfo.TsigKeyName))
                                jsonWriter.WriteString("tsigKeyName", recordInfo.TsigKeyName);
                        }
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        if (record.RDATA is DnsPTRRecordData rdata)
                        {
                            jsonWriter.WriteString("ptrName", rdata.Domain.Length == 0 ? "." : rdata.Domain);
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        if (record.RDATA is DnsMXRecordData rdata)
                        {
                            jsonWriter.WriteNumber("preference", rdata.Preference);
                            jsonWriter.WriteString("exchange", rdata.Exchange.Length == 0 ? "." : rdata.Exchange);
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        if (record.RDATA is DnsTXTRecordData rdata)
                        {
                            jsonWriter.WriteString("text", rdata.Text);
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.AAAA:
                    {
                        if (record.RDATA is DnsAAAARecordData rdata)
                        {
                            jsonWriter.WriteString("ipAddress", rdata.Address.ToString());
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        if (record.RDATA is DnsSRVRecordData rdata)
                        {
                            jsonWriter.WriteNumber("priority", rdata.Priority);
                            jsonWriter.WriteNumber("weight", rdata.Weight);
                            jsonWriter.WriteNumber("port", rdata.Port);
                            jsonWriter.WriteString("target", rdata.Target.Length == 0 ? "." : rdata.Target);
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    {
                        if (record.RDATA is DnsDNAMERecordData rdata)
                        {
                            jsonWriter.WriteString("dname", rdata.Domain.Length == 0 ? "." : rdata.Domain);
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.DS:
                    {
                        if (record.RDATA is DnsDSRecordData rdata)
                        {
                            jsonWriter.WriteNumber("keyTag", rdata.KeyTag);
                            jsonWriter.WriteString("algorithm", rdata.Algorithm.ToString());
                            jsonWriter.WriteString("digestType", rdata.DigestType.ToString());
                            jsonWriter.WriteString("digest", Convert.ToHexString(rdata.Digest));
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.SSHFP:
                    {
                        if (record.RDATA is DnsSSHFPRecordData rdata)
                        {
                            jsonWriter.WriteString("algorithm", rdata.Algorithm.ToString());
                            jsonWriter.WriteString("fingerprintType", rdata.FingerprintType.ToString());
                            jsonWriter.WriteString("fingerprint", Convert.ToHexString(rdata.Fingerprint));
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.RRSIG:
                    {
                        if (record.RDATA is DnsRRSIGRecordData rdata)
                        {
                            jsonWriter.WriteString("typeCovered", rdata.TypeCovered.ToString());
                            jsonWriter.WriteString("algorithm", rdata.Algorithm.ToString());
                            jsonWriter.WriteNumber("labels", rdata.Labels);
                            jsonWriter.WriteNumber("originalTtl", rdata.OriginalTtl);
                            jsonWriter.WriteString("signatureExpiration", DateTime.UnixEpoch.AddSeconds(rdata.SignatureExpiration));
                            jsonWriter.WriteString("signatureInception", DateTime.UnixEpoch.AddSeconds(rdata.SignatureInception));
                            jsonWriter.WriteNumber("keyTag", rdata.KeyTag);
                            jsonWriter.WriteString("signersName", rdata.SignersName.Length == 0 ? "." : rdata.SignersName);
                            jsonWriter.WriteString("signature", Convert.ToBase64String(rdata.Signature));
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.NSEC:
                    {
                        if (record.RDATA is DnsNSECRecordData rdata)
                        {
                            jsonWriter.WriteString("nextDomainName", rdata.NextDomainName);

                            jsonWriter.WritePropertyName("types");
                            jsonWriter.WriteStartArray();

                            foreach (DnsResourceRecordType type in rdata.Types)
                                jsonWriter.WriteStringValue(type.ToString());

                            jsonWriter.WriteEndArray();
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.DNSKEY:
                    {
                        if (record.RDATA is DnsDNSKEYRecordData rdata)
                        {
                            jsonWriter.WriteString("flags", rdata.Flags.ToString());
                            jsonWriter.WriteNumber("protocol", rdata.Protocol);
                            jsonWriter.WriteString("algorithm", rdata.Algorithm.ToString());
                            jsonWriter.WriteString("publicKey", rdata.PublicKey.ToString());
                            jsonWriter.WriteNumber("computedKeyTag", rdata.ComputedKeyTag);

                            if (authoritativeZoneRecords)
                            {
                                if (zoneInfo.Type == AuthZoneType.Primary)
                                {
                                    foreach (DnssecPrivateKey dnssecPrivateKey in zoneInfo.DnssecPrivateKeys)
                                    {
                                        if (dnssecPrivateKey.KeyTag == rdata.ComputedKeyTag)
                                        {
                                            jsonWriter.WriteString("dnsKeyState", dnssecPrivateKey.State.ToString());

                                            if ((dnssecPrivateKey.KeyType == DnssecPrivateKeyType.KeySigningKey) && (dnssecPrivateKey.State == DnssecPrivateKeyState.Published))
                                                jsonWriter.WriteString("dnsKeyStateReadyBy", (zoneInfo.ApexZone as PrimaryZone).GetDnsKeyStateReadyBy(dnssecPrivateKey));

                                            break;
                                        }
                                    }
                                }

                                if (rdata.Flags.HasFlag(DnsDnsKeyFlag.SecureEntryPoint))
                                {
                                    jsonWriter.WritePropertyName("computedDigests");
                                    jsonWriter.WriteStartArray();

                                    {
                                        jsonWriter.WriteStartObject();

                                        jsonWriter.WriteString("digestType", "SHA256");
                                        jsonWriter.WriteString("digest", Convert.ToHexString(rdata.CreateDS(record.Name, DnssecDigestType.SHA256).Digest));

                                        jsonWriter.WriteEndObject();
                                    }

                                    {
                                        jsonWriter.WriteStartObject();

                                        jsonWriter.WriteString("digestType", "SHA384");
                                        jsonWriter.WriteString("digest", Convert.ToHexString(rdata.CreateDS(record.Name, DnssecDigestType.SHA384).Digest));

                                        jsonWriter.WriteEndObject();
                                    }

                                    jsonWriter.WriteEndArray();
                                }
                            }
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.NSEC3:
                    {
                        if (record.RDATA is DnsNSEC3RecordData rdata)
                        {
                            jsonWriter.WriteString("hashAlgorithm", rdata.HashAlgorithm.ToString());
                            jsonWriter.WriteString("flags", rdata.Flags.ToString());
                            jsonWriter.WriteNumber("iterations", rdata.Iterations);
                            jsonWriter.WriteString("salt", Convert.ToHexString(rdata.Salt));
                            jsonWriter.WriteString("nextHashedOwnerName", rdata.NextHashedOwnerName);

                            jsonWriter.WritePropertyName("types");
                            jsonWriter.WriteStartArray();

                            foreach (DnsResourceRecordType type in rdata.Types)
                                jsonWriter.WriteStringValue(type.ToString());

                            jsonWriter.WriteEndArray();
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.NSEC3PARAM:
                    {
                        if (record.RDATA is DnsNSEC3PARAMRecordData rdata)
                        {
                            jsonWriter.WriteString("hashAlgorithm", rdata.HashAlgorithm.ToString());
                            jsonWriter.WriteString("flags", rdata.Flags.ToString());
                            jsonWriter.WriteNumber("iterations", rdata.Iterations);
                            jsonWriter.WriteString("salt", Convert.ToHexString(rdata.Salt));
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.TLSA:
                    {
                        if (record.RDATA is DnsTLSARecordData rdata)
                        {
                            jsonWriter.WriteString("certificateUsage", rdata.CertificateUsage.ToString().Replace('_', '-'));
                            jsonWriter.WriteString("selector", rdata.Selector.ToString());
                            jsonWriter.WriteString("matchingType", rdata.MatchingType.ToString().Replace('_', '-'));
                            jsonWriter.WriteString("certificateAssociationData", Convert.ToHexString(rdata.CertificateAssociationData));
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        if (record.RDATA is DnsCAARecordData rdata)
                        {
                            jsonWriter.WriteNumber("flags", rdata.Flags);
                            jsonWriter.WriteString("tag", rdata.Tag);
                            jsonWriter.WriteString("value", rdata.Value);
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        if (record.RDATA is DnsANAMERecordData rdata)
                        {
                            jsonWriter.WriteString("aname", rdata.Domain.Length == 0 ? "." : rdata.Domain);
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        if (record.RDATA is DnsForwarderRecordData rdata)
                        {
                            jsonWriter.WriteString("protocol", rdata.Protocol.ToString());
                            jsonWriter.WriteString("forwarder", rdata.Forwarder);
                            jsonWriter.WriteBoolean("dnssecValidation", rdata.DnssecValidation);
                            jsonWriter.WriteString("proxyType", rdata.ProxyType.ToString());

                            if (rdata.ProxyType != NetProxyType.None)
                            {
                                jsonWriter.WriteString("proxyAddress", rdata.ProxyAddress);
                                jsonWriter.WriteNumber("proxyPort", rdata.ProxyPort);
                                jsonWriter.WriteString("proxyUsername", rdata.ProxyUsername);
                                jsonWriter.WriteString("proxyPassword", rdata.ProxyPassword);
                            }
                        }
                    }
                    break;

                case DnsResourceRecordType.APP:
                    {
                        if (record.RDATA is DnsApplicationRecordData rdata)
                        {
                            jsonWriter.WriteString("appName", rdata.AppName);
                            jsonWriter.WriteString("classPath", rdata.ClassPath);
                            jsonWriter.WriteString("data", rdata.Data);
                        }
                    }
                    break;

                default:
                    {
                        if (record.RDATA is DnsUnknownRecordData)
                        {
                            using (MemoryStream mS = new MemoryStream())
                            {
                                record.RDATA.WriteTo(mS);

                                jsonWriter.WriteString("value", Convert.ToBase64String(mS.ToArray()));
                            }
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;
            }

            jsonWriter.WriteEndObject();

            IReadOnlyList<DnsResourceRecord> glueRecords = recordInfo.GlueRecords;
            if (glueRecords is not null)
            {
                string glue = null;

                foreach (DnsResourceRecord glueRecord in glueRecords)
                {
                    if (glue == null)
                        glue = glueRecord.RDATA.ToString();
                    else
                        glue = glue + ", " + glueRecord.RDATA.ToString();
                }

                jsonWriter.WriteString("glueRecords", glue);
            }

            IReadOnlyList<DnsResourceRecord> rrsigRecords = recordInfo.RRSIGRecords;
            IReadOnlyList<DnsResourceRecord> nsecRecords = recordInfo.NSECRecords;

            if ((rrsigRecords is not null) || (nsecRecords is not null))
            {
                jsonWriter.WritePropertyName("dnssecRecords");
                jsonWriter.WriteStartArray();

                if (rrsigRecords is not null)
                {
                    foreach (DnsResourceRecord rrsigRecord in rrsigRecords)
                        jsonWriter.WriteStringValue(rrsigRecord.ToString());
                }

                if (nsecRecords is not null)
                {
                    foreach (DnsResourceRecord nsecRecord in nsecRecords)
                        jsonWriter.WriteStringValue(nsecRecord.ToString());
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WriteString("dnssecStatus", record.DnssecStatus.ToString());

            NetworkAddress eDnsClientSubnet = recordInfo.EDnsClientSubnet;
            if (eDnsClientSubnet is not null)
            {
                jsonWriter.WriteString("eDnsClientSubnet", eDnsClientSubnet.ToString());
            }

            jsonWriter.WriteString("lastUsedOn", recordInfo.LastUsedOn);

            jsonWriter.WriteEndObject();
        }

        private static void WriteZoneInfoAsJson(AuthZoneInfo zoneInfo, Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("name", zoneInfo.Name);
            jsonWriter.WriteString("type", zoneInfo.Type.ToString());

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    jsonWriter.WriteBoolean("internal", zoneInfo.Internal);
                    jsonWriter.WriteString("dnssecStatus", zoneInfo.DnssecStatus.ToString());

                    if (!zoneInfo.Internal)
                        jsonWriter.WriteBoolean("notifyFailed", zoneInfo.NotifyFailed);

                    break;

                case AuthZoneType.Secondary:
                    jsonWriter.WriteString("dnssecStatus", zoneInfo.DnssecStatus.ToString());
                    jsonWriter.WriteString("expiry", zoneInfo.Expiry);
                    jsonWriter.WriteBoolean("isExpired", zoneInfo.IsExpired);
                    jsonWriter.WriteBoolean("notifyFailed", zoneInfo.NotifyFailed);
                    jsonWriter.WriteBoolean("syncFailed", zoneInfo.SyncFailed);
                    break;

                case AuthZoneType.Stub:
                    jsonWriter.WriteString("expiry", zoneInfo.Expiry);
                    jsonWriter.WriteBoolean("isExpired", zoneInfo.IsExpired);
                    jsonWriter.WriteBoolean("syncFailed", zoneInfo.SyncFailed);
                    break;
            }

            jsonWriter.WriteBoolean("disabled", zoneInfo.Disabled);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region public

        public void ListZones(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            List<AuthZoneInfo> zones = _dnsWebService._dnsServer.AuthZoneManager.ListZones();
            zones.Sort();

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            foreach (AuthZoneInfo zone in zones)
            {
                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zone.Name, session.User, PermissionFlag.View))
                    continue;

                WriteZoneInfoAsJson(zone, jsonWriter);
            }

            jsonWriter.WriteEndArray();
        }

        public async Task CreateZoneAsync(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryAlt("zone", "domain");
            if (zoneName.Contains('*'))
                throw new DnsWebServiceException("Domain name for a zone cannot contain wildcard character.");

            if (IPAddress.TryParse(zoneName, out IPAddress ipAddress))
            {
                zoneName = ipAddress.GetReverseDomain().ToLower();
            }
            else if (zoneName.Contains('/'))
            {
                string[] parts = zoneName.Split('/');
                if ((parts.Length == 2) && IPAddress.TryParse(parts[0], out ipAddress) && int.TryParse(parts[1], out int subnetMaskWidth))
                    zoneName = Zone.GetReverseZone(ipAddress, subnetMaskWidth);
            }
            else if (zoneName.EndsWith("."))
            {
                zoneName = zoneName.Substring(0, zoneName.Length - 1);
            }

            AuthZoneType type = request.GetQuery("type", AuthZoneType.Primary);
            AuthZoneInfo zoneInfo;

            switch (type)
            {
                case AuthZoneType.Primary:
                    {
                        zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreatePrimaryZone(zoneName, _dnsWebService._dnsServer.ServerDomain, false);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        //set permissions
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SaveConfigFile();

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Authoritative primary zone was created: " + zoneName);
                        _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
                    break;

                case AuthZoneType.Secondary:
                    {
                        string primaryNameServerAddresses = request.GetQuery("primaryNameServerAddresses", null);
                        DnsTransportProtocol zoneTransferProtocol = request.GetQuery("zoneTransferProtocol", DnsTransportProtocol.Tcp);
                        string tsigKeyName = request.GetQuery("tsigKeyName", null);

                        zoneInfo = await _dnsWebService._dnsServer.AuthZoneManager.CreateSecondaryZoneAsync(zoneName, primaryNameServerAddresses, zoneTransferProtocol, tsigKeyName);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        //set permissions
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SaveConfigFile();

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Authoritative secondary zone was created: " + zoneName);
                        _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
                    break;

                case AuthZoneType.Stub:
                    {
                        string primaryNameServerAddresses = request.GetQuery("primaryNameServerAddresses", null);

                        zoneInfo = await _dnsWebService._dnsServer.AuthZoneManager.CreateStubZoneAsync(zoneName, primaryNameServerAddresses);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        //set permissions
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SaveConfigFile();

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Stub zone was created: " + zoneName);
                        _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
                    break;

                case AuthZoneType.Forwarder:
                    {
                        DnsTransportProtocol forwarderProtocol = request.GetQuery("protocol", DnsTransportProtocol.Udp);
                        string forwarder = request.GetQuery("forwarder");
                        bool dnssecValidation = request.GetQuery("dnssecValidation", bool.Parse, false);
                        NetProxyType proxyType = request.GetQuery("proxyType", NetProxyType.None);

                        string proxyAddress = null;
                        ushort proxyPort = 0;
                        string proxyUsername = null;
                        string proxyPassword = null;

                        if (proxyType != NetProxyType.None)
                        {
                            proxyAddress = request.GetQuery("proxyAddress");
                            proxyPort = request.GetQuery("proxyPort", ushort.Parse);
                            proxyUsername = request.Query["proxyUsername"];
                            proxyPassword = request.Query["proxyPassword"];
                        }

                        zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreateForwarderZone(zoneName, forwarderProtocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, null);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        //set permissions
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SaveConfigFile();

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Forwarder zone was created: " + zoneName);
                        _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
                    break;

                default:
                    throw new NotSupportedException("Zone type not supported.");
            }

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
            _dnsWebService._dnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
            jsonWriter.WriteString("domain", string.IsNullOrEmpty(zoneInfo.Name) ? "." : zoneInfo.Name);
        }

        public void SignPrimaryZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string algorithm = request.GetQuery("algorithm");
            uint dnsKeyTtl = request.GetQuery<uint>("dnsKeyTtl", uint.Parse, 24 * 60 * 60);
            ushort zskRolloverDays = request.GetQuery<ushort>("zskRolloverDays", ushort.Parse, 90);

            bool useNSEC3 = false;
            string strNxProof = request.Query["nxProof"];
            if (!string.IsNullOrEmpty(strNxProof))
            {
                switch (strNxProof.ToUpper())
                {
                    case "NSEC":
                        useNSEC3 = false;
                        break;

                    case "NSEC3":
                        useNSEC3 = true;
                        break;

                    default:
                        throw new NotSupportedException("Non-existence proof type is not supported: " + strNxProof);
                }
            }

            ushort iterations = 0;
            byte saltLength = 0;

            if (useNSEC3)
            {
                iterations = request.GetQuery<ushort>("iterations", ushort.Parse, 0);
                saltLength = request.GetQuery<byte>("saltLength", byte.Parse, 0);
            }

            switch (algorithm.ToUpper())
            {
                case "RSA":
                    string hashAlgorithm = request.GetQuery("hashAlgorithm");
                    int kskKeySize = request.GetQuery("kskKeySize", int.Parse);
                    int zskKeySize = request.GetQuery("zskKeySize", int.Parse);

                    if (useNSEC3)
                        _dnsWebService._dnsServer.AuthZoneManager.SignPrimaryZoneWithRsaNSEC3(zoneName, hashAlgorithm, kskKeySize, zskKeySize, iterations, saltLength, dnsKeyTtl, zskRolloverDays);
                    else
                        _dnsWebService._dnsServer.AuthZoneManager.SignPrimaryZoneWithRsaNSEC(zoneName, hashAlgorithm, kskKeySize, zskKeySize, dnsKeyTtl, zskRolloverDays);

                    break;

                case "ECDSA":
                    string curve = request.GetQuery("curve");

                    if (useNSEC3)
                        _dnsWebService._dnsServer.AuthZoneManager.SignPrimaryZoneWithEcdsaNSEC3(zoneName, curve, iterations, saltLength, dnsKeyTtl, zskRolloverDays);
                    else
                        _dnsWebService._dnsServer.AuthZoneManager.SignPrimaryZoneWithEcdsaNSEC(zoneName, curve, dnsKeyTtl, zskRolloverDays);

                    break;

                default:
                    throw new NotSupportedException("Algorithm is not supported: " + algorithm);
            }

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone was signed successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UnsignPrimaryZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService._dnsServer.AuthZoneManager.UnsignPrimaryZone(zoneName);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone was unsigned successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void GetPrimaryZoneDnssecProperties(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQuery("zone").TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (zoneInfo.Type != AuthZoneType.Primary)
                throw new DnsWebServiceException("The zone must be a primary zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WriteString("name", zoneInfo.Name);
            jsonWriter.WriteString("type", zoneInfo.Type.ToString());
            jsonWriter.WriteBoolean("internal", zoneInfo.Internal);
            jsonWriter.WriteBoolean("disabled", zoneInfo.Disabled);
            jsonWriter.WriteString("dnssecStatus", zoneInfo.DnssecStatus.ToString());

            if (zoneInfo.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3)
            {
                IReadOnlyList<DnsResourceRecord> nsec3ParamRecords = zoneInfo.GetApexRecords(DnsResourceRecordType.NSEC3PARAM);
                DnsNSEC3PARAMRecordData nsec3Param = nsec3ParamRecords[0].RDATA as DnsNSEC3PARAMRecordData;

                jsonWriter.WriteNumber("nsec3Iterations", nsec3Param.Iterations);
                jsonWriter.WriteNumber("nsec3SaltLength", nsec3Param.Salt.Length);
            }

            jsonWriter.WriteNumber("dnsKeyTtl", zoneInfo.DnsKeyTtl);

            jsonWriter.WritePropertyName("dnssecPrivateKeys");
            jsonWriter.WriteStartArray();

            IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys = zoneInfo.DnssecPrivateKeys;
            if (dnssecPrivateKeys is not null)
            {
                List<DnssecPrivateKey> sortedDnssecPrivateKey = new List<DnssecPrivateKey>(dnssecPrivateKeys);

                sortedDnssecPrivateKey.Sort(delegate (DnssecPrivateKey key1, DnssecPrivateKey key2)
                {
                    int value = key1.KeyType.CompareTo(key2.KeyType);
                    if (value == 0)
                        value = key1.StateChangedOn.CompareTo(key2.StateChangedOn);

                    return value;
                });

                foreach (DnssecPrivateKey dnssecPrivateKey in sortedDnssecPrivateKey)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteNumber("keyTag", dnssecPrivateKey.KeyTag);
                    jsonWriter.WriteString("keyType", dnssecPrivateKey.KeyType.ToString());

                    switch (dnssecPrivateKey.Algorithm)
                    {
                        case DnssecAlgorithm.RSAMD5:
                        case DnssecAlgorithm.RSASHA1:
                        case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                        case DnssecAlgorithm.RSASHA256:
                        case DnssecAlgorithm.RSASHA512:
                            jsonWriter.WriteString("algorithm", dnssecPrivateKey.Algorithm.ToString() + " (" + (dnssecPrivateKey as DnssecRsaPrivateKey).KeySize + " bits)");
                            break;

                        default:
                            jsonWriter.WriteString("algorithm", dnssecPrivateKey.Algorithm.ToString());
                            break;
                    }

                    jsonWriter.WriteString("state", dnssecPrivateKey.State.ToString());
                    jsonWriter.WriteString("stateChangedOn", dnssecPrivateKey.StateChangedOn);

                    if ((dnssecPrivateKey.KeyType == DnssecPrivateKeyType.KeySigningKey) && (dnssecPrivateKey.State == DnssecPrivateKeyState.Published))
                        jsonWriter.WriteString("stateReadyBy", (zoneInfo.ApexZone as PrimaryZone).GetDnsKeyStateReadyBy(dnssecPrivateKey));

                    jsonWriter.WriteBoolean("isRetiring", dnssecPrivateKey.IsRetiring);
                    jsonWriter.WriteNumber("rolloverDays", dnssecPrivateKey.RolloverDays);

                    jsonWriter.WriteEndObject();
                }
            }

            jsonWriter.WriteEndArray();
        }

        public void ConvertPrimaryZoneToNSEC(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService._dnsServer.AuthZoneManager.ConvertPrimaryZoneToNSEC(zoneName);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone was converted to NSEC successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void ConvertPrimaryZoneToNSEC3(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort iterations = request.GetQuery<ushort>("iterations", ushort.Parse, 0);
            byte saltLength = request.GetQuery<byte>("saltLength", byte.Parse, 0);

            _dnsWebService._dnsServer.AuthZoneManager.ConvertPrimaryZoneToNSEC3(zoneName, iterations, saltLength);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone was converted to NSEC3 successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UpdatePrimaryZoneNSEC3Parameters(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort iterations = request.GetQuery<ushort>("iterations", ushort.Parse, 0);
            byte saltLength = request.GetQuery<byte>("saltLength", byte.Parse, 0);

            _dnsWebService._dnsServer.AuthZoneManager.UpdatePrimaryZoneNSEC3Parameters(zoneName, iterations, saltLength);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone NSEC3 parameters were updated successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UpdatePrimaryZoneDnssecDnsKeyTtl(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            uint dnsKeyTtl = request.GetQuery("ttl", uint.Parse);

            _dnsWebService._dnsServer.AuthZoneManager.UpdatePrimaryZoneDnsKeyTtl(zoneName, dnsKeyTtl);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone DNSKEY TTL was updated successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void GenerateAndAddPrimaryZoneDnssecPrivateKey(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            DnssecPrivateKeyType keyType = request.GetQuery<DnssecPrivateKeyType>("keyType");
            ushort rolloverDays = request.GetQuery("rolloverDays", ushort.Parse, (ushort)(keyType == DnssecPrivateKeyType.ZoneSigningKey ? 90 : 0));
            string algorithm = request.GetQuery("algorithm");

            switch (algorithm.ToUpper())
            {
                case "RSA":
                    string hashAlgorithm = request.GetQuery("hashAlgorithm");
                    int keySize = request.GetQuery("keySize", int.Parse);

                    _dnsWebService._dnsServer.AuthZoneManager.GenerateAndAddPrimaryZoneDnssecRsaPrivateKey(zoneName, keyType, hashAlgorithm, keySize, rolloverDays);
                    break;

                case "ECDSA":
                    string curve = request.GetQuery("curve");

                    _dnsWebService._dnsServer.AuthZoneManager.GenerateAndAddPrimaryZoneDnssecEcdsaPrivateKey(zoneName, keyType, curve, rolloverDays);
                    break;

                default:
                    throw new NotSupportedException("Algorithm is not supported: " + algorithm);
            }

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] DNSSEC private key was generated and added to the primary zone successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UpdatePrimaryZoneDnssecPrivateKey(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort keyTag = request.GetQuery("keyTag", ushort.Parse);
            ushort rolloverDays = request.GetQuery("rolloverDays", ushort.Parse);

            _dnsWebService._dnsServer.AuthZoneManager.UpdatePrimaryZoneDnssecPrivateKey(zoneName, keyTag, rolloverDays);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone DNSSEC private key config was updated successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void DeletePrimaryZoneDnssecPrivateKey(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort keyTag = request.GetQuery("keyTag", ushort.Parse);

            _dnsWebService._dnsServer.AuthZoneManager.DeletePrimaryZoneDnssecPrivateKey(zoneName, keyTag);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] DNSSEC private key was deleted from primary zone successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService._dnsServer.AuthZoneManager.PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(zoneName);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] All DNSSEC private keys from the primary zone were published successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void RolloverPrimaryZoneDnsKey(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort keyTag = request.GetQuery("keyTag", ushort.Parse);

            _dnsWebService._dnsServer.AuthZoneManager.RolloverPrimaryZoneDnsKey(zoneName, keyTag);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] The DNSKEY (" + keyTag + ") from the primary zone was rolled over successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void RetirePrimaryZoneDnsKey(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQuery("zone").TrimEnd('.');

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort keyTag = request.GetQuery("keyTag", ushort.Parse);

            _dnsWebService._dnsServer.AuthZoneManager.RetirePrimaryZoneDnsKey(zoneName, keyTag);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] The DNSKEY (" + keyTag + ") from the primary zone was retired successfully: " + zoneName);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void DeleteZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryAlt("zone", "domain").TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteZone(zoneInfo.Name))
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneInfo.Name);

            _dnsWebService._authManager.RemoveAllPermissions(PermissionSection.Zones, zoneInfo.Name);
            _dnsWebService._authManager.SaveConfigFile();

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone was deleted: " + zoneName);
            _dnsWebService._dnsServer.AuthZoneManager.DeleteZoneFile(zoneInfo.Name);
        }

        public void EnableZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryAlt("zone", "domain").TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            zoneInfo.Disabled = false;

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone was enabled: " + zoneInfo.Name);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
            _dnsWebService._dnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);
        }

        public void DisableZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryAlt("zone", "domain").TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            zoneInfo.Disabled = true;

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone was disabled: " + zoneInfo.Name);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void GetZoneOptions(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryAlt("zone", "domain").TrimEnd('.');
            bool includeAvailableTsigKeyNames = request.GetQuery("includeAvailableTsigKeyNames", bool.Parse, false);

            AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WriteString("name", zoneInfo.Name);
            jsonWriter.WriteString("type", zoneInfo.Type.ToString());

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    jsonWriter.WriteBoolean("internal", zoneInfo.Internal);
                    jsonWriter.WriteString("dnssecStatus", zoneInfo.DnssecStatus.ToString());
                    break;

                case AuthZoneType.Secondary:
                    jsonWriter.WriteString("dnssecStatus", zoneInfo.DnssecStatus.ToString());
                    break;
            }

            jsonWriter.WriteBoolean("disabled", zoneInfo.Disabled);

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Secondary:
                    jsonWriter.WriteString("zoneTransfer", zoneInfo.ZoneTransfer.ToString());

                    jsonWriter.WritePropertyName("zoneTransferNameServers");
                    {
                        jsonWriter.WriteStartArray();

                        if (zoneInfo.ZoneTransferNameServers is not null)
                        {
                            foreach (IPAddress nameServer in zoneInfo.ZoneTransferNameServers)
                                jsonWriter.WriteStringValue(nameServer.ToString());
                        }

                        jsonWriter.WriteEndArray();
                    }

                    jsonWriter.WritePropertyName("zoneTransferTsigKeyNames");
                    {
                        jsonWriter.WriteStartArray();

                        if (zoneInfo.ZoneTransferTsigKeyNames is not null)
                        {
                            foreach (KeyValuePair<string, object> tsigKeyName in zoneInfo.ZoneTransferTsigKeyNames)
                                jsonWriter.WriteStringValue(tsigKeyName.Key);
                        }

                        jsonWriter.WriteEndArray();
                    }

                    jsonWriter.WriteString("notify", zoneInfo.Notify.ToString());

                    jsonWriter.WritePropertyName("notifyNameServers");
                    {
                        jsonWriter.WriteStartArray();

                        if (zoneInfo.NotifyNameServers is not null)
                        {
                            foreach (IPAddress nameServer in zoneInfo.NotifyNameServers)
                                jsonWriter.WriteStringValue(nameServer.ToString());
                        }

                        jsonWriter.WriteEndArray();
                    }

                    break;
            }

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    jsonWriter.WriteString("update", zoneInfo.Update.ToString());

                    jsonWriter.WritePropertyName("updateIpAddresses");
                    {
                        jsonWriter.WriteStartArray();

                        if (zoneInfo.UpdateIpAddresses is not null)
                        {
                            foreach (IPAddress updateIpAddress in zoneInfo.UpdateIpAddresses)
                                jsonWriter.WriteStringValue(updateIpAddress.ToString());
                        }

                        jsonWriter.WriteEndArray();
                    }

                    jsonWriter.WritePropertyName("updateSecurityPolicies");
                    {
                        jsonWriter.WriteStartArray();

                        if (zoneInfo.UpdateSecurityPolicies is not null)
                        {
                            foreach (KeyValuePair<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicy in zoneInfo.UpdateSecurityPolicies)
                            {
                                foreach (KeyValuePair<string, IReadOnlyList<DnsResourceRecordType>> policy in updateSecurityPolicy.Value)
                                {
                                    jsonWriter.WriteStartObject();

                                    jsonWriter.WriteString("tsigKeyName", updateSecurityPolicy.Key);
                                    jsonWriter.WriteString("domain", policy.Key);

                                    jsonWriter.WritePropertyName("allowedTypes");
                                    jsonWriter.WriteStartArray();

                                    foreach (DnsResourceRecordType allowedType in policy.Value)
                                        jsonWriter.WriteStringValue(allowedType.ToString());

                                    jsonWriter.WriteEndArray();

                                    jsonWriter.WriteEndObject();
                                }
                            }
                        }

                        jsonWriter.WriteEndArray();
                    }
                    break;
            }

            if (includeAvailableTsigKeyNames)
            {
                jsonWriter.WritePropertyName("availableTsigKeyNames");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._dnsServer.TsigKeys is not null)
                    {
                        foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsWebService._dnsServer.TsigKeys)
                            jsonWriter.WriteStringValue(tsigKey.Key);
                    }

                    jsonWriter.WriteEndArray();
                }
            }
        }

        public void SetZoneOptions(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryAlt("zone", "domain").TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            if (request.TryGetQuery("disabled", bool.Parse, out bool disabled))
                zoneInfo.Disabled = disabled;

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Secondary:
                    if (request.TryGetQuery("zoneTransfer", out AuthZoneTransfer zoneTransfer))
                        zoneInfo.ZoneTransfer = zoneTransfer;

                    string strZoneTransferNameServers = request.Query["zoneTransferNameServers"];
                    if (strZoneTransferNameServers is not null)
                    {
                        if ((strZoneTransferNameServers.Length == 0) || strZoneTransferNameServers.Equals("false", StringComparison.OrdinalIgnoreCase))
                            zoneInfo.ZoneTransferNameServers = null;
                        else
                            zoneInfo.ZoneTransferNameServers = strZoneTransferNameServers.Split(IPAddress.Parse, ',');
                    }

                    string strZoneTransferTsigKeyNames = request.Query["zoneTransferTsigKeyNames"];
                    if (strZoneTransferTsigKeyNames is not null)
                    {
                        if ((strZoneTransferTsigKeyNames.Length == 0) || strZoneTransferTsigKeyNames.Equals("false", StringComparison.OrdinalIgnoreCase))
                        {
                            zoneInfo.ZoneTransferTsigKeyNames = null;
                        }
                        else
                        {
                            string[] strZoneTransferTsigKeyNamesParts = strZoneTransferTsigKeyNames.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                            Dictionary<string, object> zoneTransferTsigKeyNames = new Dictionary<string, object>(strZoneTransferTsigKeyNamesParts.Length);

                            for (int i = 0; i < strZoneTransferTsigKeyNamesParts.Length; i++)
                                zoneTransferTsigKeyNames.Add(strZoneTransferTsigKeyNamesParts[i].ToLower(), null);

                            zoneInfo.ZoneTransferTsigKeyNames = zoneTransferTsigKeyNames;
                        }
                    }

                    if (request.TryGetQuery("notify", out AuthZoneNotify notify))
                        zoneInfo.Notify = notify;

                    string strNotifyNameServers = request.Query["notifyNameServers"];
                    if (strNotifyNameServers is not null)
                    {
                        if ((strNotifyNameServers.Length == 0) || strNotifyNameServers.Equals("false", StringComparison.OrdinalIgnoreCase))
                            zoneInfo.NotifyNameServers = null;
                        else
                            zoneInfo.NotifyNameServers = strNotifyNameServers.Split(IPAddress.Parse, ',');
                    }
                    break;
            }

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    if (request.TryGetQuery("update", out AuthZoneUpdate update))
                        zoneInfo.Update = update;

                    string strUpdateIpAddresses = request.Query["updateIpAddresses"];
                    if (strUpdateIpAddresses is not null)
                    {
                        if ((strUpdateIpAddresses.Length == 0) || strUpdateIpAddresses.Equals("false", StringComparison.OrdinalIgnoreCase))
                            zoneInfo.UpdateIpAddresses = null;
                        else
                            zoneInfo.UpdateIpAddresses = strUpdateIpAddresses.Split(IPAddress.Parse, ',');
                    }

                    string strUpdateSecurityPolicies = request.Query["updateSecurityPolicies"];
                    if (strUpdateSecurityPolicies is not null)
                    {
                        if ((strUpdateSecurityPolicies.Length == 0) || strUpdateSecurityPolicies.Equals("false", StringComparison.OrdinalIgnoreCase))
                        {
                            zoneInfo.UpdateSecurityPolicies = null;
                        }
                        else
                        {
                            string[] strUpdateSecurityPoliciesParts = strUpdateSecurityPolicies.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries);
                            Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicies = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(strUpdateSecurityPoliciesParts.Length);

                            for (int i = 0; i < strUpdateSecurityPoliciesParts.Length; i += 3)
                            {
                                string tsigKeyName = strUpdateSecurityPoliciesParts[i].ToLower();
                                string domain = strUpdateSecurityPoliciesParts[i + 1].ToLower();
                                string strTypes = strUpdateSecurityPoliciesParts[i + 2];

                                if (!domain.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase) && !domain.EndsWith("." + zoneInfo.Name, StringComparison.OrdinalIgnoreCase))
                                    throw new DnsWebServiceException("Cannot set Dynamic Updates security policies: the domain '" + domain + "' must be part of the current zone.");

                                if (!updateSecurityPolicies.TryGetValue(tsigKeyName, out IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>> policyMap))
                                {
                                    policyMap = new Dictionary<string, IReadOnlyList<DnsResourceRecordType>>();
                                    updateSecurityPolicies.Add(tsigKeyName, policyMap);
                                }

                                if (!policyMap.TryGetValue(domain, out IReadOnlyList<DnsResourceRecordType> types))
                                {
                                    types = new List<DnsResourceRecordType>();
                                    (policyMap as Dictionary<string, IReadOnlyList<DnsResourceRecordType>>).Add(domain, types);
                                }

                                foreach (string strType in strTypes.Split(new char[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries))
                                    (types as List<DnsResourceRecordType>).Add(Enum.Parse<DnsResourceRecordType>(strType, true));
                            }

                            zoneInfo.UpdateSecurityPolicies = updateSecurityPolicies;
                        }
                    }
                    break;
            }

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone options were updated successfully: " + zoneInfo.Name);

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void ResyncZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryAlt("zone", "domain").TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

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

        public void AddRecord(HttpContext context)
        {
            HttpRequest request = context.Request;

            string domain = request.GetQuery("domain").TrimEnd('.');

            string zoneName = request.Query["zone"];
            if (zoneName is not null)
                zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            DnsResourceRecordType type = request.GetQuery<DnsResourceRecordType>("type");
            uint ttl = request.GetQuery("ttl", uint.Parse, _defaultRecordTtl);
            bool overwrite = request.GetQuery("overwrite", bool.Parse, false);
            string comments = request.Query["comments"];

            DnsResourceRecord newRecord;

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        string strIPAddress = request.GetQueryAlt("ipAddress", "value");
                        IPAddress ipAddress;

                        if (strIPAddress.Equals("request-ip-address"))
                            ipAddress = context.GetRemoteEndPoint().Address;
                        else
                            ipAddress = IPAddress.Parse(strIPAddress);

                        bool ptr = request.GetQuery("ptr", bool.Parse, false);
                        if (ptr)
                        {
                            string ptrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo reverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
                            if (reverseZoneInfo is null)
                            {
                                bool createPtrZone = request.GetQuery("createPtrZone", bool.Parse, false);
                                if (!createPtrZone)
                                    throw new DnsServerException("No reverse zone available to add PTR record.");

                                string ptrZone = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 24 : 64);

                                reverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreatePrimaryZone(ptrZone, _dnsWebService._dnsServer.ServerDomain, false);
                                if (reverseZoneInfo == null)
                                    throw new DnsServerException("Failed to create reverse zone to add PTR record: " + ptrZone);

                                //set permissions
                                _dnsWebService._authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                                _dnsWebService._authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                _dnsWebService._authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                _dnsWebService._authManager.SaveConfigFile();
                            }

                            if (reverseZoneInfo.Internal)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is an internal zone.");

                            if (reverseZoneInfo.Type != AuthZoneType.Primary)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is not a primary zone.");

                            _dnsWebService._dnsServer.AuthZoneManager.SetRecords(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecordData[] { new DnsPTRRecordData(domain) });
                            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                        }

                        if (type == DnsResourceRecordType.A)
                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsARecordData(ipAddress));
                        else
                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsAAAARecordData(ipAddress));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nameServer = request.GetQueryAlt("nameServer", "value").TrimEnd('.');
                        string glueAddresses = request.GetQuery("glue", null);

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsNSRecordData(nameServer));

                        if (glueAddresses != null)
                            newRecord.SetGlueRecords(glueAddresses);

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService._dnsServer.AuthZoneManager.GetRecords(zoneInfo.Name, domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        string cname = request.GetQueryAlt("cname", "value").TrimEnd('.');

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCNAMERecordData(cname));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        string ptrName = request.GetQueryAlt("ptrName", "value").TrimEnd('.');

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsPTRRecordData(ptrName));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        ushort preference = request.GetQuery("preference", ushort.Parse);
                        string exchange = request.GetQueryAlt("exchange", "value").TrimEnd('.');

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsMXRecordData(preference, exchange));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string text = request.GetQueryAlt("text", "value");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsTXTRecordData(text));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        ushort priority = request.GetQuery("priority", ushort.Parse);
                        ushort weight = request.GetQuery("weight", ushort.Parse);
                        ushort port = request.GetQuery("port", ushort.Parse);
                        string target = request.GetQueryAlt("target", "value").TrimEnd('.');

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSRVRecordData(priority, weight, port, target));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    {
                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService._dnsServer.AuthZoneManager.GetRecords(zoneInfo.Name, domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        string dname = request.GetQueryAlt("dname", "value").TrimEnd('.');

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsDNAMERecordData(dname));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DS:
                    {
                        ushort keyTag = request.GetQuery("keyTag", ushort.Parse);
                        DnssecAlgorithm algorithm = Enum.Parse<DnssecAlgorithm>(request.GetQuery("algorithm").Replace('-', '_'), true);
                        DnssecDigestType digestType = Enum.Parse<DnssecDigestType>(request.GetQuery("digestType").Replace('-', '_'), true);
                        byte[] digest = request.GetQueryAlt("digest", "value", Convert.FromHexString);

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsDSRecordData(keyTag, algorithm, digestType, digest));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SSHFP:
                    {
                        DnsSSHFPAlgorithm sshfpAlgorithm = request.GetQuery<DnsSSHFPAlgorithm>("sshfpAlgorithm");
                        DnsSSHFPFingerprintType sshfpFingerprintType = request.GetQuery<DnsSSHFPFingerprintType>("sshfpFingerprintType");
                        byte[] sshfpFingerprint = request.GetQuery("sshfpFingerprint", Convert.FromHexString);

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSSHFPRecordData(sshfpAlgorithm, sshfpFingerprintType, sshfpFingerprint));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TLSA:
                    {
                        DnsTLSACertificateUsage tlsaCertificateUsage = Enum.Parse<DnsTLSACertificateUsage>(request.GetQuery("tlsaCertificateUsage").Replace('-', '_'), true);
                        DnsTLSASelector tlsaSelector = request.GetQuery<DnsTLSASelector>("tlsaSelector");
                        DnsTLSAMatchingType tlsaMatchingType = Enum.Parse<DnsTLSAMatchingType>(request.GetQuery("tlsaMatchingType").Replace('-', '_'), true);
                        string tlsaCertificateAssociationData = request.GetQuery("tlsaCertificateAssociationData");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsTLSARecordData(tlsaCertificateUsage, tlsaSelector, tlsaMatchingType, tlsaCertificateAssociationData));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        byte flags = request.GetQuery("flags", byte.Parse);
                        string tag = request.GetQuery("tag");
                        string value = request.GetQuery("value");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCAARecordData(flags, tag, value));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        string aname = request.GetQueryAlt("aname", "value").TrimEnd('.');

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsANAMERecordData(aname));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        DnsTransportProtocol protocol = request.GetQuery("protocol", DnsTransportProtocol.Udp);
                        string forwarder = request.GetQueryAlt("forwarder", "value");
                        bool dnssecValidation = request.GetQuery("dnssecValidation", bool.Parse, false);

                        NetProxyType proxyType = NetProxyType.None;
                        string proxyAddress = null;
                        ushort proxyPort = 0;
                        string proxyUsername = null;
                        string proxyPassword = null;

                        if (!forwarder.Equals("this-server"))
                        {
                            proxyType = request.GetQuery("proxyType", NetProxyType.None);
                            if (proxyType != NetProxyType.None)
                            {
                                proxyAddress = request.GetQuery("proxyAddress");
                                proxyPort = request.GetQuery("proxyPort", ushort.Parse);
                                proxyUsername = request.Query["proxyUsername"];
                                proxyPassword = request.Query["proxyPassword"];
                            }
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecordData(protocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.APP:
                    {
                        string appName = request.GetQueryAlt("appName", "value");
                        string classPath = request.GetQuery("classPath");
                        string recordData = request.GetQuery("recordData", "");

                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService._dnsServer.AuthZoneManager.GetRecords(zoneInfo.Name, domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsApplicationRecordData(appName, classPath, recordData));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for AddRecords().");
            }

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] New record was added to authoritative zone {record: " + newRecord.ToString() + "}");

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WritePropertyName("zone");
            WriteZoneInfoAsJson(zoneInfo, jsonWriter);

            jsonWriter.WritePropertyName("addedRecord");
            WriteRecordAsJson(newRecord, jsonWriter, true, null);
        }

        public void GetRecords(HttpContext context)
        {
            string domain = context.Request.GetQuery("domain").TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(domain);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WritePropertyName("zone");
            WriteZoneInfoAsJson(zoneInfo, jsonWriter);

            List<DnsResourceRecord> records = new List<DnsResourceRecord>();
            _dnsWebService._dnsServer.AuthZoneManager.ListAllRecords(domain, records);

            WriteRecordsAsJson(records, jsonWriter, true, zoneInfo);
        }

        public void DeleteRecord(HttpContext context)
        {
            HttpRequest request = context.Request;

            string domain = request.GetQuery("domain").TrimEnd('.');

            string zoneName = request.Query["zone"];
            if (zoneName is not null)
                zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            DnsResourceRecordType type = request.GetQuery<DnsResourceRecordType>("type");
            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        IPAddress ipAddress = IPAddress.Parse(request.GetQueryAlt("ipAddress", "value"));

                        if (type == DnsResourceRecordType.A)
                            _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsARecordData(ipAddress));
                        else
                            _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsAAAARecordData(ipAddress));

                        string ptrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);
                        AuthZoneInfo reverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
                        if ((reverseZoneInfo != null) && !reverseZoneInfo.Internal && (reverseZoneInfo.Type == AuthZoneType.Primary))
                        {
                            IReadOnlyList<DnsResourceRecord> ptrRecords = _dnsWebService._dnsServer.AuthZoneManager.GetRecords(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR);
                            if (ptrRecords.Count > 0)
                            {
                                foreach (DnsResourceRecord ptrRecord in ptrRecords)
                                {
                                    if ((ptrRecord.RDATA as DnsPTRRecordData).Domain.Equals(domain, StringComparison.OrdinalIgnoreCase))
                                    {
                                        //delete PTR record and save reverse zone
                                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR, ptrRecord.RDATA);
                                        _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nameServer = request.GetQueryAlt("nameServer", "value").TrimEnd('.');

                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsNSRecordData(nameServer));
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    _dnsWebService._dnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type);
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        string ptrName = request.GetQueryAlt("ptrName", "value").TrimEnd('.');

                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsPTRRecordData(ptrName));
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        ushort preference = request.GetQuery("preference", ushort.Parse);
                        string exchange = request.GetQueryAlt("exchange", "value").TrimEnd('.');

                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsMXRecordData(preference, exchange));
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string text = request.GetQueryAlt("text", "value");

                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsTXTRecordData(text));
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        ushort priority = request.GetQuery("priority", ushort.Parse);
                        ushort weight = request.GetQuery("weight", ushort.Parse);
                        ushort port = request.GetQuery("port", ushort.Parse);
                        string target = request.GetQueryAlt("target", "value").TrimEnd('.');

                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsSRVRecordData(priority, weight, port, target));
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    _dnsWebService._dnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type);
                    break;

                case DnsResourceRecordType.DS:
                    {
                        ushort keyTag = request.GetQuery("keyTag", ushort.Parse);
                        DnssecAlgorithm algorithm = Enum.Parse<DnssecAlgorithm>(request.GetQuery("algorithm").Replace('-', '_'), true);
                        DnssecDigestType digestType = Enum.Parse<DnssecDigestType>(request.GetQuery("digestType").Replace('-', '_'), true);
                        byte[] digest = Convert.FromHexString(request.GetQueryAlt("digest", "value"));

                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsDSRecordData(keyTag, algorithm, digestType, digest));
                    }
                    break;

                case DnsResourceRecordType.SSHFP:
                    {
                        DnsSSHFPAlgorithm sshfpAlgorithm = request.GetQuery<DnsSSHFPAlgorithm>("sshfpAlgorithm");
                        DnsSSHFPFingerprintType sshfpFingerprintType = request.GetQuery<DnsSSHFPFingerprintType>("sshfpFingerprintType");
                        byte[] sshfpFingerprint = request.GetQuery("sshfpFingerprint", Convert.FromHexString);

                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsSSHFPRecordData(sshfpAlgorithm, sshfpFingerprintType, sshfpFingerprint));
                    }
                    break;

                case DnsResourceRecordType.TLSA:
                    {
                        DnsTLSACertificateUsage tlsaCertificateUsage = Enum.Parse<DnsTLSACertificateUsage>(request.GetQuery("tlsaCertificateUsage").Replace('-', '_'), true);
                        DnsTLSASelector tlsaSelector = request.GetQuery<DnsTLSASelector>("tlsaSelector");
                        DnsTLSAMatchingType tlsaMatchingType = Enum.Parse<DnsTLSAMatchingType>(request.GetQuery("tlsaMatchingType").Replace('-', '_'), true);
                        string tlsaCertificateAssociationData = request.GetQuery("tlsaCertificateAssociationData");

                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsTLSARecordData(tlsaCertificateUsage, tlsaSelector, tlsaMatchingType, tlsaCertificateAssociationData));
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        byte flags = request.GetQuery("flags", byte.Parse);
                        string tag = request.GetQuery("tag");
                        string value = request.GetQuery("value");

                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsCAARecordData(flags, tag, value));
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        string aname = request.GetQueryAlt("aname", "value").TrimEnd('.');

                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsANAMERecordData(aname));
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        DnsTransportProtocol protocol = request.GetQuery("protocol", DnsTransportProtocol.Udp);
                        string forwarder = request.GetQueryAlt("forwarder", "value");

                        _dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsForwarderRecordData(protocol, forwarder));
                    }
                    break;

                case DnsResourceRecordType.APP:
                    _dnsWebService._dnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type);
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for DeleteRecord().");
            }

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Record was deleted from authoritative zone {domain: " + domain + "; type: " + type + ";}");

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void UpdateRecord(HttpContext context)
        {
            HttpRequest request = context.Request;

            string domain = request.GetQuery("domain").TrimEnd('.');

            string zoneName = request.Query["zone"];
            if (zoneName is not null)
                zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string newDomain = request.GetQuery("newDomain", domain).TrimEnd('.');
            uint ttl = request.GetQuery("ttl", uint.Parse, _defaultRecordTtl);
            bool disable = request.GetQuery("disable", bool.Parse, false);
            string comments = request.Query["comments"];
            DnsResourceRecordType type = request.GetQuery<DnsResourceRecordType>("type");

            DnsResourceRecord oldRecord = null;
            DnsResourceRecord newRecord;

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        IPAddress ipAddress = IPAddress.Parse(request.GetQueryAlt("ipAddress", "value"));
                        IPAddress newIpAddress = IPAddress.Parse(request.GetQueryAlt("newIpAddress", "newValue", ipAddress.ToString()));

                        bool ptr = request.GetQuery("ptr", bool.Parse, false);
                        if (ptr)
                        {
                            string newPtrDomain = Zone.GetReverseZone(newIpAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo newReverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(newPtrDomain);
                            if (newReverseZoneInfo is null)
                            {
                                bool createPtrZone = request.GetQuery("createPtrZone", bool.Parse, false);
                                if (!createPtrZone)
                                    throw new DnsServerException("No reverse zone available to add PTR record.");

                                string ptrZone = Zone.GetReverseZone(newIpAddress, type == DnsResourceRecordType.A ? 24 : 64);

                                newReverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreatePrimaryZone(ptrZone, _dnsWebService._dnsServer.ServerDomain, false);
                                if (newReverseZoneInfo is null)
                                    throw new DnsServerException("Failed to create reverse zone to add PTR record: " + ptrZone);

                                //set permissions
                                _dnsWebService._authManager.SetPermission(PermissionSection.Zones, newReverseZoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                                _dnsWebService._authManager.SetPermission(PermissionSection.Zones, newReverseZoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                _dnsWebService._authManager.SetPermission(PermissionSection.Zones, newReverseZoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                _dnsWebService._authManager.SaveConfigFile();
                            }

                            if (newReverseZoneInfo.Internal)
                                throw new DnsServerException("Reverse zone '" + newReverseZoneInfo.Name + "' is an internal zone.");

                            if (newReverseZoneInfo.Type != AuthZoneType.Primary)
                                throw new DnsServerException("Reverse zone '" + newReverseZoneInfo.Name + "' is not a primary zone.");

                            string oldPtrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo oldReverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(oldPtrDomain);
                            if ((oldReverseZoneInfo != null) && !oldReverseZoneInfo.Internal && (oldReverseZoneInfo.Type == AuthZoneType.Primary))
                            {
                                //delete old PTR record if any and save old reverse zone
                                _dnsWebService._dnsServer.AuthZoneManager.DeleteRecords(oldReverseZoneInfo.Name, oldPtrDomain, DnsResourceRecordType.PTR);
                                _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(oldReverseZoneInfo.Name);
                            }

                            //add new PTR record and save reverse zone
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecords(newReverseZoneInfo.Name, newPtrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecordData[] { new DnsPTRRecordData(domain) });
                            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(newReverseZoneInfo.Name);
                        }

                        if (type == DnsResourceRecordType.A)
                        {
                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsARecordData(ipAddress));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsARecordData(newIpAddress));
                        }
                        else
                        {
                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsAAAARecordData(ipAddress));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsAAAARecordData(newIpAddress));
                        }

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nameServer = request.GetQueryAlt("nameServer", "value").TrimEnd('.');
                        string newNameServer = request.GetQueryAlt("newNameServer", "newValue", nameServer).TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsNSRecordData(nameServer));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsNSRecordData(newNameServer));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (request.TryGetQuery("glue", out string glueAddresses))
                            newRecord.SetGlueRecords(glueAddresses);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        string cname = request.GetQueryAlt("cname", "value").TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCNAMERecordData(cname));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCNAMERecordData(cname));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SOA:
                    {
                        string primaryNameServer = request.GetQuery("primaryNameServer").TrimEnd('.');
                        string responsiblePerson = request.GetQuery("responsiblePerson").TrimEnd('.');
                        uint serial = request.GetQuery("serial", uint.Parse);
                        uint refresh = request.GetQuery("refresh", uint.Parse);
                        uint retry = request.GetQuery("retry", uint.Parse);
                        uint expire = request.GetQuery("expire", uint.Parse);
                        uint minimum = request.GetQuery("minimum", uint.Parse);

                        DnsResourceRecord newSOARecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSOARecordData(primaryNameServer, responsiblePerson, serial, refresh, retry, expire, minimum));

                        switch (zoneInfo.Type)
                        {
                            case AuthZoneType.Secondary:
                            case AuthZoneType.Stub:
                                if (request.TryGetQuery("primaryAddresses", out string primaryAddresses))
                                    newSOARecord.SetPrimaryNameServers(primaryAddresses);

                                break;
                        }

                        if (zoneInfo.Type == AuthZoneType.Secondary)
                        {
                            DnsResourceRecordInfo recordInfo = newSOARecord.GetRecordInfo();

                            if (request.TryGetQuery("zoneTransferProtocol", out DnsTransportProtocol zoneTransferProtocol))
                                recordInfo.ZoneTransferProtocol = zoneTransferProtocol;

                            if (request.TryGetQuery("tsigKeyName", out string tsigKeyName))
                                recordInfo.TsigKeyName = tsigKeyName;
                        }

                        if (!string.IsNullOrEmpty(comments))
                            newSOARecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newSOARecord);

                        newRecord = zoneInfo.GetApexRecords(DnsResourceRecordType.SOA)[0];
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        string ptrName = request.GetQueryAlt("ptrName", "value").TrimEnd('.');
                        string newPtrName = request.GetQueryAlt("newPtrName", "newValue", ptrName).TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsPTRRecordData(ptrName));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsPTRRecordData(newPtrName));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        ushort preference = request.GetQuery("preference", ushort.Parse);
                        ushort newPreference = request.GetQuery("newPreference", ushort.Parse, preference);

                        string exchange = request.GetQueryAlt("exchange", "value").TrimEnd('.');
                        string newExchange = request.GetQueryAlt("newExchange", "newValue", exchange).TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsMXRecordData(preference, exchange));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsMXRecordData(newPreference, newExchange));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string text = request.GetQueryAlt("text", "value");
                        string newText = request.GetQueryAlt("newText", "newValue", text);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsTXTRecordData(text));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsTXTRecordData(newText));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        ushort priority = request.GetQuery("priority", ushort.Parse);
                        ushort newPriority = request.GetQuery("newPriority", ushort.Parse, priority);

                        ushort weight = request.GetQuery("weight", ushort.Parse);
                        ushort newWeight = request.GetQuery("newWeight", ushort.Parse, weight);

                        ushort port = request.GetQuery("port", ushort.Parse);
                        ushort newPort = request.GetQuery("newPort", ushort.Parse, port);

                        string target = request.GetQueryAlt("target", "value").TrimEnd('.');
                        string newTarget = request.GetQueryAlt("newTarget", "newValue", target).TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSRVRecordData(priority, weight, port, target));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSRVRecordData(newPriority, newWeight, newPort, newTarget));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    {
                        string dname = request.GetQueryAlt("dname", "value").TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsDNAMERecordData(dname));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsDNAMERecordData(dname));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DS:
                    {
                        ushort keyTag = request.GetQuery("keyTag", ushort.Parse);
                        ushort newKeyTag = request.GetQuery("newKeyTag", ushort.Parse, keyTag);

                        DnssecAlgorithm algorithm = Enum.Parse<DnssecAlgorithm>(request.GetQuery("algorithm").Replace('-', '_'), true);
                        DnssecAlgorithm newAlgorithm = Enum.Parse<DnssecAlgorithm>(request.GetQuery("newAlgorithm", algorithm.ToString()).Replace('-', '_'), true);

                        DnssecDigestType digestType = Enum.Parse<DnssecDigestType>(request.GetQuery("digestType").Replace('-', '_'), true);
                        DnssecDigestType newDigestType = Enum.Parse<DnssecDigestType>(request.GetQuery("newDigestType", digestType.ToString()).Replace('-', '_'), true);

                        byte[] digest = request.GetQueryAlt("digest", "value", Convert.FromHexString);
                        byte[] newDigest = request.GetQueryAlt("newDigest", "newValue", Convert.FromHexString, digest);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsDSRecordData(keyTag, algorithm, digestType, digest));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsDSRecordData(newKeyTag, newAlgorithm, newDigestType, newDigest));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SSHFP:
                    {
                        DnsSSHFPAlgorithm sshfpAlgorithm = request.GetQuery<DnsSSHFPAlgorithm>("sshfpAlgorithm");
                        DnsSSHFPAlgorithm newSshfpAlgorithm = request.GetQuery("newSshfpAlgorithm", sshfpAlgorithm);

                        DnsSSHFPFingerprintType sshfpFingerprintType = request.GetQuery<DnsSSHFPFingerprintType>("sshfpFingerprintType");
                        DnsSSHFPFingerprintType newSshfpFingerprintType = request.GetQuery("newSshfpFingerprintType", sshfpFingerprintType);

                        byte[] sshfpFingerprint = request.GetQuery("sshfpFingerprint", Convert.FromHexString);
                        byte[] newSshfpFingerprint = request.GetQuery("newSshfpFingerprint", Convert.FromHexString, sshfpFingerprint);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSSHFPRecordData(sshfpAlgorithm, sshfpFingerprintType, sshfpFingerprint));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSSHFPRecordData(newSshfpAlgorithm, newSshfpFingerprintType, newSshfpFingerprint));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TLSA:
                    {
                        DnsTLSACertificateUsage tlsaCertificateUsage = Enum.Parse<DnsTLSACertificateUsage>(request.GetQuery("tlsaCertificateUsage").Replace('-', '_'), true);
                        DnsTLSACertificateUsage newTlsaCertificateUsage = Enum.Parse<DnsTLSACertificateUsage>(request.GetQuery("newTlsaCertificateUsage", tlsaCertificateUsage.ToString()).Replace('-', '_'), true);

                        DnsTLSASelector tlsaSelector = request.GetQuery<DnsTLSASelector>("tlsaSelector");
                        DnsTLSASelector newTlsaSelector = request.GetQuery("newTlsaSelector", tlsaSelector);

                        DnsTLSAMatchingType tlsaMatchingType = Enum.Parse<DnsTLSAMatchingType>(request.GetQuery("tlsaMatchingType").Replace('-', '_'), true);
                        DnsTLSAMatchingType newTlsaMatchingType = Enum.Parse<DnsTLSAMatchingType>(request.GetQuery("newTlsaMatchingType", tlsaMatchingType.ToString()).Replace('-', '_'), true);

                        string tlsaCertificateAssociationData = request.GetQuery("tlsaCertificateAssociationData");
                        string newTlsaCertificateAssociationData = request.GetQuery("newTlsaCertificateAssociationData", tlsaCertificateAssociationData);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsTLSARecordData(tlsaCertificateUsage, tlsaSelector, tlsaMatchingType, tlsaCertificateAssociationData));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsTLSARecordData(newTlsaCertificateUsage, newTlsaSelector, newTlsaMatchingType, newTlsaCertificateAssociationData));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        byte flags = request.GetQuery("flags", byte.Parse);
                        byte newFlags = request.GetQuery("newFlags", byte.Parse, flags);

                        string tag = request.GetQuery("tag");
                        string newTag = request.GetQuery("newTag", tag);

                        string value = request.GetQuery("value");
                        string newValue = request.GetQuery("newValue", value);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCAARecordData(flags, tag, value));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCAARecordData(newFlags, newTag, newValue));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        string aname = request.GetQueryAlt("aname", "value").TrimEnd('.');
                        string newAName = request.GetQueryAlt("newAName", "newValue", aname).TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsANAMERecordData(aname));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsANAMERecordData(newAName));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        DnsTransportProtocol protocol = request.GetQuery("protocol", DnsTransportProtocol.Udp);
                        DnsTransportProtocol newProtocol = request.GetQuery("newProtocol", protocol);

                        string forwarder = request.GetQueryAlt("forwarder", "value");
                        string newForwarder = request.GetQueryAlt("newForwarder", "newValue", forwarder);

                        bool dnssecValidation = request.GetQuery("dnssecValidation", bool.Parse, false);

                        NetProxyType proxyType = NetProxyType.None;
                        string proxyAddress = null;
                        ushort proxyPort = 0;
                        string proxyUsername = null;
                        string proxyPassword = null;

                        if (!newForwarder.Equals("this-server"))
                        {
                            proxyType = request.GetQuery("proxyType", NetProxyType.None);
                            if (proxyType != NetProxyType.None)
                            {
                                proxyAddress = request.GetQuery("proxyAddress");
                                proxyPort = request.GetQuery("proxyPort", ushort.Parse);
                                proxyUsername = request.Query["proxyUsername"];
                                proxyPassword = request.Query["proxyPassword"];
                            }
                        }

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecordData(protocol, forwarder));
                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecordData(newProtocol, newForwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.APP:
                    {
                        string appName = request.GetQueryAlt("appName", "value");
                        string classPath = request.GetQuery("classPath");
                        string recordData = request.GetQuery("recordData", "");

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsApplicationRecordData(appName, classPath, recordData));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsApplicationRecordData(appName, classPath, recordData));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for UpdateRecords().");
            }

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Record was updated for authoritative zone {" + (oldRecord is null ? "" : "oldRecord: " + oldRecord.ToString() + "; ") + "newRecord: " + newRecord.ToString() + "}");

            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WritePropertyName("zone");
            WriteZoneInfoAsJson(zoneInfo, jsonWriter);

            jsonWriter.WritePropertyName("updatedRecord");
            WriteRecordAsJson(newRecord, jsonWriter, true, null);
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
