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
using DnsServerCore.Dns.ZoneManagers;
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

            jsonWriter.WriteString("name", record.Name);

            if (DnsClient.TryConvertDomainNameToUnicode(record.Name, out string idn))
                jsonWriter.WriteString("nameIdn", idn);

            jsonWriter.WriteString("type", record.Type.ToString());

            if (authoritativeZoneRecords)
            {
                AuthRecordInfo authRecordInfo = record.GetAuthRecordInfo();

                jsonWriter.WriteNumber("ttl", record.TTL);
                jsonWriter.WriteBoolean("disabled", authRecordInfo.Disabled);

                string comments = authRecordInfo.Comments;
                if (!string.IsNullOrEmpty(comments))
                    jsonWriter.WriteString("comments", comments);
            }
            else
            {
                if (record.IsStale)
                    jsonWriter.WriteString("ttl", "0 (0 sec)");
                else
                    jsonWriter.WriteString("ttl", record.TTL + " (" + WebUtilities.GetFormattedTime((int)record.TTL) + ")");
            }

            jsonWriter.WritePropertyName("rData");
            jsonWriter.WriteStartObject();

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

                            if (DnsClient.TryConvertDomainNameToUnicode(rdata.NameServer, out string nameServerIdn))
                                jsonWriter.WriteString("nameServerIdn", nameServerIdn);

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

                            if (DnsClient.TryConvertDomainNameToUnicode(rdata.Domain, out string cnameIdn))
                                jsonWriter.WriteString("cnameIdn", cnameIdn);
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

                            if (DnsClient.TryConvertDomainNameToUnicode(rdata.PrimaryNameServer, out string primaryNameServerIdn))
                                jsonWriter.WriteString("primaryNameServerIdn", primaryNameServerIdn);

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
                            AuthRecordInfo authRecordInfo = record.GetAuthRecordInfo();

                            if ((zoneInfo is not null) && (zoneInfo.Type == AuthZoneType.Primary))
                                jsonWriter.WriteBoolean("useSerialDateScheme", authRecordInfo.UseSoaSerialDateScheme);

                            IReadOnlyList<NameServerAddress> primaryNameServers = authRecordInfo.PrimaryNameServers;
                            if (primaryNameServers is not null)
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

                            if (authRecordInfo.ZoneTransferProtocol != DnsTransportProtocol.Udp)
                                jsonWriter.WriteString("zoneTransferProtocol", authRecordInfo.ZoneTransferProtocol.ToString());

                            if (!string.IsNullOrEmpty(authRecordInfo.TsigKeyName))
                                jsonWriter.WriteString("tsigKeyName", authRecordInfo.TsigKeyName);
                        }
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        if (record.RDATA is DnsPTRRecordData rdata)
                        {
                            jsonWriter.WriteString("ptrName", rdata.Domain.Length == 0 ? "." : rdata.Domain);

                            if (DnsClient.TryConvertDomainNameToUnicode(rdata.Domain, out string ptrNameIdn))
                                jsonWriter.WriteString("ptrNameIdn", ptrNameIdn);
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

                            if (DnsClient.TryConvertDomainNameToUnicode(rdata.Exchange, out string exchangeIdn))
                                jsonWriter.WriteString("exchangeIdn", exchangeIdn);
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

                            if (DnsClient.TryConvertDomainNameToUnicode(rdata.Target, out string targetIdn))
                                jsonWriter.WriteString("targetIdn", targetIdn);
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

                            if (DnsClient.TryConvertDomainNameToUnicode(rdata.Domain, out string dnameIdn))
                                jsonWriter.WriteString("dnameIdn", dnameIdn);
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
                                if ((zoneInfo is not null) && (zoneInfo.Type == AuthZoneType.Primary))
                                {
                                    IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys = zoneInfo.DnssecPrivateKeys;
                                    if (dnssecPrivateKeys is not null)
                                    {
                                        foreach (DnssecPrivateKey dnssecPrivateKey in dnssecPrivateKeys)
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

                case DnsResourceRecordType.SVCB:
                case DnsResourceRecordType.HTTPS:
                    {
                        if (record.RDATA is DnsSVCBRecordData rdata)
                        {
                            jsonWriter.WriteNumber("svcPriority", rdata.SvcPriority);
                            jsonWriter.WriteString("svcTargetName", rdata.TargetName);

                            jsonWriter.WritePropertyName("svcParams");
                            jsonWriter.WriteStartObject();

                            foreach (KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> svcParam in rdata.SvcParams)
                                jsonWriter.WriteString(svcParam.Key.ToString().ToLower().Replace('_', '-'), svcParam.Value.ToString());

                            jsonWriter.WriteEndObject();

                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                case DnsResourceRecordType.URI:
                    {
                        if (record.RDATA is DnsURIRecordData rdata)
                        {
                            jsonWriter.WriteNumber("priority", rdata.Priority);
                            jsonWriter.WriteNumber("weight", rdata.Weight);
                            jsonWriter.WriteString("uri", rdata.Uri.AbsoluteUri);
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

                            if (DnsClient.TryConvertDomainNameToUnicode(rdata.Domain, out string anameIdn))
                                jsonWriter.WriteString("anameIdn", anameIdn);
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

                            switch (rdata.ProxyType)
                            {
                                case DnsForwarderRecordProxyType.Http:
                                case DnsForwarderRecordProxyType.Socks5:
                                    jsonWriter.WriteString("proxyAddress", rdata.ProxyAddress);
                                    jsonWriter.WriteNumber("proxyPort", rdata.ProxyPort);
                                    jsonWriter.WriteString("proxyUsername", rdata.ProxyUsername);
                                    jsonWriter.WriteString("proxyPassword", rdata.ProxyPassword);
                                    break;
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

                case DnsResourceRecordType.ALIAS:
                    {
                        if (record.RDATA is DnsALIASRecordData rdata)
                        {
                            jsonWriter.WriteString("type", rdata.Type.ToString());
                            jsonWriter.WriteString("alias", rdata.Domain.Length == 0 ? "." : rdata.Domain);

                            if (DnsClient.TryConvertDomainNameToUnicode(rdata.Domain, out string aliasIdn))
                                jsonWriter.WriteString("aliasIdn", aliasIdn);
                        }
                        else
                        {
                            jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                            jsonWriter.WriteString("data", record.RDATA.ToString());
                        }
                    }
                    break;

                default:
                    {
                        if (record.RDATA is DnsUnknownRecordData rdata)
                        {
                            jsonWriter.WriteString("value", BitConverter.ToString(rdata.DATA).Replace('-', ':'));
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

            jsonWriter.WriteString("dnssecStatus", record.DnssecStatus.ToString());

            if (authoritativeZoneRecords)
            {
                AuthRecordInfo authRecordInfo = record.GetAuthRecordInfo();

                IReadOnlyList<DnsResourceRecord> glueRecords = authRecordInfo.GlueRecords;
                if (glueRecords is not null)
                {
                    jsonWriter.WritePropertyName("glueRecords");
                    jsonWriter.WriteStartArray();

                    foreach (DnsResourceRecord glueRecord in glueRecords)
                        jsonWriter.WriteStringValue(glueRecord.RDATA.ToString());

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteString("lastUsedOn", authRecordInfo.LastUsedOn);
            }
            else
            {
                CacheRecordInfo cacheRecordInfo = record.GetCacheRecordInfo();

                IReadOnlyList<DnsResourceRecord> glueRecords = cacheRecordInfo.GlueRecords;
                if (glueRecords is not null)
                {
                    jsonWriter.WritePropertyName("glueRecords");
                    jsonWriter.WriteStartArray();

                    foreach (DnsResourceRecord glueRecord in glueRecords)
                        jsonWriter.WriteStringValue(glueRecord.RDATA.ToString());

                    jsonWriter.WriteEndArray();
                }

                IReadOnlyList<DnsResourceRecord> rrsigRecords = cacheRecordInfo.RRSIGRecords;
                IReadOnlyList<DnsResourceRecord> nsecRecords = cacheRecordInfo.NSECRecords;

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

                NetworkAddress eDnsClientSubnet = cacheRecordInfo.EDnsClientSubnet;
                if (eDnsClientSubnet is not null)
                    jsonWriter.WriteString("eDnsClientSubnet", eDnsClientSubnet.ToString());

                jsonWriter.WriteString("lastUsedOn", cacheRecordInfo.LastUsedOn);
            }

            jsonWriter.WriteEndObject();
        }

        private static void WriteZoneInfoAsJson(AuthZoneInfo zoneInfo, Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("name", zoneInfo.Name);

            if (DnsClient.TryConvertDomainNameToUnicode(zoneInfo.Name, out string nameIdn))
                jsonWriter.WriteString("nameIdn", nameIdn);

            jsonWriter.WriteString("type", zoneInfo.Type.ToString());

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    jsonWriter.WriteBoolean("internal", zoneInfo.Internal);
                    jsonWriter.WriteString("dnssecStatus", zoneInfo.DnssecStatus.ToString());
                    jsonWriter.WriteNumber("soaSerial", (zoneInfo.GetApexRecords(DnsResourceRecordType.SOA)[0].RDATA as DnsSOARecordData).Serial);

                    if (!zoneInfo.Internal)
                    {
                        string[] notifyFailed = zoneInfo.NotifyFailed;

                        jsonWriter.WriteBoolean("notifyFailed", notifyFailed.Length > 0);

                        jsonWriter.WritePropertyName("notifyFailedFor");
                        jsonWriter.WriteStartArray();

                        foreach (string server in notifyFailed)
                            jsonWriter.WriteStringValue(server);

                        jsonWriter.WriteEndArray();
                    }

                    break;

                case AuthZoneType.Secondary:
                    jsonWriter.WriteString("dnssecStatus", zoneInfo.DnssecStatus.ToString());
                    jsonWriter.WriteNumber("soaSerial", (zoneInfo.GetApexRecords(DnsResourceRecordType.SOA)[0].RDATA as DnsSOARecordData).Serial);
                    jsonWriter.WriteString("expiry", zoneInfo.Expiry);
                    jsonWriter.WriteBoolean("isExpired", zoneInfo.IsExpired);
                    jsonWriter.WriteBoolean("syncFailed", zoneInfo.SyncFailed);

                    {
                        string[] notifyFailed = zoneInfo.NotifyFailed;

                        jsonWriter.WriteBoolean("notifyFailed", notifyFailed.Length > 0);

                        jsonWriter.WritePropertyName("notifyFailedFor");
                        jsonWriter.WriteStartArray();

                        foreach (string server in notifyFailed)
                            jsonWriter.WriteStringValue(server);

                        jsonWriter.WriteEndArray();
                    }
                    break;

                case AuthZoneType.Stub:
                    jsonWriter.WriteNumber("soaSerial", (zoneInfo.GetApexRecords(DnsResourceRecordType.SOA)[0].RDATA as DnsSOARecordData).Serial);
                    jsonWriter.WriteString("expiry", zoneInfo.Expiry);
                    jsonWriter.WriteBoolean("isExpired", zoneInfo.IsExpired);
                    jsonWriter.WriteBoolean("syncFailed", zoneInfo.SyncFailed);
                    break;
            }

            jsonWriter.WriteString("lastModified", zoneInfo.LastModified);
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

            HttpRequest request = context.Request;
            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
            IReadOnlyList<AuthZoneInfo> zones;

            if (request.TryGetQueryOrForm("pageNumber", int.Parse, out int pageNumber))
            {
                int zonesPerPage = request.GetQueryOrForm("zonesPerPage", int.Parse, 10);

                AuthZoneManager.ZonesPage page = _dnsWebService.DnsServer.AuthZoneManager.GetZonesPage(pageNumber, zonesPerPage);
                zones = page.Zones;

                jsonWriter.WriteNumber("pageNumber", page.PageNumber);
                jsonWriter.WriteNumber("totalPages", page.TotalPages);
                jsonWriter.WriteNumber("totalZones", page.TotalZones);
            }
            else
            {
                zones = _dnsWebService.DnsServer.AuthZoneManager.GetAllZones();
            }

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

            string zoneName = request.GetQueryOrFormAlt("zone", "domain");
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

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            AuthZoneType type = request.GetQueryOrFormEnum("type", AuthZoneType.Primary);
            AuthZoneInfo zoneInfo;

            switch (type)
            {
                case AuthZoneType.Primary:
                    {
                        bool useSoaSerialDateScheme = request.GetQueryOrForm("useSoaSerialDateScheme", bool.Parse, _dnsWebService.DnsServer.AuthZoneManager.UseSoaSerialDateScheme);

                        zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreatePrimaryZone(zoneName, _dnsWebService.DnsServer.ServerDomain, false, useSoaSerialDateScheme);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        //set permissions
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SaveConfigFile();

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Authoritative primary zone was created: " + zoneName);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
                    break;

                case AuthZoneType.Secondary:
                    {
                        string primaryNameServerAddresses = request.GetQueryOrForm("primaryNameServerAddresses", null);
                        DnsTransportProtocol zoneTransferProtocol = request.GetQueryOrFormEnum("zoneTransferProtocol", DnsTransportProtocol.Tcp);
                        string tsigKeyName = request.GetQueryOrForm("tsigKeyName", null);

                        if (zoneTransferProtocol == DnsTransportProtocol.Quic)
                            DnsWebService.ValidateQuicSupport();

                        zoneInfo = await _dnsWebService.DnsServer.AuthZoneManager.CreateSecondaryZoneAsync(zoneName, primaryNameServerAddresses, zoneTransferProtocol, tsigKeyName);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        //set permissions
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SaveConfigFile();

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Authoritative secondary zone was created: " + zoneName);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
                    break;

                case AuthZoneType.Stub:
                    {
                        string primaryNameServerAddresses = request.GetQueryOrForm("primaryNameServerAddresses", null);

                        zoneInfo = await _dnsWebService.DnsServer.AuthZoneManager.CreateStubZoneAsync(zoneName, primaryNameServerAddresses);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        //set permissions
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SaveConfigFile();

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Stub zone was created: " + zoneName);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
                    break;

                case AuthZoneType.Forwarder:
                    {
                        DnsTransportProtocol forwarderProtocol = request.GetQueryOrFormEnum("protocol", DnsTransportProtocol.Udp);
                        string forwarder = request.GetQueryOrForm("forwarder");
                        bool dnssecValidation = request.GetQueryOrForm("dnssecValidation", bool.Parse, false);
                        DnsForwarderRecordProxyType proxyType = request.GetQueryOrFormEnum("proxyType", DnsForwarderRecordProxyType.DefaultProxy);

                        string proxyAddress = null;
                        ushort proxyPort = 0;
                        string proxyUsername = null;
                        string proxyPassword = null;

                        switch (proxyType)
                        {
                            case DnsForwarderRecordProxyType.Http:
                            case DnsForwarderRecordProxyType.Socks5:
                                proxyAddress = request.GetQueryOrForm("proxyAddress");
                                proxyPort = request.GetQueryOrForm("proxyPort", ushort.Parse);
                                proxyUsername = request.QueryOrForm("proxyUsername");
                                proxyPassword = request.QueryOrForm("proxyPassword");
                                break;
                        }

                        switch (forwarderProtocol)
                        {
                            case DnsTransportProtocol.HttpsJson:
                                forwarderProtocol = DnsTransportProtocol.Https;
                                break;

                            case DnsTransportProtocol.Quic:
                                DnsWebService.ValidateQuicSupport();
                                break;
                        }

                        zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreateForwarderZone(zoneName, forwarderProtocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, null);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        //set permissions
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SaveConfigFile();

                        _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Forwarder zone was created: " + zoneName);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
                    break;

                default:
                    throw new NotSupportedException("Zone type not supported.");
            }

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
            _dnsWebService.DnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
            jsonWriter.WriteString("domain", string.IsNullOrEmpty(zoneInfo.Name) ? "." : zoneInfo.Name);
        }

        public async Task ImportZoneAsync(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');
            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            bool overwrite = request.GetQueryOrForm("overwrite", bool.Parse, true);

            TextReader textReader;

            switch (request.ContentType?.ToLowerInvariant())
            {
                case "application/x-www-form-urlencoded":
                    string zoneRecords = request.GetQueryOrForm("records");
                    textReader = new StringReader(zoneRecords);
                    break;

                case "text/plain":
                    textReader = new StreamReader(request.Body);
                    break;

                default:
                    throw new DnsWebServiceException("Content type is not supported: " + request.ContentType);
            }

            using TextReader zoneReader = textReader;

            IReadOnlyCollection<DnsResourceRecord> records = await ZoneFile.ReadZoneFileFromAsync(zoneReader, zoneInfo.Name, _dnsWebService._zonesApi.DefaultRecordTtl);
            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                if (record.Class != DnsClass.IN)
                    throw new DnsWebServiceException("Cannot import records: only IN class is supported by the DNS server.");

                switch (record.Type)
                {
                    case DnsResourceRecordType.DNSKEY:
                    case DnsResourceRecordType.RRSIG:
                    case DnsResourceRecordType.NSEC:
                    case DnsResourceRecordType.NSEC3:
                    case DnsResourceRecordType.NSEC3PARAM:
                        continue; //skip DNSSEC records

                    default:
                        if (record.Tag is string comments)
                        {
                            AuthRecordInfo rrInfo = new AuthRecordInfo();
                            rrInfo.Comments = comments;

                            record.Tag = rrInfo;
                        }

                        newRecords.Add(record);
                        break;
                }
            }

            _dnsWebService.DnsServer.AuthZoneManager.ImportRecords(zoneInfo.Name, newRecords, overwrite);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Total " + newRecords.Count + " record(s) were imported successfully into authoritative zone: " + zoneInfo.Name);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public async Task ExportZoneAsync(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');
            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            List<DnsResourceRecord> records = new List<DnsResourceRecord>();

            _dnsWebService.DnsServer.AuthZoneManager.ListAllZoneRecords(zoneInfo.Name, records);

            HttpResponse response = context.Response;

            response.ContentType = "text/plain";
            response.Headers.ContentDisposition = "attachment;filename=" + (zoneInfo.Name == "." ? "root.zone" : zoneInfo.Name + ".zone");

            await using (StreamWriter sW = new StreamWriter(response.Body))
            {
                await ZoneFile.WriteZoneFileToAsync(sW, zoneInfo.Name, records, delegate (DnsResourceRecord record)
                {
                    if (record.Tag is null)
                        return null;

                    return record.GetAuthRecordInfo().Comments;
                });
            }
        }

        public void CloneZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');
            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            string sourceZoneName = request.GetQueryOrForm("sourceZone").TrimEnd('.');
            if (DnsClient.IsDomainNameUnicode(sourceZoneName))
                sourceZoneName = DnsClient.ConvertDomainNameToAscii(sourceZoneName);

            AuthZoneInfo sourceZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(sourceZoneName);
            if (sourceZoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + sourceZoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sourceZoneInfo.Name, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CloneZone(zoneName, sourceZoneName);

            //set permissions
            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _dnsWebService._authManager.SaveConfigFile();

            //save zone
            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] " + sourceZoneInfo.Type.ToString() + " zone '" + sourceZoneInfo.Name + "' was cloned as '" + zoneName + "' sucessfully.");
        }

        public void ConvertZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');
            AuthZoneType type = request.GetQueryOrFormEnum<AuthZoneType>("type");

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService.DnsServer.AuthZoneManager.ConvertZoneType(zoneInfo.Name, type);
            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone '" + zoneInfo.Name + "' was converted to " + type.ToString() + " zone sucessfully.");
        }

        public void SignPrimaryZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string algorithm = request.GetQueryOrForm("algorithm");
            uint dnsKeyTtl = request.GetQueryOrForm<uint>("dnsKeyTtl", uint.Parse, 24 * 60 * 60);
            ushort zskRolloverDays = request.GetQueryOrForm<ushort>("zskRolloverDays", ushort.Parse, 30);

            bool useNSEC3 = false;
            string strNxProof = request.QueryOrForm("nxProof");
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
                iterations = request.GetQueryOrForm<ushort>("iterations", ushort.Parse, 0);
                saltLength = request.GetQueryOrForm<byte>("saltLength", byte.Parse, 0);
            }

            switch (algorithm.ToUpper())
            {
                case "RSA":
                    string hashAlgorithm = request.GetQueryOrForm("hashAlgorithm");
                    int kskKeySize = request.GetQueryOrForm("kskKeySize", int.Parse);
                    int zskKeySize = request.GetQueryOrForm("zskKeySize", int.Parse);

                    if (useNSEC3)
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithRsaNSEC3(zoneName, hashAlgorithm, kskKeySize, zskKeySize, iterations, saltLength, dnsKeyTtl, zskRolloverDays);
                    else
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithRsaNSEC(zoneName, hashAlgorithm, kskKeySize, zskKeySize, dnsKeyTtl, zskRolloverDays);

                    break;

                case "ECDSA":
                    string curve = request.GetQueryOrForm("curve");

                    if (useNSEC3)
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithEcdsaNSEC3(zoneName, curve, iterations, saltLength, dnsKeyTtl, zskRolloverDays);
                    else
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithEcdsaNSEC(zoneName, curve, dnsKeyTtl, zskRolloverDays);

                    break;

                default:
                    throw new NotSupportedException("Algorithm is not supported: " + algorithm);
            }

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone was signed successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UnsignPrimaryZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService.DnsServer.AuthZoneManager.UnsignPrimaryZone(zoneName);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone was unsigned successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void GetPrimaryZoneDsInfo(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (zoneInfo.Type != AuthZoneType.Primary)
                throw new DnsWebServiceException("The zone must be a primary zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            if (zoneInfo.DnssecStatus == AuthZoneDnssecStatus.Unsigned)
                throw new DnsWebServiceException("The zone must be signed with DNSSEC.");

            IReadOnlyList<DnsResourceRecord> dnsKeyRecords = zoneInfo.GetApexRecords(DnsResourceRecordType.DNSKEY);

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WriteString("name", zoneInfo.Name);
            jsonWriter.WriteString("type", zoneInfo.Type.ToString());
            jsonWriter.WriteBoolean("internal", zoneInfo.Internal);
            jsonWriter.WriteBoolean("disabled", zoneInfo.Disabled);
            jsonWriter.WriteString("dnssecStatus", zoneInfo.DnssecStatus.ToString());

            jsonWriter.WritePropertyName("dsRecords");
            jsonWriter.WriteStartArray();

            foreach (DnsResourceRecord record in dnsKeyRecords)
            {
                if (record.RDATA is DnsDNSKEYRecordData rdata && rdata.Flags.HasFlag(DnsDnsKeyFlag.SecureEntryPoint))
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteNumber("keyTag", rdata.ComputedKeyTag);

                    IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys = zoneInfo.DnssecPrivateKeys;
                    if (dnssecPrivateKeys is not null)
                    {
                        foreach (DnssecPrivateKey dnssecPrivateKey in dnssecPrivateKeys)
                        {
                            if ((dnssecPrivateKey.KeyType == DnssecPrivateKeyType.KeySigningKey) && (dnssecPrivateKey.KeyTag == rdata.ComputedKeyTag))
                            {
                                jsonWriter.WriteString("dnsKeyState", dnssecPrivateKey.State.ToString());

                                if (dnssecPrivateKey.State == DnssecPrivateKeyState.Published)
                                    jsonWriter.WriteString("dnsKeyStateReadyBy", (zoneInfo.ApexZone as PrimaryZone).GetDnsKeyStateReadyBy(dnssecPrivateKey));

                                break;
                            }
                        }
                    }

                    jsonWriter.WriteString("algorithm", rdata.Algorithm.ToString());
                    jsonWriter.WriteString("publicKey", rdata.PublicKey.ToString());

                    jsonWriter.WritePropertyName("digests");
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

                    jsonWriter.WriteEndObject();
                }
            }

            jsonWriter.WriteEndArray();
        }

        public void GetPrimaryZoneDnssecProperties(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + zoneName);

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

            string zoneName = context.Request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService.DnsServer.AuthZoneManager.ConvertPrimaryZoneToNSEC(zoneName);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone was converted to NSEC successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void ConvertPrimaryZoneToNSEC3(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort iterations = request.GetQueryOrForm<ushort>("iterations", ushort.Parse, 0);
            byte saltLength = request.GetQueryOrForm<byte>("saltLength", byte.Parse, 0);

            _dnsWebService.DnsServer.AuthZoneManager.ConvertPrimaryZoneToNSEC3(zoneName, iterations, saltLength);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone was converted to NSEC3 successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UpdatePrimaryZoneNSEC3Parameters(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort iterations = request.GetQueryOrForm<ushort>("iterations", ushort.Parse, 0);
            byte saltLength = request.GetQueryOrForm<byte>("saltLength", byte.Parse, 0);

            _dnsWebService.DnsServer.AuthZoneManager.UpdatePrimaryZoneNSEC3Parameters(zoneName, iterations, saltLength);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone NSEC3 parameters were updated successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UpdatePrimaryZoneDnssecDnsKeyTtl(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            uint dnsKeyTtl = request.GetQueryOrForm("ttl", uint.Parse);

            _dnsWebService.DnsServer.AuthZoneManager.UpdatePrimaryZoneDnsKeyTtl(zoneName, dnsKeyTtl);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone DNSKEY TTL was updated successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void GenerateAndAddPrimaryZoneDnssecPrivateKey(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            DnssecPrivateKeyType keyType = request.GetQueryOrFormEnum<DnssecPrivateKeyType>("keyType");
            ushort rolloverDays = request.GetQueryOrForm("rolloverDays", ushort.Parse, (ushort)(keyType == DnssecPrivateKeyType.ZoneSigningKey ? 30 : 0));
            string algorithm = request.GetQueryOrForm("algorithm");

            switch (algorithm.ToUpper())
            {
                case "RSA":
                    string hashAlgorithm = request.GetQueryOrForm("hashAlgorithm");
                    int keySize = request.GetQueryOrForm("keySize", int.Parse);

                    _dnsWebService.DnsServer.AuthZoneManager.GenerateAndAddPrimaryZoneDnssecRsaPrivateKey(zoneName, keyType, hashAlgorithm, keySize, rolloverDays);
                    break;

                case "ECDSA":
                    string curve = request.GetQueryOrForm("curve");

                    _dnsWebService.DnsServer.AuthZoneManager.GenerateAndAddPrimaryZoneDnssecEcdsaPrivateKey(zoneName, keyType, curve, rolloverDays);
                    break;

                default:
                    throw new NotSupportedException("Algorithm is not supported: " + algorithm);
            }

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] DNSSEC private key was generated and added to the primary zone successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UpdatePrimaryZoneDnssecPrivateKey(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);
            ushort rolloverDays = request.GetQueryOrForm("rolloverDays", ushort.Parse);

            _dnsWebService.DnsServer.AuthZoneManager.UpdatePrimaryZoneDnssecPrivateKey(zoneName, keyTag, rolloverDays);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Primary zone DNSSEC private key config was updated successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void DeletePrimaryZoneDnssecPrivateKey(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);

            _dnsWebService.DnsServer.AuthZoneManager.DeletePrimaryZoneDnssecPrivateKey(zoneName, keyTag);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] DNSSEC private key was deleted from primary zone successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService.DnsServer.AuthZoneManager.PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(zoneName);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] All DNSSEC private keys from the primary zone were published successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void RolloverPrimaryZoneDnsKey(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);

            _dnsWebService.DnsServer.AuthZoneManager.RolloverPrimaryZoneDnsKey(zoneName, keyTag);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] The DNSKEY (" + keyTag + ") from the primary zone was rolled over successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void RetirePrimaryZoneDnsKey(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrForm("zone").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);

            _dnsWebService.DnsServer.AuthZoneManager.RetirePrimaryZoneDnsKey(zoneName, keyTag);

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] The DNSKEY (" + keyTag + ") from the primary zone was retired successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void DeleteZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryOrFormAlt("zone", "domain").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            if (!_dnsWebService.DnsServer.AuthZoneManager.DeleteZone(zoneInfo.Name))
                throw new DnsWebServiceException("Failed to delete the zone: " + zoneInfo.Name);

            _dnsWebService._authManager.RemoveAllPermissions(PermissionSection.Zones, zoneInfo.Name);
            _dnsWebService._authManager.SaveConfigFile();

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone was deleted: " + zoneName);
            _dnsWebService.DnsServer.AuthZoneManager.DeleteZoneFile(zoneInfo.Name);
        }

        public void EnableZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryOrFormAlt("zone", "domain").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            zoneInfo.Disabled = false;

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone was enabled: " + zoneInfo.Name);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
            _dnsWebService.DnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);
        }

        public void DisableZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryOrFormAlt("zone", "domain").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            zoneInfo.Disabled = true;

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone was disabled: " + zoneInfo.Name);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void GetZoneOptions(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string zoneName = request.GetQueryOrFormAlt("zone", "domain").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            bool includeAvailableTsigKeyNames = request.GetQueryOrForm("includeAvailableTsigKeyNames", bool.Parse, false);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WriteString("name", zoneInfo.Name);

            if (DnsClient.TryConvertDomainNameToUnicode(zoneInfo.Name, out string nameIdn))
                jsonWriter.WriteString("nameIdn", nameIdn);

            jsonWriter.WriteString("type", zoneInfo.Type.ToString());

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    jsonWriter.WriteBoolean("internal", zoneInfo.Internal);
                    jsonWriter.WriteString("dnssecStatus", zoneInfo.DnssecStatus.ToString());

                    if (!zoneInfo.Internal)
                    {
                        string[] notifyFailed = zoneInfo.NotifyFailed;

                        jsonWriter.WriteBoolean("notifyFailed", notifyFailed.Length > 0);

                        jsonWriter.WritePropertyName("notifyFailedFor");
                        jsonWriter.WriteStartArray();

                        foreach (string server in notifyFailed)
                            jsonWriter.WriteStringValue(server);

                        jsonWriter.WriteEndArray();
                    }

                    break;

                case AuthZoneType.Secondary:
                    jsonWriter.WriteString("dnssecStatus", zoneInfo.DnssecStatus.ToString());

                    {
                        string[] notifyFailed = zoneInfo.NotifyFailed;

                        jsonWriter.WriteBoolean("notifyFailed", notifyFailed.Length > 0);

                        jsonWriter.WritePropertyName("notifyFailedFor");
                        jsonWriter.WriteStartArray();

                        foreach (string server in notifyFailed)
                            jsonWriter.WriteStringValue(server);

                        jsonWriter.WriteEndArray();
                    }

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
                            foreach (NetworkAddress networkAddress in zoneInfo.ZoneTransferNameServers)
                                jsonWriter.WriteStringValue(networkAddress.ToString());
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
                            foreach (NetworkAddress networkAddress in zoneInfo.UpdateIpAddresses)
                                jsonWriter.WriteStringValue(networkAddress.ToString());
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

                    if (_dnsWebService.DnsServer.TsigKeys is not null)
                    {
                        foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsWebService.DnsServer.TsigKeys)
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

            string zoneName = request.GetQueryOrFormAlt("zone", "domain").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            if (request.TryGetQueryOrForm("disabled", bool.Parse, out bool disabled))
                zoneInfo.Disabled = disabled;

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Secondary:
                    if (request.TryGetQueryOrFormEnum("zoneTransfer", out AuthZoneTransfer zoneTransfer))
                        zoneInfo.ZoneTransfer = zoneTransfer;

                    string strZoneTransferNameServers = request.QueryOrForm("zoneTransferNameServers");
                    if (strZoneTransferNameServers is not null)
                    {
                        if ((strZoneTransferNameServers.Length == 0) || strZoneTransferNameServers.Equals("false", StringComparison.OrdinalIgnoreCase))
                            zoneInfo.ZoneTransferNameServers = null;
                        else
                            zoneInfo.ZoneTransferNameServers = strZoneTransferNameServers.Split(NetworkAddress.Parse, ',');
                    }

                    string strZoneTransferTsigKeyNames = request.QueryOrForm("zoneTransferTsigKeyNames");
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

                    if (request.TryGetQueryOrFormEnum("notify", out AuthZoneNotify notify))
                        zoneInfo.Notify = notify;

                    string strNotifyNameServers = request.QueryOrForm("notifyNameServers");
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
                    if (request.TryGetQueryOrFormEnum("update", out AuthZoneUpdate update))
                        zoneInfo.Update = update;

                    string strUpdateIpAddresses = request.QueryOrForm("updateIpAddresses");
                    if (strUpdateIpAddresses is not null)
                    {
                        if ((strUpdateIpAddresses.Length == 0) || strUpdateIpAddresses.Equals("false", StringComparison.OrdinalIgnoreCase))
                            zoneInfo.UpdateIpAddresses = null;
                        else
                            zoneInfo.UpdateIpAddresses = strUpdateIpAddresses.Split(NetworkAddress.Parse, ',');
                    }

                    string strUpdateSecurityPolicies = request.QueryOrForm("updateSecurityPolicies");
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

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void ResyncZone(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string zoneName = context.Request.GetQueryOrFormAlt("zone", "domain").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(zoneName))
                zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + zoneName);

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

            string domain = request.GetQueryOrForm("domain").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            string zoneName = request.QueryOrForm("zone");
            if (zoneName is not null)
            {
                zoneName = zoneName.TrimEnd('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);
            }

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            DnsResourceRecordType type = request.GetQueryOrFormEnum<DnsResourceRecordType>("type");
            uint ttl = request.GetQueryOrForm("ttl", uint.Parse, _defaultRecordTtl);
            bool overwrite = request.GetQueryOrForm("overwrite", bool.Parse, false);
            string comments = request.QueryOrForm("comments");

            DnsResourceRecord newRecord;

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        string strIPAddress = request.GetQueryOrFormAlt("ipAddress", "value");
                        IPAddress ipAddress;

                        if (strIPAddress.Equals("request-ip-address"))
                            ipAddress = context.GetRemoteEndPoint().Address;
                        else
                            ipAddress = IPAddress.Parse(strIPAddress);

                        bool ptr = request.GetQueryOrForm("ptr", bool.Parse, false);
                        if (ptr)
                        {
                            string ptrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
                            if (reverseZoneInfo is null)
                            {
                                bool createPtrZone = request.GetQueryOrForm("createPtrZone", bool.Parse, false);
                                if (!createPtrZone)
                                    throw new DnsServerException("No reverse zone available to add PTR record.");

                                string ptrZone = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 24 : 64);

                                reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreatePrimaryZone(ptrZone, _dnsWebService.DnsServer.ServerDomain, false);
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

                            if ((reverseZoneInfo.Type != AuthZoneType.Primary) && (reverseZoneInfo.Type != AuthZoneType.Forwarder))
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is not a primary or forwarder zone.");

                            _dnsWebService.DnsServer.AuthZoneManager.SetRecords(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecordData[] { new DnsPTRRecordData(domain) });
                            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                        }

                        if (type == DnsResourceRecordType.A)
                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsARecordData(ipAddress));
                        else
                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsAAAARecordData(ipAddress));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nameServer = request.GetQueryOrFormAlt("nameServer", "value").TrimEnd('.');
                        string glueAddresses = request.GetQueryOrForm("glue", null);

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsNSRecordData(nameServer));

                        if (!string.IsNullOrEmpty(glueAddresses))
                            newRecord.SetGlueRecords(glueAddresses);

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(zoneInfo.Name, domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        string cname = request.GetQueryOrFormAlt("cname", "value").TrimEnd('.');

                        if (cname.Equals(domain, StringComparison.OrdinalIgnoreCase))
                            throw new DnsWebServiceException("CNAME domain name cannot be same as that of the record name.");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCNAMERecordData(cname));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        string ptrName = request.GetQueryOrFormAlt("ptrName", "value").TrimEnd('.');

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsPTRRecordData(ptrName));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        ushort preference = request.GetQueryOrForm("preference", ushort.Parse);
                        string exchange = request.GetQueryOrFormAlt("exchange", "value").TrimEnd('.');

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsMXRecordData(preference, exchange));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string text = request.GetQueryOrFormAlt("text", "value");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsTXTRecordData(text));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        ushort priority = request.GetQueryOrForm("priority", ushort.Parse);
                        ushort weight = request.GetQueryOrForm("weight", ushort.Parse);
                        ushort port = request.GetQueryOrForm("port", ushort.Parse);
                        string target = request.GetQueryOrFormAlt("target", "value").TrimEnd('.');

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSRVRecordData(priority, weight, port, target));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    {
                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(zoneInfo.Name, domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        string dname = request.GetQueryOrFormAlt("dname", "value").TrimEnd('.');

                        if (dname.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                            throw new DnsWebServiceException("DNAME domain name cannot be a sub domain of the record name.");

                        if (dname.Equals(domain, StringComparison.OrdinalIgnoreCase))
                            throw new DnsWebServiceException("DNAME domain name cannot be same as that of the record name.");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsDNAMERecordData(dname));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DS:
                    {
                        ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);
                        DnssecAlgorithm algorithm = Enum.Parse<DnssecAlgorithm>(request.GetQueryOrForm("algorithm").Replace('-', '_'), true);
                        DnssecDigestType digestType = Enum.Parse<DnssecDigestType>(request.GetQueryOrForm("digestType").Replace('-', '_'), true);
                        byte[] digest = request.GetQueryOrFormAlt("digest", "value", Convert.FromHexString);

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsDSRecordData(keyTag, algorithm, digestType, digest));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SSHFP:
                    {
                        DnsSSHFPAlgorithm sshfpAlgorithm = request.GetQueryOrFormEnum<DnsSSHFPAlgorithm>("sshfpAlgorithm");
                        DnsSSHFPFingerprintType sshfpFingerprintType = request.GetQueryOrFormEnum<DnsSSHFPFingerprintType>("sshfpFingerprintType");
                        byte[] sshfpFingerprint = request.GetQueryOrForm("sshfpFingerprint", Convert.FromHexString);

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSSHFPRecordData(sshfpAlgorithm, sshfpFingerprintType, sshfpFingerprint));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TLSA:
                    {
                        DnsTLSACertificateUsage tlsaCertificateUsage = Enum.Parse<DnsTLSACertificateUsage>(request.GetQueryOrForm("tlsaCertificateUsage").Replace('-', '_'), true);
                        DnsTLSASelector tlsaSelector = request.GetQueryOrFormEnum<DnsTLSASelector>("tlsaSelector");
                        DnsTLSAMatchingType tlsaMatchingType = Enum.Parse<DnsTLSAMatchingType>(request.GetQueryOrForm("tlsaMatchingType").Replace('-', '_'), true);
                        string tlsaCertificateAssociationData = request.GetQueryOrForm("tlsaCertificateAssociationData");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsTLSARecordData(tlsaCertificateUsage, tlsaSelector, tlsaMatchingType, tlsaCertificateAssociationData));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SVCB:
                case DnsResourceRecordType.HTTPS:
                    {
                        ushort svcPriority = request.GetQueryOrForm("svcPriority", ushort.Parse);
                        string targetName = request.GetQueryOrForm("svcTargetName").TrimEnd('.');
                        string strSvcParams = request.GetQueryOrForm("svcParams");

                        Dictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams;

                        if (strSvcParams.Equals("false", StringComparison.OrdinalIgnoreCase))
                        {
                            svcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>(0);
                        }
                        else
                        {
                            string[] strSvcParamsParts = strSvcParams.Split('|');
                            svcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>(strSvcParamsParts.Length / 2);

                            for (int i = 0; i < strSvcParamsParts.Length; i += 2)
                            {
                                DnsSvcParamKey svcParamKey = Enum.Parse<DnsSvcParamKey>(strSvcParamsParts[i].Replace('-', '_'), true);
                                DnsSvcParamValue svcParamValue = DnsSvcParamValue.Parse(svcParamKey, strSvcParamsParts[i + 1]);

                                svcParams.Add(svcParamKey, svcParamValue);
                            }
                        }

                        switch (type)
                        {
                            case DnsResourceRecordType.HTTPS:
                                newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsHTTPSRecordData(svcPriority, targetName, svcParams));
                                break;

                            default:
                                newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSVCBRecordData(svcPriority, targetName, svcParams));
                                break;
                        }

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.URI:
                    {
                        ushort priority = request.GetQueryOrForm("uriPriority", ushort.Parse);
                        ushort weight = request.GetQueryOrForm("uriWeight", ushort.Parse);
                        Uri uri = request.GetQueryOrForm("uri", delegate (string value) { return new Uri(value); });

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsURIRecordData(priority, weight, uri));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        byte flags = request.GetQueryOrForm("flags", byte.Parse);
                        string tag = request.GetQueryOrForm("tag");
                        string value = request.GetQueryOrForm("value");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCAARecordData(flags, tag, value));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        string aname = request.GetQueryOrFormAlt("aname", "value").TrimEnd('.');

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsANAMERecordData(aname));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        DnsTransportProtocol protocol = request.GetQueryOrFormEnum("protocol", DnsTransportProtocol.Udp);
                        string forwarder = request.GetQueryOrFormAlt("forwarder", "value");
                        bool dnssecValidation = request.GetQueryOrForm("dnssecValidation", bool.Parse, false);

                        DnsForwarderRecordProxyType proxyType = DnsForwarderRecordProxyType.DefaultProxy;
                        string proxyAddress = null;
                        ushort proxyPort = 0;
                        string proxyUsername = null;
                        string proxyPassword = null;

                        if (!forwarder.Equals("this-server"))
                        {
                            proxyType = request.GetQueryOrFormEnum("proxyType", DnsForwarderRecordProxyType.DefaultProxy);
                            switch (proxyType)
                            {
                                case DnsForwarderRecordProxyType.Http:
                                case DnsForwarderRecordProxyType.Socks5:
                                    proxyAddress = request.GetQueryOrForm("proxyAddress");
                                    proxyPort = request.GetQueryOrForm("proxyPort", ushort.Parse);
                                    proxyUsername = request.QueryOrForm("proxyUsername");
                                    proxyPassword = request.QueryOrForm("proxyPassword");
                                    break;
                            }
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecordData(protocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.APP:
                    {
                        string appName = request.GetQueryOrFormAlt("appName", "value");
                        string classPath = request.GetQueryOrForm("classPath");
                        string recordData = request.GetQueryOrForm("recordData", "");

                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(zoneInfo.Name, domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsApplicationRecordData(appName, classPath, recordData));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                default:
                    {
                        string strRData = request.GetQueryOrForm("rdata");

                        byte[] rdata;

                        if (strRData.Contains(':'))
                            rdata = strRData.ParseColonHexString();
                        else
                            rdata = Convert.FromHexString(strRData);

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, DnsResourceRecord.ReadRecordDataFrom(type, rdata));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;
            }

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] New record was added to authoritative zone '" + zoneInfo.Name + "' successfully {record: " + newRecord.ToString() + "}");

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WritePropertyName("zone");
            WriteZoneInfoAsJson(zoneInfo, jsonWriter);

            jsonWriter.WritePropertyName("addedRecord");
            WriteRecordAsJson(newRecord, jsonWriter, true, null);
        }

        public void GetRecords(HttpContext context)
        {
            HttpRequest request = context.Request;

            string domain = request.GetQueryOrForm("domain").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            string zoneName = request.QueryOrForm("zone");
            if (zoneName is not null)
            {
                zoneName = zoneName.TrimEnd('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);
            }

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + domain);

            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            bool listZone = request.GetQueryOrForm("listZone", bool.Parse, false);

            List<DnsResourceRecord> records = new List<DnsResourceRecord>();

            if (listZone)
                _dnsWebService.DnsServer.AuthZoneManager.ListAllZoneRecords(zoneInfo.Name, records);
            else
                _dnsWebService.DnsServer.AuthZoneManager.ListAllRecords(zoneInfo.Name, domain, records);

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WritePropertyName("zone");
            WriteZoneInfoAsJson(zoneInfo, jsonWriter);

            WriteRecordsAsJson(records, jsonWriter, true, zoneInfo);
        }

        public void DeleteRecord(HttpContext context)
        {
            HttpRequest request = context.Request;

            string domain = request.GetQueryOrForm("domain").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            string zoneName = request.QueryOrForm("zone");
            if (zoneName is not null)
            {
                zoneName = zoneName.TrimEnd('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);
            }

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            DnsResourceRecordType type = request.GetQueryOrFormEnum<DnsResourceRecordType>("type");
            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        IPAddress ipAddress = IPAddress.Parse(request.GetQueryOrFormAlt("ipAddress", "value"));

                        if (type == DnsResourceRecordType.A)
                            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsARecordData(ipAddress));
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsAAAARecordData(ipAddress));

                        string ptrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);
                        AuthZoneInfo reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
                        if ((reverseZoneInfo != null) && !reverseZoneInfo.Internal && (reverseZoneInfo.Type == AuthZoneType.Primary))
                        {
                            IReadOnlyList<DnsResourceRecord> ptrRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR);
                            if (ptrRecords.Count > 0)
                            {
                                foreach (DnsResourceRecord ptrRecord in ptrRecords)
                                {
                                    if ((ptrRecord.RDATA as DnsPTRRecordData).Domain.Equals(domain, StringComparison.OrdinalIgnoreCase))
                                    {
                                        //delete PTR record and save reverse zone
                                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR, ptrRecord.RDATA);
                                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nameServer = request.GetQueryOrFormAlt("nameServer", "value").TrimEnd('.');

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsNSRecordData(nameServer, false));
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type);
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        string ptrName = request.GetQueryOrFormAlt("ptrName", "value").TrimEnd('.');

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsPTRRecordData(ptrName));
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        ushort preference = request.GetQueryOrForm("preference", ushort.Parse);
                        string exchange = request.GetQueryOrFormAlt("exchange", "value").TrimEnd('.');

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsMXRecordData(preference, exchange));
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string text = request.GetQueryOrFormAlt("text", "value");

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsTXTRecordData(text));
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        ushort priority = request.GetQueryOrForm("priority", ushort.Parse);
                        ushort weight = request.GetQueryOrForm("weight", ushort.Parse);
                        ushort port = request.GetQueryOrForm("port", ushort.Parse);
                        string target = request.GetQueryOrFormAlt("target", "value").TrimEnd('.');

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsSRVRecordData(priority, weight, port, target));
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type);
                    break;

                case DnsResourceRecordType.DS:
                    {
                        ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);
                        DnssecAlgorithm algorithm = Enum.Parse<DnssecAlgorithm>(request.GetQueryOrForm("algorithm").Replace('-', '_'), true);
                        DnssecDigestType digestType = Enum.Parse<DnssecDigestType>(request.GetQueryOrForm("digestType").Replace('-', '_'), true);
                        byte[] digest = Convert.FromHexString(request.GetQueryOrFormAlt("digest", "value"));

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsDSRecordData(keyTag, algorithm, digestType, digest));
                    }
                    break;

                case DnsResourceRecordType.SSHFP:
                    {
                        DnsSSHFPAlgorithm sshfpAlgorithm = request.GetQueryOrFormEnum<DnsSSHFPAlgorithm>("sshfpAlgorithm");
                        DnsSSHFPFingerprintType sshfpFingerprintType = request.GetQueryOrFormEnum<DnsSSHFPFingerprintType>("sshfpFingerprintType");
                        byte[] sshfpFingerprint = request.GetQueryOrForm("sshfpFingerprint", Convert.FromHexString);

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsSSHFPRecordData(sshfpAlgorithm, sshfpFingerprintType, sshfpFingerprint));
                    }
                    break;

                case DnsResourceRecordType.TLSA:
                    {
                        DnsTLSACertificateUsage tlsaCertificateUsage = Enum.Parse<DnsTLSACertificateUsage>(request.GetQueryOrForm("tlsaCertificateUsage").Replace('-', '_'), true);
                        DnsTLSASelector tlsaSelector = request.GetQueryOrFormEnum<DnsTLSASelector>("tlsaSelector");
                        DnsTLSAMatchingType tlsaMatchingType = Enum.Parse<DnsTLSAMatchingType>(request.GetQueryOrForm("tlsaMatchingType").Replace('-', '_'), true);
                        string tlsaCertificateAssociationData = request.GetQueryOrForm("tlsaCertificateAssociationData");

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsTLSARecordData(tlsaCertificateUsage, tlsaSelector, tlsaMatchingType, tlsaCertificateAssociationData));
                    }
                    break;

                case DnsResourceRecordType.SVCB:
                case DnsResourceRecordType.HTTPS:
                    {
                        ushort svcPriority = request.GetQueryOrForm("svcPriority", ushort.Parse);
                        string targetName = request.GetQueryOrForm("svcTargetName").TrimEnd('.');
                        string strSvcParams = request.GetQueryOrForm("svcParams");

                        Dictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams;

                        if (strSvcParams.Equals("false", StringComparison.OrdinalIgnoreCase))
                        {
                            svcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>(0);
                        }
                        else
                        {
                            string[] strSvcParamsParts = strSvcParams.Split('|');
                            svcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>(strSvcParamsParts.Length / 2);

                            for (int i = 0; i < strSvcParamsParts.Length; i += 2)
                            {
                                DnsSvcParamKey svcParamKey = Enum.Parse<DnsSvcParamKey>(strSvcParamsParts[i].Replace('-', '_'), true);
                                DnsSvcParamValue svcParamValue = DnsSvcParamValue.Parse(svcParamKey, strSvcParamsParts[i + 1]);

                                svcParams.Add(svcParamKey, svcParamValue);
                            }
                        }

                        switch (type)
                        {
                            case DnsResourceRecordType.HTTPS:
                                _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsHTTPSRecordData(svcPriority, targetName, svcParams));
                                break;

                            default:
                                _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsSVCBRecordData(svcPriority, targetName, svcParams));
                                break;
                        }
                    }
                    break;

                case DnsResourceRecordType.URI:
                    {
                        ushort priority = request.GetQueryOrForm("uriPriority", ushort.Parse);
                        ushort weight = request.GetQueryOrForm("uriWeight", ushort.Parse);
                        Uri uri = request.GetQueryOrForm("uri", delegate (string value) { return new Uri(value); });

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsURIRecordData(priority, weight, uri));
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        byte flags = request.GetQueryOrForm("flags", byte.Parse);
                        string tag = request.GetQueryOrForm("tag");
                        string value = request.GetQueryOrForm("value");

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsCAARecordData(flags, tag, value));
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        string aname = request.GetQueryOrFormAlt("aname", "value").TrimEnd('.');

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsANAMERecordData(aname));
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        DnsTransportProtocol protocol = request.GetQueryOrFormEnum("protocol", DnsTransportProtocol.Udp);
                        string forwarder = request.GetQueryOrFormAlt("forwarder", "value");

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsForwarderRecordData(protocol, forwarder));
                    }
                    break;

                case DnsResourceRecordType.APP:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type);
                    break;

                default:
                    {
                        string strRData = request.GetQueryOrForm("rdata", string.Empty);

                        byte[] rdata;

                        if (strRData.Contains(':'))
                            rdata = strRData.ParseColonHexString();
                        else
                            rdata = Convert.FromHexString(strRData);

                        if (!_dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsUnknownRecordData(rdata)))
                            throw new DnsWebServiceException("Failed to delete the record.");
                    }
                    break;
            }

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Record was deleted from authoritative zone '" + zoneInfo.Name + "' successfully {domain: " + domain + "; type: " + type + ";}");

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void UpdateRecord(HttpContext context)
        {
            HttpRequest request = context.Request;

            string domain = request.GetQueryOrForm("domain").TrimEnd('.');

            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            string zoneName = request.QueryOrForm("zone");
            if (zoneName is not null)
            {
                zoneName = zoneName.TrimEnd('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);
            }

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such authoritative zone was found: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string newDomain = request.GetQueryOrForm("newDomain", domain).TrimEnd('.');
            uint ttl = request.GetQueryOrForm("ttl", uint.Parse, _defaultRecordTtl);
            bool disable = request.GetQueryOrForm("disable", bool.Parse, false);
            string comments = request.QueryOrForm("comments");
            DnsResourceRecordType type = request.GetQueryOrFormEnum<DnsResourceRecordType>("type");

            DnsResourceRecord oldRecord = null;
            DnsResourceRecord newRecord;

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        IPAddress ipAddress = IPAddress.Parse(request.GetQueryOrFormAlt("ipAddress", "value"));
                        IPAddress newIpAddress = IPAddress.Parse(request.GetQueryOrFormAlt("newIpAddress", "newValue", ipAddress.ToString()));

                        bool ptr = request.GetQueryOrForm("ptr", bool.Parse, false);
                        if (ptr)
                        {
                            string newPtrDomain = Zone.GetReverseZone(newIpAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo newReverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(newPtrDomain);
                            if (newReverseZoneInfo is null)
                            {
                                bool createPtrZone = request.GetQueryOrForm("createPtrZone", bool.Parse, false);
                                if (!createPtrZone)
                                    throw new DnsServerException("No reverse zone available to add PTR record.");

                                string ptrZone = Zone.GetReverseZone(newIpAddress, type == DnsResourceRecordType.A ? 24 : 64);

                                newReverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreatePrimaryZone(ptrZone, _dnsWebService.DnsServer.ServerDomain, false);
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

                            if ((newReverseZoneInfo.Type != AuthZoneType.Primary) && (newReverseZoneInfo.Type != AuthZoneType.Forwarder))
                                throw new DnsServerException("Reverse zone '" + newReverseZoneInfo.Name + "' is not a primary or forwarder zone.");

                            string oldPtrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo oldReverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(oldPtrDomain);
                            if ((oldReverseZoneInfo != null) && !oldReverseZoneInfo.Internal && (oldReverseZoneInfo.Type == AuthZoneType.Primary))
                            {
                                //delete old PTR record if any and save old reverse zone
                                _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(oldReverseZoneInfo.Name, oldPtrDomain, DnsResourceRecordType.PTR);
                                _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(oldReverseZoneInfo.Name);
                            }

                            //add new PTR record and save reverse zone
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecords(newReverseZoneInfo.Name, newPtrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecordData[] { new DnsPTRRecordData(domain) });
                            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(newReverseZoneInfo.Name);
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
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nameServer = request.GetQueryOrFormAlt("nameServer", "value").TrimEnd('.');
                        string newNameServer = request.GetQueryOrFormAlt("newNameServer", "newValue", nameServer).TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsNSRecordData(nameServer));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsNSRecordData(newNameServer));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        if (request.TryGetQueryOrForm("glue", out string glueAddresses))
                            newRecord.SetGlueRecords(glueAddresses);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        string cname = request.GetQueryOrFormAlt("cname", "value").TrimEnd('.');

                        if (cname.Equals(newDomain, StringComparison.OrdinalIgnoreCase))
                            throw new DnsWebServiceException("CNAME domain name cannot be same as that of the record name.");

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCNAMERecordData(cname));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCNAMERecordData(cname));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SOA:
                    {
                        string primaryNameServer = request.GetQueryOrForm("primaryNameServer").TrimEnd('.');
                        string responsiblePerson = request.GetQueryOrForm("responsiblePerson").TrimEnd('.');
                        uint serial = request.GetQueryOrForm("serial", uint.Parse);
                        uint refresh = request.GetQueryOrForm("refresh", uint.Parse);
                        uint retry = request.GetQueryOrForm("retry", uint.Parse);
                        uint expire = request.GetQueryOrForm("expire", uint.Parse);
                        uint minimum = request.GetQueryOrForm("minimum", uint.Parse);

                        DnsResourceRecord newSOARecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSOARecordData(primaryNameServer, responsiblePerson, serial, refresh, retry, expire, minimum));

                        switch (zoneInfo.Type)
                        {
                            case AuthZoneType.Primary:
                                {
                                    AuthRecordInfo recordInfo = newSOARecord.GetAuthRecordInfo();

                                    if (request.TryGetQueryOrForm("useSerialDateScheme", bool.Parse, out bool useSerialDateScheme))
                                        recordInfo.UseSoaSerialDateScheme = useSerialDateScheme;
                                }
                                break;

                            case AuthZoneType.Secondary:
                                {
                                    AuthRecordInfo recordInfo = newSOARecord.GetAuthRecordInfo();

                                    if (request.TryGetQueryOrFormEnum("zoneTransferProtocol", out DnsTransportProtocol zoneTransferProtocol))
                                    {
                                        if (zoneTransferProtocol == DnsTransportProtocol.Quic)
                                            DnsWebService.ValidateQuicSupport();

                                        recordInfo.ZoneTransferProtocol = zoneTransferProtocol;
                                    }

                                    if (request.TryGetQueryOrForm("primaryAddresses", out string primaryAddresses))
                                    {
                                        recordInfo.PrimaryNameServers = primaryAddresses.Split(delegate (string address)
                                        {
                                            NameServerAddress nameServer = NameServerAddress.Parse(address);

                                            if (nameServer.Protocol != zoneTransferProtocol)
                                                nameServer = nameServer.ChangeProtocol(zoneTransferProtocol);

                                            return nameServer;
                                        }, ',');
                                    }

                                    if (request.TryGetQueryOrForm("tsigKeyName", out string tsigKeyName))
                                        recordInfo.TsigKeyName = tsigKeyName;
                                }
                                break;

                            case AuthZoneType.Stub:
                                {
                                    if (request.TryGetQueryOrForm("primaryAddresses", out string primaryAddresses))
                                    {
                                        newSOARecord.GetAuthRecordInfo().PrimaryNameServers = primaryAddresses.Split(delegate (string address)
                                        {
                                            NameServerAddress nameServer = NameServerAddress.Parse(address);

                                            if (nameServer.Protocol != DnsTransportProtocol.Udp)
                                                nameServer = nameServer.ChangeProtocol(DnsTransportProtocol.Udp);

                                            return nameServer;
                                        }, ',');
                                    }
                                }
                                break;
                        }

                        if (!string.IsNullOrEmpty(comments))
                            newSOARecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newSOARecord);

                        newRecord = zoneInfo.GetApexRecords(DnsResourceRecordType.SOA)[0];
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        string ptrName = request.GetQueryOrFormAlt("ptrName", "value").TrimEnd('.');
                        string newPtrName = request.GetQueryOrFormAlt("newPtrName", "newValue", ptrName).TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsPTRRecordData(ptrName));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsPTRRecordData(newPtrName));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        ushort preference = request.GetQueryOrForm("preference", ushort.Parse);
                        ushort newPreference = request.GetQueryOrForm("newPreference", ushort.Parse, preference);

                        string exchange = request.GetQueryOrFormAlt("exchange", "value").TrimEnd('.');
                        string newExchange = request.GetQueryOrFormAlt("newExchange", "newValue", exchange).TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsMXRecordData(preference, exchange));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsMXRecordData(newPreference, newExchange));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string text = request.GetQueryOrFormAlt("text", "value");
                        string newText = request.GetQueryOrFormAlt("newText", "newValue", text);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsTXTRecordData(text));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsTXTRecordData(newText));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        ushort priority = request.GetQueryOrForm("priority", ushort.Parse);
                        ushort newPriority = request.GetQueryOrForm("newPriority", ushort.Parse, priority);

                        ushort weight = request.GetQueryOrForm("weight", ushort.Parse);
                        ushort newWeight = request.GetQueryOrForm("newWeight", ushort.Parse, weight);

                        ushort port = request.GetQueryOrForm("port", ushort.Parse);
                        ushort newPort = request.GetQueryOrForm("newPort", ushort.Parse, port);

                        string target = request.GetQueryOrFormAlt("target", "value").TrimEnd('.');
                        string newTarget = request.GetQueryOrFormAlt("newTarget", "newValue", target).TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSRVRecordData(priority, weight, port, target));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSRVRecordData(newPriority, newWeight, newPort, newTarget));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    {
                        string dname = request.GetQueryOrFormAlt("dname", "value").TrimEnd('.');

                        if (dname.EndsWith("." + newDomain, StringComparison.OrdinalIgnoreCase))
                            throw new DnsWebServiceException("DNAME domain name cannot be a sub domain of the record name.");

                        if (dname.Equals(newDomain, StringComparison.OrdinalIgnoreCase))
                            throw new DnsWebServiceException("DNAME domain name cannot be same as that of the record name.");

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsDNAMERecordData(dname));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsDNAMERecordData(dname));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DS:
                    {
                        ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);
                        ushort newKeyTag = request.GetQueryOrForm("newKeyTag", ushort.Parse, keyTag);

                        DnssecAlgorithm algorithm = Enum.Parse<DnssecAlgorithm>(request.GetQueryOrForm("algorithm").Replace('-', '_'), true);
                        DnssecAlgorithm newAlgorithm = Enum.Parse<DnssecAlgorithm>(request.GetQueryOrForm("newAlgorithm", algorithm.ToString()).Replace('-', '_'), true);

                        DnssecDigestType digestType = Enum.Parse<DnssecDigestType>(request.GetQueryOrForm("digestType").Replace('-', '_'), true);
                        DnssecDigestType newDigestType = Enum.Parse<DnssecDigestType>(request.GetQueryOrForm("newDigestType", digestType.ToString()).Replace('-', '_'), true);

                        byte[] digest = request.GetQueryOrFormAlt("digest", "value", Convert.FromHexString);
                        byte[] newDigest = request.GetQueryOrFormAlt("newDigest", "newValue", Convert.FromHexString, digest);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsDSRecordData(keyTag, algorithm, digestType, digest));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsDSRecordData(newKeyTag, newAlgorithm, newDigestType, newDigest));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SSHFP:
                    {
                        DnsSSHFPAlgorithm sshfpAlgorithm = request.GetQueryOrFormEnum<DnsSSHFPAlgorithm>("sshfpAlgorithm");
                        DnsSSHFPAlgorithm newSshfpAlgorithm = request.GetQueryOrFormEnum("newSshfpAlgorithm", sshfpAlgorithm);

                        DnsSSHFPFingerprintType sshfpFingerprintType = request.GetQueryOrFormEnum<DnsSSHFPFingerprintType>("sshfpFingerprintType");
                        DnsSSHFPFingerprintType newSshfpFingerprintType = request.GetQueryOrFormEnum("newSshfpFingerprintType", sshfpFingerprintType);

                        byte[] sshfpFingerprint = request.GetQueryOrForm("sshfpFingerprint", Convert.FromHexString);
                        byte[] newSshfpFingerprint = request.GetQueryOrForm("newSshfpFingerprint", Convert.FromHexString, sshfpFingerprint);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSSHFPRecordData(sshfpAlgorithm, sshfpFingerprintType, sshfpFingerprint));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSSHFPRecordData(newSshfpAlgorithm, newSshfpFingerprintType, newSshfpFingerprint));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TLSA:
                    {
                        DnsTLSACertificateUsage tlsaCertificateUsage = Enum.Parse<DnsTLSACertificateUsage>(request.GetQueryOrForm("tlsaCertificateUsage").Replace('-', '_'), true);
                        DnsTLSACertificateUsage newTlsaCertificateUsage = Enum.Parse<DnsTLSACertificateUsage>(request.GetQueryOrForm("newTlsaCertificateUsage", tlsaCertificateUsage.ToString()).Replace('-', '_'), true);

                        DnsTLSASelector tlsaSelector = request.GetQueryOrFormEnum<DnsTLSASelector>("tlsaSelector");
                        DnsTLSASelector newTlsaSelector = request.GetQueryOrFormEnum("newTlsaSelector", tlsaSelector);

                        DnsTLSAMatchingType tlsaMatchingType = Enum.Parse<DnsTLSAMatchingType>(request.GetQueryOrForm("tlsaMatchingType").Replace('-', '_'), true);
                        DnsTLSAMatchingType newTlsaMatchingType = Enum.Parse<DnsTLSAMatchingType>(request.GetQueryOrForm("newTlsaMatchingType", tlsaMatchingType.ToString()).Replace('-', '_'), true);

                        string tlsaCertificateAssociationData = request.GetQueryOrForm("tlsaCertificateAssociationData");
                        string newTlsaCertificateAssociationData = request.GetQueryOrForm("newTlsaCertificateAssociationData", tlsaCertificateAssociationData);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsTLSARecordData(tlsaCertificateUsage, tlsaSelector, tlsaMatchingType, tlsaCertificateAssociationData));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsTLSARecordData(newTlsaCertificateUsage, newTlsaSelector, newTlsaMatchingType, newTlsaCertificateAssociationData));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SVCB:
                case DnsResourceRecordType.HTTPS:
                    {
                        ushort svcPriority = request.GetQueryOrForm("svcPriority", ushort.Parse);
                        ushort newSvcPriority = request.GetQueryOrForm("newSvcPriority", ushort.Parse, svcPriority);

                        string targetName = request.GetQueryOrForm("svcTargetName").TrimEnd('.');
                        string newTargetName = request.GetQueryOrForm("newSvcTargetName", targetName).TrimEnd('.');

                        string strSvcParams = request.GetQueryOrForm("svcParams");
                        string strNewSvcParams = request.GetQueryOrForm("newSvcParams", strSvcParams);

                        Dictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams;

                        if (strSvcParams.Equals("false", StringComparison.OrdinalIgnoreCase))
                        {
                            svcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>(0);
                        }
                        else
                        {
                            string[] strSvcParamsParts = strSvcParams.Split('|');
                            svcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>(strSvcParamsParts.Length / 2);

                            for (int i = 0; i < strSvcParamsParts.Length; i += 2)
                            {
                                DnsSvcParamKey svcParamKey = Enum.Parse<DnsSvcParamKey>(strSvcParamsParts[i].Replace('-', '_'), true);
                                DnsSvcParamValue svcParamValue = DnsSvcParamValue.Parse(svcParamKey, strSvcParamsParts[i + 1]);

                                svcParams.Add(svcParamKey, svcParamValue);
                            }
                        }

                        Dictionary<DnsSvcParamKey, DnsSvcParamValue> newSvcParams;

                        if (strNewSvcParams.Equals("false", StringComparison.OrdinalIgnoreCase))
                        {
                            newSvcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>(0);
                        }
                        else
                        {
                            string[] strSvcParamsParts = strNewSvcParams.Split('|');
                            newSvcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>(strSvcParamsParts.Length / 2);

                            for (int i = 0; i < strSvcParamsParts.Length; i += 2)
                            {
                                DnsSvcParamKey svcParamKey = Enum.Parse<DnsSvcParamKey>(strSvcParamsParts[i].Replace('-', '_'), true);
                                DnsSvcParamValue svcParamValue = DnsSvcParamValue.Parse(svcParamKey, strSvcParamsParts[i + 1]);

                                newSvcParams.Add(svcParamKey, svcParamValue);
                            }
                        }

                        switch (type)
                        {
                            case DnsResourceRecordType.HTTPS:
                                oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsHTTPSRecordData(svcPriority, targetName, svcParams));
                                newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsHTTPSRecordData(newSvcPriority, newTargetName, newSvcParams));
                                break;

                            default:
                                oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSVCBRecordData(svcPriority, targetName, svcParams));
                                newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSVCBRecordData(newSvcPriority, newTargetName, newSvcParams));
                                break;
                        }

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.URI:
                    {
                        ushort priority = request.GetQueryOrForm("uriPriority", ushort.Parse);
                        ushort newPriority = request.GetQueryOrForm("newUriPriority", ushort.Parse, priority);

                        ushort weight = request.GetQueryOrForm("uriWeight", ushort.Parse);
                        ushort newWeight = request.GetQueryOrForm("newUriWeight", ushort.Parse, weight);

                        Uri uri = request.GetQueryOrForm("uri", delegate (string value) { return new Uri(value); });
                        Uri newUri = request.GetQueryOrForm("newUri", delegate (string value) { return new Uri(value); }, uri);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsURIRecordData(priority, weight, uri));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsURIRecordData(newPriority, newWeight, newUri));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        byte flags = request.GetQueryOrForm("flags", byte.Parse);
                        byte newFlags = request.GetQueryOrForm("newFlags", byte.Parse, flags);

                        string tag = request.GetQueryOrForm("tag");
                        string newTag = request.GetQueryOrForm("newTag", tag);

                        string value = request.GetQueryOrForm("value");
                        string newValue = request.GetQueryOrForm("newValue", value);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCAARecordData(flags, tag, value));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCAARecordData(newFlags, newTag, newValue));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        string aname = request.GetQueryOrFormAlt("aname", "value").TrimEnd('.');
                        string newAName = request.GetQueryOrFormAlt("newAName", "newValue", aname).TrimEnd('.');

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsANAMERecordData(aname));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsANAMERecordData(newAName));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        DnsTransportProtocol protocol = request.GetQueryOrFormEnum("protocol", DnsTransportProtocol.Udp);
                        DnsTransportProtocol newProtocol = request.GetQueryOrFormEnum("newProtocol", protocol);

                        string forwarder = request.GetQueryOrFormAlt("forwarder", "value");
                        string newForwarder = request.GetQueryOrFormAlt("newForwarder", "newValue", forwarder);

                        bool dnssecValidation = request.GetQueryOrForm("dnssecValidation", bool.Parse, false);

                        DnsForwarderRecordProxyType proxyType = DnsForwarderRecordProxyType.DefaultProxy;
                        string proxyAddress = null;
                        ushort proxyPort = 0;
                        string proxyUsername = null;
                        string proxyPassword = null;

                        if (!newForwarder.Equals("this-server"))
                        {
                            proxyType = request.GetQueryOrFormEnum("proxyType", DnsForwarderRecordProxyType.DefaultProxy);
                            switch (proxyType)
                            {
                                case DnsForwarderRecordProxyType.Http:
                                case DnsForwarderRecordProxyType.Socks5:
                                    proxyAddress = request.GetQueryOrForm("proxyAddress");
                                    proxyPort = request.GetQueryOrForm("proxyPort", ushort.Parse);
                                    proxyUsername = request.QueryOrForm("proxyUsername");
                                    proxyPassword = request.QueryOrForm("proxyPassword");
                                    break;
                            }
                        }

                        switch (newProtocol)
                        {
                            case DnsTransportProtocol.HttpsJson:
                                newProtocol = DnsTransportProtocol.Https;
                                break;

                            case DnsTransportProtocol.Quic:
                                DnsWebService.ValidateQuicSupport();
                                break;
                        }

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecordData(protocol, forwarder));
                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecordData(newProtocol, newForwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.APP:
                    {
                        string appName = request.GetQueryOrFormAlt("appName", "value");
                        string classPath = request.GetQueryOrForm("classPath");
                        string recordData = request.GetQueryOrForm("recordData", "");

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsApplicationRecordData(appName, classPath, recordData));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsApplicationRecordData(appName, classPath, recordData));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                default:
                    {
                        string strRData = request.GetQueryOrForm("rdata");
                        string strNewRData = request.GetQueryOrForm("newRData", strRData);

                        byte[] rdata;

                        if (strRData.Contains(':'))
                            rdata = strRData.ParseColonHexString();
                        else
                            rdata = Convert.FromHexString(strRData);

                        byte[] newRData;

                        if (strNewRData.Contains(':'))
                            newRData = strNewRData.ParseColonHexString();
                        else
                            newRData = Convert.FromHexString(strNewRData);

                        oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsUnknownRecordData(rdata));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsUnknownRecordData(newRData));

                        if (disable)
                            newRecord.GetAuthRecordInfo().Disabled = true;

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.GetAuthRecordInfo().Comments = comments;

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;
            }

            _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] Record was updated for authoritative zone '" + zoneInfo.Name + "' successfully {" + (oldRecord is null ? "" : "oldRecord: " + oldRecord.ToString() + "; ") + "newRecord: " + newRecord.ToString() + "}");

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            jsonWriter.WritePropertyName("zone");
            WriteZoneInfoAsJson(zoneInfo, jsonWriter);

            jsonWriter.WritePropertyName("updatedRecord");
            WriteRecordAsJson(newRecord, jsonWriter, true, zoneInfo);
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
