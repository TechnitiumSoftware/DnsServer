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
using DnsServerCore.Cluster;
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
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        class WebServiceZonesApi
        {
            #region variables

            static readonly char[] _commaSeparator = new char[] { ',' };
            static readonly char[] _pipeSeparator = new char[] { '|' };
            static readonly char[] _commaSpaceSeparator = new char[] { ',', ' ' };
            static readonly char[] _newLineSeparator = new char[] { '\r', '\n' };

            readonly DnsWebService _dnsWebService;

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
                    GenericRecordInfo authRecordInfo = record.GetAuthGenericRecordInfo();

                    jsonWriter.WriteNumber("ttl", record.TTL);
                    jsonWriter.WriteString("ttlString", ZoneFile.GetTtlString(record.TTL));
                    jsonWriter.WriteBoolean("disabled", authRecordInfo.Disabled);

                    string comments = authRecordInfo.Comments;
                    if (!string.IsNullOrEmpty(comments))
                        jsonWriter.WriteString("comments", comments);
                }
                else
                {
                    if (record.IsStale)
                        jsonWriter.WriteString("ttl", "0 (0s)");
                    else
                        jsonWriter.WriteString("ttl", record.TTL + " (" + ZoneFile.GetTtlString(record.TTL) + ")");
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

                                if (authoritativeZoneRecords)
                                {
                                    jsonWriter.WriteNumber("refresh", rdata.Refresh);
                                    jsonWriter.WriteNumber("retry", rdata.Retry);
                                    jsonWriter.WriteNumber("expire", rdata.Expire);
                                    jsonWriter.WriteNumber("minimum", rdata.Minimum);

                                    jsonWriter.WriteString("refreshString", ZoneFile.GetTtlString(rdata.Refresh));
                                    jsonWriter.WriteString("retryString", ZoneFile.GetTtlString(rdata.Retry));
                                    jsonWriter.WriteString("expireString", ZoneFile.GetTtlString(rdata.Expire));
                                    jsonWriter.WriteString("minimumString", ZoneFile.GetTtlString(rdata.Minimum));
                                }
                                else
                                {
                                    jsonWriter.WriteString("refresh", rdata.Refresh + " (" + ZoneFile.GetTtlString(rdata.Refresh) + ")");
                                    jsonWriter.WriteString("retry", rdata.Retry + " (" + ZoneFile.GetTtlString(rdata.Retry) + ")");
                                    jsonWriter.WriteString("expire", rdata.Expire + " (" + ZoneFile.GetTtlString(rdata.Expire) + ")");
                                    jsonWriter.WriteString("minimum", rdata.Minimum + " (" + ZoneFile.GetTtlString(rdata.Minimum) + ")");
                                }
                            }
                            else
                            {
                                jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                                jsonWriter.WriteString("data", record.RDATA.ToString());
                            }

                            if (authoritativeZoneRecords && (zoneInfo is not null))
                            {
                                switch (zoneInfo.Type)
                                {
                                    case AuthZoneType.Primary:
                                    case AuthZoneType.Forwarder:
                                    case AuthZoneType.Catalog:
                                        jsonWriter.WriteBoolean("useSerialDateScheme", record.GetAuthSOARecordInfo().UseSoaSerialDateScheme);
                                        break;
                                }
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
                                jsonWriter.WriteString("text", rdata.GetText());
                                jsonWriter.WriteBoolean("splitText", rdata.CharacterStrings.Count > 1);

                                jsonWriter.WriteStartArray("characterStrings");

                                foreach (string characterString in rdata.CharacterStrings)
                                    jsonWriter.WriteStringValue(characterString);

                                jsonWriter.WriteEndArray();
                            }
                            else
                            {
                                jsonWriter.WriteString("dataType", record.RDATA.GetType().Name);
                                jsonWriter.WriteString("data", record.RDATA.ToString());
                            }
                        }
                        break;

                    case DnsResourceRecordType.RP:
                        {
                            if (record.RDATA is DnsRPRecordData rdata)
                            {
                                jsonWriter.WriteString("mailbox", rdata.Mailbox);
                                jsonWriter.WriteString("txtDomain", rdata.TxtDomain);

                                if (DnsClient.TryConvertDomainNameToUnicode(rdata.Mailbox, out string txtDomainIdn))
                                    jsonWriter.WriteString("txtDomainIdn", txtDomainIdn);
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

                    case DnsResourceRecordType.NAPTR:
                        {
                            if (record.RDATA is DnsNAPTRRecordData rdata)
                            {
                                jsonWriter.WriteNumber("order", rdata.Order);
                                jsonWriter.WriteNumber("preference", rdata.Preference);
                                jsonWriter.WriteString("flags", rdata.Flags);
                                jsonWriter.WriteString("services", rdata.Services);
                                jsonWriter.WriteString("regexp", rdata.Regexp);
                                jsonWriter.WriteString("replacement", rdata.Replacement.Length == 0 ? "." : rdata.Replacement);

                                if (DnsClient.TryConvertDomainNameToUnicode(rdata.Replacement, out string replacementIdn))
                                    jsonWriter.WriteString("replacementIdn", replacementIdn);
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

                    case DnsResourceRecordType.APL:
                        {
                            if (record.RDATA is DnsAPLRecordData rdata)
                            {
                                jsonWriter.WriteStartArray("addressPrefixes");

                                foreach (DnsAPLRecordData.APItem apItem in rdata.APItems)
                                {
                                    jsonWriter.WriteStartObject();

                                    jsonWriter.WriteString("addressFamily", apItem.AddressFamily.ToString());
                                    jsonWriter.WriteNumber("prefix", apItem.Prefix);
                                    jsonWriter.WriteBoolean("negation", apItem.Negation);
                                    jsonWriter.WriteString("afdPart", apItem.NetworkAddress.Address.ToString());

                                    jsonWriter.WriteEndObject();
                                }

                                jsonWriter.WriteEndArray();
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
                                jsonWriter.WriteNumber("algorithmNumber", (byte)rdata.Algorithm);
                                jsonWriter.WriteString("digestType", rdata.DigestType.ToString());
                                jsonWriter.WriteNumber("digestTypeNumber", (byte)rdata.DigestType);
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
                                jsonWriter.WriteNumber("algorithmNumber", (byte)rdata.Algorithm);
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
                                jsonWriter.WriteNumber("algorithmNumber", (byte)rdata.Algorithm);
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

                                                    if (dnssecPrivateKey.State == DnssecPrivateKeyState.Published)
                                                    {
                                                        switch (dnssecPrivateKey.KeyType)
                                                        {
                                                            case DnssecPrivateKeyType.KeySigningKey:
                                                                jsonWriter.WriteString("dnsKeyStateReadyBy", dnssecPrivateKey.StateTransitionByWithDelays);
                                                                break;

                                                            case DnssecPrivateKeyType.ZoneSigningKey:
                                                                jsonWriter.WriteString("dnsKeyStateActiveBy", dnssecPrivateKey.StateTransitionByWithDelays);
                                                                break;
                                                        }
                                                    }

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

                    case DnsResourceRecordType.ZONEMD:
                        {
                            if (record.RDATA is DnsZONEMDRecordData rdata)
                            {
                                jsonWriter.WriteNumber("serial", rdata.Serial);
                                jsonWriter.WriteString("scheme", rdata.Scheme.ToString());
                                jsonWriter.WriteString("hashAlgorithm", rdata.HashAlgorithm.ToString());
                                jsonWriter.WriteString("digest", Convert.ToHexString(rdata.Digest));
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
                                    jsonWriter.WriteString(svcParam.Key.ToString().ToLowerInvariant().Replace('_', '-'), svcParam.Value.ToString());

                                jsonWriter.WriteEndObject();

                                if (authoritativeZoneRecords)
                                {
                                    SVCBRecordInfo rrInfo = record.GetAuthSVCBRecordInfo();

                                    jsonWriter.WriteBoolean("autoIpv4Hint", rrInfo.AutoIpv4Hint);
                                    jsonWriter.WriteBoolean("autoIpv6Hint", rrInfo.AutoIpv6Hint);
                                }
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
                                jsonWriter.WriteNumber("priority", rdata.Priority);
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
                    GenericRecordInfo authRecordInfo = record.GetAuthGenericRecordInfo();

                    if (authRecordInfo is NSRecordInfo nsRecordInfo)
                    {
                        IReadOnlyList<DnsResourceRecord> glueRecords = nsRecordInfo.GlueRecords;
                        if (glueRecords is not null)
                        {
                            jsonWriter.WritePropertyName("glueRecords");
                            jsonWriter.WriteStartArray();

                            foreach (DnsResourceRecord glueRecord in glueRecords)
                                jsonWriter.WriteStringValue(glueRecord.RDATA.ToString());

                            jsonWriter.WriteEndArray();
                        }
                    }

                    jsonWriter.WriteString("lastUsedOn", authRecordInfo.LastUsedOn);
                    jsonWriter.WriteString("lastModified", authRecordInfo.LastModified);
                    jsonWriter.WriteNumber("expiryTtl", authRecordInfo.ExpiryTtl);
                    jsonWriter.WriteString("expiryTtlString", ZoneFile.GetTtlString(authRecordInfo.ExpiryTtl));
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

                    if (record.RDATA is DnsNSRecordData nsRData)
                    {
                        NameServerMetadata metadata = nsRData.Metadata;

                        jsonWriter.WriteStartObject("nameServerMetadata");

                        jsonWriter.WriteNumber("totalQueries", metadata.TotalQueries);
                        jsonWriter.WriteString("answerRate", Math.Round(metadata.GetAnswerRate(), 2) + "%");
                        jsonWriter.WriteString("smoothedRoundTripTime", Math.Round(metadata.SRTT, 2) + " ms");
                        jsonWriter.WriteString("smoothedPenaltyRoundTripTime", Math.Round(metadata.SPRTT, 2) + " ms");
                        jsonWriter.WriteString("netRoundTripTime", Math.Round(metadata.GetNetRTT(), 2) + " ms");

                        jsonWriter.WriteEndObject();
                    }

                    DnsDatagramMetadata responseMetadata = cacheRecordInfo.ResponseMetadata;
                    if (responseMetadata is not null)
                    {
                        jsonWriter.WritePropertyName("responseMetadata");
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("nameServer", responseMetadata.NameServer?.ToString());
                        jsonWriter.WriteString("protocol", (responseMetadata.NameServer is null ? DnsTransportProtocol.Udp : responseMetadata.NameServer.Protocol).ToString());
                        jsonWriter.WriteString("datagramSize", responseMetadata.DatagramSize + " bytes");
                        jsonWriter.WriteString("roundTripTime", Math.Round(responseMetadata.RoundTripTime, 2) + " ms");

                        jsonWriter.WriteEndObject();
                    }

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
                jsonWriter.WriteString("lastModified", zoneInfo.LastModified);
                jsonWriter.WriteBoolean("disabled", zoneInfo.Disabled);
                jsonWriter.WriteNumber("soaSerial", zoneInfo.ApexZone.GetZoneSoaSerial());

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                        jsonWriter.WriteBoolean("internal", zoneInfo.Internal);
                        break;
                }

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Stub:
                    case AuthZoneType.Forwarder:
                    case AuthZoneType.SecondaryForwarder:
                        jsonWriter.WriteString("catalog", zoneInfo.CatalogZoneName);
                        break;
                }

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                        jsonWriter.WriteString("dnssecStatus", zoneInfo.ApexZone.DnssecStatus.ToString());
                        jsonWriter.WriteBoolean("hasDnssecPrivateKeys", (zoneInfo.DnssecPrivateKeys is not null) && (zoneInfo.DnssecPrivateKeys.Count > 0));
                        break;
                }

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Secondary:
                        jsonWriter.WriteBoolean("validationFailed", zoneInfo.ValidationFailed);
                        break;
                }

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Stub:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        jsonWriter.WriteString("expiry", zoneInfo.Expiry);
                        jsonWriter.WriteBoolean("isExpired", zoneInfo.IsExpired);
                        jsonWriter.WriteBoolean("syncFailed", zoneInfo.SyncFailed);
                        break;
                }

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Forwarder:
                    case AuthZoneType.Catalog:
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
                }

                jsonWriter.WriteEndObject();
            }

            private static void WriteDnssecPrivateKeyAsJson(DnssecPrivateKey dnssecPrivateKey, Utf8JsonWriter jsonWriter)
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

                jsonWriter.WriteNumber("algorithmNumber", (byte)dnssecPrivateKey.Algorithm);

                jsonWriter.WriteString("state", dnssecPrivateKey.State.ToString());
                jsonWriter.WriteString("stateChangedOn", dnssecPrivateKey.StateChangedOn);

                if (dnssecPrivateKey.State == DnssecPrivateKeyState.Published)
                {
                    switch (dnssecPrivateKey.KeyType)
                    {
                        case DnssecPrivateKeyType.KeySigningKey:
                            jsonWriter.WriteString("stateReadyBy", dnssecPrivateKey.StateTransitionByWithDelays);
                            break;

                        case DnssecPrivateKeyType.ZoneSigningKey:
                            jsonWriter.WriteString("stateActiveBy", dnssecPrivateKey.StateTransitionByWithDelays);
                            break;
                    }
                }

                jsonWriter.WriteBoolean("isRetiring", dnssecPrivateKey.IsRetiring);
                jsonWriter.WriteNumber("rolloverDays", dnssecPrivateKey.RolloverDays);

                jsonWriter.WriteEndObject();
            }

            private static string[] DecodeCharacterStrings(string text)
            {
                string[] characterStrings = text.Split(_newLineSeparator, StringSplitOptions.RemoveEmptyEntries);

                for (int i = 0; i < characterStrings.Length; i++)
                    characterStrings[i] = Unescape(characterStrings[i]);

                return characterStrings;
            }

            private static string Unescape(string text)
            {
                StringBuilder sb = new StringBuilder(text.Length);

                for (int i = 0, j; i < text.Length; i++)
                {
                    char c = text[i];
                    if (c == '\\')
                    {
                        j = i + 1;

                        if (j == text.Length)
                        {
                            sb.Append(c);
                            break;
                        }

                        char next = text[j];
                        switch (next)
                        {
                            case 'n':
                                sb.Append('\n');
                                break;

                            case 'r':
                                sb.Append('\r');
                                break;

                            case 't':
                                sb.Append('\t');
                                break;

                            case '\\':
                                sb.Append('\\');
                                break;

                            default:
                                sb.Append(c).Append(next);
                                break;
                        }

                        i++;
                    }
                    else
                    {
                        sb.Append(c);
                    }
                }

                return sb.ToString();
            }

            private static string GetSvcbTargetName(DnsResourceRecord svcbRecord)
            {
                DnsSVCBRecordData rData = svcbRecord.RDATA as DnsSVCBRecordData;

                if (rData.TargetName.Length > 0)
                    return rData.TargetName;

                if (rData.SvcPriority == 0) //alias mode
                    return null;

                //service mode
                return svcbRecord.Name;
            }

            private void ResolveSvcbAutoHints(string zoneName, DnsResourceRecord svcbRecord, bool resolveIpv4Hint, bool resolveIpv6Hint, Dictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams, IReadOnlyCollection<DnsResourceRecord> importRecords = null)
            {
                string targetName = GetSvcbTargetName(svcbRecord);
                if (targetName is not null)
                    ResolveSvcbAutoHints(zoneName, targetName, resolveIpv4Hint, resolveIpv6Hint, svcParams, importRecords);
            }

            private void ResolveSvcbAutoHints(string zoneName, string targetName, bool resolveIpv4Hint, bool resolveIpv6Hint, Dictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams, IReadOnlyCollection<DnsResourceRecord> importRecords = null)
            {
                if (resolveIpv4Hint)
                {
                    List<IPAddress> ipv4Hint = new List<IPAddress>();

                    IReadOnlyList<DnsResourceRecord> records = _dnsWebService._dnsServer.AuthZoneManager.GetRecords(zoneName, targetName, DnsResourceRecordType.A);

                    foreach (DnsResourceRecord record in records)
                    {
                        if (record.GetAuthGenericRecordInfo().Disabled)
                            continue;

                        ipv4Hint.Add((record.RDATA as DnsARecordData).Address);
                    }

                    if (importRecords is not null)
                    {
                        foreach (DnsResourceRecord record in importRecords)
                        {
                            if (record.Type != DnsResourceRecordType.A)
                                continue;

                            if (record.Name.Equals(targetName, StringComparison.OrdinalIgnoreCase))
                            {
                                IPAddress address = (record.RDATA as DnsARecordData).Address;

                                if (!ipv4Hint.Contains(address))
                                    ipv4Hint.Add(address);
                            }
                        }
                    }

                    if (ipv4Hint.Count > 0)
                        svcParams[DnsSvcParamKey.IPv4Hint] = new DnsSvcIPv4HintParamValue(ipv4Hint);
                    else
                        svcParams.Remove(DnsSvcParamKey.IPv4Hint);
                }

                if (resolveIpv6Hint)
                {
                    List<IPAddress> ipv6Hint = new List<IPAddress>();

                    IReadOnlyList<DnsResourceRecord> records = _dnsWebService._dnsServer.AuthZoneManager.GetRecords(zoneName, targetName, DnsResourceRecordType.AAAA);

                    foreach (DnsResourceRecord record in records)
                    {
                        if (record.GetAuthGenericRecordInfo().Disabled)
                            continue;

                        ipv6Hint.Add((record.RDATA as DnsAAAARecordData).Address);
                    }

                    if (importRecords is not null)
                    {
                        foreach (DnsResourceRecord record in importRecords)
                        {
                            if (record.Type != DnsResourceRecordType.AAAA)
                                continue;

                            if (record.Name.Equals(targetName, StringComparison.OrdinalIgnoreCase))
                            {
                                IPAddress address = (record.RDATA as DnsAAAARecordData).Address;

                                if (!ipv6Hint.Contains(address))
                                    ipv6Hint.Add(address);
                            }
                        }
                    }

                    if (ipv6Hint.Count > 0)
                        svcParams[DnsSvcParamKey.IPv6Hint] = new DnsSvcIPv6HintParamValue(ipv6Hint);
                    else
                        svcParams.Remove(DnsSvcParamKey.IPv6Hint);
                }
            }

            private void UpdateSvcbAutoHints(string zoneName, string targetName, bool resolveIpv4Hint, bool resolveIpv6Hint)
            {
                List<DnsResourceRecord> allSvcbRecords = new List<DnsResourceRecord>();
                _dnsWebService._dnsServer.AuthZoneManager.ListAllZoneRecords(zoneName, [DnsResourceRecordType.SVCB, DnsResourceRecordType.HTTPS], allSvcbRecords);

                foreach (DnsResourceRecord record in allSvcbRecords)
                {
                    SVCBRecordInfo info = record.GetAuthSVCBRecordInfo();
                    if ((info.AutoIpv4Hint && resolveIpv4Hint) || (info.AutoIpv6Hint && resolveIpv6Hint))
                    {
                        string scvbTargetName = GetSvcbTargetName(record);
                        if (targetName.Equals(scvbTargetName, StringComparison.OrdinalIgnoreCase))
                        {
                            DnsSVCBRecordData oldRData = record.RDATA as DnsSVCBRecordData;

                            Dictionary<DnsSvcParamKey, DnsSvcParamValue> newSvcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>(oldRData.SvcParams);
                            ResolveSvcbAutoHints(zoneName, targetName, resolveIpv4Hint, resolveIpv6Hint, newSvcParams);

                            DnsSVCBRecordData newRData = new DnsSVCBRecordData(oldRData.SvcPriority, oldRData.TargetName, newSvcParams);
                            DnsResourceRecord newRecord = new DnsResourceRecord(record.Name, record.Type, record.Class, record.TTL, newRData) { Tag = record.Tag };

                            _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneName, record, newRecord);
                        }
                    }
                }
            }

            private async Task<List<DnsResourceRecord>> ReadRecordsToImportFromAsync(string zoneName, AuthZoneType zoneType, string catalogZoneName, bool overwrite, TextReader zoneFile)
            {
                List<DnsResourceRecord> records = await ZoneFile.ReadZoneFileFromAsync(zoneFile, zoneName, _dnsWebService._dnsServer.AuthZoneManager.DefaultRecordTtl);
                List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Count);

                foreach (DnsResourceRecord record in records)
                {
                    if (record.Class != DnsClass.IN)
                        throw new DnsWebServiceException("Cannot import records: only IN class is supported by the DNS server.");

                    if (!AuthZoneManager.DomainBelongsToZone(zoneName, record.Name))
                    {
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                continue; //glue records

                            default:
                                throw new DnsServerException("Cannot import records: the domain name '" + record.Name + "' does not belong to the zone '" + zoneName + "'.");
                        }
                    }

                    bool disabled = false;
                    string comments = null;

                    if (record.Tag is string tagValue)
                    {
                        if (tagValue.TrimStart().StartsWith('{'))
                        {
                            try
                            {
                                using JsonDocument jsonDocument = JsonDocument.Parse(tagValue);
                                JsonElement json = jsonDocument.RootElement;

                                if (json.TryGetProperty("disabled", out JsonElement jsonDisabled))
                                    disabled = jsonDisabled.ValueKind == JsonValueKind.True;

                                if (json.TryGetProperty("comments", out JsonElement jsonComments) && (jsonComments.ValueKind == JsonValueKind.String))
                                    comments = jsonComments.GetString();
                            }
                            catch
                            {
                                comments = tagValue.Replace("\\r", "").Replace("\\n", "\n");
                            }
                        }
                        else
                        {
                            comments = tagValue.Replace("\\r", "").Replace("\\n", "\n");
                        }
                    }

                    switch (record.Type)
                    {
                        case DnsResourceRecordType.DNSKEY:
                        case DnsResourceRecordType.RRSIG:
                        case DnsResourceRecordType.NSEC:
                        case DnsResourceRecordType.NSEC3:
                        case DnsResourceRecordType.NSEC3PARAM:
                            continue; //skip DNSSEC records

                        case DnsResourceRecordType.NS:
                            {
                                if (record.Tag is string)
                                {
                                    NSRecordInfo rrInfo = new NSRecordInfo();

                                    rrInfo.Disabled = disabled;
                                    rrInfo.Comments = comments;

                                    record.Tag = rrInfo;
                                }

                                record.SyncGlueRecords(records);

                                newRecords.Add(record);
                            }
                            break;

                        case DnsResourceRecordType.SOA:
                            {
                                if (record.Tag is string)
                                {
                                    SOARecordInfo rrInfo = new SOARecordInfo();
                                    rrInfo.Comments = comments;

                                    record.Tag = rrInfo;
                                }

                                newRecords.Add(record);
                            }
                            break;

                        case DnsResourceRecordType.SVCB:
                        case DnsResourceRecordType.HTTPS:
                            {
                                if (record.Tag is string)
                                {
                                    SVCBRecordInfo rrInfo = new SVCBRecordInfo();

                                    rrInfo.Disabled = disabled;
                                    rrInfo.Comments = comments;

                                    record.Tag = rrInfo;
                                }

                                if (record.RDATA is DnsSVCBRecordData rdata && (rdata.AutoIpv4Hint || rdata.AutoIpv6Hint))
                                {
                                    if (rdata.AutoIpv4Hint)
                                        record.GetAuthSVCBRecordInfo().AutoIpv4Hint = true;

                                    if (rdata.AutoIpv6Hint)
                                        record.GetAuthSVCBRecordInfo().AutoIpv6Hint = true;

                                    Dictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>(rdata.SvcParams);
                                    DnsResourceRecord newRecord = new DnsResourceRecord(record.Name, record.Type, record.Class, record.TTL, new DnsSVCBRecordData(rdata.SvcPriority, rdata.TargetName, svcParams)) { Tag = record.Tag };

                                    ResolveSvcbAutoHints(zoneName, record, rdata.AutoIpv4Hint, rdata.AutoIpv6Hint, svcParams, records);

                                    newRecords.Add(newRecord);
                                    break;
                                }

                                newRecords.Add(record);
                            }
                            break;

                        default:
                            {
                                if (record.Tag is string)
                                {
                                    GenericRecordInfo rrInfo = new GenericRecordInfo();

                                    rrInfo.Disabled = disabled;
                                    rrInfo.Comments = comments;

                                    record.Tag = rrInfo;
                                }

                                newRecords.Add(record);
                            }
                            break;
                    }
                }

                //validate records
                if ((zoneType == AuthZoneType.Primary) && _dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterCatalogZone(catalogZoneName))
                {
                    int nsCount = 0;

                    foreach (DnsResourceRecord newRecord in newRecords)
                    {
                        switch (newRecord.Type)
                        {
                            case DnsResourceRecordType.NS:
                                if (zoneName.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                                {
                                    NSRecordInfo recordInfo = newRecord.GetAuthNSRecordInfo();

                                    if (recordInfo.Disabled)
                                        throw new DnsWebServiceException("Cannot import disabled NS records for Primary zones that are members of the Cluster Catalog zone. These NS records are automatically managed by the Cluster and only their TTL values can be updated.");

                                    if (recordInfo.GlueRecords is not null)
                                        throw new DnsWebServiceException("Cannot import NS records with glue addresses for Primary zones that are members of the Cluster Catalog zone. These NS records are automatically managed by the Cluster and only their TTL values can be updated.");

                                    string nsDomain = (newRecord.RDATA as DnsNSRecordData).NameServer;
                                    bool found = false;

                                    foreach (KeyValuePair<int, ClusterNode> clusterNode in _dnsWebService._clusterManager.ClusterNodes)
                                    {
                                        if (nsDomain.Equals(clusterNode.Value.Name, StringComparison.OrdinalIgnoreCase))
                                        {
                                            found = true;
                                            break;
                                        }
                                    }

                                    if (!found)
                                        throw new DnsWebServiceException("Cannot import NS records for Primary zones that are members of the Cluster Catalog zone. These NS records are automatically managed by the Cluster and only their TTL values can be updated.");
                                }

                                nsCount++;
                                break;

                            case DnsResourceRecordType.SOA:
                                DnsSOARecordData soa = newRecord.RDATA as DnsSOARecordData;

                                if (!soa.PrimaryNameServer.Equals(_dnsWebService._dnsServer.ServerDomain, StringComparison.OrdinalIgnoreCase))
                                    throw new DnsWebServiceException("Cannot import SOA record for Primary zones that are members of the Cluster Catalog zone. The SOA primary name server field must match the Cluster Primary node's domain name.");

                                break;
                        }
                    }

                    if (overwrite)
                    {
                        if ((nsCount > 0) && (nsCount != _dnsWebService._clusterManager.ClusterNodes.Count)) //check attempt to replace NS records
                            throw new DnsWebServiceException("Cannot import NS records for Primary zones that are members of the Cluster Catalog zone. These NS records are automatically managed by the Cluster and only their TTL values can be updated.");
                    }
                    else
                    {
                        if (nsCount > 0) //check attempt to add NS records
                            throw new DnsWebServiceException("Cannot import NS records for Primary zones that are members of the Cluster Catalog zone. These NS records are automatically managed by the Cluster and only their TTL values can be updated.");
                    }
                }

                return newRecords;
            }

            #endregion

            #region public

            public void ListZones(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;
                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                IReadOnlyList<AuthZoneInfo> zoneInfoList = _dnsWebService._dnsServer.AuthZoneManager.GetZones(delegate (AuthZoneInfo zoneInfo)
                {
                    return _dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.View);
                });

                if (request.TryGetQueryOrForm("pageNumber", int.Parse, out int pageNumber))
                {
                    int zonesPerPage = request.GetQueryOrForm("zonesPerPage", int.Parse, 10);
                    int totalPages;
                    int totalZones = zoneInfoList.Count;

                    if (totalZones > 0)
                    {
                        if (pageNumber == 0)
                            pageNumber = 1;

                        totalPages = (totalZones / zonesPerPage) + (totalZones % zonesPerPage > 0 ? 1 : 0);

                        if ((pageNumber > totalPages) || (pageNumber < 0))
                            pageNumber = totalPages;

                        int start = (pageNumber - 1) * zonesPerPage;
                        int end = Math.Min(start + zonesPerPage, totalZones);

                        List<AuthZoneInfo> zoneInfoPageList = new List<AuthZoneInfo>(end - start);

                        for (int i = start; i < end; i++)
                            zoneInfoPageList.Add(zoneInfoList[i]);

                        zoneInfoList = zoneInfoPageList;
                    }
                    else
                    {
                        pageNumber = 0;
                        totalPages = 0;
                    }

                    jsonWriter.WriteNumber("pageNumber", pageNumber);
                    jsonWriter.WriteNumber("totalPages", totalPages);
                    jsonWriter.WriteNumber("totalZones", totalZones);
                }

                jsonWriter.WritePropertyName("zones");
                jsonWriter.WriteStartArray();

                foreach (AuthZoneInfo zoneInfo in zoneInfoList)
                    WriteZoneInfoAsJson(zoneInfo, jsonWriter);

                jsonWriter.WriteEndArray();
            }

            public void ListCatalogZones(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                IReadOnlyList<AuthZoneInfo> catalogZoneInfoList = _dnsWebService._dnsServer.AuthZoneManager.GetCatalogZones(delegate (AuthZoneInfo catalogZoneInfo)
                {
                    return !catalogZoneInfo.Disabled && _dnsWebService._authManager.IsPermitted(PermissionSection.Zones, catalogZoneInfo.Name, sessionUser, PermissionFlag.Modify);
                });

                jsonWriter.WritePropertyName("catalogZoneNames");
                jsonWriter.WriteStartArray();

                foreach (AuthZoneInfo catalogZoneInfo in catalogZoneInfoList)
                    jsonWriter.WriteStringValue(catalogZoneInfo.Name);

                jsonWriter.WriteEndArray();
            }

            public async Task CreateZoneAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrFormAlt("zone", "domain");

                if (IPAddress.TryParse(zoneName, out IPAddress ipAddress))
                {
                    zoneName = ipAddress.GetReverseDomain().ToLowerInvariant();
                }
                else
                {
                    if (zoneName.Contains('/'))
                    {
                        string[] parts = zoneName.Split('/');
                        if ((parts.Length == 2) && IPAddress.TryParse(parts[0], out ipAddress) && int.TryParse(parts[1], out int subnetMaskWidth))
                            zoneName = Zone.GetReverseZone(ipAddress, subnetMaskWidth);
                    }
                    else
                    {
                        zoneName = zoneName.Trim('.');
                    }

                    if (zoneName.Contains('*'))
                        throw new DnsWebServiceException("Domain name for a zone cannot contain wildcard character.");

                    foreach (char invalidChar in Path.GetInvalidFileNameChars())
                    {
                        if (zoneName.Contains(invalidChar))
                            throw new DnsWebServiceException("The zone name contains an invalid character: " + invalidChar);
                    }

                    if (DnsClient.IsDomainNameUnicode(zoneName))
                        zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);
                }

                AuthZoneType type = request.GetQueryOrFormEnum("type", AuthZoneType.Primary);
                string catalogZoneName = request.GetQueryOrForm("catalog", null);

                //read records to import, if any
                List<DnsResourceRecord> importRecords = null;

                switch (type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Forwarder:
                        if (request.HasFormContentType && (request.Form.Files.Count > 0))
                        {
                            using (TextReader zoneFile = new StreamReader(request.Form.Files[0].OpenReadStream()))
                            {
                                importRecords = await ReadRecordsToImportFromAsync(zoneName, type, catalogZoneName, false, zoneFile);
                            }
                        }

                        break;
                }

                //create zone
                AuthZoneInfo zoneInfo;

                switch (type)
                {
                    case AuthZoneType.Primary:
                        {
                            bool useSoaSerialDateScheme = request.GetQueryOrForm("useSoaSerialDateScheme", bool.Parse, _dnsWebService._dnsServer.AuthZoneManager.UseSoaSerialDateScheme);

                            AuthZoneInfo catalogZoneInfo = null;

                            if (catalogZoneName is not null)
                            {
                                catalogZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(catalogZoneName);
                                if (catalogZoneInfo is null)
                                    throw new DnsWebServiceException("No such Catalog zone was found: " + catalogZoneName);

                                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, catalogZoneInfo.Name, sessionUser, PermissionFlag.Modify))
                                    throw new DnsWebServiceException("Access was denied to use Catalog zone: " + catalogZoneInfo.Name);
                            }

                            zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreatePrimaryZone(zoneName, useSoaSerialDateScheme);
                            if (zoneInfo is null)
                                throw new DnsWebServiceException("Zone already exists: " + zoneName);

                            //set permissions
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SaveConfigFile();

                            //add membership for catalog zone
                            if (catalogZoneInfo is not null)
                            {
                                _dnsWebService._dnsServer.AuthZoneManager.AddCatalogMemberZone(catalogZoneInfo.Name, zoneInfo);

                                if (_dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterCatalogZone(catalogZoneInfo.Name))
                                    _dnsWebService._clusterManager.UpdateClusterRecordsFor(zoneInfo);
                            }

                            _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Authoritative Primary zone was created: " + zoneInfo.DisplayName);
                        }
                        break;

                    case AuthZoneType.Secondary:
                        {
                            string primaryNameServerAddresses = request.GetQueryOrForm("primaryNameServerAddresses", null);
                            DnsTransportProtocol primaryZoneTransferProtocol = request.GetQueryOrFormEnum("zoneTransferProtocol", DnsTransportProtocol.Tcp);
                            string primaryZoneTransferTsigKeyName = request.GetQueryOrForm("tsigKeyName", null);
                            bool validateZone = request.GetQueryOrForm("validateZone", bool.Parse, false);

                            if (primaryZoneTransferProtocol == DnsTransportProtocol.Quic)
                                DnsWebService.ValidateQuicSupport();

                            zoneInfo = await _dnsWebService._dnsServer.AuthZoneManager.CreateSecondaryZoneAsync(zoneName, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName, validateZone);
                            if (zoneInfo is null)
                                throw new DnsWebServiceException("Zone already exists: " + zoneName);

                            //set permissions
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SaveConfigFile();

                            _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Authoritative Secondary zone was created: " + zoneInfo.DisplayName);
                        }
                        break;

                    case AuthZoneType.Stub:
                        {
                            string primaryNameServerAddresses = request.GetQueryOrForm("primaryNameServerAddresses", null);

                            AuthZoneInfo catalogZoneInfo = null;

                            if (catalogZoneName is not null)
                            {
                                catalogZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(catalogZoneName);
                                if (catalogZoneInfo is null)
                                    throw new DnsWebServiceException("No such Catalog zone was found: " + catalogZoneName);

                                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, catalogZoneInfo.Name, sessionUser, PermissionFlag.Modify))
                                    throw new DnsWebServiceException("Access was denied to use Catalog zone: " + catalogZoneInfo.Name);
                            }

                            zoneInfo = await _dnsWebService._dnsServer.AuthZoneManager.CreateStubZoneAsync(zoneName, primaryNameServerAddresses);
                            if (zoneInfo is null)
                                throw new DnsWebServiceException("Zone already exists: " + zoneName);

                            //set permissions
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SaveConfigFile();

                            //add membership for catalog zone
                            if (catalogZoneInfo is not null)
                                _dnsWebService._dnsServer.AuthZoneManager.AddCatalogMemberZone(catalogZoneInfo.Name, zoneInfo);

                            _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Stub zone was created: " + zoneInfo.DisplayName);
                        }
                        break;

                    case AuthZoneType.Forwarder:
                        {
                            bool initializeForwarder = request.GetQueryOrForm("initializeForwarder", bool.Parse, true);

                            AuthZoneInfo catalogZoneInfo = null;

                            if (catalogZoneName is not null)
                            {
                                catalogZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(catalogZoneName);
                                if (catalogZoneInfo is null)
                                    throw new DnsWebServiceException("No such Catalog zone was found: " + catalogZoneName);

                                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, catalogZoneInfo.Name, sessionUser, PermissionFlag.Modify))
                                    throw new DnsWebServiceException("Access was denied to use Catalog zone: " + catalogZoneInfo.Name);
                            }

                            if (initializeForwarder)
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

                                if (forwarderProtocol == DnsTransportProtocol.Quic)
                                    DnsWebService.ValidateQuicSupport();

                                zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreateForwarderZone(zoneName, forwarderProtocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, null);
                                if (zoneInfo is null)
                                    throw new DnsWebServiceException("Zone already exists: " + zoneName);
                            }
                            else
                            {
                                zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreateForwarderZone(zoneName);
                                if (zoneInfo is null)
                                    throw new DnsWebServiceException("Zone already exists: " + zoneName);
                            }

                            //set permissions
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SaveConfigFile();

                            //add membership for catalog zone
                            if (catalogZoneInfo is not null)
                                _dnsWebService._dnsServer.AuthZoneManager.AddCatalogMemberZone(catalogZoneInfo.Name, zoneInfo);

                            _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Forwarder zone was created: " + zoneInfo.DisplayName);
                        }
                        break;

                    case AuthZoneType.SecondaryForwarder:
                        {
                            string primaryNameServerAddresses = request.GetQueryOrForm("primaryNameServerAddresses");
                            DnsTransportProtocol primaryZoneTransferProtocol = request.GetQueryOrFormEnum("zoneTransferProtocol", DnsTransportProtocol.Tcp);
                            string primaryZoneTransferTsigKeyName = request.GetQueryOrForm("tsigKeyName", null);

                            if (primaryZoneTransferProtocol == DnsTransportProtocol.Quic)
                                DnsWebService.ValidateQuicSupport();

                            zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreateSecondaryForwarderZone(zoneName, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName);
                            if (zoneInfo is null)
                                throw new DnsWebServiceException("Zone already exists: " + zoneName);

                            //set permissions
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SaveConfigFile();

                            _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Secondary Forwarder zone was created: " + zoneInfo.DisplayName);
                        }
                        break;

                    case AuthZoneType.Catalog:
                        {
                            zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreateCatalogZone(zoneName);
                            if (zoneInfo is null)
                                throw new DnsWebServiceException("Zone already exists: " + zoneName);

                            //set permissions
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SaveConfigFile();

                            _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Catalog zone was created: " + zoneInfo.DisplayName);
                        }
                        break;

                    case AuthZoneType.SecondaryCatalog:
                        {
                            string primaryNameServerAddresses = request.GetQueryOrForm("primaryNameServerAddresses");
                            DnsTransportProtocol primaryZoneTransferProtocol = request.GetQueryOrFormEnum("zoneTransferProtocol", DnsTransportProtocol.Tcp);
                            string primaryZoneTransferTsigKeyName = request.GetQueryOrForm("tsigKeyName", null);

                            if (primaryZoneTransferProtocol == DnsTransportProtocol.Quic)
                                DnsWebService.ValidateQuicSupport();

                            zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreateSecondaryCatalogZone(zoneName, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName);
                            if (zoneInfo is null)
                                throw new DnsWebServiceException("Zone already exists: " + zoneName);

                            //set permissions
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                            _dnsWebService._authManager.SaveConfigFile();

                            _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Secondary Catalog zone was created: " + zoneInfo.DisplayName);
                        }
                        break;

                    default:
                        throw new NotSupportedException("Zone type not supported.");
                }

                //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
                _dnsWebService._dnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);

                //import records, if any
                if (importRecords is not null)
                {
                    //delete existing NS/FWD record 
                    switch (type)
                    {
                        case AuthZoneType.Primary:
                            _dnsWebService._dnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, zoneInfo.Name, DnsResourceRecordType.NS);
                            break;

                        case AuthZoneType.Forwarder:
                            _dnsWebService._dnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, zoneInfo.Name, DnsResourceRecordType.FWD);
                            break;
                    }

                    //import records
                    _dnsWebService._dnsServer.AuthZoneManager.ImportRecords(zoneInfo.Name, importRecords, false, false);
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteString("domain", string.IsNullOrEmpty(zoneInfo.Name) ? "." : zoneInfo.Name);
            }

            public async Task ImportZoneAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');
                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + zoneName);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                bool overwrite = request.GetQueryOrForm("overwrite", bool.Parse, true);
                bool overwriteSoaSerial = request.GetQueryOrForm("overwriteSoaSerial", bool.Parse, false);

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
                        if (!request.HasFormContentType || (request.Form.Files.Count == 0))
                            throw new DnsWebServiceException("The zone file to import is missing.");

                        textReader = new StreamReader(request.Form.Files[0].OpenReadStream());
                        break;
                }

                List<DnsResourceRecord> records;

                using (TextReader zoneFile = textReader)
                {
                    records = await ReadRecordsToImportFromAsync(zoneInfo.Name, zoneInfo.Type, zoneInfo.CatalogZoneName, overwrite, zoneFile);
                }

                _dnsWebService._dnsServer.AuthZoneManager.ImportRecords(zoneInfo.Name, records, overwrite, overwriteSoaSerial);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Total " + records.Count + " record(s) were imported successfully into " + zoneInfo.TypeName + " zone: " + zoneInfo.DisplayName);
            }

            public async Task ExportZoneAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');
                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + zoneName);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                List<DnsResourceRecord> records = new List<DnsResourceRecord>();

                _dnsWebService._dnsServer.AuthZoneManager.ListAllZoneRecords(zoneInfo.Name, records);

                foreach (DnsResourceRecord record in records)
                {
                    switch (record.Type)
                    {
                        case DnsResourceRecordType.SVCB:
                        case DnsResourceRecordType.HTTPS:
                            SVCBRecordInfo info = record.GetAuthSVCBRecordInfo();

                            if (info.AutoIpv4Hint)
                                (record.RDATA as DnsSVCBRecordData).AutoIpv4Hint = true;

                            if (info.AutoIpv6Hint)
                                (record.RDATA as DnsSVCBRecordData).AutoIpv6Hint = true;

                            break;
                    }
                }

                HttpResponse response = context.Response;

                response.ContentType = "text/plain";
                response.Headers.ContentDisposition = "attachment;filename=" + (zoneInfo.Name.Length == 0 ? "root.zone" : zoneInfo.Name + ".zone");

                await using (StreamWriter sW = new StreamWriter(response.Body))
                {
                    await ZoneFile.WriteZoneFileToAsync(sW, zoneInfo.Name, records, delegate (DnsResourceRecord record)
                    {
                        if (record.Tag is null)
                            return null;

                        GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();

                        if (recordInfo.Disabled || ((recordInfo.Comments is not null) && recordInfo.Comments.TrimStart().StartsWith('{')))
                        {
                            using (MemoryStream mS = new MemoryStream())
                            {
                                Utf8JsonWriter jsonWriter = new Utf8JsonWriter(mS);

                                jsonWriter.WriteStartObject();
                                jsonWriter.WriteBoolean("disabled", recordInfo.Disabled);
                                jsonWriter.WriteString("comments", recordInfo.Comments);
                                jsonWriter.WriteEndObject();

                                jsonWriter.Flush();

                                return Encoding.UTF8.GetString(mS.ToArray());
                            }
                        }

                        return recordInfo.Comments?.Replace("\r", "").Replace("\n", "\\n");
                    });
                }
            }

            public void CloneZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');
                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                string sourceZoneName = request.GetQueryOrForm("sourceZone").Trim('.');
                if (DnsClient.IsDomainNameUnicode(sourceZoneName))
                    sourceZoneName = DnsClient.ConvertDomainNameToAscii(sourceZoneName);

                AuthZoneInfo sourceZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(sourceZoneName);
                if (sourceZoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + sourceZoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sourceZoneInfo.Name, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CloneZone(zoneName, sourceZoneInfo.Name);

                //clone user/group permissions from source zone
                Permission sourceZonePermissions = _dnsWebService._authManager.GetPermission(PermissionSection.Zones, sourceZoneInfo.Name);

                foreach (KeyValuePair<User, PermissionFlag> userPermission in sourceZonePermissions.UserPermissions)
                    _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, userPermission.Key, userPermission.Value);

                foreach (KeyValuePair<Group, PermissionFlag> groupPermissions in sourceZonePermissions.GroupPermissions)
                    _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, groupPermissions.Key, groupPermissions.Value);

                //set default permissions
                _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.ViewModifyDelete);
                _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                _dnsWebService._authManager.SaveConfigFile();

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] " + sourceZoneInfo.TypeName + " zone '" + sourceZoneInfo.DisplayName + "' was cloned as '" + zoneInfo.DisplayName + "' sucessfully.");
            }

            public void ConvertZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');
                AuthZoneType type = request.GetQueryOrFormEnum<AuthZoneType>("type");

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + zoneName);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                if ((zoneInfo.Type == AuthZoneType.Primary) && _dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterPrimaryZone(zoneInfo.Name))
                    throw new DnsWebServiceException("Cannot convert the Cluster Primary zone '" + zoneInfo.DisplayName + "'.");

                _dnsWebService._dnsServer.AuthZoneManager.ConvertZoneTypeTo(zoneInfo.Name, type);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] " + zoneInfo.TypeName + " zone '" + zoneInfo.DisplayName + "' was converted to " + AuthZoneInfo.GetZoneTypeName(type) + " zone sucessfully.");
            }

            public void SignPrimaryZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                string algorithm = request.GetQueryOrForm("algorithm");
                string pemKskPrivateKey = request.GetQueryOrForm("pemKskPrivateKey", null);
                string pemZskPrivateKey = request.GetQueryOrForm("pemZskPrivateKey", null);
                uint dnsKeyTtl = request.GetQueryOrForm("dnsKeyTtl", ZoneFile.ParseTtl, 3600u);
                ushort zskRolloverDays = request.GetQueryOrForm("zskRolloverDays", ushort.Parse, Convert.ToUInt16(pemZskPrivateKey is null ? 30 : 0));

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

                DnssecPrivateKey kskPrivateKey;
                DnssecPrivateKey zskPrivateKey;

                switch (algorithm.ToUpper())
                {
                    case "RSA":
                        {
                            string hashAlgorithm = request.GetQueryOrForm("hashAlgorithm");

                            DnssecAlgorithm dnssecAlgorithm;

                            switch (hashAlgorithm.ToUpper())
                            {
                                case "MD5":
                                    dnssecAlgorithm = DnssecAlgorithm.RSAMD5;
                                    break;

                                case "SHA1":
                                    dnssecAlgorithm = DnssecAlgorithm.RSASHA1;
                                    break;

                                case "SHA256":
                                    dnssecAlgorithm = DnssecAlgorithm.RSASHA256;
                                    break;

                                case "SHA512":
                                    dnssecAlgorithm = DnssecAlgorithm.RSASHA512;
                                    break;

                                default:
                                    throw new NotSupportedException("Hash algorithm is not supported: " + hashAlgorithm);
                            }

                            if (pemKskPrivateKey is null)
                                kskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.KeySigningKey, request.GetQueryOrForm("kskKeySize", int.Parse));
                            else
                                kskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.KeySigningKey, pemKskPrivateKey);

                            if (pemZskPrivateKey is null)
                                zskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.ZoneSigningKey, request.GetQueryOrForm("zskKeySize", int.Parse));
                            else
                                zskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.ZoneSigningKey, pemZskPrivateKey);
                        }
                        break;

                    case "ECDSA":
                        {
                            string curve = request.GetQueryOrForm("curve");

                            DnssecAlgorithm dnssecAlgorithm;

                            switch (curve.ToUpper())
                            {
                                case "P256":
                                    dnssecAlgorithm = DnssecAlgorithm.ECDSAP256SHA256;
                                    break;

                                case "P384":
                                    dnssecAlgorithm = DnssecAlgorithm.ECDSAP384SHA384;
                                    break;

                                default:
                                    throw new NotSupportedException("ECDSA curve is not supported: " + curve);
                            }

                            if (pemKskPrivateKey is null)
                                kskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.KeySigningKey);
                            else
                                kskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.KeySigningKey, pemKskPrivateKey);

                            if (pemZskPrivateKey is null)
                                zskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.ZoneSigningKey);
                            else
                                zskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.ZoneSigningKey, pemZskPrivateKey);
                        }
                        break;

                    case "EDDSA":
                        {
                            string curve = request.GetQueryOrForm("curve");

                            DnssecAlgorithm dnssecAlgorithm;

                            switch (curve.ToUpper())
                            {
                                case "ED25519":
                                    dnssecAlgorithm = DnssecAlgorithm.ED25519;
                                    break;

                                case "ED448":
                                    dnssecAlgorithm = DnssecAlgorithm.ED448;
                                    break;

                                default:
                                    throw new NotSupportedException("EdDSA curve is not supported: " + curve);
                            }

                            if (pemKskPrivateKey is null)
                                kskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.KeySigningKey);
                            else
                                kskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.KeySigningKey, pemKskPrivateKey);

                            if (pemZskPrivateKey is null)
                                zskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.ZoneSigningKey);
                            else
                                zskPrivateKey = DnssecPrivateKey.Create(dnssecAlgorithm, DnssecPrivateKeyType.ZoneSigningKey, pemZskPrivateKey);
                        }
                        break;

                    default:
                        throw new NotSupportedException("Algorithm is not supported: " + algorithm);
                }

                zskPrivateKey.RolloverDays = zskRolloverDays;

                _dnsWebService._dnsServer.AuthZoneManager.SignPrimaryZone(zoneName, kskPrivateKey, zskPrivateKey, dnsKeyTtl, useNSEC3, iterations, saltLength);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Primary zone was signed successfully: " + zoneName);
            }

            public void UnsignPrimaryZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string zoneName = context.Request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._dnsServer.AuthZoneManager.UnsignPrimaryZone(zoneName);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Primary zone was unsigned successfully: " + zoneName);
            }

            public void GetPrimaryZoneDsInfo(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                string zoneName = context.Request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + zoneName);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                if (zoneInfo.Type != AuthZoneType.Primary)
                    throw new DnsWebServiceException("The zone must be a primary zone.");

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                if (zoneInfo.ApexZone.DnssecStatus == AuthZoneDnssecStatus.Unsigned)
                    throw new DnsWebServiceException("The zone must be signed with DNSSEC.");

                IReadOnlyList<DnsResourceRecord> dnsKeyRecords = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.DNSKEY);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WriteString("name", zoneInfo.Name);
                jsonWriter.WriteString("type", zoneInfo.Type.ToString());
                jsonWriter.WriteBoolean("internal", zoneInfo.Internal);
                jsonWriter.WriteBoolean("disabled", zoneInfo.Disabled);
                jsonWriter.WriteString("dnssecStatus", zoneInfo.ApexZone.DnssecStatus.ToString());

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
                                        jsonWriter.WriteString("dnsKeyStateReadyBy", dnssecPrivateKey.StateTransitionByWithDelays);

                                    jsonWriter.WriteBoolean("isRetiring", dnssecPrivateKey.IsRetiring);
                                    break;
                                }
                            }
                        }

                        jsonWriter.WriteString("algorithm", rdata.Algorithm.ToString());
                        jsonWriter.WriteNumber("algorithmNumber", (byte)rdata.Algorithm);
                        jsonWriter.WriteString("publicKey", rdata.PublicKey.ToString());

                        jsonWriter.WritePropertyName("digests");
                        jsonWriter.WriteStartArray();

                        {
                            jsonWriter.WriteStartObject();

                            jsonWriter.WriteString("digestType", "SHA256");
                            jsonWriter.WriteString("digestTypeNumber", "2");
                            jsonWriter.WriteString("digest", Convert.ToHexString(rdata.CreateDS(record.Name, DnssecDigestType.SHA256).Digest));

                            jsonWriter.WriteEndObject();
                        }

                        {
                            jsonWriter.WriteStartObject();

                            jsonWriter.WriteString("digestType", "SHA384");
                            jsonWriter.WriteString("digestTypeNumber", "4");
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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string zoneName = context.Request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + zoneName);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                if (zoneInfo.Type != AuthZoneType.Primary)
                    throw new DnsWebServiceException("The zone must be a primary zone.");

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WriteString("name", zoneInfo.Name);
                jsonWriter.WriteString("type", zoneInfo.Type.ToString());
                jsonWriter.WriteBoolean("internal", zoneInfo.Internal);
                jsonWriter.WriteBoolean("disabled", zoneInfo.Disabled);
                jsonWriter.WriteString("dnssecStatus", zoneInfo.ApexZone.DnssecStatus.ToString());

                if (zoneInfo.ApexZone.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3)
                {
                    IReadOnlyList<DnsResourceRecord> nsec3ParamRecords = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.NSEC3PARAM);
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
                        WriteDnssecPrivateKeyAsJson(dnssecPrivateKey, jsonWriter);
                }

                jsonWriter.WriteEndArray();
            }

            public void ConvertPrimaryZoneToNSEC(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string zoneName = context.Request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._dnsServer.AuthZoneManager.ConvertPrimaryZoneToNSEC(zoneName);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Primary zone was converted to NSEC successfully: " + zoneName);
            }

            public void ConvertPrimaryZoneToNSEC3(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                ushort iterations = request.GetQueryOrForm<ushort>("iterations", ushort.Parse, 0);
                byte saltLength = request.GetQueryOrForm<byte>("saltLength", byte.Parse, 0);

                _dnsWebService._dnsServer.AuthZoneManager.ConvertPrimaryZoneToNSEC3(zoneName, iterations, saltLength);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Primary zone was converted to NSEC3 successfully: " + zoneName);
            }

            public void UpdatePrimaryZoneNSEC3Parameters(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                ushort iterations = request.GetQueryOrForm<ushort>("iterations", ushort.Parse, 0);
                byte saltLength = request.GetQueryOrForm<byte>("saltLength", byte.Parse, 0);

                _dnsWebService._dnsServer.AuthZoneManager.UpdatePrimaryZoneNSEC3Parameters(zoneName, iterations, saltLength);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Primary zone NSEC3 parameters were updated successfully: " + zoneName);
            }

            public void UpdatePrimaryZoneDnssecDnsKeyTtl(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                uint dnsKeyTtl = request.GetQueryOrForm("ttl", ZoneFile.ParseTtl);

                _dnsWebService._dnsServer.AuthZoneManager.UpdatePrimaryZoneDnsKeyTtl(zoneName, dnsKeyTtl);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Primary zone DNSKEY TTL was updated successfully: " + zoneName);
            }

            public void AddPrimaryZoneDnssecPrivateKey(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                DnssecPrivateKeyType keyType = request.GetQueryOrFormEnum<DnssecPrivateKeyType>("keyType");
                ushort rolloverDays = request.GetQueryOrForm("rolloverDays", ushort.Parse, (ushort)(keyType == DnssecPrivateKeyType.ZoneSigningKey ? 30 : 0));
                string algorithm = request.GetQueryOrForm("algorithm");
                string pemPrivateKey = request.GetQueryOrForm("pemPrivateKey", null);

                DnssecPrivateKey privateKey;

                switch (algorithm.ToUpper())
                {
                    case "RSA":
                        {
                            string hashAlgorithm = request.GetQueryOrForm("hashAlgorithm");

                            DnssecAlgorithm dnssecAlgorithm;

                            switch (hashAlgorithm.ToUpper())
                            {
                                case "MD5":
                                    dnssecAlgorithm = DnssecAlgorithm.RSAMD5;
                                    break;

                                case "SHA1":
                                    dnssecAlgorithm = DnssecAlgorithm.RSASHA1;
                                    break;

                                case "SHA256":
                                    dnssecAlgorithm = DnssecAlgorithm.RSASHA256;
                                    break;

                                case "SHA512":
                                    dnssecAlgorithm = DnssecAlgorithm.RSASHA512;
                                    break;

                                default:
                                    throw new NotSupportedException("Hash algorithm is not supported: " + hashAlgorithm);
                            }

                            if (pemPrivateKey is null)
                            {
                                int keySize = request.GetQueryOrForm("keySize", int.Parse);

                                privateKey = _dnsWebService._dnsServer.AuthZoneManager.GenerateAndAddPrimaryZoneDnssecPrivateKey(zoneName, keyType, dnssecAlgorithm, rolloverDays, keySize);
                            }
                            else
                            {
                                privateKey = DnssecPrivateKey.Create(dnssecAlgorithm, keyType, pemPrivateKey);
                                privateKey.RolloverDays = rolloverDays;

                                _dnsWebService._dnsServer.AuthZoneManager.AddPrimaryZoneDnssecPrivateKey(zoneName, privateKey);
                            }
                        }
                        break;

                    case "ECDSA":
                        {
                            string curve = request.GetQueryOrForm("curve");

                            DnssecAlgorithm dnssecAlgorithm;

                            switch (curve.ToUpper())
                            {
                                case "P256":
                                    dnssecAlgorithm = DnssecAlgorithm.ECDSAP256SHA256;
                                    break;

                                case "P384":
                                    dnssecAlgorithm = DnssecAlgorithm.ECDSAP384SHA384;
                                    break;

                                default:
                                    throw new NotSupportedException("ECDSA curve is not supported: " + curve);
                            }

                            if (pemPrivateKey is null)
                            {
                                privateKey = _dnsWebService._dnsServer.AuthZoneManager.GenerateAndAddPrimaryZoneDnssecPrivateKey(zoneName, keyType, dnssecAlgorithm, rolloverDays);
                            }
                            else
                            {
                                privateKey = DnssecPrivateKey.Create(dnssecAlgorithm, keyType, pemPrivateKey);
                                privateKey.RolloverDays = rolloverDays;

                                _dnsWebService._dnsServer.AuthZoneManager.AddPrimaryZoneDnssecPrivateKey(zoneName, privateKey);
                            }
                        }
                        break;

                    case "EDDSA":
                        {
                            string curve = request.GetQueryOrForm("curve");

                            DnssecAlgorithm dnssecAlgorithm;

                            switch (curve.ToUpper())
                            {
                                case "ED25519":
                                    dnssecAlgorithm = DnssecAlgorithm.ED25519;
                                    break;

                                case "ED448":
                                    dnssecAlgorithm = DnssecAlgorithm.ED448;
                                    break;

                                default:
                                    throw new NotSupportedException("EdDSA curve is not supported: " + curve);
                            }

                            if (pemPrivateKey is null)
                            {
                                privateKey = _dnsWebService._dnsServer.AuthZoneManager.GenerateAndAddPrimaryZoneDnssecPrivateKey(zoneName, keyType, dnssecAlgorithm, rolloverDays);
                            }
                            else
                            {
                                privateKey = DnssecPrivateKey.Create(dnssecAlgorithm, keyType, pemPrivateKey);
                                privateKey.RolloverDays = rolloverDays;

                                _dnsWebService._dnsServer.AuthZoneManager.AddPrimaryZoneDnssecPrivateKey(zoneName, privateKey);
                            }
                        }
                        break;

                    default:
                        throw new NotSupportedException("Algorithm is not supported: " + algorithm);
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("addedDnssecPrivateKey");
                WriteDnssecPrivateKeyAsJson(privateKey, jsonWriter);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DNSSEC private key was generated and added to the primary zone successfully: " + zoneName);
            }

            public void UpdatePrimaryZoneDnssecPrivateKey(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);
                ushort rolloverDays = request.GetQueryOrForm("rolloverDays", ushort.Parse);

                DnssecPrivateKey privateKey = _dnsWebService._dnsServer.AuthZoneManager.UpdatePrimaryZoneDnssecPrivateKey(zoneName, keyTag, rolloverDays);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("updatedDnssecPrivateKey");
                WriteDnssecPrivateKeyAsJson(privateKey, jsonWriter);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Primary zone DNSSEC private key config was updated successfully: " + zoneName);
            }

            public void DeletePrimaryZoneDnssecPrivateKey(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);

                _dnsWebService._dnsServer.AuthZoneManager.DeletePrimaryZoneDnssecPrivateKey(zoneName, keyTag);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DNSSEC private key was deleted from primary zone successfully: " + zoneName);
            }

            public void PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string zoneName = context.Request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._dnsServer.AuthZoneManager.PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(zoneName);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] All DNSSEC private keys from the primary zone were published successfully: " + zoneName);
            }

            public void RolloverPrimaryZoneDnsKey(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);

                _dnsWebService._dnsServer.AuthZoneManager.RolloverPrimaryZoneDnsKey(zoneName, keyTag);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] The DNSKEY (" + keyTag + ") from the primary zone was rolled over successfully: " + zoneName);
            }

            public async Task RetirePrimaryZoneDnsKeyAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrForm("zone").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneName, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);

                await _dnsWebService._dnsServer.AuthZoneManager.RetirePrimaryZoneDnsKeyAsync(zoneName, keyTag);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] The DNSKEY (" + keyTag + ") from the primary zone was retired successfully: " + zoneName);
            }

            public void DeleteZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                string zoneName = context.Request.GetQueryOrFormAlt("zone", "domain").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + zoneName);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                        if (_dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterPrimaryZone(zoneInfo.Name))
                            throw new DnsWebServiceException("Cannot delete the Cluster Primary zone '" + zoneInfo.DisplayName + "'.");

                        break;

                    case AuthZoneType.Catalog:
                        if (_dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterCatalogZone(zoneInfo.Name))
                            throw new DnsWebServiceException("Cannot delete the Cluster Catalog zone '" + zoneInfo.DisplayName + "'.");

                        break;
                }

                if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteZone(zoneInfo, true))
                    throw new DnsWebServiceException("Failed to delete the zone '" + zoneInfo.DisplayName + "': no such zone exists.");

                _dnsWebService._authManager.RemoveAllPermissions(PermissionSection.Zones, zoneInfo.Name);
                _dnsWebService._authManager.SaveConfigFile();

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] " + zoneInfo.TypeName + " zone was deleted: " + zoneInfo.DisplayName);

                //delete cache for this zone to allow rebuilding cache data without using the current zone
                _dnsWebService._dnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);
            }

            public void EnableZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string zoneName = context.Request.GetQueryOrFormAlt("zone", "domain").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + zoneName);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                zoneInfo.Disabled = false;
                _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] " + zoneInfo.TypeName + " zone was enabled: " + zoneInfo.DisplayName);

                //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zone
                _dnsWebService._dnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);
            }

            public void DisableZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string zoneName = context.Request.GetQueryOrFormAlt("zone", "domain").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + zoneName);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                        if (_dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterPrimaryZone(zoneInfo.Name))
                            throw new DnsWebServiceException("Cannot disable the Cluster Primary zone '" + zoneInfo.DisplayName + "'.");

                        break;

                    case AuthZoneType.Catalog:
                        if (_dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterCatalogZone(zoneInfo.Name))
                            throw new DnsWebServiceException("Cannot disable the Cluster Catalog zone '" + zoneInfo.DisplayName + "'.");

                        break;
                }

                zoneInfo.Disabled = true;
                _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] " + zoneInfo.TypeName + " zone was disabled: " + zoneInfo.DisplayName);

                //delete cache for this zone to allow rebuilding cache data without using the current zone
                _dnsWebService._dnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);
            }

            public void GetZoneOptions(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrFormAlt("zone", "domain").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                bool includeAvailableCatalogZoneNames = request.GetQueryOrForm("includeAvailableCatalogZoneNames", bool.Parse, false);
                bool includeAvailableTsigKeyNames = request.GetQueryOrForm("includeAvailableTsigKeyNames", bool.Parse, false);

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + zoneName);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WriteString("name", zoneInfo.Name);

                if (DnsClient.TryConvertDomainNameToUnicode(zoneInfo.Name, out string nameIdn))
                    jsonWriter.WriteString("nameIdn", nameIdn);

                jsonWriter.WriteString("type", zoneInfo.Type.ToString());

                if (zoneInfo.Type == AuthZoneType.Primary)
                    jsonWriter.WriteBoolean("internal", zoneInfo.Internal);

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                        jsonWriter.WriteString("dnssecStatus", zoneInfo.ApexZone.DnssecStatus.ToString());
                        break;
                }

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Forwarder:
                    case AuthZoneType.Catalog:
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
                }

                jsonWriter.WriteBoolean("disabled", zoneInfo.Disabled);

                //catalog zone
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Forwarder:
                        jsonWriter.WriteString("catalog", zoneInfo.CatalogZoneName);

                        if (zoneInfo.CatalogZoneName is not null)
                        {
                            jsonWriter.WriteBoolean("overrideCatalogQueryAccess", zoneInfo.OverrideCatalogQueryAccess);
                            jsonWriter.WriteBoolean("overrideCatalogZoneTransfer", zoneInfo.OverrideCatalogZoneTransfer);
                            jsonWriter.WriteBoolean("overrideCatalogNotify", zoneInfo.OverrideCatalogNotify);
                        }

                        break;

                    case AuthZoneType.Stub:
                        jsonWriter.WriteString("catalog", zoneInfo.CatalogZoneName);

                        if (zoneInfo.CatalogZoneName is not null)
                        {
                            jsonWriter.WriteBoolean("isSecondaryCatalogMember", zoneInfo.ApexZone.SecondaryCatalogZone is not null);
                            jsonWriter.WriteBoolean("overrideCatalogQueryAccess", zoneInfo.OverrideCatalogQueryAccess);
                        }
                        break;

                    case AuthZoneType.Secondary:
                        jsonWriter.WriteString("catalog", zoneInfo.CatalogZoneName);

                        if (zoneInfo.CatalogZoneName is not null)
                        {
                            jsonWriter.WriteBoolean("overrideCatalogQueryAccess", zoneInfo.OverrideCatalogQueryAccess);
                            jsonWriter.WriteBoolean("overrideCatalogZoneTransfer", zoneInfo.OverrideCatalogZoneTransfer);
                            jsonWriter.WriteBoolean("overrideCatalogPrimaryNameServers", zoneInfo.OverrideCatalogPrimaryNameServers);
                        }
                        break;

                    case AuthZoneType.SecondaryForwarder:
                        jsonWriter.WriteString("catalog", zoneInfo.CatalogZoneName);

                        if (zoneInfo.CatalogZoneName is not null)
                            jsonWriter.WriteBoolean("overrideCatalogQueryAccess", zoneInfo.OverrideCatalogQueryAccess);

                        break;
                }

                //primary server
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                    case AuthZoneType.Stub:
                        jsonWriter.WriteStartArray("primaryNameServerAddresses");

                        IReadOnlyList<NameServerAddress> primaryNameServerAddresses = zoneInfo.PrimaryNameServerAddresses;
                        if (primaryNameServerAddresses is not null)
                        {
                            foreach (NameServerAddress primaryNameServerAddress in primaryNameServerAddresses)
                                jsonWriter.WriteStringValue(primaryNameServerAddress.OriginalAddress);
                        }

                        jsonWriter.WriteEndArray();
                        break;
                }

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        if (zoneInfo.PrimaryZoneTransferProtocol == DnsTransportProtocol.Udp)
                            jsonWriter.WriteString("primaryZoneTransferProtocol", "Tcp");
                        else
                            jsonWriter.WriteString("primaryZoneTransferProtocol", zoneInfo.PrimaryZoneTransferProtocol.ToString());

                        jsonWriter.WriteString("primaryZoneTransferTsigKeyName", zoneInfo.PrimaryZoneTransferTsigKeyName);
                        break;
                }

                if (zoneInfo.Type == AuthZoneType.Secondary)
                    jsonWriter.WriteBoolean("validateZone", zoneInfo.ValidateZone);

                //query access
                {
                    jsonWriter.WriteString("queryAccess", zoneInfo.QueryAccess.ToString());
                    jsonWriter.WriteStartArray("queryAccessNetworkACL");

                    if (zoneInfo.QueryAccessNetworkACL is not null)
                    {
                        foreach (NetworkAccessControl nac in zoneInfo.QueryAccessNetworkACL)
                            jsonWriter.WriteStringValue(nac.ToString());
                    }

                    jsonWriter.WriteEndArray();
                }

                //zone transfer
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Forwarder:
                    case AuthZoneType.Catalog:
                    case AuthZoneType.SecondaryCatalog:
                        jsonWriter.WriteString("zoneTransfer", zoneInfo.ZoneTransfer.ToString());

                        jsonWriter.WritePropertyName("zoneTransferNetworkACL");
                        {
                            jsonWriter.WriteStartArray();

                            if (zoneInfo.ZoneTransferNetworkACL is not null)
                            {
                                foreach (NetworkAccessControl nac in zoneInfo.ZoneTransferNetworkACL)
                                    jsonWriter.WriteStringValue(nac.ToString());
                            }

                            jsonWriter.WriteEndArray();
                        }

                        jsonWriter.WritePropertyName("zoneTransferTsigKeyNames");
                        {
                            jsonWriter.WriteStartArray();

                            if (zoneInfo.ZoneTransferTsigKeyNames is not null)
                            {
                                foreach (string tsigKeyName in zoneInfo.ZoneTransferTsigKeyNames)
                                    jsonWriter.WriteStringValue(tsigKeyName);
                            }

                            jsonWriter.WriteEndArray();
                        }

                        break;
                }

                //notify
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Forwarder:
                    case AuthZoneType.Catalog:
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

                        if (zoneInfo.Type == AuthZoneType.Catalog)
                        {
                            jsonWriter.WriteStartArray("notifySecondaryCatalogsNameServers");

                            if (zoneInfo.NotifySecondaryCatalogNameServers is not null)
                            {
                                foreach (IPAddress nameServer in zoneInfo.NotifySecondaryCatalogNameServers)
                                    jsonWriter.WriteStringValue(nameServer.ToString());
                            }

                            jsonWriter.WriteEndArray();
                        }
                        break;
                }

                //update
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.Forwarder:
                        jsonWriter.WriteString("update", zoneInfo.Update.ToString());

                        jsonWriter.WritePropertyName("updateNetworkACL");
                        {
                            jsonWriter.WriteStartArray();

                            if (zoneInfo.UpdateNetworkACL is not null)
                            {
                                foreach (NetworkAccessControl nac in zoneInfo.UpdateNetworkACL)
                                    jsonWriter.WriteStringValue(nac.ToString());
                            }

                            jsonWriter.WriteEndArray();
                        }
                        break;
                }

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Forwarder:
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

                if (includeAvailableCatalogZoneNames)
                {
                    IReadOnlyList<AuthZoneInfo> catalogZoneInfoList = _dnsWebService._dnsServer.AuthZoneManager.GetCatalogZones(delegate (AuthZoneInfo catalogZoneInfo)
                    {
                        return !catalogZoneInfo.Disabled && _dnsWebService._authManager.IsPermitted(PermissionSection.Zones, catalogZoneInfo.Name, sessionUser, PermissionFlag.Modify);
                    });

                    jsonWriter.WritePropertyName("availableCatalogZoneNames");
                    jsonWriter.WriteStartArray();

                    foreach (AuthZoneInfo catalogZoneInfo in catalogZoneInfoList)
                        jsonWriter.WriteStringValue(catalogZoneInfo.Name);

                    jsonWriter.WriteEndArray();
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
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string zoneName = request.GetQueryOrFormAlt("zone", "domain").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + zoneName);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                if (request.TryGetQueryOrForm("disabled", bool.Parse, out bool disabled))
                    zoneInfo.Disabled = disabled;

                //catalog zone override options
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Forwarder:
                        {
                            if (request.TryGetQueryOrForm("overrideCatalogQueryAccess", bool.Parse, out bool overrideCatalogQueryAccess))
                                zoneInfo.OverrideCatalogQueryAccess = overrideCatalogQueryAccess;

                            if (request.TryGetQueryOrForm("overrideCatalogZoneTransfer", bool.Parse, out bool overrideCatalogZoneTransfer))
                                zoneInfo.OverrideCatalogZoneTransfer = overrideCatalogZoneTransfer;

                            if (request.TryGetQueryOrForm("overrideCatalogNotify", bool.Parse, out bool overrideCatalogNotify))
                                zoneInfo.OverrideCatalogNotify = overrideCatalogNotify;
                        }
                        break;

                    case AuthZoneType.Stub:
                        {
                            if (zoneInfo.ApexZone.SecondaryCatalogZone is not null)
                                break; //cannot set option for Stub zone that is a member of Secondary Catalog Zone

                            if (request.TryGetQueryOrForm("overrideCatalogQueryAccess", bool.Parse, out bool overrideCatalogQueryAccess))
                                zoneInfo.OverrideCatalogQueryAccess = overrideCatalogQueryAccess;
                        }
                        break;
                }

                //primary server
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        {
                            if (zoneInfo.ApexZone.SecondaryCatalogZone is not null)
                                break; //cannot set option for zone that is a member of Secondary Catalog Zone

                            if (request.TryGetQueryOrFormEnum("primaryZoneTransferProtocol", out DnsTransportProtocol primaryZoneTransferProtocol))
                            {
                                if (primaryZoneTransferProtocol == DnsTransportProtocol.Quic)
                                    DnsWebService.ValidateQuicSupport();

                                zoneInfo.PrimaryZoneTransferProtocol = primaryZoneTransferProtocol;
                            }

                            string primaryNameServerAddresses = request.QueryOrForm("primaryNameServerAddresses");
                            if (primaryNameServerAddresses is not null)
                            {
                                if (primaryNameServerAddresses.Length == 0)
                                {
                                    zoneInfo.PrimaryNameServerAddresses = null;
                                }
                                else
                                {
                                    zoneInfo.PrimaryNameServerAddresses = primaryNameServerAddresses.Split(delegate (string address)
                                    {
                                        NameServerAddress nameServer = NameServerAddress.Parse(address);

                                        if (nameServer.Protocol != primaryZoneTransferProtocol)
                                            nameServer = nameServer.ChangeProtocol(primaryZoneTransferProtocol);

                                        return nameServer;
                                    }, ',');
                                }
                            }

                            string primaryZoneTransferTsigKeyName = request.QueryOrForm("primaryZoneTransferTsigKeyName");
                            if (primaryZoneTransferTsigKeyName is not null)
                            {
                                if (primaryZoneTransferTsigKeyName.Length == 0)
                                    zoneInfo.PrimaryZoneTransferTsigKeyName = null;
                                else
                                    zoneInfo.PrimaryZoneTransferTsigKeyName = primaryZoneTransferTsigKeyName;
                            }
                        }
                        break;

                    case AuthZoneType.Stub:
                        {
                            if (zoneInfo.ApexZone.SecondaryCatalogZone is not null)
                                break; //cannot set option for Stub zone that is a member of Secondary Catalog Zone

                            string primaryNameServerAddresses = request.QueryOrForm("primaryNameServerAddresses");
                            if (primaryNameServerAddresses is not null)
                            {
                                if (primaryNameServerAddresses.Length == 0)
                                {
                                    zoneInfo.PrimaryNameServerAddresses = null;
                                }
                                else
                                {
                                    zoneInfo.PrimaryNameServerAddresses = primaryNameServerAddresses.Split(delegate (string address)
                                    {
                                        NameServerAddress nameServer = NameServerAddress.Parse(address);

                                        if (nameServer.Protocol != DnsTransportProtocol.Udp)
                                            nameServer = nameServer.ChangeProtocol(DnsTransportProtocol.Udp);

                                        return nameServer;
                                    }, ',');
                                }
                            }
                        }
                        break;
                }

                if (zoneInfo.Type == AuthZoneType.Secondary)
                {
                    if (zoneInfo.ApexZone.SecondaryCatalogZone is not null)
                    {
                        //cannot set option for zone that is a member of Secondary Catalog Zone
                    }
                    else if (request.TryGetQueryOrForm("validateZone", bool.Parse, out bool validateZone))
                    {
                        zoneInfo.ValidateZone = validateZone;
                    }
                }

                //query access
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Stub:
                    case AuthZoneType.Forwarder:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.Catalog:
                        if (zoneInfo.ApexZone.SecondaryCatalogZone is not null)
                            break; //cannot set option for zone that is a member of Secondary Catalog Zone

                        string queryAccessNetworkACL = request.QueryOrForm("queryAccessNetworkACL");
                        if (queryAccessNetworkACL is not null)
                        {
                            if ((queryAccessNetworkACL.Length == 0) || queryAccessNetworkACL.Equals("false", StringComparison.OrdinalIgnoreCase))
                                zoneInfo.QueryAccessNetworkACL = null;
                            else
                                zoneInfo.QueryAccessNetworkACL = queryAccessNetworkACL.Split(NetworkAccessControl.Parse, ',');
                        }

                        if (request.TryGetQueryOrFormEnum("queryAccess", out AuthZoneQueryAccess queryAccess))
                            zoneInfo.QueryAccess = queryAccess;

                        break;
                }

                //zone transfer
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Forwarder:
                    case AuthZoneType.Catalog:
                        if (zoneInfo.ApexZone.SecondaryCatalogZone is not null)
                            break; //cannot set option for zone that is a member of Secondary Catalog Zone

                        string strZoneTransferNetworkACL = request.QueryOrForm("zoneTransferNetworkACL");
                        if (strZoneTransferNetworkACL is not null)
                        {
                            if ((strZoneTransferNetworkACL.Length == 0) || strZoneTransferNetworkACL.Equals("false", StringComparison.OrdinalIgnoreCase))
                                zoneInfo.ZoneTransferNetworkACL = null;
                            else
                                zoneInfo.ZoneTransferNetworkACL = strZoneTransferNetworkACL.Split(NetworkAccessControl.Parse, ',');
                        }

                        if (request.TryGetQueryOrFormEnum("zoneTransfer", out AuthZoneTransfer zoneTransfer))
                            zoneInfo.ZoneTransfer = zoneTransfer;

                        string strZoneTransferTsigKeyNames = request.QueryOrForm("zoneTransferTsigKeyNames");
                        if (strZoneTransferTsigKeyNames is not null)
                        {
                            if ((strZoneTransferTsigKeyNames.Length == 0) || strZoneTransferTsigKeyNames.Equals("false", StringComparison.OrdinalIgnoreCase))
                            {
                                zoneInfo.ZoneTransferTsigKeyNames = null;
                            }
                            else
                            {
                                string[] strZoneTransferTsigKeyNamesParts = strZoneTransferTsigKeyNames.Split(_commaSeparator, StringSplitOptions.RemoveEmptyEntries);
                                HashSet<string> zoneTransferTsigKeyNames = new HashSet<string>(strZoneTransferTsigKeyNamesParts.Length);

                                for (int i = 0; i < strZoneTransferTsigKeyNamesParts.Length; i++)
                                    zoneTransferTsigKeyNames.Add(strZoneTransferTsigKeyNamesParts[i].Trim('.').ToLowerInvariant());

                                zoneInfo.ZoneTransferTsigKeyNames = zoneTransferTsigKeyNames;
                            }
                        }

                        break;
                }

                //notify
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Forwarder:
                    case AuthZoneType.Catalog:
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

                        if (zoneInfo.Type == AuthZoneType.Catalog)
                        {
                            string strNotifySecondaryCatalogNameServers = request.QueryOrForm("notifySecondaryCatalogsNameServers");
                            if (strNotifySecondaryCatalogNameServers is not null)
                            {
                                if ((strNotifySecondaryCatalogNameServers.Length == 0) || strNotifySecondaryCatalogNameServers.Equals("false", StringComparison.OrdinalIgnoreCase))
                                    zoneInfo.NotifySecondaryCatalogNameServers = null;
                                else
                                    zoneInfo.NotifySecondaryCatalogNameServers = strNotifySecondaryCatalogNameServers.Split(IPAddress.Parse, ',');
                            }
                        }

                        break;
                }

                //update
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.Forwarder:
                        if (request.TryGetQueryOrFormEnum("update", out AuthZoneUpdate update))
                            zoneInfo.Update = update;

                        string strUpdateNetworkACL = request.QueryOrForm("updateNetworkACL");
                        if (strUpdateNetworkACL is not null)
                        {
                            if ((strUpdateNetworkACL.Length == 0) || strUpdateNetworkACL.Equals("false", StringComparison.OrdinalIgnoreCase))
                                zoneInfo.UpdateNetworkACL = null;
                            else
                                zoneInfo.UpdateNetworkACL = strUpdateNetworkACL.Split(NetworkAccessControl.Parse, ',');
                        }
                        break;
                }

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Forwarder:
                        string strUpdateSecurityPolicies = request.QueryOrForm("updateSecurityPolicies");
                        if (strUpdateSecurityPolicies is not null)
                        {
                            if ((strUpdateSecurityPolicies.Length == 0) || strUpdateSecurityPolicies.Equals("false", StringComparison.OrdinalIgnoreCase))
                            {
                                zoneInfo.UpdateSecurityPolicies = null;
                            }
                            else
                            {
                                string[] strUpdateSecurityPoliciesParts = strUpdateSecurityPolicies.Split(_pipeSeparator, StringSplitOptions.RemoveEmptyEntries);
                                Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicies = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(strUpdateSecurityPoliciesParts.Length);

                                for (int i = 0; i < strUpdateSecurityPoliciesParts.Length; i += 3)
                                {
                                    string tsigKeyName = strUpdateSecurityPoliciesParts[i].Trim('.').ToLowerInvariant();
                                    string domain = strUpdateSecurityPoliciesParts[i + 1].Trim('.').ToLowerInvariant();
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

                                    foreach (string strType in strTypes.Split(_commaSpaceSeparator, StringSplitOptions.RemoveEmptyEntries))
                                        (types as List<DnsResourceRecordType>).Add(Enum.Parse<DnsResourceRecordType>(strType, true));
                                }

                                zoneInfo.UpdateSecurityPolicies = updateSecurityPolicies;
                            }
                        }
                        break;
                }

                //catalog zone; done last to allow using updated properties when there is change of ownership
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Stub:
                    case AuthZoneType.Forwarder:
                        if (zoneInfo.ApexZone.SecondaryCatalogZone is not null)
                            break; //cannot set option for Stub zone that is a member of Secondary Catalog Zone

                        string catalogZoneName = request.QueryOrForm("catalog");
                        if (catalogZoneName is not null)
                        {
                            string oldCatalogZoneName = zoneInfo.CatalogZoneName;

                            if (catalogZoneName.Length == 0)
                            {
                                if (!string.IsNullOrEmpty(oldCatalogZoneName))
                                    _dnsWebService._dnsServer.AuthZoneManager.RemoveCatalogMemberZone(zoneInfo);
                            }
                            else
                            {
                                if (string.IsNullOrEmpty(oldCatalogZoneName))
                                {
                                    //check catalog permissions
                                    AuthZoneInfo catalogZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(catalogZoneName);
                                    if (catalogZoneInfo is null)
                                        throw new DnsWebServiceException("No such Catalog zone was found: " + catalogZoneName);

                                    if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, catalogZoneInfo.Name, sessionUser, PermissionFlag.Modify))
                                        throw new DnsWebServiceException("Access was denied to use Catalog zone: " + catalogZoneInfo.Name);

                                    _dnsWebService._dnsServer.AuthZoneManager.AddCatalogMemberZone(catalogZoneInfo.Name, zoneInfo);

                                    if ((zoneInfo.Type == AuthZoneType.Primary) && _dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterCatalogZone(catalogZoneInfo.Name))
                                        _dnsWebService._clusterManager.UpdateClusterRecordsFor(zoneInfo);
                                }
                                else if (!catalogZoneName.Equals(oldCatalogZoneName, StringComparison.OrdinalIgnoreCase))
                                {
                                    //check catalog permissions
                                    AuthZoneInfo catalogZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(catalogZoneName);
                                    if (catalogZoneInfo is null)
                                        throw new DnsWebServiceException("No such Catalog zone was found: " + catalogZoneName);

                                    if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, catalogZoneInfo.Name, sessionUser, PermissionFlag.Modify))
                                        throw new DnsWebServiceException("Access was denied to use Catalog zone: " + catalogZoneInfo.Name);

                                    _dnsWebService._dnsServer.AuthZoneManager.ChangeCatalogMemberZoneOwnership(zoneInfo, catalogZoneInfo.Name);

                                    if ((zoneInfo.Type == AuthZoneType.Primary) && _dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterCatalogZone(catalogZoneInfo.Name))
                                        _dnsWebService._clusterManager.UpdateClusterRecordsFor(zoneInfo);
                                }
                            }
                        }

                        if (zoneInfo.ApexZone.CatalogZone is not null)
                            _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.ApexZone.CatalogZoneName);

                        break;
                }

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] " + zoneInfo.TypeName + " zone options were updated successfully: " + zoneInfo.DisplayName);

                _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
            }

            public void ResyncZone(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string zoneName = context.Request.GetQueryOrFormAlt("zone", "domain").Trim('.');

                if (DnsClient.IsDomainNameUnicode(zoneName))
                    zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + zoneName);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                    case AuthZoneType.Stub:
                        zoneInfo.TriggerResync();
                        break;

                    default:
                        throw new DnsWebServiceException("Only Secondary, Secondary Forwarder, Secondary Catalog, and Stub zones support resync.");
                }
            }

            public void AddRecord(HttpContext context)
            {
                HttpRequest request = context.Request;

                string domain = request.GetQueryOrForm("domain").Trim('.');

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                string zoneName = request.QueryOrForm("zone");
                if (zoneName is not null)
                {
                    zoneName = zoneName.Trim('.');

                    if (DnsClient.IsDomainNameUnicode(zoneName))
                        zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);
                }

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + domain);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                DnsResourceRecordType type = request.GetQueryOrFormEnum<DnsResourceRecordType>("type");
                uint ttl = request.GetQueryOrForm("ttl", ZoneFile.ParseTtl, _dnsWebService._dnsServer.AuthZoneManager.DefaultRecordTtl);
                bool overwrite = request.GetQueryOrForm("overwrite", bool.Parse, false);
                string comments = request.QueryOrForm("comments");
                uint expiryTtl = request.GetQueryOrForm("expiryTtl", ZoneFile.ParseTtl, 0u);

                DnsResourceRecord newRecord;

                switch (type)
                {
                    case DnsResourceRecordType.A:
                    case DnsResourceRecordType.AAAA:
                        {
                            string strIPAddress = request.GetQueryOrFormAlt("ipAddress", "value");
                            IPAddress ipAddress;

                            if (strIPAddress.Equals("request-ip-address"))
                                ipAddress = context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader).Address;
                            else
                                ipAddress = IPAddress.Parse(strIPAddress);

                            bool ptr = request.GetQueryOrForm("ptr", bool.Parse, false);
                            if (ptr)
                            {
                                string ptrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);

                                AuthZoneInfo reverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
                                if (reverseZoneInfo is null)
                                {
                                    bool createPtrZone = request.GetQueryOrForm("createPtrZone", bool.Parse, false);
                                    if (!createPtrZone)
                                        throw new DnsWebServiceException("No reverse zone available to add PTR record.");

                                    string ptrZone = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 24 : 64);

                                    reverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreatePrimaryZone(ptrZone);
                                    if (reverseZoneInfo == null)
                                        throw new DnsWebServiceException("Failed to create reverse zone to add PTR record: " + ptrZone);

                                    //set permissions
                                    _dnsWebService._authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, sessionUser, PermissionFlag.ViewModifyDelete);
                                    _dnsWebService._authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                    _dnsWebService._authManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                    _dnsWebService._authManager.SaveConfigFile();
                                }

                                if (reverseZoneInfo.Internal)
                                    throw new DnsWebServiceException("Reverse zone '" + reverseZoneInfo.DisplayName + "' is an internal zone.");

                                if ((reverseZoneInfo.Type != AuthZoneType.Primary) && (reverseZoneInfo.Type != AuthZoneType.Forwarder))
                                    throw new DnsWebServiceException("Reverse zone '" + reverseZoneInfo.DisplayName + "' is not a primary or forwarder zone.");

                                DnsResourceRecord ptrRecord = new DnsResourceRecord(ptrDomain, DnsResourceRecordType.PTR, DnsClass.IN, ttl, new DnsPTRRecordData(domain));
                                ptrRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;
                                ptrRecord.GetAuthGenericRecordInfo().ExpiryTtl = expiryTtl;

                                _dnsWebService._dnsServer.AuthZoneManager.SetRecord(reverseZoneInfo.Name, ptrRecord);
                                _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                            }

                            if (type == DnsResourceRecordType.A)
                                newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsARecordData(ipAddress));
                            else
                                newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsAAAARecordData(ipAddress));
                        }
                        break;

                    case DnsResourceRecordType.NS:
                        {
                            if ((zoneInfo.Type == AuthZoneType.Primary) && zoneInfo.Name.Equals(domain, StringComparison.OrdinalIgnoreCase) && _dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterCatalogZone(zoneInfo.CatalogZoneName))
                                throw new DnsWebServiceException("Cannot add NS records for Primary zones that are members of the Cluster Catalog zone. These NS records are automatically managed by the Cluster and only their TTL values can be updated.");

                            string nameServer = request.GetQueryOrFormAlt("nameServer", "value").Trim('.');
                            string glueAddresses = request.GetQueryOrForm("glue", null);

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsNSRecordData(nameServer));

                            if (!string.IsNullOrEmpty(glueAddresses))
                            {
                                if (zoneInfo.Name.Equals(domain, StringComparison.OrdinalIgnoreCase) && (nameServer.Equals(domain, StringComparison.OrdinalIgnoreCase) || nameServer.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase)))
                                    throw new DnsWebServiceException("The zone's own NS records cannot have glue addresses. Please add separate A/AAAA records in the zone instead.");

                                newRecord.SetGlueRecords(glueAddresses);
                            }
                        }
                        break;

                    case DnsResourceRecordType.CNAME:
                        {
                            if (!overwrite)
                            {
                                IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService._dnsServer.AuthZoneManager.GetRecords(zoneInfo.Name, domain, type);
                                if (existingRecords.Count > 0)
                                    throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing record.");
                            }

                            string cname = request.GetQueryOrFormAlt("cname", "value").Trim('.');

                            if (cname.Equals(domain, StringComparison.OrdinalIgnoreCase))
                                throw new DnsWebServiceException("CNAME domain name cannot be same as that of the record name.");

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCNAMERecordData(cname));

                            overwrite = true; //force SetRecord
                        }
                        break;

                    case DnsResourceRecordType.PTR:
                        {
                            string ptrName = request.GetQueryOrFormAlt("ptrName", "value").Trim('.');

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsPTRRecordData(ptrName));
                        }
                        break;

                    case DnsResourceRecordType.MX:
                        {
                            ushort preference = request.GetQueryOrForm("preference", ushort.Parse);
                            string exchange = request.GetQueryOrFormAlt("exchange", "value").Trim('.');

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsMXRecordData(preference, exchange));
                        }
                        break;

                    case DnsResourceRecordType.TXT:
                        {
                            string text = request.GetQueryOrFormAlt("text", "value");
                            bool splitText = request.GetQueryOrForm("splitText", bool.Parse, false);

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, splitText ? new DnsTXTRecordData(DecodeCharacterStrings(text)) : new DnsTXTRecordData(text));
                        }
                        break;

                    case DnsResourceRecordType.RP:
                        {
                            string mailbox = request.GetQueryOrForm("mailbox", "").Trim('.');
                            string txtDomain = request.GetQueryOrForm("txtDomain", "").Trim('.');

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsRPRecordData(mailbox, txtDomain));
                        }
                        break;

                    case DnsResourceRecordType.SRV:
                        {
                            ushort priority = request.GetQueryOrForm("priority", ushort.Parse);
                            ushort weight = request.GetQueryOrForm("weight", ushort.Parse);
                            ushort port = request.GetQueryOrForm("port", ushort.Parse);
                            string target = request.GetQueryOrFormAlt("target", "value").Trim('.');

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSRVRecordData(priority, weight, port, target));
                        }
                        break;

                    case DnsResourceRecordType.NAPTR:
                        {
                            ushort order = request.GetQueryOrForm("naptrOrder", ushort.Parse);
                            ushort preference = request.GetQueryOrForm("naptrPreference", ushort.Parse);
                            string flags = request.GetQueryOrForm("naptrFlags", "");
                            string services = request.GetQueryOrForm("naptrServices", "");
                            string regexp = request.GetQueryOrForm("naptrRegexp", "");
                            string replacement = request.GetQueryOrForm("naptrReplacement", "").Trim('.');

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsNAPTRRecordData(order, preference, flags, services, regexp, replacement));
                        }
                        break;

                    case DnsResourceRecordType.DNAME:
                        {
                            if (!overwrite)
                            {
                                IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService._dnsServer.AuthZoneManager.GetRecords(zoneInfo.Name, domain, type);
                                if (existingRecords.Count > 0)
                                    throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing record.");
                            }

                            string dname = request.GetQueryOrFormAlt("dname", "value").Trim('.');

                            if (dname.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                                throw new DnsWebServiceException("DNAME domain name cannot be a sub domain of the record name.");

                            if (dname.Equals(domain, StringComparison.OrdinalIgnoreCase))
                                throw new DnsWebServiceException("DNAME domain name cannot be same as that of the record name.");

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsDNAMERecordData(dname));

                            overwrite = true; //force SetRecord
                        }
                        break;

                    case DnsResourceRecordType.DS:
                        {
                            ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);
                            DnssecAlgorithm algorithm = Enum.Parse<DnssecAlgorithm>(request.GetQueryOrForm("algorithm").Replace('-', '_'), true);
                            DnssecDigestType digestType = Enum.Parse<DnssecDigestType>(request.GetQueryOrForm("digestType").Replace('-', '_'), true);
                            byte[] digest = request.GetQueryOrFormAlt("digest", "value", Convert.FromHexString);

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsDSRecordData(keyTag, algorithm, digestType, digest));
                        }
                        break;

                    case DnsResourceRecordType.SSHFP:
                        {
                            DnsSSHFPAlgorithm sshfpAlgorithm = request.GetQueryOrFormEnum<DnsSSHFPAlgorithm>("sshfpAlgorithm");
                            DnsSSHFPFingerprintType sshfpFingerprintType = request.GetQueryOrFormEnum<DnsSSHFPFingerprintType>("sshfpFingerprintType");
                            byte[] sshfpFingerprint = request.GetQueryOrForm("sshfpFingerprint", Convert.FromHexString);

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSSHFPRecordData(sshfpAlgorithm, sshfpFingerprintType, sshfpFingerprint));
                        }
                        break;

                    case DnsResourceRecordType.TLSA:
                        {
                            DnsTLSACertificateUsage tlsaCertificateUsage = Enum.Parse<DnsTLSACertificateUsage>(request.GetQueryOrForm("tlsaCertificateUsage").Replace('-', '_'), true);
                            DnsTLSASelector tlsaSelector = request.GetQueryOrFormEnum<DnsTLSASelector>("tlsaSelector");
                            DnsTLSAMatchingType tlsaMatchingType = Enum.Parse<DnsTLSAMatchingType>(request.GetQueryOrForm("tlsaMatchingType").Replace('-', '_'), true);
                            string tlsaCertificateAssociationData = request.GetQueryOrForm("tlsaCertificateAssociationData");

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsTLSARecordData(tlsaCertificateUsage, tlsaSelector, tlsaMatchingType, tlsaCertificateAssociationData));
                        }
                        break;

                    case DnsResourceRecordType.SVCB:
                    case DnsResourceRecordType.HTTPS:
                        {
                            ushort svcPriority = request.GetQueryOrForm("svcPriority", ushort.Parse);
                            string targetName = request.GetQueryOrForm("svcTargetName").Trim('.');
                            string strSvcParams = request.GetQueryOrForm("svcParams");
                            bool autoIpv4Hint = request.GetQueryOrForm("autoIpv4Hint", bool.Parse, false);
                            bool autoIpv6Hint = request.GetQueryOrForm("autoIpv6Hint", bool.Parse, false);

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

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSVCBRecordData(svcPriority, targetName, svcParams));

                            if (autoIpv4Hint)
                                newRecord.GetAuthSVCBRecordInfo().AutoIpv4Hint = true;

                            if (autoIpv6Hint)
                                newRecord.GetAuthSVCBRecordInfo().AutoIpv6Hint = true;

                            if (autoIpv4Hint || autoIpv6Hint)
                                ResolveSvcbAutoHints(zoneInfo.Name, newRecord, autoIpv4Hint, autoIpv6Hint, svcParams);
                        }
                        break;

                    case DnsResourceRecordType.URI:
                        {
                            ushort priority = request.GetQueryOrForm("uriPriority", ushort.Parse);
                            ushort weight = request.GetQueryOrForm("uriWeight", ushort.Parse);
                            Uri uri = request.GetQueryOrForm("uri", delegate (string value) { return new Uri(value); });

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsURIRecordData(priority, weight, uri));
                        }
                        break;

                    case DnsResourceRecordType.CAA:
                        {
                            byte flags = request.GetQueryOrForm("flags", byte.Parse);
                            string tag = request.GetQueryOrForm("tag");
                            string value = request.GetQueryOrForm("value");

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCAARecordData(flags, tag, value));
                        }
                        break;

                    case DnsResourceRecordType.ANAME:
                        {
                            string aname = request.GetQueryOrFormAlt("aname", "value").Trim('.');

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsANAMERecordData(aname));
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

                            byte priority = request.GetQueryOrForm("forwarderPriority", byte.Parse, byte.MinValue);

                            if (protocol == DnsTransportProtocol.Quic)
                                DnsWebService.ValidateQuicSupport();

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecordData(protocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, priority));
                        }
                        break;

                    case DnsResourceRecordType.APP:
                        {
                            if (!overwrite)
                            {
                                IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService._dnsServer.AuthZoneManager.GetRecords(zoneInfo.Name, domain, type);
                                if (existingRecords.Count > 0)
                                    throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing record.");
                            }

                            string appName = request.GetQueryOrFormAlt("appName", "value");
                            string classPath = request.GetQueryOrForm("classPath");
                            string recordData = request.GetQueryOrForm("recordData", "");

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsApplicationRecordData(appName, classPath, recordData));

                            overwrite = true; //force SetRecord
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
                        }
                        break;
                }

                //update record info
                GenericRecordInfo recordInfo = newRecord.GetAuthGenericRecordInfo();

                recordInfo.LastModified = DateTime.UtcNow;
                recordInfo.ExpiryTtl = expiryTtl;

                if (!string.IsNullOrEmpty(comments))
                    recordInfo.Comments = comments;

                //add record
                if (overwrite)
                {
                    _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                }
                else
                {
                    if (!_dnsWebService._dnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord))
                        throw new DnsWebServiceException("Cannot add record: record already exists.");
                }

                //additional processing
                if ((type == DnsResourceRecordType.A) || (type == DnsResourceRecordType.AAAA))
                {
                    bool updateSvcbHints = request.GetQueryOrForm("updateSvcbHints", bool.Parse, false);
                    if (updateSvcbHints)
                        UpdateSvcbAutoHints(zoneInfo.Name, domain, type == DnsResourceRecordType.A, type == DnsResourceRecordType.AAAA);
                }

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] New record was added to " + zoneInfo.TypeName + " zone '" + zoneInfo.DisplayName + "' successfully {record: " + newRecord.ToString() + "}");

                //save zone
                _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("zone");
                WriteZoneInfoAsJson(zoneInfo, jsonWriter);

                jsonWriter.WritePropertyName("addedRecord");
                WriteRecordAsJson(newRecord, jsonWriter, true, null);
            }

            public void GetRecords(HttpContext context)
            {
                HttpRequest request = context.Request;

                string domain = request.GetQueryOrForm("domain").Trim('.');

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                string zoneName = request.QueryOrForm("zone");
                if (zoneName is not null)
                {
                    zoneName = zoneName.Trim('.');

                    if (DnsClient.IsDomainNameUnicode(zoneName))
                        zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);
                }

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + domain);

                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                bool listZone = request.GetQueryOrForm("listZone", bool.Parse, false);

                List<DnsResourceRecord> records = new List<DnsResourceRecord>();

                if (listZone)
                    _dnsWebService._dnsServer.AuthZoneManager.ListAllZoneRecords(zoneInfo.Name, records);
                else
                    _dnsWebService._dnsServer.AuthZoneManager.ListAllRecords(zoneInfo.Name, domain, records);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("zone");
                WriteZoneInfoAsJson(zoneInfo, jsonWriter);

                WriteRecordsAsJson(records, jsonWriter, true, zoneInfo);
            }

            public void DeleteRecord(HttpContext context)
            {
                HttpRequest request = context.Request;

                string domain = request.GetQueryOrForm("domain").Trim('.');

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                string zoneName = request.QueryOrForm("zone");
                if (zoneName is not null)
                {
                    zoneName = zoneName.Trim('.');

                    if (DnsClient.IsDomainNameUnicode(zoneName))
                        zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);
                }

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + domain);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                DnsResourceRecordType type = request.GetQueryOrFormEnum<DnsResourceRecordType>("type");
                switch (type)
                {
                    case DnsResourceRecordType.A:
                    case DnsResourceRecordType.AAAA:
                        {
                            IPAddress ipAddress = IPAddress.Parse(request.GetQueryOrFormAlt("ipAddress", "value"));

                            if (type == DnsResourceRecordType.A)
                            {
                                if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsARecordData(ipAddress)))
                                    throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                            }
                            else
                            {
                                if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsAAAARecordData(ipAddress)))
                                    throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                            }

                            string ptrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);
                            AuthZoneInfo reverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
                            if ((reverseZoneInfo is not null) && !reverseZoneInfo.Internal && ((reverseZoneInfo.Type == AuthZoneType.Primary) || (reverseZoneInfo.Type == AuthZoneType.Forwarder)))
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

                            bool updateSvcbHints = request.GetQueryOrForm("updateSvcbHints", bool.Parse, false);
                            if (updateSvcbHints)
                                UpdateSvcbAutoHints(zoneInfo.Name, domain, type == DnsResourceRecordType.A, type == DnsResourceRecordType.AAAA);
                        }
                        break;

                    case DnsResourceRecordType.NS:
                        {
                            if ((zoneInfo.Type == AuthZoneType.Primary) && zoneInfo.Name.Equals(domain, StringComparison.OrdinalIgnoreCase) && _dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterCatalogZone(zoneInfo.CatalogZoneName))
                                throw new DnsWebServiceException("Cannot delete NS records for Primary zones that are members of the Cluster Catalog zone. These NS records are automatically managed by the Cluster and only their TTL values can be updated.");

                            string nameServer = request.GetQueryOrFormAlt("nameServer", "value").Trim('.');

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsNSRecordData(nameServer, false)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.CNAME:
                        if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type))
                            throw new DnsWebServiceException("Cannot delete record: no such record exists.");

                        break;

                    case DnsResourceRecordType.PTR:
                        {
                            string ptrName = request.GetQueryOrFormAlt("ptrName", "value").Trim('.');

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsPTRRecordData(ptrName)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.MX:
                        {
                            ushort preference = request.GetQueryOrForm("preference", ushort.Parse);
                            string exchange = request.GetQueryOrFormAlt("exchange", "value").Trim('.');

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsMXRecordData(preference, exchange)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.TXT:
                        {
                            string text = request.GetQueryOrFormAlt("text", "value");
                            bool splitText = request.GetQueryOrForm("splitText", bool.Parse, false);

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, splitText ? new DnsTXTRecordData(DecodeCharacterStrings(text)) : new DnsTXTRecordData(text)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.RP:
                        {
                            string mailbox = request.GetQueryOrForm("mailbox", "").Trim('.');
                            string txtDomain = request.GetQueryOrForm("txtDomain", "").Trim('.');

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsRPRecordData(mailbox, txtDomain)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.SRV:
                        {
                            ushort priority = request.GetQueryOrForm("priority", ushort.Parse);
                            ushort weight = request.GetQueryOrForm("weight", ushort.Parse);
                            ushort port = request.GetQueryOrForm("port", ushort.Parse);
                            string target = request.GetQueryOrFormAlt("target", "value").Trim('.');

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsSRVRecordData(priority, weight, port, target)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.NAPTR:
                        {
                            ushort order = request.GetQueryOrForm("naptrOrder", ushort.Parse);
                            ushort preference = request.GetQueryOrForm("naptrPreference", ushort.Parse);
                            string flags = request.GetQueryOrForm("naptrFlags", "");
                            string services = request.GetQueryOrForm("naptrServices", "");
                            string regexp = request.GetQueryOrForm("naptrRegexp", "");
                            string replacement = request.GetQueryOrForm("naptrReplacement", "").Trim('.');

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsNAPTRRecordData(order, preference, flags, services, regexp, replacement)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.DNAME:
                        if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type))
                            throw new DnsWebServiceException("Cannot delete record: no such record exists.");

                        break;

                    case DnsResourceRecordType.DS:
                        {
                            ushort keyTag = request.GetQueryOrForm("keyTag", ushort.Parse);
                            DnssecAlgorithm algorithm = Enum.Parse<DnssecAlgorithm>(request.GetQueryOrForm("algorithm").Replace('-', '_'), true);
                            DnssecDigestType digestType = Enum.Parse<DnssecDigestType>(request.GetQueryOrForm("digestType").Replace('-', '_'), true);
                            byte[] digest = Convert.FromHexString(request.GetQueryOrFormAlt("digest", "value"));

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsDSRecordData(keyTag, algorithm, digestType, digest)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.SSHFP:
                        {
                            DnsSSHFPAlgorithm sshfpAlgorithm = request.GetQueryOrFormEnum<DnsSSHFPAlgorithm>("sshfpAlgorithm");
                            DnsSSHFPFingerprintType sshfpFingerprintType = request.GetQueryOrFormEnum<DnsSSHFPFingerprintType>("sshfpFingerprintType");
                            byte[] sshfpFingerprint = request.GetQueryOrForm("sshfpFingerprint", Convert.FromHexString);

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsSSHFPRecordData(sshfpAlgorithm, sshfpFingerprintType, sshfpFingerprint)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.TLSA:
                        {
                            DnsTLSACertificateUsage tlsaCertificateUsage = Enum.Parse<DnsTLSACertificateUsage>(request.GetQueryOrForm("tlsaCertificateUsage").Replace('-', '_'), true);
                            DnsTLSASelector tlsaSelector = request.GetQueryOrFormEnum<DnsTLSASelector>("tlsaSelector");
                            DnsTLSAMatchingType tlsaMatchingType = Enum.Parse<DnsTLSAMatchingType>(request.GetQueryOrForm("tlsaMatchingType").Replace('-', '_'), true);
                            string tlsaCertificateAssociationData = request.GetQueryOrForm("tlsaCertificateAssociationData");

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsTLSARecordData(tlsaCertificateUsage, tlsaSelector, tlsaMatchingType, tlsaCertificateAssociationData)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.SVCB:
                    case DnsResourceRecordType.HTTPS:
                        {
                            ushort svcPriority = request.GetQueryOrForm("svcPriority", ushort.Parse);
                            string targetName = request.GetQueryOrForm("svcTargetName").Trim('.');
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

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsSVCBRecordData(svcPriority, targetName, svcParams)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.URI:
                        {
                            ushort priority = request.GetQueryOrForm("uriPriority", ushort.Parse);
                            ushort weight = request.GetQueryOrForm("uriWeight", ushort.Parse);
                            Uri uri = request.GetQueryOrForm("uri", delegate (string value) { return new Uri(value); });

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsURIRecordData(priority, weight, uri)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.CAA:
                        {
                            byte flags = request.GetQueryOrForm("flags", byte.Parse);
                            string tag = request.GetQueryOrForm("tag");
                            string value = request.GetQueryOrForm("value");

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsCAARecordData(flags, tag, value)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.ANAME:
                        {
                            string aname = request.GetQueryOrFormAlt("aname", "value").Trim('.');

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsANAMERecordData(aname)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.FWD:
                        {
                            DnsTransportProtocol protocol = request.GetQueryOrFormEnum("protocol", DnsTransportProtocol.Udp);
                            string forwarder = request.GetQueryOrFormAlt("forwarder", "value");

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, DnsForwarderRecordData.CreatePartialRecordData(protocol, forwarder)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;

                    case DnsResourceRecordType.APP:
                        if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type))
                            throw new DnsWebServiceException("Cannot delete record: no such record exists.");

                        break;

                    default:
                        {
                            string strRData = request.GetQueryOrForm("rdata", string.Empty);

                            byte[] rdata;

                            if (strRData.Contains(':'))
                                rdata = strRData.ParseColonHexString();
                            else
                                rdata = Convert.FromHexString(strRData);

                            if (!_dnsWebService._dnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsUnknownRecordData(rdata)))
                                throw new DnsWebServiceException("Cannot delete record: no such record exists.");
                        }
                        break;
                }

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Record was deleted from " + zoneInfo.TypeName + " zone '" + zoneInfo.DisplayName + "' successfully {domain: " + domain + "; type: " + type + ";}");

                _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
            }

            public void UpdateRecord(HttpContext context)
            {
                HttpRequest request = context.Request;

                string domain = request.GetQueryOrForm("domain").Trim('.');

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                string zoneName = request.QueryOrForm("zone");
                if (zoneName is not null)
                {
                    zoneName = zoneName.Trim('.');

                    if (DnsClient.IsDomainNameUnicode(zoneName))
                        zoneName = DnsClient.ConvertDomainNameToAscii(zoneName);
                }

                AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
                if (zoneInfo is null)
                    throw new DnsWebServiceException("No such zone was found: " + domain);

                if (zoneInfo.Internal)
                    throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string newDomain = request.GetQueryOrForm("newDomain", domain).Trim('.');
                uint ttl = request.GetQueryOrForm("ttl", ZoneFile.ParseTtl, _dnsWebService._dnsServer.AuthZoneManager.DefaultRecordTtl);
                bool disable = request.GetQueryOrForm("disable", bool.Parse, false);
                string comments = request.QueryOrForm("comments");
                uint expiryTtl = request.GetQueryOrForm("expiryTtl", ZoneFile.ParseTtl, 0u);
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

                                AuthZoneInfo newReverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(newPtrDomain);
                                if (newReverseZoneInfo is null)
                                {
                                    bool createPtrZone = request.GetQueryOrForm("createPtrZone", bool.Parse, false);
                                    if (!createPtrZone)
                                        throw new DnsWebServiceException("No reverse zone available to add PTR record.");

                                    string ptrZone = Zone.GetReverseZone(newIpAddress, type == DnsResourceRecordType.A ? 24 : 64);

                                    newReverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreatePrimaryZone(ptrZone);
                                    if (newReverseZoneInfo is null)
                                        throw new DnsWebServiceException("Failed to create reverse zone to add PTR record: " + ptrZone);

                                    //set permissions
                                    _dnsWebService._authManager.SetPermission(PermissionSection.Zones, newReverseZoneInfo.Name, sessionUser, PermissionFlag.ViewModifyDelete);
                                    _dnsWebService._authManager.SetPermission(PermissionSection.Zones, newReverseZoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                    _dnsWebService._authManager.SetPermission(PermissionSection.Zones, newReverseZoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                    _dnsWebService._authManager.SaveConfigFile();
                                }

                                if (newReverseZoneInfo.Internal)
                                    throw new DnsWebServiceException("Reverse zone '" + newReverseZoneInfo.DisplayName + "' is an internal zone.");

                                if ((newReverseZoneInfo.Type != AuthZoneType.Primary) && (newReverseZoneInfo.Type != AuthZoneType.Forwarder))
                                    throw new DnsWebServiceException("Reverse zone '" + newReverseZoneInfo.DisplayName + "' is not a primary or forwarder zone.");

                                string oldPtrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);

                                AuthZoneInfo oldReverseZoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(oldPtrDomain);
                                if ((oldReverseZoneInfo is not null) && !oldReverseZoneInfo.Internal && ((oldReverseZoneInfo.Type == AuthZoneType.Primary) || (oldReverseZoneInfo.Type == AuthZoneType.Forwarder)))
                                {
                                    //delete old PTR record if any and save old reverse zone
                                    _dnsWebService._dnsServer.AuthZoneManager.DeleteRecords(oldReverseZoneInfo.Name, oldPtrDomain, DnsResourceRecordType.PTR);
                                    _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(oldReverseZoneInfo.Name);
                                }

                                //add new PTR record and save reverse zone
                                DnsResourceRecord ptrRecord = new DnsResourceRecord(newPtrDomain, DnsResourceRecordType.PTR, DnsClass.IN, ttl, new DnsPTRRecordData(domain));
                                ptrRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;
                                ptrRecord.GetAuthGenericRecordInfo().ExpiryTtl = expiryTtl;

                                _dnsWebService._dnsServer.AuthZoneManager.SetRecord(newReverseZoneInfo.Name, ptrRecord);
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
                        }
                        break;

                    case DnsResourceRecordType.NS:
                        {
                            string nameServer = request.GetQueryOrFormAlt("nameServer", "value").Trim('.');
                            string newNameServer = request.GetQueryOrFormAlt("newNameServer", "newValue", nameServer).Trim('.');

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsNSRecordData(nameServer));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsNSRecordData(newNameServer));

                            if (request.TryGetQueryOrForm("glue", out string glueAddresses))
                            {
                                if (zoneInfo.Name.Equals(newDomain, StringComparison.OrdinalIgnoreCase) && (newNameServer.Equals(newDomain, StringComparison.OrdinalIgnoreCase) || newNameServer.EndsWith("." + newDomain, StringComparison.OrdinalIgnoreCase)))
                                    throw new DnsWebServiceException("The zone's own NS records cannot have glue addresses. Please add separate A/AAAA records in the zone instead.");

                                newRecord.SetGlueRecords(glueAddresses);
                            }

                            if ((zoneInfo.Type == AuthZoneType.Primary) && zoneInfo.Name.Equals(domain, StringComparison.OrdinalIgnoreCase) && _dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterCatalogZone(zoneInfo.CatalogZoneName))
                            {
                                if (disable)
                                    throw new DnsWebServiceException("Cannot disable NS records for Primary zones that are members of the Cluster Catalog zone. These NS records are automatically managed by the Cluster and only their TTL values can be updated.");

                                if (expiryTtl > 0)
                                    throw new DnsWebServiceException("Cannot set automatic expiry TTL for NS records for Primary zones that are members of the Cluster Catalog zone. These NS records are automatically managed by the Cluster and only their TTL values can be updated.");

                                if (!nameServer.Equals(newNameServer, StringComparison.OrdinalIgnoreCase))
                                    throw new DnsWebServiceException("Cannot update NS records for Primary zones that are members of the Cluster Catalog zone. These NS records are automatically managed by the Cluster and only their TTL values can be updated.");

                                if (!string.IsNullOrEmpty(glueAddresses))
                                    throw new DnsWebServiceException("Cannot update NS records for Primary zones that are members of the Cluster Catalog zone. These NS records are automatically managed by the Cluster and only their TTL values can be updated.");
                            }
                        }
                        break;

                    case DnsResourceRecordType.CNAME:
                        {
                            string cname = request.GetQueryOrFormAlt("cname", "value").Trim('.');

                            if (cname.Equals(newDomain, StringComparison.OrdinalIgnoreCase))
                                throw new DnsWebServiceException("CNAME domain name cannot be same as that of the record name.");

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCNAMERecordData(cname));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCNAMERecordData(cname));
                        }
                        break;

                    case DnsResourceRecordType.SOA:
                        {
                            string primaryNameServer = request.GetQueryOrForm("primaryNameServer").Trim('.');
                            string responsiblePerson = request.GetQueryOrForm("responsiblePerson").Trim('.');
                            uint serial = request.GetQueryOrForm("serial", uint.Parse);
                            uint refresh = request.GetQueryOrForm("refresh", ZoneFile.ParseTtl);
                            uint retry = request.GetQueryOrForm("retry", ZoneFile.ParseTtl);
                            uint expire = request.GetQueryOrForm("expire", ZoneFile.ParseTtl);
                            uint minimum = request.GetQueryOrForm("minimum", ZoneFile.ParseTtl);

                            if ((zoneInfo.Type == AuthZoneType.Primary) && _dnsWebService._clusterManager.ClusterInitialized && _dnsWebService._clusterManager.IsClusterCatalogZone(zoneInfo.CatalogZoneName))
                            {
                                if (!primaryNameServer.Equals(_dnsWebService._dnsServer.ServerDomain, StringComparison.OrdinalIgnoreCase))
                                    throw new DnsWebServiceException("Cannot update SOA record for Primary zones that are members of the Cluster Catalog zone. The SOA primary name server field must match the Cluster Primary node's domain name.");
                            }

                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSOARecordData(primaryNameServer, responsiblePerson, serial, refresh, retry, expire, minimum));

                            switch (zoneInfo.Type)
                            {
                                case AuthZoneType.Primary:
                                case AuthZoneType.Forwarder:
                                case AuthZoneType.Catalog:
                                    {
                                        if (request.TryGetQueryOrForm("useSerialDateScheme", bool.Parse, out bool useSerialDateScheme))
                                            newRecord.GetAuthSOARecordInfo().UseSoaSerialDateScheme = useSerialDateScheme;
                                    }
                                    break;
                            }
                        }
                        break;

                    case DnsResourceRecordType.PTR:
                        {
                            string ptrName = request.GetQueryOrFormAlt("ptrName", "value").Trim('.');
                            string newPtrName = request.GetQueryOrFormAlt("newPtrName", "newValue", ptrName).Trim('.');

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsPTRRecordData(ptrName));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsPTRRecordData(newPtrName));
                        }
                        break;

                    case DnsResourceRecordType.MX:
                        {
                            ushort preference = request.GetQueryOrForm("preference", ushort.Parse);
                            ushort newPreference = request.GetQueryOrForm("newPreference", ushort.Parse, preference);

                            string exchange = request.GetQueryOrFormAlt("exchange", "value").Trim('.');
                            string newExchange = request.GetQueryOrFormAlt("newExchange", "newValue", exchange).Trim('.');

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsMXRecordData(preference, exchange));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsMXRecordData(newPreference, newExchange));
                        }
                        break;

                    case DnsResourceRecordType.TXT:
                        {
                            string text = request.GetQueryOrFormAlt("text", "value");
                            string newText = request.GetQueryOrFormAlt("newText", "newValue", text);

                            bool splitText = request.GetQueryOrForm("splitText", bool.Parse, false);
                            bool newSplitText = request.GetQueryOrForm("newSplitText", bool.Parse, splitText);

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, splitText ? new DnsTXTRecordData(DecodeCharacterStrings(text)) : new DnsTXTRecordData(text));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, newSplitText ? new DnsTXTRecordData(DecodeCharacterStrings(newText)) : new DnsTXTRecordData(newText));
                        }
                        break;

                    case DnsResourceRecordType.RP:
                        {
                            string mailbox = request.GetQueryOrForm("mailbox", "").Trim('.');
                            string newMailbox = request.GetQueryOrForm("newMailbox", mailbox).Trim('.');

                            string txtDomain = request.GetQueryOrForm("txtDomain", "").Trim('.');
                            string newTxtDomain = request.GetQueryOrForm("newTxtDomain", txtDomain).Trim('.');

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsRPRecordData(mailbox, txtDomain));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsRPRecordData(newMailbox, newTxtDomain));
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

                            string target = request.GetQueryOrFormAlt("target", "value").Trim('.');
                            string newTarget = request.GetQueryOrFormAlt("newTarget", "newValue", target).Trim('.');

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSRVRecordData(priority, weight, port, target));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSRVRecordData(newPriority, newWeight, newPort, newTarget));
                        }
                        break;

                    case DnsResourceRecordType.NAPTR:
                        {
                            ushort order = request.GetQueryOrForm("naptrOrder", ushort.Parse);
                            ushort newOrder = request.GetQueryOrForm("naptrNewOrder", ushort.Parse, order);

                            ushort preference = request.GetQueryOrForm("naptrPreference", ushort.Parse);
                            ushort newPreference = request.GetQueryOrForm("naptrNewPreference", ushort.Parse, preference);

                            string flags = request.GetQueryOrForm("naptrFlags", "");
                            string newFlags = request.GetQueryOrForm("naptrNewFlags", flags);

                            string services = request.GetQueryOrForm("naptrServices", "");
                            string newServices = request.GetQueryOrForm("naptrNewServices", services);

                            string regexp = request.GetQueryOrForm("naptrRegexp", "");
                            string newRegexp = request.GetQueryOrForm("naptrNewRegexp", regexp);

                            string replacement = request.GetQueryOrForm("naptrReplacement", "").Trim('.');
                            string newReplacement = request.GetQueryOrForm("naptrNewReplacement", replacement).Trim('.');

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsNAPTRRecordData(order, preference, flags, services, regexp, replacement));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsNAPTRRecordData(newOrder, newPreference, newFlags, newServices, newRegexp, newReplacement));
                        }
                        break;

                    case DnsResourceRecordType.DNAME:
                        {
                            string dname = request.GetQueryOrFormAlt("dname", "value").Trim('.');

                            if (dname.EndsWith("." + newDomain, StringComparison.OrdinalIgnoreCase))
                                throw new DnsWebServiceException("DNAME domain name cannot be a sub domain of the record name.");

                            if (dname.Equals(newDomain, StringComparison.OrdinalIgnoreCase))
                                throw new DnsWebServiceException("DNAME domain name cannot be same as that of the record name.");

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsDNAMERecordData(dname));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsDNAMERecordData(dname));
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
                        }
                        break;

                    case DnsResourceRecordType.SVCB:
                    case DnsResourceRecordType.HTTPS:
                        {
                            ushort svcPriority = request.GetQueryOrForm("svcPriority", ushort.Parse);
                            ushort newSvcPriority = request.GetQueryOrForm("newSvcPriority", ushort.Parse, svcPriority);

                            string targetName = request.GetQueryOrForm("svcTargetName").Trim('.');
                            string newTargetName = request.GetQueryOrForm("newSvcTargetName", targetName).Trim('.');

                            string strSvcParams = request.GetQueryOrForm("svcParams");
                            string strNewSvcParams = request.GetQueryOrForm("newSvcParams", strSvcParams);

                            bool autoIpv4Hint = request.GetQueryOrForm("autoIpv4Hint", bool.Parse, false);
                            bool autoIpv6Hint = request.GetQueryOrForm("autoIpv6Hint", bool.Parse, false);

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

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSVCBRecordData(svcPriority, targetName, svcParams));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSVCBRecordData(newSvcPriority, newTargetName, newSvcParams));

                            if (autoIpv4Hint)
                                newRecord.GetAuthSVCBRecordInfo().AutoIpv4Hint = true;

                            if (autoIpv6Hint)
                                newRecord.GetAuthSVCBRecordInfo().AutoIpv6Hint = true;

                            if (autoIpv4Hint || autoIpv6Hint)
                                ResolveSvcbAutoHints(zoneInfo.Name, newRecord, autoIpv4Hint, autoIpv6Hint, newSvcParams);
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
                        }
                        break;

                    case DnsResourceRecordType.ANAME:
                        {
                            string aname = request.GetQueryOrFormAlt("aname", "value").Trim('.');
                            string newAName = request.GetQueryOrFormAlt("newAName", "newValue", aname).Trim('.');

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsANAMERecordData(aname));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsANAMERecordData(newAName));
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

                            byte priority = request.GetQueryOrForm("forwarderPriority", byte.Parse, byte.MinValue);

                            if (newProtocol == DnsTransportProtocol.Quic)
                                DnsWebService.ValidateQuicSupport();

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, DnsForwarderRecordData.CreatePartialRecordData(protocol, forwarder));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, 0, new DnsForwarderRecordData(newProtocol, newForwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, priority));
                        }
                        break;

                    case DnsResourceRecordType.APP:
                        {
                            string appName = request.GetQueryOrFormAlt("appName", "value");
                            string classPath = request.GetQueryOrForm("classPath");
                            string recordData = request.GetQueryOrForm("recordData", "");

                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsApplicationRecordData(appName, classPath, recordData));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsApplicationRecordData(appName, classPath, recordData));
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
                        }
                        break;
                }

                //update record info
                GenericRecordInfo recordInfo = newRecord.GetAuthGenericRecordInfo();

                recordInfo.LastModified = DateTime.UtcNow;
                recordInfo.ExpiryTtl = expiryTtl;
                recordInfo.Disabled = disable;
                recordInfo.Comments = comments;

                //update record
                if (type == DnsResourceRecordType.SOA)
                {
                    //special SOA case
                    switch (zoneInfo.Type)
                    {
                        case AuthZoneType.Primary:
                        case AuthZoneType.Forwarder:
                        case AuthZoneType.Catalog:
                            _dnsWebService._dnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                            break;
                    }

                    //get updated record to return json
                    newRecord = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.SOA)[0];
                }
                else
                {
                    _dnsWebService._dnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                }

                //additional processing
                if ((type == DnsResourceRecordType.A) || (type == DnsResourceRecordType.AAAA))
                {
                    bool updateSvcbHints = request.GetQueryOrForm("updateSvcbHints", bool.Parse, false);
                    if (updateSvcbHints)
                        UpdateSvcbAutoHints(zoneInfo.Name, newDomain, type == DnsResourceRecordType.A, type == DnsResourceRecordType.AAAA);
                }

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Record was updated for " + zoneInfo.TypeName + " zone '" + zoneInfo.DisplayName + "' successfully {" + (oldRecord is null ? "" : "oldRecord: " + oldRecord.ToString() + "; ") + "newRecord: " + newRecord.ToString() + "}");

                //save zone
                _dnsWebService._dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("zone");
                WriteZoneInfoAsJson(zoneInfo, jsonWriter);

                jsonWriter.WritePropertyName("updatedRecord");
                WriteRecordAsJson(newRecord, jsonWriter, true, zoneInfo);
            }

            #endregion
        }
    }
}
