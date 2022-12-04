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

using DnsServerCore.Auth;
using DnsServerCore.Dns;
using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;
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

        public static void WriteRecordsAsJson(List<DnsResourceRecord> records, JsonTextWriter jsonWriter, bool authoritativeZoneRecords, AuthZoneInfo zoneInfo = null)
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

        private static void WriteRecordAsJson(DnsResourceRecord record, JsonTextWriter jsonWriter, bool authoritativeZoneRecords, AuthZoneInfo zoneInfo = null)
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

            DnsResourceRecordInfo recordInfo = record.GetRecordInfo();

            switch (record.Type)
            {
                case DnsResourceRecordType.A:
                    {
                        if (record.RDATA is DnsARecordData rdata)
                        {
                            jsonWriter.WritePropertyName("ipAddress");
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

                case DnsResourceRecordType.NS:
                    {
                        if (record.RDATA is DnsNSRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("nameServer");
                            jsonWriter.WriteValue(rdata.NameServer.Length == 0 ? "." : rdata.NameServer);

                            if (!authoritativeZoneRecords)
                            {
                                if (rdata.IsParentSideTtlSet)
                                {
                                    int parentSideTtl = (int)rdata.ParentSideTtl;

                                    jsonWriter.WritePropertyName("parentSideTtl");
                                    jsonWriter.WriteValue(parentSideTtl + " (" + WebUtilities.GetFormattedTime(parentSideTtl) + ")");
                                }
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
                        if (record.RDATA is DnsCNAMERecordData rdata)
                        {
                            jsonWriter.WritePropertyName("cname");
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

                case DnsResourceRecordType.SOA:
                    {
                        if (record.RDATA is DnsSOARecordData rdata)
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
                        if (record.RDATA is DnsPTRRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("ptrName");
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
                        if (record.RDATA is DnsMXRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("preference");
                            jsonWriter.WriteValue(rdata.Preference);

                            jsonWriter.WritePropertyName("exchange");
                            jsonWriter.WriteValue(rdata.Exchange.Length == 0 ? "." : rdata.Exchange);

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
                        if (record.RDATA is DnsTXTRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("text");
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

                case DnsResourceRecordType.AAAA:
                    {
                        if (record.RDATA is DnsAAAARecordData rdata)
                        {
                            jsonWriter.WritePropertyName("ipAddress");
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

                case DnsResourceRecordType.SRV:
                    {
                        if (record.RDATA is DnsSRVRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("priority");
                            jsonWriter.WriteValue(rdata.Priority);

                            jsonWriter.WritePropertyName("weight");
                            jsonWriter.WriteValue(rdata.Weight);

                            jsonWriter.WritePropertyName("port");
                            jsonWriter.WriteValue(rdata.Port);

                            jsonWriter.WritePropertyName("target");
                            jsonWriter.WriteValue(rdata.Target.Length == 0 ? "." : rdata.Target);
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
                        if (record.RDATA is DnsDNAMERecordData rdata)
                        {
                            jsonWriter.WritePropertyName("dname");
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

                case DnsResourceRecordType.DS:
                    {
                        if (record.RDATA is DnsDSRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("keyTag");
                            jsonWriter.WriteValue(rdata.KeyTag);

                            jsonWriter.WritePropertyName("algorithm");
                            jsonWriter.WriteValue(rdata.Algorithm.ToString());

                            jsonWriter.WritePropertyName("digestType");
                            jsonWriter.WriteValue(rdata.DigestType.ToString());

                            jsonWriter.WritePropertyName("digest");
                            jsonWriter.WriteValue(rdata.Digest);
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

                case DnsResourceRecordType.SSHFP:
                    {
                        if (record.RDATA is DnsSSHFPRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("algorithm");
                            jsonWriter.WriteValue(rdata.Algorithm.ToString());

                            jsonWriter.WritePropertyName("fingerprintType");
                            jsonWriter.WriteValue(rdata.FingerprintType.ToString());

                            jsonWriter.WritePropertyName("fingerprint");
                            jsonWriter.WriteValue(rdata.Fingerprint);
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

                case DnsResourceRecordType.RRSIG:
                    {
                        if (record.RDATA is DnsRRSIGRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("typeCovered");
                            jsonWriter.WriteValue(rdata.TypeCovered.ToString());

                            jsonWriter.WritePropertyName("algorithm");
                            jsonWriter.WriteValue(rdata.Algorithm.ToString());

                            jsonWriter.WritePropertyName("labels");
                            jsonWriter.WriteValue(rdata.Labels);

                            jsonWriter.WritePropertyName("originalTtl");
                            jsonWriter.WriteValue(rdata.OriginalTtl);

                            jsonWriter.WritePropertyName("signatureExpiration");
                            jsonWriter.WriteValue(rdata.SignatureExpiration);

                            jsonWriter.WritePropertyName("signatureInception");
                            jsonWriter.WriteValue(rdata.SignatureInception);

                            jsonWriter.WritePropertyName("keyTag");
                            jsonWriter.WriteValue(rdata.KeyTag);

                            jsonWriter.WritePropertyName("signersName");
                            jsonWriter.WriteValue(rdata.SignersName.Length == 0 ? "." : rdata.SignersName);

                            jsonWriter.WritePropertyName("signature");
                            jsonWriter.WriteValue(Convert.ToBase64String(rdata.Signature));
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

                case DnsResourceRecordType.NSEC:
                    {
                        if (record.RDATA is DnsNSECRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("nextDomainName");
                            jsonWriter.WriteValue(rdata.NextDomainName);

                            jsonWriter.WritePropertyName("types");
                            jsonWriter.WriteStartArray();

                            foreach (DnsResourceRecordType type in rdata.Types)
                                jsonWriter.WriteValue(type.ToString());

                            jsonWriter.WriteEndArray();
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

                case DnsResourceRecordType.DNSKEY:
                    {
                        if (record.RDATA is DnsDNSKEYRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("flags");
                            jsonWriter.WriteValue(rdata.Flags.ToString());

                            jsonWriter.WritePropertyName("protocol");
                            jsonWriter.WriteValue(rdata.Protocol);

                            jsonWriter.WritePropertyName("algorithm");
                            jsonWriter.WriteValue(rdata.Algorithm.ToString());

                            jsonWriter.WritePropertyName("publicKey");
                            jsonWriter.WriteValue(rdata.PublicKey.ToString());

                            jsonWriter.WritePropertyName("computedKeyTag");
                            jsonWriter.WriteValue(rdata.ComputedKeyTag);

                            if (authoritativeZoneRecords)
                            {
                                if (zoneInfo.Type == AuthZoneType.Primary)
                                {
                                    foreach (DnssecPrivateKey dnssecPrivateKey in zoneInfo.DnssecPrivateKeys)
                                    {
                                        if (dnssecPrivateKey.KeyTag == rdata.ComputedKeyTag)
                                        {
                                            jsonWriter.WritePropertyName("dnsKeyState");
                                            jsonWriter.WriteValue(dnssecPrivateKey.State.ToString());

                                            if ((dnssecPrivateKey.KeyType == DnssecPrivateKeyType.KeySigningKey) && (dnssecPrivateKey.State == DnssecPrivateKeyState.Published))
                                            {
                                                jsonWriter.WritePropertyName("dnsKeyStateReadyBy");
                                                jsonWriter.WriteValue((zoneInfo.ApexZone as PrimaryZone).GetDnsKeyStateReadyBy(dnssecPrivateKey));
                                            }
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

                                        jsonWriter.WritePropertyName("digestType");
                                        jsonWriter.WriteValue("SHA256");

                                        jsonWriter.WritePropertyName("digest");
                                        jsonWriter.WriteValue(rdata.CreateDS(record.Name, DnssecDigestType.SHA256).Digest);

                                        jsonWriter.WriteEndObject();
                                    }

                                    {
                                        jsonWriter.WriteStartObject();

                                        jsonWriter.WritePropertyName("digestType");
                                        jsonWriter.WriteValue("SHA384");

                                        jsonWriter.WritePropertyName("digest");
                                        jsonWriter.WriteValue(rdata.CreateDS(record.Name, DnssecDigestType.SHA384).Digest);

                                        jsonWriter.WriteEndObject();
                                    }

                                    jsonWriter.WriteEndArray();
                                }
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

                case DnsResourceRecordType.NSEC3:
                    {
                        if (record.RDATA is DnsNSEC3RecordData rdata)
                        {
                            jsonWriter.WritePropertyName("hashAlgorithm");
                            jsonWriter.WriteValue(rdata.HashAlgorithm.ToString());

                            jsonWriter.WritePropertyName("flags");
                            jsonWriter.WriteValue(rdata.Flags.ToString());

                            jsonWriter.WritePropertyName("iterations");
                            jsonWriter.WriteValue(rdata.Iterations);

                            jsonWriter.WritePropertyName("salt");
                            jsonWriter.WriteValue(rdata.Salt);

                            jsonWriter.WritePropertyName("nextHashedOwnerName");
                            jsonWriter.WriteValue(rdata.NextHashedOwnerName);

                            jsonWriter.WritePropertyName("types");
                            jsonWriter.WriteStartArray();

                            foreach (DnsResourceRecordType type in rdata.Types)
                                jsonWriter.WriteValue(type.ToString());

                            jsonWriter.WriteEndArray();
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

                case DnsResourceRecordType.NSEC3PARAM:
                    {
                        if (record.RDATA is DnsNSEC3PARAMRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("hashAlgorithm");
                            jsonWriter.WriteValue(rdata.HashAlgorithm.ToString());

                            jsonWriter.WritePropertyName("flags");
                            jsonWriter.WriteValue(rdata.Flags.ToString());

                            jsonWriter.WritePropertyName("iterations");
                            jsonWriter.WriteValue(rdata.Iterations);

                            jsonWriter.WritePropertyName("salt");
                            jsonWriter.WriteValue(rdata.Salt);
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

                case DnsResourceRecordType.TLSA:
                    {
                        if (record.RDATA is DnsTLSARecordData rdata)
                        {
                            jsonWriter.WritePropertyName("certificateUsage");
                            jsonWriter.WriteValue(rdata.CertificateUsage.ToString().Replace('_', '-'));

                            jsonWriter.WritePropertyName("selector");
                            jsonWriter.WriteValue(rdata.Selector.ToString());

                            jsonWriter.WritePropertyName("matchingType");
                            jsonWriter.WriteValue(rdata.MatchingType.ToString().Replace('_', '-'));

                            jsonWriter.WritePropertyName("certificateAssociationData");
                            jsonWriter.WriteValue(rdata.CertificateAssociationData);
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
                        if (record.RDATA is DnsCAARecordData rdata)
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
                        if (record.RDATA is DnsANAMERecordData rdata)
                        {
                            jsonWriter.WritePropertyName("aname");
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
                        if (record.RDATA is DnsForwarderRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("protocol");
                            jsonWriter.WriteValue(rdata.Protocol.ToString());

                            jsonWriter.WritePropertyName("forwarder");
                            jsonWriter.WriteValue(rdata.Forwarder);

                            jsonWriter.WritePropertyName("dnssecValidation");
                            jsonWriter.WriteValue(rdata.DnssecValidation);

                            jsonWriter.WritePropertyName("proxyType");
                            jsonWriter.WriteValue(rdata.ProxyType.ToString());

                            if (rdata.ProxyType != NetProxyType.None)
                            {
                                jsonWriter.WritePropertyName("proxyAddress");
                                jsonWriter.WriteValue(rdata.ProxyAddress);

                                jsonWriter.WritePropertyName("proxyPort");
                                jsonWriter.WriteValue(rdata.ProxyPort);

                                jsonWriter.WritePropertyName("proxyUsername");
                                jsonWriter.WriteValue(rdata.ProxyUsername);

                                jsonWriter.WritePropertyName("proxyPassword");
                                jsonWriter.WriteValue(rdata.ProxyPassword);
                            }
                        }
                    }
                    break;

                case DnsResourceRecordType.APP:
                    {
                        if (record.RDATA is DnsApplicationRecordData rdata)
                        {
                            jsonWriter.WritePropertyName("appName");
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
                        if (record.RDATA is DnsUnknownRecordData)
                        {
                            jsonWriter.WritePropertyName("value");

                            using (MemoryStream mS = new MemoryStream())
                            {
                                record.RDATA.WriteTo(mS);

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

                jsonWriter.WritePropertyName("glueRecords");
                jsonWriter.WriteValue(glue);
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
                        jsonWriter.WriteValue(rrsigRecord.ToString());
                }

                if (nsecRecords is not null)
                {
                    foreach (DnsResourceRecord nsecRecord in nsecRecords)
                        jsonWriter.WriteValue(nsecRecord.ToString());
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("dnssecStatus");
            jsonWriter.WriteValue(record.DnssecStatus.ToString());

            NetworkAddress eDnsClientSubnet = recordInfo.EDnsClientSubnet;
            if (eDnsClientSubnet is not null)
            {
                jsonWriter.WritePropertyName("eDnsClientSubnet");
                jsonWriter.WriteValue(eDnsClientSubnet.ToString());
            }

            jsonWriter.WritePropertyName("lastUsedOn");
            jsonWriter.WriteValue(recordInfo.LastUsedOn);

            jsonWriter.WriteEndObject();
        }

        private static void WriteZoneInfoAsJson(AuthZoneInfo zoneInfo, JsonTextWriter jsonWriter)
        {
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

                    jsonWriter.WritePropertyName("dnssecStatus");
                    jsonWriter.WriteValue(zoneInfo.DnssecStatus.ToString());

                    if (!zoneInfo.Internal)
                    {
                        jsonWriter.WritePropertyName("notifyFailed");
                        jsonWriter.WriteValue(zoneInfo.NotifyFailed);
                    }
                    break;

                case AuthZoneType.Secondary:
                    jsonWriter.WritePropertyName("dnssecStatus");
                    jsonWriter.WriteValue(zoneInfo.DnssecStatus.ToString());

                    jsonWriter.WritePropertyName("expiry");
                    jsonWriter.WriteValue(zoneInfo.Expiry);

                    jsonWriter.WritePropertyName("isExpired");
                    jsonWriter.WriteValue(zoneInfo.IsExpired);

                    jsonWriter.WritePropertyName("notifyFailed");
                    jsonWriter.WriteValue(zoneInfo.NotifyFailed);

                    jsonWriter.WritePropertyName("syncFailed");
                    jsonWriter.WriteValue(zoneInfo.SyncFailed);
                    break;

                case AuthZoneType.Stub:
                    jsonWriter.WritePropertyName("expiry");
                    jsonWriter.WriteValue(zoneInfo.Expiry);

                    jsonWriter.WritePropertyName("isExpired");
                    jsonWriter.WriteValue(zoneInfo.IsExpired);

                    jsonWriter.WritePropertyName("syncFailed");
                    jsonWriter.WriteValue(zoneInfo.SyncFailed);
                    break;
            }

            jsonWriter.WritePropertyName("disabled");
            jsonWriter.WriteValue(zoneInfo.Disabled);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region public

        public void ListZones(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            List<AuthZoneInfo> zones = _dnsWebService.DnsServer.AuthZoneManager.ListZones();
            zones.Sort();

            UserSession session = _dnsWebService.GetSession(request);

            jsonWriter.WritePropertyName("zones");
            jsonWriter.WriteStartArray();

            foreach (AuthZoneInfo zone in zones)
            {
                if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zone.Name, session.User, PermissionFlag.View))
                    continue;

                WriteZoneInfoAsJson(zone, jsonWriter);
            }

            jsonWriter.WriteEndArray();
        }

        public async Task CreateZoneAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                zoneName = request.QueryString["domain"];

            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

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

            AuthZoneType type = AuthZoneType.Primary;
            string strType = request.QueryString["type"];
            if (!string.IsNullOrEmpty(strType))
                type = Enum.Parse<AuthZoneType>(strType, true);

            AuthZoneInfo zoneInfo;

            switch (type)
            {
                case AuthZoneType.Primary:
                    {
                        zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreatePrimaryZone(zoneName, _dnsWebService.DnsServer.ServerDomain, false);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        UserSession session = _dnsWebService.GetSession(request);

                        //set permissions
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SaveConfigFile();

                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Authoritative primary zone was created: " + zoneName);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
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

                        zoneInfo = await _dnsWebService.DnsServer.AuthZoneManager.CreateSecondaryZoneAsync(zoneName, primaryNameServerAddresses, zoneTransferProtocol, tsigKeyName);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        UserSession session = _dnsWebService.GetSession(request);

                        //set permissions
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SaveConfigFile();

                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Authoritative secondary zone was created: " + zoneName);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
                    break;

                case AuthZoneType.Stub:
                    {
                        string strPrimaryNameServerAddresses = request.QueryString["primaryNameServerAddresses"];
                        if (string.IsNullOrEmpty(strPrimaryNameServerAddresses))
                            strPrimaryNameServerAddresses = null;

                        zoneInfo = await _dnsWebService.DnsServer.AuthZoneManager.CreateStubZoneAsync(zoneName, strPrimaryNameServerAddresses);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        UserSession session = _dnsWebService.GetSession(request);

                        //set permissions
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SaveConfigFile();

                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Stub zone was created: " + zoneName);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
                    break;

                case AuthZoneType.Forwarder:
                    {
                        DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;
                        string strForwarderProtocol = request.QueryString["protocol"];
                        if (!string.IsNullOrEmpty(strForwarderProtocol))
                            forwarderProtocol = Enum.Parse<DnsTransportProtocol>(strForwarderProtocol, true);

                        string strForwarder = request.QueryString["forwarder"];
                        if (string.IsNullOrEmpty(strForwarder))
                            throw new DnsWebServiceException("Parameter 'forwarder' missing.");

                        bool dnssecValidation = false;
                        string strDnssecValidation = request.QueryString["dnssecValidation"];
                        if (!string.IsNullOrEmpty(strDnssecValidation))
                            dnssecValidation = bool.Parse(strDnssecValidation);

                        NetProxyType proxyType = NetProxyType.None;
                        string strProxyType = request.QueryString["proxyType"];
                        if (!string.IsNullOrEmpty(strProxyType))
                            proxyType = Enum.Parse<NetProxyType>(strProxyType, true);

                        string proxyAddress = null;
                        ushort proxyPort = 0;
                        string proxyUsername = null;
                        string proxyPassword = null;

                        if (proxyType != NetProxyType.None)
                        {
                            proxyAddress = request.QueryString["proxyAddress"];
                            if (string.IsNullOrEmpty(proxyAddress))
                                throw new DnsWebServiceException("Parameter 'proxyAddress' missing.");

                            string strProxyPort = request.QueryString["proxyPort"];
                            if (string.IsNullOrEmpty(strProxyPort))
                                throw new DnsWebServiceException("Parameter 'proxyPort' missing.");

                            proxyPort = ushort.Parse(strProxyPort);
                            proxyUsername = request.QueryString["proxyUsername"];
                            proxyPassword = request.QueryString["proxyPassword"];
                        }

                        zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreateForwarderZone(zoneName, forwarderProtocol, strForwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, null);
                        if (zoneInfo is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        UserSession session = _dnsWebService.GetSession(request);

                        //set permissions
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService.AuthManager.SaveConfigFile();

                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Forwarder zone was created: " + zoneName);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                    }
                    break;

                default:
                    throw new NotSupportedException("Zone type not supported.");
            }

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
            _dnsWebService.DnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(string.IsNullOrEmpty(zoneInfo.Name) ? "." : zoneInfo.Name);
        }

        public void SignPrimaryZone(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string algorithm = request.QueryString["algorithm"];
            if (string.IsNullOrEmpty(algorithm))
                throw new DnsWebServiceException("Parameter 'algorithm' missing.");

            uint dnsKeyTtl;
            string strDnsKeyTtl = request.QueryString["dnsKeyTtl"];
            if (string.IsNullOrEmpty(strDnsKeyTtl))
                dnsKeyTtl = 24 * 60 * 60;
            else
                dnsKeyTtl = uint.Parse(strDnsKeyTtl);

            ushort zskRolloverDays;
            string strZskRolloverDays = request.QueryString["zskRolloverDays"];
            if (string.IsNullOrEmpty(strZskRolloverDays))
                zskRolloverDays = 90;
            else
                zskRolloverDays = ushort.Parse(strZskRolloverDays);

            bool useNSEC3 = false;
            string strNxProof = request.QueryString["nxProof"];
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
                string strIterations = request.QueryString["iterations"];
                if (!string.IsNullOrEmpty(strIterations))
                    iterations = ushort.Parse(strIterations);

                string strSaltLength = request.QueryString["saltLength"];
                if (!string.IsNullOrEmpty(strSaltLength))
                    saltLength = byte.Parse(strSaltLength);
            }

            switch (algorithm.ToUpper())
            {
                case "RSA":
                    string hashAlgorithm = request.QueryString["hashAlgorithm"];
                    if (string.IsNullOrEmpty(hashAlgorithm))
                        throw new DnsWebServiceException("Parameter 'hashAlgorithm' missing.");

                    string strKSKKeySize = request.QueryString["kskKeySize"];
                    if (string.IsNullOrEmpty(strKSKKeySize))
                        throw new DnsWebServiceException("Parameter 'kskKeySize' missing.");

                    string strZSKKeySize = request.QueryString["zskKeySize"];
                    if (string.IsNullOrEmpty(strZSKKeySize))
                        throw new DnsWebServiceException("Parameter 'zskKeySize' missing.");

                    int kskKeySize = int.Parse(strKSKKeySize);
                    int zskKeySize = int.Parse(strZSKKeySize);

                    if (useNSEC3)
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithRsaNSEC3(zoneName, hashAlgorithm, kskKeySize, zskKeySize, iterations, saltLength, dnsKeyTtl, zskRolloverDays);
                    else
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithRsaNSEC(zoneName, hashAlgorithm, kskKeySize, zskKeySize, dnsKeyTtl, zskRolloverDays);

                    break;

                case "ECDSA":
                    string curve = request.QueryString["curve"];
                    if (string.IsNullOrEmpty(curve))
                        throw new DnsWebServiceException("Parameter 'curve' missing.");

                    if (useNSEC3)
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithEcdsaNSEC3(zoneName, curve, iterations, saltLength, dnsKeyTtl, zskRolloverDays);
                    else
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithEcdsaNSEC(zoneName, curve, dnsKeyTtl, zskRolloverDays);

                    break;

                default:
                    throw new NotSupportedException("Algorithm is not supported: " + algorithm);
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Primary zone was signed successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UnsignPrimaryZone(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService.DnsServer.AuthZoneManager.UnsignPrimaryZone(zoneName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Primary zone was unsigned successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void GetPrimaryZoneDnssecProperties(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (zoneInfo.Type != AuthZoneType.Primary)
                throw new DnsWebServiceException("The zone must be a primary zone.");

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            jsonWriter.WritePropertyName("name");
            jsonWriter.WriteValue(zoneInfo.Name);

            jsonWriter.WritePropertyName("type");
            jsonWriter.WriteValue(zoneInfo.Type.ToString());

            jsonWriter.WritePropertyName("internal");
            jsonWriter.WriteValue(zoneInfo.Internal);

            jsonWriter.WritePropertyName("disabled");
            jsonWriter.WriteValue(zoneInfo.Disabled);

            jsonWriter.WritePropertyName("dnssecStatus");
            jsonWriter.WriteValue(zoneInfo.DnssecStatus.ToString());

            if (zoneInfo.DnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC3)
            {
                IReadOnlyList<DnsResourceRecord> nsec3ParamRecords = zoneInfo.GetApexRecords(DnsResourceRecordType.NSEC3PARAM);
                DnsNSEC3PARAMRecordData nsec3Param = nsec3ParamRecords[0].RDATA as DnsNSEC3PARAMRecordData;

                jsonWriter.WritePropertyName("nsec3Iterations");
                jsonWriter.WriteValue(nsec3Param.Iterations);

                jsonWriter.WritePropertyName("nsec3SaltLength");
                jsonWriter.WriteValue(nsec3Param.SaltValue.Length);
            }

            jsonWriter.WritePropertyName("dnsKeyTtl");
            jsonWriter.WriteValue(zoneInfo.DnsKeyTtl);

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

                    jsonWriter.WritePropertyName("keyTag");
                    jsonWriter.WriteValue(dnssecPrivateKey.KeyTag);

                    jsonWriter.WritePropertyName("keyType");
                    jsonWriter.WriteValue(dnssecPrivateKey.KeyType.ToString());

                    jsonWriter.WritePropertyName("algorithm");
                    switch (dnssecPrivateKey.Algorithm)
                    {
                        case DnssecAlgorithm.RSAMD5:
                        case DnssecAlgorithm.RSASHA1:
                        case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                        case DnssecAlgorithm.RSASHA256:
                        case DnssecAlgorithm.RSASHA512:
                            jsonWriter.WriteValue(dnssecPrivateKey.Algorithm.ToString() + " (" + (dnssecPrivateKey as DnssecRsaPrivateKey).KeySize + " bits)");
                            break;

                        default:
                            jsonWriter.WriteValue(dnssecPrivateKey.Algorithm.ToString());
                            break;
                    }

                    jsonWriter.WritePropertyName("state");
                    jsonWriter.WriteValue(dnssecPrivateKey.State.ToString());

                    jsonWriter.WritePropertyName("stateChangedOn");
                    jsonWriter.WriteValue(dnssecPrivateKey.StateChangedOn);

                    jsonWriter.WritePropertyName("isRetiring");
                    jsonWriter.WriteValue(dnssecPrivateKey.IsRetiring);

                    jsonWriter.WritePropertyName("rolloverDays");
                    jsonWriter.WriteValue(dnssecPrivateKey.RolloverDays);

                    jsonWriter.WriteEndObject();
                }
            }

            jsonWriter.WriteEndArray();
        }

        public void ConvertPrimaryZoneToNSEC(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService.DnsServer.AuthZoneManager.ConvertPrimaryZoneToNSEC(zoneName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Primary zone was converted to NSEC successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void ConvertPrimaryZoneToNSEC3(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort iterations = 0;
            string strIterations = request.QueryString["iterations"];
            if (!string.IsNullOrEmpty(strIterations))
                iterations = ushort.Parse(strIterations);

            byte saltLength = 0;
            string strSaltLength = request.QueryString["saltLength"];
            if (!string.IsNullOrEmpty(strSaltLength))
                saltLength = byte.Parse(strSaltLength);

            _dnsWebService.DnsServer.AuthZoneManager.ConvertPrimaryZoneToNSEC3(zoneName, iterations, saltLength);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Primary zone was converted to NSEC3 successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UpdatePrimaryZoneNSEC3Parameters(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            ushort iterations = 0;
            string strIterations = request.QueryString["iterations"];
            if (!string.IsNullOrEmpty(strIterations))
                iterations = ushort.Parse(strIterations);

            byte saltLength = 0;
            string strSaltLength = request.QueryString["saltLength"];
            if (!string.IsNullOrEmpty(strSaltLength))
                saltLength = byte.Parse(strSaltLength);

            _dnsWebService.DnsServer.AuthZoneManager.UpdatePrimaryZoneNSEC3Parameters(zoneName, iterations, saltLength);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Primary zone NSEC3 parameters were updated successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UpdatePrimaryZoneDnssecDnsKeyTtl(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string strDnsKeyTtl = request.QueryString["ttl"];
            if (string.IsNullOrEmpty(strDnsKeyTtl))
                throw new DnsWebServiceException("Parameter 'ttl' missing.");

            uint dnsKeyTtl = uint.Parse(strDnsKeyTtl);

            _dnsWebService.DnsServer.AuthZoneManager.UpdatePrimaryZoneDnsKeyTtl(zoneName, dnsKeyTtl);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Primary zone DNSKEY TTL was updated successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void GenerateAndAddPrimaryZoneDnssecPrivateKey(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string strKeyType = request.QueryString["keyType"];
            if (string.IsNullOrEmpty(strKeyType))
                throw new DnsWebServiceException("Parameter 'keyType' missing.");

            DnssecPrivateKeyType keyType = Enum.Parse<DnssecPrivateKeyType>(strKeyType, true);

            ushort rolloverDays;
            string strRolloverDays = request.QueryString["rolloverDays"];
            if (string.IsNullOrEmpty(strRolloverDays))
                rolloverDays = (ushort)(keyType == DnssecPrivateKeyType.ZoneSigningKey ? 90 : 0);
            else
                rolloverDays = ushort.Parse(strRolloverDays);

            string algorithm = request.QueryString["algorithm"];
            if (string.IsNullOrEmpty(algorithm))
                throw new DnsWebServiceException("Parameter 'algorithm' missing.");

            switch (algorithm.ToUpper())
            {
                case "RSA":
                    string hashAlgorithm = request.QueryString["hashAlgorithm"];
                    if (string.IsNullOrEmpty(hashAlgorithm))
                        throw new DnsWebServiceException("Parameter 'hashAlgorithm' missing.");

                    string strKeySize = request.QueryString["keySize"];
                    if (string.IsNullOrEmpty(strKeySize))
                        throw new DnsWebServiceException("Parameter 'keySize' missing.");

                    int keySize = int.Parse(strKeySize);

                    _dnsWebService.DnsServer.AuthZoneManager.GenerateAndAddPrimaryZoneDnssecRsaPrivateKey(zoneName, keyType, hashAlgorithm, keySize, rolloverDays);
                    break;

                case "ECDSA":
                    string curve = request.QueryString["curve"];
                    if (string.IsNullOrEmpty(curve))
                        throw new DnsWebServiceException("Parameter 'curve' missing.");

                    _dnsWebService.DnsServer.AuthZoneManager.GenerateAndAddPrimaryZoneDnssecEcdsaPrivateKey(zoneName, keyType, curve, rolloverDays);
                    break;

                default:
                    throw new NotSupportedException("Algorithm is not supported: " + algorithm);
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] DNSSEC private key was generated and added to the primary zone successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UpdatePrimaryZoneDnssecPrivateKey(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string strKeyTag = request.QueryString["keyTag"];
            if (string.IsNullOrEmpty(strKeyTag))
                throw new DnsWebServiceException("Parameter 'keyTag' missing.");

            ushort keyTag = ushort.Parse(strKeyTag);

            string strRolloverDays = request.QueryString["rolloverDays"];
            if (string.IsNullOrEmpty(strRolloverDays))
                throw new DnsWebServiceException("Parameter 'rolloverDays' missing.");

            ushort rolloverDays = ushort.Parse(strRolloverDays);

            _dnsWebService.DnsServer.AuthZoneManager.UpdatePrimaryZoneDnssecPrivateKey(zoneName, keyTag, rolloverDays);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Primary zone DNSSEC private key config was updated successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void DeletePrimaryZoneDnssecPrivateKey(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string strKeyTag = request.QueryString["keyTag"];
            if (string.IsNullOrEmpty(strKeyTag))
                throw new DnsWebServiceException("Parameter 'keyTag' missing.");

            ushort keyTag = ushort.Parse(strKeyTag);

            _dnsWebService.DnsServer.AuthZoneManager.DeletePrimaryZoneDnssecPrivateKey(zoneName, keyTag);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] DNSSEC private key was deleted from primary zone successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            _dnsWebService.DnsServer.AuthZoneManager.PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(zoneName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] All DNSSEC private keys from the primary zone were published successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void RolloverPrimaryZoneDnsKey(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string strKeyTag = request.QueryString["keyTag"];
            if (string.IsNullOrEmpty(strKeyTag))
                throw new DnsWebServiceException("Parameter 'keyTag' missing.");

            ushort keyTag = ushort.Parse(strKeyTag);

            _dnsWebService.DnsServer.AuthZoneManager.RolloverPrimaryZoneDnsKey(zoneName, keyTag);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] The DNSKEY (" + keyTag + ") from the primary zone was rolled over successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void RetirePrimaryZoneDnsKey(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneName, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string strKeyTag = request.QueryString["keyTag"];
            if (string.IsNullOrEmpty(strKeyTag))
                throw new DnsWebServiceException("Parameter 'keyTag' missing.");

            ushort keyTag = ushort.Parse(strKeyTag);

            _dnsWebService.DnsServer.AuthZoneManager.RetirePrimaryZoneDnsKey(zoneName, keyTag);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] The DNSKEY (" + keyTag + ") from the primary zone was retired successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void DeleteZone(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                zoneName = request.QueryString["domain"];

            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            if (!_dnsWebService.DnsServer.AuthZoneManager.DeleteZone(zoneInfo.Name))
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneInfo.Name);

            _dnsWebService.AuthManager.RemoveAllPermissions(PermissionSection.Zones, zoneInfo.Name);
            _dnsWebService.AuthManager.SaveConfigFile();

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone was deleted: " + zoneName);
            _dnsWebService.DnsServer.AuthZoneManager.DeleteZoneFile(zoneInfo.Name);
        }

        public void EnableZone(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                zoneName = request.QueryString["domain"];

            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            zoneInfo.Disabled = false;

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone was enabled: " + zoneInfo.Name);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
            _dnsWebService.DnsServer.CacheZoneManager.DeleteZone(zoneInfo.Name);
        }

        public void DisableZone(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                zoneName = request.QueryString["domain"];

            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            zoneInfo.Disabled = true;

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone was disabled: " + zoneInfo.Name);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void GetZoneOptions(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                zoneName = request.QueryString["domain"];

            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            bool includeAvailableTsigKeyNames;
            string strIncludeAvailableTsigKeyNames = request.QueryString["includeAvailableTsigKeyNames"];
            if (string.IsNullOrEmpty(strIncludeAvailableTsigKeyNames))
                includeAvailableTsigKeyNames = false;
            else
                includeAvailableTsigKeyNames = bool.Parse(strIncludeAvailableTsigKeyNames);

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such zone was found: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            jsonWriter.WritePropertyName("name");
            jsonWriter.WriteValue(zoneInfo.Name);

            jsonWriter.WritePropertyName("type");
            jsonWriter.WriteValue(zoneInfo.Type.ToString());

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    jsonWriter.WritePropertyName("internal");
                    jsonWriter.WriteValue(zoneInfo.Internal);

                    jsonWriter.WritePropertyName("dnssecStatus");
                    jsonWriter.WriteValue(zoneInfo.DnssecStatus.ToString());
                    break;

                case AuthZoneType.Secondary:
                    jsonWriter.WritePropertyName("dnssecStatus");
                    jsonWriter.WriteValue(zoneInfo.DnssecStatus.ToString());
                    break;
            }

            jsonWriter.WritePropertyName("disabled");
            jsonWriter.WriteValue(zoneInfo.Disabled);

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Secondary:
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

                    jsonWriter.WritePropertyName("zoneTransferTsigKeyNames");
                    {
                        jsonWriter.WriteStartArray();

                        if (zoneInfo.ZoneTransferTsigKeyNames is not null)
                        {
                            foreach (KeyValuePair<string, object> tsigKeyName in zoneInfo.ZoneTransferTsigKeyNames)
                                jsonWriter.WriteValue(tsigKeyName.Key);
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

                    break;
            }

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    jsonWriter.WritePropertyName("update");
                    jsonWriter.WriteValue(zoneInfo.Update.ToString());

                    jsonWriter.WritePropertyName("updateIpAddresses");
                    {
                        jsonWriter.WriteStartArray();

                        if (zoneInfo.UpdateIpAddresses is not null)
                        {
                            foreach (IPAddress updateIpAddress in zoneInfo.UpdateIpAddresses)
                                jsonWriter.WriteValue(updateIpAddress.ToString());
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

                                    jsonWriter.WritePropertyName("tsigKeyName");
                                    jsonWriter.WriteValue(updateSecurityPolicy.Key);

                                    jsonWriter.WritePropertyName("domain");
                                    jsonWriter.WriteValue(policy.Key);

                                    jsonWriter.WritePropertyName("allowedTypes");
                                    jsonWriter.WriteStartArray();

                                    foreach (DnsResourceRecordType allowedType in policy.Value)
                                        jsonWriter.WriteValue(allowedType.ToString());

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
                            jsonWriter.WriteValue(tsigKey.Key);
                    }

                    jsonWriter.WriteEndArray();
                }
            }
        }

        public void SetZoneOptions(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                zoneName = request.QueryString["domain"];

            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string strDisabled = request.QueryString["disabled"];
            if (!string.IsNullOrEmpty(strDisabled))
                zoneInfo.Disabled = bool.Parse(strDisabled);

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                case AuthZoneType.Secondary:
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

                    string strZoneTransferTsigKeyNames = request.QueryString["zoneTransferTsigKeyNames"];
                    if (!string.IsNullOrEmpty(strZoneTransferTsigKeyNames))
                    {
                        if (strZoneTransferTsigKeyNames == "false")
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
                    break;
            }

            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    string strUpdate = request.QueryString["update"];
                    if (!string.IsNullOrEmpty(strUpdate))
                        zoneInfo.Update = Enum.Parse<AuthZoneUpdate>(strUpdate, true);

                    string strUpdateIpAddresses = request.QueryString["updateIpAddresses"];
                    if (!string.IsNullOrEmpty(strUpdateIpAddresses))
                    {
                        if (strUpdateIpAddresses == "false")
                        {
                            zoneInfo.UpdateIpAddresses = null;
                        }
                        else
                        {
                            string[] strIpAddresses = strUpdateIpAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                            IPAddress[] ipAddresses = new IPAddress[strIpAddresses.Length];

                            for (int i = 0; i < strIpAddresses.Length; i++)
                                ipAddresses[i] = IPAddress.Parse(strIpAddresses[i]);

                            zoneInfo.UpdateIpAddresses = ipAddresses;
                        }
                    }

                    string strUpdateSecurityPolicies = request.QueryString["updateSecurityPolicies"];
                    if (!string.IsNullOrEmpty(strUpdateSecurityPolicies))
                    {
                        if (strUpdateSecurityPolicies == "false")
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

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] " + zoneInfo.Type.ToString() + " zone options were updated successfully: " + zoneInfo.Name);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void ResyncZone(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                zoneName = request.QueryString["domain"];

            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
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

        public void AddRecord(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            string zoneName = request.QueryString["zone"];
            if (zoneName is not null)
                zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = Enum.Parse<DnsResourceRecordType>(strType, true);

            string value = request.QueryString["value"];

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

            DnsResourceRecord newRecord;

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        string strIPAddress = request.QueryString["ipAddress"];
                        if (string.IsNullOrEmpty(strIPAddress))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'ipAddress' missing.");

                            strIPAddress = value;
                        }

                        IPAddress ipAddress;

                        if (strIPAddress.Equals("request-ip-address"))
                            ipAddress = DnsWebService.GetRequestRemoteEndPoint(request).Address;
                        else
                            ipAddress = IPAddress.Parse(strIPAddress);

                        bool ptr = false;
                        string strPtr = request.QueryString["ptr"];
                        if (!string.IsNullOrEmpty(strPtr))
                            ptr = bool.Parse(strPtr);

                        if (ptr)
                        {
                            string ptrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
                            if (reverseZoneInfo is null)
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

                                //set permissions
                                _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                                _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                _dnsWebService.AuthManager.SaveConfigFile();
                            }

                            if (reverseZoneInfo.Internal)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is an internal zone.");

                            if (reverseZoneInfo.Type != AuthZoneType.Primary)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is not a primary zone.");

                            _dnsWebService.DnsServer.AuthZoneManager.SetRecords(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecordData[] { new DnsPTRRecordData(domain) });
                            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                        }

                        if (type == DnsResourceRecordType.A)
                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsARecordData(ipAddress));
                        else
                            newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsAAAARecordData(ipAddress));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nameServer = request.QueryString["nameServer"];
                        if (string.IsNullOrEmpty(nameServer))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'nameServer' missing.");

                            nameServer = value;
                        }

                        string glueAddresses = request.QueryString["glue"];
                        if (string.IsNullOrEmpty(glueAddresses))
                            glueAddresses = null;

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsNSRecordData(nameServer.TrimEnd('.')));

                        if (glueAddresses != null)
                            newRecord.SetGlueRecords(glueAddresses);

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

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

                        string cname = request.QueryString["cname"];
                        if (string.IsNullOrEmpty(cname))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'cname' missing.");

                            cname = value;
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCNAMERecordData(cname.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        string ptrName = request.QueryString["ptrName"];
                        if (string.IsNullOrEmpty(ptrName))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'ptrName' missing.");

                            ptrName = value;
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsPTRRecordData(ptrName.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        string exchange = request.QueryString["exchange"];
                        if (string.IsNullOrEmpty(exchange))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'exchange' missing.");

                            exchange = value;
                        }

                        string preference = request.QueryString["preference"];
                        if (string.IsNullOrEmpty(preference))
                            throw new DnsWebServiceException("Parameter 'preference' missing.");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsMXRecordData(ushort.Parse(preference), exchange.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string text = request.QueryString["text"];
                        if (string.IsNullOrEmpty(text))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'text' missing.");

                            text = value;
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsTXTRecordData(text));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
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

                        string target = request.QueryString["target"];
                        if (string.IsNullOrEmpty(target))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'target' missing.");

                            target = value;
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSRVRecordData(ushort.Parse(priority), ushort.Parse(weight), ushort.Parse(port), target.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

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

                        string dname = request.QueryString["dname"];
                        if (string.IsNullOrEmpty(dname))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'dname' missing.");

                            dname = value;
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsDNAMERecordData(dname.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DS:
                    {
                        string strKeyTag = request.QueryString["keyTag"];
                        if (string.IsNullOrEmpty(strKeyTag))
                            throw new DnsWebServiceException("Parameter 'keyTag' missing.");

                        string strAlgorithm = request.QueryString["algorithm"];
                        if (string.IsNullOrEmpty(strAlgorithm))
                            throw new DnsWebServiceException("Parameter 'algorithm' missing.");

                        string strDigestType = request.QueryString["digestType"];
                        if (string.IsNullOrEmpty(strDigestType))
                            throw new DnsWebServiceException("Parameter 'digestType' missing.");

                        string digest = request.QueryString["digest"];
                        if (string.IsNullOrEmpty(digest))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'digest' missing.");

                            digest = value;
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsDSRecordData(ushort.Parse(strKeyTag), Enum.Parse<DnssecAlgorithm>(strAlgorithm.Replace('-', '_'), true), Enum.Parse<DnssecDigestType>(strDigestType.Replace('-', '_'), true), Convert.FromHexString(digest)));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SSHFP:
                    {
                        string strAlgorithm = request.QueryString["sshfpAlgorithm"];
                        if (string.IsNullOrEmpty(strAlgorithm))
                            throw new DnsWebServiceException("Parameter 'sshfpAlgorithm' missing.");

                        string strFingerprintType = request.QueryString["sshfpFingerprintType"];
                        if (string.IsNullOrEmpty(strFingerprintType))
                            throw new DnsWebServiceException("Parameter 'sshfpFingerprintType' missing.");

                        string strFingerprint = request.QueryString["sshfpFingerprint"];
                        if (string.IsNullOrEmpty(strFingerprint))
                            throw new DnsWebServiceException("Parameter 'sshfpFingerprint' missing.");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSSHFPRecordData(Enum.Parse<DnsSSHFPAlgorithm>(strAlgorithm, true), Enum.Parse<DnsSSHFPFingerprintType>(strFingerprintType, true), Convert.FromHexString(strFingerprint)));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TLSA:
                    {
                        string strCertificateUsage = request.QueryString["tlsaCertificateUsage"];
                        if (string.IsNullOrEmpty(strCertificateUsage))
                            throw new DnsWebServiceException("Parameter 'tlsaCertificateUsage' missing.");

                        string strSelector = request.QueryString["tlsaSelector"];
                        if (string.IsNullOrEmpty(strSelector))
                            throw new DnsWebServiceException("Parameter 'tlsaSelector' missing.");

                        string strMatchingType = request.QueryString["tlsaMatchingType"];
                        if (string.IsNullOrEmpty(strMatchingType))
                            throw new DnsWebServiceException("Parameter 'tlsaMatchingType' missing.");

                        string strCertificateAssociationData = request.QueryString["tlsaCertificateAssociationData"];
                        if (string.IsNullOrEmpty(strCertificateAssociationData))
                            throw new DnsWebServiceException("Parameter 'tlsaCertificateAssociationData' missing.");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsTLSARecordData(Enum.Parse<DnsTLSACertificateUsage>(strCertificateUsage.Replace('-', '_'), true), Enum.Parse<DnsTLSASelector>(strSelector, true), Enum.Parse<DnsTLSAMatchingType>(strMatchingType.Replace('-', '_'), true), strCertificateAssociationData));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
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

                        if (string.IsNullOrEmpty(value))
                            throw new DnsWebServiceException("Parameter 'value' missing.");

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCAARecordData(byte.Parse(flags), tag, value));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        string aname = request.QueryString["aname"];
                        if (string.IsNullOrEmpty(aname))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'aname' missing.");

                            aname = value;
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsANAMERecordData(aname.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        DnsTransportProtocol protocol = DnsTransportProtocol.Udp;
                        string strProtocol = request.QueryString["protocol"];
                        if (!string.IsNullOrEmpty(strProtocol))
                            protocol = Enum.Parse<DnsTransportProtocol>(strProtocol, true);

                        string forwarder = request.QueryString["forwarder"];
                        if (string.IsNullOrEmpty(forwarder))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'forwarder' missing.");

                            forwarder = value;
                        }

                        bool dnssecValidation = false;
                        string strDnssecValidation = request.QueryString["dnssecValidation"];
                        if (!string.IsNullOrEmpty(strDnssecValidation))
                            dnssecValidation = bool.Parse(strDnssecValidation);

                        NetProxyType proxyType = NetProxyType.None;
                        string proxyAddress = null;
                        ushort proxyPort = 0;
                        string proxyUsername = null;
                        string proxyPassword = null;

                        if (!forwarder.Equals("this-server"))
                        {
                            string strProxyType = request.QueryString["proxyType"];
                            if (!string.IsNullOrEmpty(strProxyType))
                                proxyType = Enum.Parse<NetProxyType>(strProxyType, true);

                            if (proxyType != NetProxyType.None)
                            {
                                proxyAddress = request.QueryString["proxyAddress"];
                                if (string.IsNullOrEmpty(proxyAddress))
                                    throw new DnsWebServiceException("Parameter 'proxyAddress' missing.");

                                string strProxyPort = request.QueryString["proxyPort"];
                                if (string.IsNullOrEmpty(strProxyPort))
                                    throw new DnsWebServiceException("Parameter 'proxyPort' missing.");

                                proxyPort = ushort.Parse(strProxyPort);
                                proxyUsername = request.QueryString["proxyUsername"];
                                proxyPassword = request.QueryString["proxyPassword"];
                            }
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecordData(protocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                case DnsResourceRecordType.APP:
                    {
                        string appName = request.QueryString["appName"];
                        if (string.IsNullOrEmpty(appName))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'appName' missing.");

                            appName = value;
                        }

                        string classPath = request.QueryString["classPath"];
                        if (string.IsNullOrEmpty(classPath))
                            throw new DnsWebServiceException("Parameter 'classPath' missing.");

                        string recordData = request.QueryString["recordData"];
                        if (string.IsNullOrEmpty(recordData))
                            recordData = "";

                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(zoneInfo.Name, domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsApplicationRecordData(appName, classPath, recordData));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newRecord);
                    }
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for AddRecords().");
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] New record was added to authoritative zone {domain: " + domain + "; type: " + type + "; value: " + value + "; ttl: " + ttl + ";}");

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

            jsonWriter.WritePropertyName("zone");
            WriteZoneInfoAsJson(zoneInfo, jsonWriter);

            jsonWriter.WritePropertyName("addedRecord");
            WriteRecordAsJson(newRecord, jsonWriter, true, null);
        }

        public void GetRecords(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(domain);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            jsonWriter.WritePropertyName("zone");
            WriteZoneInfoAsJson(zoneInfo, jsonWriter);

            List<DnsResourceRecord> records = new List<DnsResourceRecord>();
            _dnsWebService.DnsServer.AuthZoneManager.ListAllRecords(domain, records);

            WriteRecordsAsJson(records, jsonWriter, true, zoneInfo);
        }

        public void DeleteRecord(HttpListenerRequest request)
        {
            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            string zoneName = request.QueryString["zone"];
            if (zoneName is not null)
                zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Delete))
                throw new DnsWebServiceException("Access was denied.");

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = Enum.Parse<DnsResourceRecordType>(strType, true);

            string value = request.QueryString["value"];

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        string strIPAddress = request.QueryString["ipAddress"];
                        if (string.IsNullOrEmpty(strIPAddress))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'ipAddress' missing.");

                            strIPAddress = value;
                        }

                        IPAddress ipAddress = IPAddress.Parse(strIPAddress);

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
                        string nameServer = request.QueryString["nameServer"];
                        if (string.IsNullOrEmpty(nameServer))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'nameServer' missing.");

                            nameServer = value;
                        }

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsNSRecordData(nameServer));
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type);
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        string ptrName = request.QueryString["ptrName"];
                        if (string.IsNullOrEmpty(ptrName))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'ptrName' missing.");

                            ptrName = value;
                        }

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsPTRRecordData(ptrName));
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        string preference = request.QueryString["preference"];
                        if (string.IsNullOrEmpty(preference))
                            throw new DnsWebServiceException("Parameter 'preference' missing.");

                        string exchange = request.QueryString["exchange"];
                        if (string.IsNullOrEmpty(exchange))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'exchange' missing.");

                            exchange = value;
                        }

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsMXRecordData(ushort.Parse(preference), exchange));
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string text = request.QueryString["text"];
                        if (string.IsNullOrEmpty(text))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'text' missing.");

                            text = value;
                        }

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsTXTRecordData(text));
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

                        string target = request.QueryString["target"];
                        if (string.IsNullOrEmpty(target))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'target' missing.");

                            target = value;
                        }

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsSRVRecordData(ushort.Parse(priority), ushort.Parse(weight), ushort.Parse(port), target));
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type);
                    break;

                case DnsResourceRecordType.DS:
                    {
                        string strKeyTag = request.QueryString["keyTag"];
                        if (string.IsNullOrEmpty(strKeyTag))
                            throw new DnsWebServiceException("Parameter 'keyTag' missing.");

                        string strAlgorithm = request.QueryString["algorithm"];
                        if (string.IsNullOrEmpty(strAlgorithm))
                            throw new DnsWebServiceException("Parameter 'algorithm' missing.");

                        string strDigestType = request.QueryString["digestType"];
                        if (string.IsNullOrEmpty(strDigestType))
                            throw new DnsWebServiceException("Parameter 'digestType' missing.");

                        string digest = request.QueryString["digest"];
                        if (string.IsNullOrEmpty(digest))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'digest' missing.");

                            digest = value;
                        }

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsDSRecordData(ushort.Parse(strKeyTag), Enum.Parse<DnssecAlgorithm>(strAlgorithm.Replace('-', '_'), true), Enum.Parse<DnssecDigestType>(strDigestType.Replace('-', '_'), true), Convert.FromHexString(digest)));
                    }
                    break;

                case DnsResourceRecordType.SSHFP:
                    {
                        string strAlgorithm = request.QueryString["sshfpAlgorithm"];
                        if (string.IsNullOrEmpty(strAlgorithm))
                            throw new DnsWebServiceException("Parameter 'sshfpAlgorithm' missing.");

                        string strFingerprintType = request.QueryString["sshfpFingerprintType"];
                        if (string.IsNullOrEmpty(strFingerprintType))
                            throw new DnsWebServiceException("Parameter 'sshfpFingerprintType' missing.");

                        string strFingerprint = request.QueryString["sshfpFingerprint"];
                        if (string.IsNullOrEmpty(strFingerprint))
                            throw new DnsWebServiceException("Parameter 'sshfpFingerprint' missing.");

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsSSHFPRecordData(Enum.Parse<DnsSSHFPAlgorithm>(strAlgorithm, true), Enum.Parse<DnsSSHFPFingerprintType>(strFingerprintType, true), Convert.FromHexString(strFingerprint)));
                    }
                    break;

                case DnsResourceRecordType.TLSA:
                    {
                        string strCertificateUsage = request.QueryString["tlsaCertificateUsage"];
                        if (string.IsNullOrEmpty(strCertificateUsage))
                            throw new DnsWebServiceException("Parameter 'tlsaCertificateUsage' missing.");

                        string strSelector = request.QueryString["tlsaSelector"];
                        if (string.IsNullOrEmpty(strSelector))
                            throw new DnsWebServiceException("Parameter 'tlsaSelector' missing.");

                        string strMatchingType = request.QueryString["tlsaMatchingType"];
                        if (string.IsNullOrEmpty(strMatchingType))
                            throw new DnsWebServiceException("Parameter 'tlsaMatchingType' missing.");

                        string strCertificateAssociationData = request.QueryString["tlsaCertificateAssociationData"];
                        if (string.IsNullOrEmpty(strCertificateAssociationData))
                            throw new DnsWebServiceException("Parameter 'tlsaCertificateAssociationData' missing.");

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsTLSARecordData(Enum.Parse<DnsTLSACertificateUsage>(strCertificateUsage.Replace('-', '_'), true), Enum.Parse<DnsTLSASelector>(strSelector, true), Enum.Parse<DnsTLSAMatchingType>(strMatchingType.Replace('-', '_'), true), strCertificateAssociationData));
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

                        if (string.IsNullOrEmpty(value))
                            throw new DnsWebServiceException("Parameter 'value' missing.");

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsCAARecordData(byte.Parse(flags), tag, value));
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        string aname = request.QueryString["aname"];
                        if (string.IsNullOrEmpty(aname))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'aname' missing.");

                            aname = value;
                        }

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsANAMERecordData(aname));
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        string strProtocol = request.QueryString["protocol"];
                        if (string.IsNullOrEmpty(strProtocol))
                            strProtocol = "Udp";

                        string forwarder = request.QueryString["forwarder"];
                        if (string.IsNullOrEmpty(forwarder))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'forwarder' missing.");

                            forwarder = value;
                        }

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneInfo.Name, domain, type, new DnsForwarderRecordData(Enum.Parse<DnsTransportProtocol>(strProtocol, true), forwarder));
                    }
                    break;

                case DnsResourceRecordType.APP:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(zoneInfo.Name, domain, type);
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for DeleteRecord().");
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Record was deleted from authoritative zone {domain: " + domain + "; type: " + type + ";}");

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
        }

        public void UpdateRecord(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = Enum.Parse<DnsResourceRecordType>(strType, true);

            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.TrimEnd('.');

            string zoneName = request.QueryString["zone"];
            if (zoneName is not null)
                zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            UserSession session = _dnsWebService.GetSession(request);

            if (!_dnsWebService.AuthManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                throw new DnsWebServiceException("Access was denied.");

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

            bool disable = false;
            string strDisable = request.QueryString["disable"];
            if (!string.IsNullOrEmpty(strDisable))
                disable = bool.Parse(strDisable);

            string comments = request.QueryString["comments"];

            DnsResourceRecord newRecord;

            switch (type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    {
                        string strIPAddress = request.QueryString["ipAddress"];
                        if (string.IsNullOrEmpty(strIPAddress))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'ipAddress' missing.");

                            strIPAddress = value;
                        }

                        IPAddress oldIpAddress = IPAddress.Parse(strIPAddress);

                        string strNewIPAddress = request.QueryString["newIpAddress"];
                        if (string.IsNullOrEmpty(strNewIPAddress))
                        {
                            if (string.IsNullOrEmpty(newValue))
                                newValue = strIPAddress;

                            strNewIPAddress = newValue;
                        }
                        IPAddress newIpAddress = IPAddress.Parse(strNewIPAddress);

                        bool ptr = false;
                        string strPtr = request.QueryString["ptr"];
                        if (!string.IsNullOrEmpty(strPtr))
                            ptr = bool.Parse(strPtr);

                        if (ptr)
                        {
                            string ptrDomain = Zone.GetReverseZone(newIpAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
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
                                if (reverseZoneInfo is null)
                                    throw new DnsServerException("Failed to create reverse zone to add PTR record: " + ptrZone);

                                //set permissions
                                _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                                _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, reverseZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                                _dnsWebService.AuthManager.SaveConfigFile();
                            }

                            if (reverseZoneInfo.Internal)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is an internal zone.");

                            if (reverseZoneInfo.Type != AuthZoneType.Primary)
                                throw new DnsServerException("Reverse zone '" + reverseZoneInfo.Name + "' is not a primary zone.");

                            string oldPtrDomain = Zone.GetReverseZone(oldIpAddress, type == DnsResourceRecordType.A ? 32 : 128);

                            AuthZoneInfo oldReverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(oldPtrDomain);
                            if ((oldReverseZoneInfo != null) && !oldReverseZoneInfo.Internal && (oldReverseZoneInfo.Type == AuthZoneType.Primary))
                            {
                                //delete old PTR record if any and save old reverse zone
                                _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(oldReverseZoneInfo.Name, oldPtrDomain, DnsResourceRecordType.PTR);
                                _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(oldReverseZoneInfo.Name);
                            }

                            //add new PTR record and save reverse zone
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecords(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecordData[] { new DnsPTRRecordData(domain) });
                            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                        }

                        DnsResourceRecord oldRecord;

                        if (type == DnsResourceRecordType.A)
                        {
                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsARecordData(oldIpAddress));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsARecordData(newIpAddress));
                        }
                        else
                        {
                            oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsAAAARecordData(oldIpAddress));
                            newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsAAAARecordData(newIpAddress));
                        }

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.NS:
                    {
                        string nameServer = request.QueryString["nameServer"];
                        if (string.IsNullOrEmpty(nameServer))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'nameServer' missing.");

                            nameServer = value;
                        }

                        string newNameServer = request.QueryString["newNameServer"];
                        if (string.IsNullOrEmpty(newNameServer))
                        {
                            if (string.IsNullOrEmpty(newValue))
                                newValue = nameServer;

                            newNameServer = newValue;
                        }

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsNSRecordData(nameServer.TrimEnd('.')));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsNSRecordData(newNameServer.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        string glueAddresses = request.QueryString["glue"];
                        if (!string.IsNullOrEmpty(glueAddresses))
                            newRecord.SetGlueRecords(glueAddresses);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        string cname = request.QueryString["cname"];
                        if (string.IsNullOrEmpty(cname))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'cname' missing.");

                            cname = value;
                        }

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCNAMERecordData(cname.TrimEnd('.')));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCNAMERecordData(cname.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
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

                        DnsResourceRecord newSOARecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSOARecordData(primaryNameServer.TrimEnd('.'), responsiblePerson.TrimEnd('.'), uint.Parse(serial), uint.Parse(refresh), uint.Parse(retry), uint.Parse(expire), uint.Parse(minimum)));

                        switch (zoneInfo.Type)
                        {
                            case AuthZoneType.Secondary:
                            case AuthZoneType.Stub:
                                string primaryAddresses = request.QueryString["primaryAddresses"];
                                if (!string.IsNullOrEmpty(primaryAddresses))
                                    newSOARecord.SetPrimaryNameServers(primaryAddresses);

                                break;
                        }

                        if (zoneInfo.Type == AuthZoneType.Secondary)
                        {
                            DnsResourceRecordInfo recordInfo = newSOARecord.GetRecordInfo();

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
                            newSOARecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneInfo.Name, newSOARecord);

                        newRecord = zoneInfo.GetApexRecords(DnsResourceRecordType.SOA)[0];
                    }
                    break;

                case DnsResourceRecordType.PTR:
                    {
                        string ptrName = request.QueryString["ptrName"];
                        if (string.IsNullOrEmpty(ptrName))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'ptrName' missing.");

                            ptrName = value;
                        }

                        string newPtrName = request.QueryString["newPtrName"];
                        if (string.IsNullOrEmpty(newPtrName))
                        {
                            if (string.IsNullOrEmpty(newValue))
                                newValue = ptrName;

                            newPtrName = newValue;
                        }

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsPTRRecordData(ptrName.TrimEnd('.')));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsPTRRecordData(newPtrName.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        string preference = request.QueryString["preference"];
                        if (string.IsNullOrEmpty(preference))
                            preference = "1";

                        string newPreference = request.QueryString["newPreference"];
                        if (string.IsNullOrEmpty(newPreference))
                            newPreference = preference;

                        string exchange = request.QueryString["exchange"];
                        if (string.IsNullOrEmpty(exchange))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'exchange' missing.");

                            exchange = value;
                        }

                        string newExchange = request.QueryString["newExchange"];
                        if (string.IsNullOrEmpty(newExchange))
                        {
                            if (string.IsNullOrEmpty(newValue))
                                newValue = exchange;

                            newExchange = newValue;
                        }

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsMXRecordData(ushort.Parse(preference), exchange.TrimEnd('.')));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsMXRecordData(ushort.Parse(newPreference), newExchange.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TXT:
                    {
                        string text = request.QueryString["text"];
                        if (string.IsNullOrEmpty(text))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'text' missing.");

                            text = value;
                        }

                        string newText = request.QueryString["newText"];
                        if (string.IsNullOrEmpty(newText))
                        {
                            if (string.IsNullOrEmpty(newValue))
                                newValue = text;

                            newText = newValue;
                        }

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsTXTRecordData(text));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsTXTRecordData(newText));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
                        string priority = request.QueryString["priority"];
                        if (string.IsNullOrEmpty(priority))
                            throw new DnsWebServiceException("Parameter 'priority' missing.");

                        string newPriority = request.QueryString["newPriority"];
                        if (string.IsNullOrEmpty(newPriority))
                            newPriority = priority;

                        string weight = request.QueryString["weight"];
                        if (string.IsNullOrEmpty(weight))
                            throw new DnsWebServiceException("Parameter 'weight' missing.");

                        string newWeight = request.QueryString["newWeight"];
                        if (string.IsNullOrEmpty(newWeight))
                            newWeight = weight;

                        string port = request.QueryString["port"];
                        if (string.IsNullOrEmpty(port))
                            throw new DnsWebServiceException("Parameter 'port' missing.");

                        string newPort = request.QueryString["newPort"];
                        if (string.IsNullOrEmpty(newPort))
                            newPort = port;

                        string target = request.QueryString["target"];
                        if (string.IsNullOrEmpty(target))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'target' missing.");

                            target = value;
                        }

                        string newTarget = request.QueryString["newTarget"];
                        if (string.IsNullOrEmpty(newTarget))
                        {
                            if (string.IsNullOrEmpty(newValue))
                                newValue = target;

                            newTarget = newValue;
                        }

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSRVRecordData(ushort.Parse(priority), ushort.Parse(weight), ushort.Parse(port), target.TrimEnd('.')));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSRVRecordData(ushort.Parse(newPriority), ushort.Parse(newWeight), ushort.Parse(newPort), newTarget.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    {
                        string dname = request.QueryString["dname"];
                        if (string.IsNullOrEmpty(dname))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'dname' missing.");

                            dname = value;
                        }

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsDNAMERecordData(dname.TrimEnd('.')));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsDNAMERecordData(dname.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DS:
                    {
                        string strKeyTag = request.QueryString["keyTag"];
                        if (string.IsNullOrEmpty(strKeyTag))
                            throw new DnsWebServiceException("Parameter 'keyTag' missing.");

                        string strNewKeyTag = request.QueryString["newKeyTag"];
                        if (string.IsNullOrEmpty(strNewKeyTag))
                            strNewKeyTag = strKeyTag;

                        string strAlgorithm = request.QueryString["algorithm"];
                        if (string.IsNullOrEmpty(strAlgorithm))
                            throw new DnsWebServiceException("Parameter 'algorithm' missing.");

                        string strNewAlgorithm = request.QueryString["newAlgorithm"];
                        if (string.IsNullOrEmpty(strNewAlgorithm))
                            strNewAlgorithm = strAlgorithm;

                        string strDigestType = request.QueryString["digestType"];
                        if (string.IsNullOrEmpty(strDigestType))
                            throw new DnsWebServiceException("Parameter 'digestType' missing.");

                        string strNewDigestType = request.QueryString["newDigestType"];
                        if (string.IsNullOrEmpty(strNewDigestType))
                            strNewDigestType = strDigestType;

                        string digest = request.QueryString["digest"];
                        if (string.IsNullOrEmpty(digest))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'digest' missing.");

                            digest = value;
                        }

                        string newDigest = request.QueryString["newDigest"];
                        if (string.IsNullOrEmpty(newDigest))
                        {
                            if (string.IsNullOrEmpty(newValue))
                                newValue = digest;

                            newDigest = newValue;
                        }

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsDSRecordData(ushort.Parse(strKeyTag), Enum.Parse<DnssecAlgorithm>(strAlgorithm.Replace('-', '_'), true), Enum.Parse<DnssecDigestType>(strDigestType.Replace('-', '_'), true), Convert.FromHexString(digest)));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsDSRecordData(ushort.Parse(strNewKeyTag), Enum.Parse<DnssecAlgorithm>(strNewAlgorithm.Replace('-', '_'), true), Enum.Parse<DnssecDigestType>(strNewDigestType.Replace('-', '_'), true), Convert.FromHexString(newDigest)));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.SSHFP:
                    {
                        string strAlgorithm = request.QueryString["sshfpAlgorithm"];
                        if (string.IsNullOrEmpty(strAlgorithm))
                            throw new DnsWebServiceException("Parameter 'sshfpAlgorithm' missing.");

                        string strNewAlgorithm = request.QueryString["newSshfpAlgorithm"];
                        if (string.IsNullOrEmpty(strNewAlgorithm))
                            strNewAlgorithm = strAlgorithm;

                        string strFingerprintType = request.QueryString["sshfpFingerprintType"];
                        if (string.IsNullOrEmpty(strFingerprintType))
                            throw new DnsWebServiceException("Parameter 'sshfpFingerprintType' missing.");

                        string strNewFingerprintType = request.QueryString["newSshfpFingerprintType"];
                        if (string.IsNullOrEmpty(strNewFingerprintType))
                            strNewFingerprintType = strFingerprintType;

                        string strFingerprint = request.QueryString["sshfpFingerprint"];
                        if (string.IsNullOrEmpty(strFingerprint))
                            throw new DnsWebServiceException("Parameter 'sshfpFingerprint' missing.");

                        string strNewFingerprint = request.QueryString["newSshfpFingerprint"];
                        if (string.IsNullOrEmpty(strNewFingerprint))
                            strNewFingerprint = strFingerprint;

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSSHFPRecordData(Enum.Parse<DnsSSHFPAlgorithm>(strAlgorithm, true), Enum.Parse<DnsSSHFPFingerprintType>(strFingerprintType, true), Convert.FromHexString(strFingerprint)));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSSHFPRecordData(Enum.Parse<DnsSSHFPAlgorithm>(strNewAlgorithm, true), Enum.Parse<DnsSSHFPFingerprintType>(strNewFingerprintType, true), Convert.FromHexString(strNewFingerprint)));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.TLSA:
                    {
                        string strCertificateUsage = request.QueryString["tlsaCertificateUsage"];
                        if (string.IsNullOrEmpty(strCertificateUsage))
                            throw new DnsWebServiceException("Parameter 'tlsaCertificateUsage' missing.");

                        string strNewCertificateUsage = request.QueryString["newTlsaCertificateUsage"];
                        if (string.IsNullOrEmpty(strNewCertificateUsage))
                            strNewCertificateUsage = strCertificateUsage;

                        string strSelector = request.QueryString["tlsaSelector"];
                        if (string.IsNullOrEmpty(strSelector))
                            throw new DnsWebServiceException("Parameter 'tlsaSelector' missing.");

                        string strNewSelector = request.QueryString["newTlsaSelector"];
                        if (string.IsNullOrEmpty(strNewSelector))
                            strNewSelector = strSelector;

                        string strMatchingType = request.QueryString["tlsaMatchingType"];
                        if (string.IsNullOrEmpty(strMatchingType))
                            throw new DnsWebServiceException("Parameter 'tlsaMatchingType' missing.");

                        string strNewMatchingType = request.QueryString["newTlsaMatchingType"];
                        if (string.IsNullOrEmpty(strNewMatchingType))
                            strNewMatchingType = strMatchingType;

                        string strCertificateAssociationData = request.QueryString["tlsaCertificateAssociationData"];
                        if (string.IsNullOrEmpty(strCertificateAssociationData))
                            throw new DnsWebServiceException("Parameter 'tlsaCertificateAssociationData' missing.");

                        string strNewCertificateAssociationData = request.QueryString["newTlsaCertificateAssociationData"];
                        if (string.IsNullOrEmpty(strNewCertificateAssociationData))
                            strNewCertificateAssociationData = strCertificateAssociationData;

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsTLSARecordData(Enum.Parse<DnsTLSACertificateUsage>(strCertificateUsage.Replace('-', '_'), true), Enum.Parse<DnsTLSASelector>(strSelector, true), Enum.Parse<DnsTLSAMatchingType>(strMatchingType.Replace('-', '_'), true), strCertificateAssociationData));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsTLSARecordData(Enum.Parse<DnsTLSACertificateUsage>(strNewCertificateUsage.Replace('-', '_'), true), Enum.Parse<DnsTLSASelector>(strNewSelector, true), Enum.Parse<DnsTLSAMatchingType>(strNewMatchingType.Replace('-', '_'), true), strNewCertificateAssociationData));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CAA:
                    {
                        string flags = request.QueryString["flags"];
                        if (string.IsNullOrEmpty(flags))
                            throw new DnsWebServiceException("Parameter 'flags' missing.");

                        string newFlags = request.QueryString["newFlags"];
                        if (string.IsNullOrEmpty(newFlags))
                            newFlags = flags;

                        string tag = request.QueryString["tag"];
                        if (string.IsNullOrEmpty(tag))
                            throw new DnsWebServiceException("Parameter 'tag' missing.");

                        string newTag = request.QueryString["newTag"];
                        if (string.IsNullOrEmpty(newTag))
                            newTag = tag;

                        if (string.IsNullOrEmpty(value))
                            throw new DnsWebServiceException("Parameter 'value' missing.");

                        if (string.IsNullOrEmpty(newValue))
                            newValue = value;

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCAARecordData(byte.Parse(flags), tag, value));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCAARecordData(byte.Parse(newFlags), newTag, newValue));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.ANAME:
                    {
                        string aname = request.QueryString["aname"];
                        if (string.IsNullOrEmpty(aname))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'aname' missing.");

                            aname = value;
                        }

                        string newAName = request.QueryString["newAName"];
                        if (string.IsNullOrEmpty(newAName))
                        {
                            if (string.IsNullOrEmpty(newValue))
                                newValue = aname;

                            newAName = newValue;
                        }

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsANAMERecordData(aname.TrimEnd('.')));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsANAMERecordData(newAName.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.FWD:
                    {
                        DnsTransportProtocol protocol = DnsTransportProtocol.Udp;
                        string strProtocol = request.QueryString["protocol"];
                        if (!string.IsNullOrEmpty(strProtocol))
                            protocol = Enum.Parse<DnsTransportProtocol>(strProtocol, true);

                        DnsTransportProtocol newProtocol = protocol;
                        string strNewProtocol = request.QueryString["newProtocol"];
                        if (!string.IsNullOrEmpty(strNewProtocol))
                            newProtocol = Enum.Parse<DnsTransportProtocol>(strNewProtocol, true);

                        string forwarder = request.QueryString["forwarder"];
                        if (string.IsNullOrEmpty(forwarder))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'forwarder' missing.");

                            forwarder = value;
                        }

                        string newForwarder = request.QueryString["newForwarder"];
                        if (string.IsNullOrEmpty(newForwarder))
                        {
                            if (string.IsNullOrEmpty(newValue))
                                newValue = forwarder;

                            newForwarder = newValue;
                        }

                        bool dnssecValidation = false;
                        string strDnssecValidation = request.QueryString["dnssecValidation"];
                        if (!string.IsNullOrEmpty(strDnssecValidation))
                            dnssecValidation = bool.Parse(strDnssecValidation);

                        NetProxyType proxyType = NetProxyType.None;
                        string proxyAddress = null;
                        ushort proxyPort = 0;
                        string proxyUsername = null;
                        string proxyPassword = null;

                        if (!newForwarder.Equals("this-server"))
                        {
                            string strProxyType = request.QueryString["proxyType"];
                            if (!string.IsNullOrEmpty(strProxyType))
                                proxyType = Enum.Parse<NetProxyType>(strProxyType, true);

                            if (proxyType != NetProxyType.None)
                            {
                                proxyAddress = request.QueryString["proxyAddress"];
                                if (string.IsNullOrEmpty(proxyAddress))
                                    throw new DnsWebServiceException("Parameter 'proxyAddress' missing.");

                                string strProxyPort = request.QueryString["proxyPort"];
                                if (string.IsNullOrEmpty(strProxyPort))
                                    throw new DnsWebServiceException("Parameter 'proxyPort' missing.");

                                proxyPort = ushort.Parse(strProxyPort);
                                proxyUsername = request.QueryString["proxyUsername"];
                                proxyPassword = request.QueryString["proxyPassword"];
                            }
                        }

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecordData(protocol, forwarder));
                        newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecordData(newProtocol, newForwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.APP:
                    {
                        string appName = request.QueryString["appName"];
                        if (string.IsNullOrEmpty(appName))
                        {
                            if (string.IsNullOrEmpty(value))
                                throw new DnsWebServiceException("Parameter 'appName' missing.");

                            appName = value;
                        }

                        string classPath = request.QueryString["classPath"];
                        if (string.IsNullOrEmpty(classPath))
                            throw new DnsWebServiceException("Parameter 'classPath' missing.");

                        string recordData = request.QueryString["recordData"];
                        if (string.IsNullOrEmpty(recordData))
                            recordData = "";

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsApplicationRecordData(appName, classPath, recordData));
                        newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsApplicationRecordData(appName, classPath, recordData));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneInfo.Name, oldRecord, newRecord);
                    }
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for UpdateRecords().");
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Record was updated for authoritative zone {oldDomain: " + domain + "; domain: " + newDomain + "; type: " + type + "; oldValue: " + value + "; value: " + newValue + "; ttl: " + ttl + "; disabled: " + disable + ";}");

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);

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
