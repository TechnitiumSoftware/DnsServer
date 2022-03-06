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

                        jsonWriter.WritePropertyName("dnssecStatus");
                        jsonWriter.WriteValue(zone.DnssecStatus.ToString());
                        break;

                    case AuthZoneType.Secondary:
                        jsonWriter.WritePropertyName("dnssecStatus");
                        jsonWriter.WriteValue(zone.DnssecStatus.ToString());

                        jsonWriter.WritePropertyName("expiry");
                        jsonWriter.WriteValue(zone.Expiry);

                        jsonWriter.WritePropertyName("isExpired");
                        jsonWriter.WriteValue(zone.IsExpired);
                        break;

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
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                zoneName = request.QueryString["domain"];

            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            if (zoneName.Contains('*'))
                throw new DnsWebServiceException("Domain name for a zone cannot contain wildcard character.");

            if (IPAddress.TryParse(zoneName, out IPAddress ipAddress))
            {
                zoneName = new DnsQuestionRecord(ipAddress, DnsClass.IN).Name.ToLower();
            }
            else if (zoneName.Contains("/"))
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

            switch (type)
            {
                case AuthZoneType.Primary:
                    if (_dnsWebService.DnsServer.AuthZoneManager.CreatePrimaryZone(zoneName, _dnsWebService.DnsServer.ServerDomain, false) is null)
                        throw new DnsWebServiceException("Zone already exists: " + zoneName);

                    _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Authoritative primary zone was created: " + zoneName);
                    _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
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

                        if (await _dnsWebService.DnsServer.AuthZoneManager.CreateSecondaryZoneAsync(zoneName, primaryNameServerAddresses, zoneTransferProtocol, tsigKeyName) is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Authoritative secondary zone was created: " + zoneName);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
                    }
                    break;

                case AuthZoneType.Stub:
                    {
                        string strPrimaryNameServerAddresses = request.QueryString["primaryNameServerAddresses"];
                        if (string.IsNullOrEmpty(strPrimaryNameServerAddresses))
                            strPrimaryNameServerAddresses = null;

                        if (await _dnsWebService.DnsServer.AuthZoneManager.CreateStubZoneAsync(zoneName, strPrimaryNameServerAddresses) is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Stub zone was created: " + zoneName);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
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

                        if (_dnsWebService.DnsServer.AuthZoneManager.CreateForwarderZone(zoneName, forwarderProtocol, strForwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword) is null)
                            throw new DnsWebServiceException("Zone already exists: " + zoneName);

                        _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Forwarder zone was created: " + zoneName);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
                    }
                    break;

                default:
                    throw new NotSupportedException("Zone type not supported.");
            }

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zones
            _dnsWebService.DnsServer.CacheZoneManager.DeleteZone(zoneName);

            jsonWriter.WritePropertyName("domain");
            jsonWriter.WriteValue(string.IsNullOrEmpty(zoneName) ? "." : zoneName);
        }

        public void SignPrimaryZone(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            string algorithm = request.QueryString["algorithm"];
            if (string.IsNullOrEmpty(algorithm))
                throw new DnsWebServiceException("Parameter 'algorithm' missing.");

            uint dnsKeyTtl;
            string strDnsKeyTtl = request.QueryString["dnsKeyTtl"];
            if (string.IsNullOrEmpty(strDnsKeyTtl))
                dnsKeyTtl = 24 * 60 * 60;
            else
                dnsKeyTtl = uint.Parse(strDnsKeyTtl);

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
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithRsaNSEC3(zoneName, hashAlgorithm, kskKeySize, zskKeySize, iterations, saltLength, dnsKeyTtl);
                    else
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithRsaNSEC(zoneName, hashAlgorithm, kskKeySize, zskKeySize, dnsKeyTtl);

                    break;

                case "ECDSA":
                    string curve = request.QueryString["curve"];
                    if (string.IsNullOrEmpty(curve))
                        throw new DnsWebServiceException("Parameter 'curve' missing.");

                    if (useNSEC3)
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithEcdsaNSEC3(zoneName, curve, iterations, saltLength, dnsKeyTtl);
                    else
                        _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZoneWithEcdsaNSEC(zoneName, curve, dnsKeyTtl);

                    break;

                default:
                    throw new NotSupportedException("Algorithm is not supported: " + algorithm);
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Primary zone was signed successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UnsignPrimaryZone(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            _dnsWebService.DnsServer.AuthZoneManager.UnsignPrimaryZone(zoneName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Primary zone was unsigned successfully: " + zoneName);

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
                IReadOnlyList<DnsResourceRecord> nsec3ParamRecords = zoneInfo.GetRecords(DnsResourceRecordType.NSEC3PARAM);
                DnsNSEC3PARAMRecord nsec3Param = nsec3ParamRecords[0].RDATA as DnsNSEC3PARAMRecord;

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

            _dnsWebService.DnsServer.AuthZoneManager.ConvertPrimaryZoneToNSEC(zoneName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Primary zone was converted to NSEC successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void ConvertPrimaryZoneToNSEC3(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            ushort iterations = 0;
            string strIterations = request.QueryString["iterations"];
            if (!string.IsNullOrEmpty(strIterations))
                iterations = ushort.Parse(strIterations);

            byte saltLength = 0;
            string strSaltLength = request.QueryString["saltLength"];
            if (!string.IsNullOrEmpty(strSaltLength))
                saltLength = byte.Parse(strSaltLength);

            _dnsWebService.DnsServer.AuthZoneManager.ConvertPrimaryZoneToNSEC3(zoneName, iterations, saltLength);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Primary zone was converted to NSEC3 successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UpdatePrimaryZoneNSEC3Parameters(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            ushort iterations = 0;
            string strIterations = request.QueryString["iterations"];
            if (!string.IsNullOrEmpty(strIterations))
                iterations = ushort.Parse(strIterations);

            byte saltLength = 0;
            string strSaltLength = request.QueryString["saltLength"];
            if (!string.IsNullOrEmpty(strSaltLength))
                saltLength = byte.Parse(strSaltLength);

            _dnsWebService.DnsServer.AuthZoneManager.UpdatePrimaryZoneNSEC3Parameters(zoneName, iterations, saltLength);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Primary zone NSEC3 parameters were updated successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void UpdatePrimaryZoneDnssecDnsKeyTtl(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            string strDnsKeyTtl = request.QueryString["ttl"];
            if (string.IsNullOrEmpty(strDnsKeyTtl))
                throw new DnsWebServiceException("Parameter 'ttl' missing.");

            uint dnsKeyTtl = uint.Parse(strDnsKeyTtl);

            _dnsWebService.DnsServer.AuthZoneManager.UpdatePrimaryZoneDnsKeyTtl(zoneName, dnsKeyTtl);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Primary zone DNSKEY TTL was updated successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void GenerateAndAddPrimaryZoneDnssecPrivateKey(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            string strKeyType = request.QueryString["keyType"];
            if (string.IsNullOrEmpty(strKeyType))
                throw new DnsWebServiceException("Parameter 'keyType' missing.");

            DnssecPrivateKeyType keyType = Enum.Parse<DnssecPrivateKeyType>(strKeyType, true);

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

                    _dnsWebService.DnsServer.AuthZoneManager.GenerateAndAddPrimaryZoneDnssecRsaPrivateKey(zoneName, keyType, hashAlgorithm, keySize);
                    break;

                case "ECDSA":
                    string curve = request.QueryString["curve"];
                    if (string.IsNullOrEmpty(curve))
                        throw new DnsWebServiceException("Parameter 'curve' missing.");

                    _dnsWebService.DnsServer.AuthZoneManager.GenerateAndAddPrimaryZoneDnssecEcdsaPrivateKey(zoneName, keyType, curve);
                    break;

                default:
                    throw new NotSupportedException("Algorithm is not supported: " + algorithm);
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DNSSEC private key was generated and added to the primary zone successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void DeletePrimaryZoneDnssecPrivateKey(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            string strKeyTag = request.QueryString["keyTag"];
            if (string.IsNullOrEmpty(strKeyTag))
                throw new DnsWebServiceException("Parameter 'keyTag' missing.");

            ushort keyTag = ushort.Parse(strKeyTag);

            _dnsWebService.DnsServer.AuthZoneManager.DeletePrimaryZoneDnssecPrivateKey(zoneName, keyTag);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DNSSEC private key was deleted from primary zone successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            _dnsWebService.DnsServer.AuthZoneManager.PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(zoneName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] All DNSSEC private keys from the primary zone were published successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void RolloverPrimaryZoneDnsKey(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            string strKeyTag = request.QueryString["keyTag"];
            if (string.IsNullOrEmpty(strKeyTag))
                throw new DnsWebServiceException("Parameter 'keyTag' missing.");

            ushort keyTag = ushort.Parse(strKeyTag);

            _dnsWebService.DnsServer.AuthZoneManager.RolloverPrimaryZoneDnsKey(zoneName, keyTag);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] The DNSKEY (" + keyTag + ") from the primary zone was rolled over successfully: " + zoneName);

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneName);
        }

        public void RetirePrimaryZoneDnsKey(HttpListenerRequest request)
        {
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            string strKeyTag = request.QueryString["keyTag"];
            if (string.IsNullOrEmpty(strKeyTag))
                throw new DnsWebServiceException("Parameter 'keyTag' missing.");

            ushort keyTag = ushort.Parse(strKeyTag);

            _dnsWebService.DnsServer.AuthZoneManager.RetirePrimaryZoneDnsKey(zoneName, keyTag);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] The DNSKEY (" + keyTag + ") from the primary zone was retired successfully: " + zoneName);

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

            if (!_dnsWebService.DnsServer.AuthZoneManager.DeleteZone(zoneName))
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] " + zoneInfo.Type.ToString() + " zone was deleted: " + zoneName);

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
            if (zoneInfo == null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

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
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                zoneName = request.QueryString["domain"];

            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo == null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            zoneInfo.Disabled = true;

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] " + zoneInfo.Type.ToString() + " zone was disabled: " + zoneInfo.Name);

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

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No such zone was found: " + zoneName);

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
            string zoneName = request.QueryString["zone"];
            if (string.IsNullOrEmpty(zoneName))
                zoneName = request.QueryString["domain"];

            if (string.IsNullOrEmpty(zoneName))
                throw new DnsWebServiceException("Parameter 'zone' missing.");

            zoneName = zoneName.TrimEnd('.');

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName);
            if (zoneInfo == null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + zoneName);

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
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

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

            string zoneName = request.QueryString["zone"];
            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo == null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (string.IsNullOrEmpty(zoneName))
                zoneName = zoneInfo.Name;

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

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

                            _dnsWebService.DnsServer.AuthZoneManager.SetRecords(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecord[] { new DnsPTRRecord(domain) });
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
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneName, newRecord);
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

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsNSRecord(nameServer.TrimEnd('.')));

                        if (glueAddresses != null)
                            newRecord.SetGlueRecords(glueAddresses);

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneName, newRecord);
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    {
                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(zoneName, domain, type);
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

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCNAMERecord(cname.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
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

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsPTRRecord(ptrName.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneName, newRecord);
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

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsMXRecord(ushort.Parse(preference), exchange.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneName, newRecord);
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

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsTXTRecord(text));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneName, newRecord);
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

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsSRVRecord(ushort.Parse(priority), ushort.Parse(weight), ushort.Parse(port), target.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneName, newRecord);
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    {
                        if (!overwrite)
                        {
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(zoneName, domain, type);
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

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsDNAMERecord(dname.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
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

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsDSRecord(ushort.Parse(strKeyTag), Enum.Parse<DnssecAlgorithm>(strAlgorithm), Enum.Parse<DnssecDigestType>(strDigestType), Convert.FromHexString(digest)));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneName, newRecord);
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

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsCAARecord(byte.Parse(flags), tag, value));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneName, newRecord);
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

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsANAMERecord(aname.TrimEnd('.')));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneName, newRecord);
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
                        NetProxyType proxyType = NetProxyType.None;
                        string proxyAddress = null;
                        ushort proxyPort = 0;
                        string proxyUsername = null;
                        string proxyPassword = null;

                        if (!forwarder.Equals("this-server"))
                        {
                            string strDnssecValidation = request.QueryString["dnssecValidation"];
                            if (!string.IsNullOrEmpty(strDnssecValidation))
                                dnssecValidation = bool.Parse(strDnssecValidation);

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

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecord(protocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        if (overwrite)
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(zoneName, newRecord);
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
                            IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(zoneName, domain, type);
                            if (existingRecords.Count > 0)
                                throw new DnsWebServiceException("Record already exists. Use overwrite option if you wish to overwrite existing records.");
                        }

                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, new DnsApplicationRecord(appName, classPath, recordData));

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newRecord);
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

            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(domain);
            if (zoneInfo is null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

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

                    jsonWriter.WritePropertyName("dnssecStatus");
                    jsonWriter.WriteValue(zoneInfo.DnssecStatus.ToString());
                    break;

                case AuthZoneType.Secondary:
                    jsonWriter.WritePropertyName("dnssecStatus");
                    jsonWriter.WriteValue(zoneInfo.DnssecStatus.ToString());

                    jsonWriter.WritePropertyName("expiry");
                    jsonWriter.WriteValue(zoneInfo.Expiry);

                    jsonWriter.WritePropertyName("isExpired");
                    jsonWriter.WriteValue(zoneInfo.IsExpired);
                    break;

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

            WriteRecordsAsJson(records, jsonWriter, true, zoneInfo);
        }

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
                                    if (record.RDATA is DnsARecord rdata)
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
                                    if (record.RDATA is DnsNSRecord rdata)
                                    {
                                        jsonWriter.WritePropertyName("nameServer");
                                        jsonWriter.WriteValue(rdata.NameServer.Length == 0 ? "." : rdata.NameServer);
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
                                    if (record.RDATA is DnsMXRecord rdata)
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
                                    if (record.RDATA is DnsTXTRecord rdata)
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
                                    if (record.RDATA is DnsAAAARecord rdata)
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
                                    if (record.RDATA is DnsSRVRecord rdata)
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
                                    if (record.RDATA is DnsDNAMERecord rdata)
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
                                    if (record.RDATA is DnsDSRecord rdata)
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

                            case DnsResourceRecordType.RRSIG:
                                {
                                    if (record.RDATA is DnsRRSIGRecord rdata)
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
                                    if (record.RDATA is DnsNSECRecord rdata)
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
                                    if (record.RDATA is DnsDNSKEYRecord rdata)
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
                                                    jsonWriter.WriteValue("SHA1");

                                                    jsonWriter.WritePropertyName("digest");
                                                    jsonWriter.WriteValue(rdata.CreateDS(record.Name, DnssecDigestType.SHA1).Digest);

                                                    jsonWriter.WriteEndObject();
                                                }

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
                                    if (record.RDATA is DnsNSEC3Record rdata)
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
                                    if (record.RDATA is DnsNSEC3PARAMRecord rdata)
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
                                    if (record.RDATA is DnsForwarderRecord rdata)
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
                                    if (record.RDATA is DnsApplicationRecord rdata)
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
                                    if (record.RDATA is DnsUnknownRecord)
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

            string zoneName = request.QueryString["zone"];
            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo == null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (string.IsNullOrEmpty(zoneName))
                zoneName = zoneInfo.Name;

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = (DnsResourceRecordType)Enum.Parse(typeof(DnsResourceRecordType), strType);

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
                            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, type, new DnsARecord(ipAddress));
                        else
                            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, type, new DnsAAAARecord(ipAddress));

                        string ptrDomain = Zone.GetReverseZone(ipAddress, type == DnsResourceRecordType.A ? 32 : 128);
                        AuthZoneInfo reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
                        if ((reverseZoneInfo != null) && !reverseZoneInfo.Internal && (reverseZoneInfo.Type == AuthZoneType.Primary))
                        {
                            IReadOnlyList<DnsResourceRecord> ptrRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR);
                            if (ptrRecords.Count > 0)
                            {
                                foreach (DnsResourceRecord ptrRecord in ptrRecords)
                                {
                                    if ((ptrRecord.RDATA as DnsPTRRecord).Domain.Equals(domain, StringComparison.OrdinalIgnoreCase))
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

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, type, new DnsNSRecord(nameServer));
                    }
                    break;

                case DnsResourceRecordType.CNAME:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(zoneName, domain, type);
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

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, type, new DnsPTRRecord(ptrName));
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

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, type, new DnsMXRecord(0, exchange));
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

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, type, new DnsTXTRecord(text));
                    }
                    break;

                case DnsResourceRecordType.SRV:
                    {
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

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, type, new DnsSRVRecord(0, 0, ushort.Parse(port), target));
                    }
                    break;

                case DnsResourceRecordType.DNAME:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(zoneName, domain, type);
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

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, type, new DnsDSRecord(ushort.Parse(strKeyTag), Enum.Parse<DnssecAlgorithm>(strAlgorithm), Enum.Parse<DnssecDigestType>(strDigestType), Convert.FromHexString(digest)));
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

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, type, new DnsCAARecord(byte.Parse(flags), tag, value));
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

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, type, new DnsANAMERecord(aname));
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

                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(zoneName, domain, type, new DnsForwarderRecord(Enum.Parse<DnsTransportProtocol>(strProtocol, true), forwarder));
                    }
                    break;

                case DnsResourceRecordType.APP:
                    _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(zoneName, domain, type);
                    break;

                default:
                    throw new DnsWebServiceException("Type not supported for DeleteRecord().");
            }

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] Record was deleted from authoritative zone {domain: " + domain + "; type: " + type + ";}");

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

            string zoneName = request.QueryString["zone"];
            AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(string.IsNullOrEmpty(zoneName) ? domain : zoneName);
            if (zoneInfo == null)
                throw new DnsWebServiceException("No authoritative zone was not found for domain: " + domain);

            if (zoneInfo.Internal)
                throw new DnsWebServiceException("Access was denied to manage internal DNS Server zone.");

            if (string.IsNullOrEmpty(zoneName))
                zoneName = zoneInfo.Name;

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
                                if (reverseZoneInfo == null)
                                    throw new DnsServerException("Failed to create reverse zone to add PTR record: " + ptrZone);
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
                            _dnsWebService.DnsServer.AuthZoneManager.SetRecords(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR, ttl, new DnsPTRRecord[] { new DnsPTRRecord(domain) });
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

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsNSRecord(nameServer.TrimEnd('.')));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsNSRecord(newNameServer.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        string glueAddresses = request.QueryString["glue"];
                        if (!string.IsNullOrEmpty(glueAddresses))
                            newRecord.SetGlueRecords(glueAddresses);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCNAMERecord(cname.TrimEnd('.')));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCNAMERecord(cname.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(zoneName, newSoaRecord);
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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsPTRRecord(ptrName.TrimEnd('.')));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsPTRRecord(newPtrName.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
                    }
                    break;

                case DnsResourceRecordType.MX:
                    {
                        string preference = request.QueryString["preference"];
                        if (string.IsNullOrEmpty(preference))
                            preference = "1";

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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsMXRecord(0, exchange.TrimEnd('.')));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsMXRecord(ushort.Parse(preference), newExchange.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsTXTRecord(text));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsTXTRecord(newText));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsSRVRecord(0, 0, ushort.Parse(port), target.TrimEnd('.')));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsSRVRecord(ushort.Parse(priority), ushort.Parse(weight), ushort.Parse(newPort), newTarget.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsDNAMERecord(dname.TrimEnd('.')));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsDNAMERecord(dname.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsDSRecord(ushort.Parse(strKeyTag), Enum.Parse<DnssecAlgorithm>(strAlgorithm), Enum.Parse<DnssecDigestType>(strDigestType), Convert.FromHexString(digest)));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsDSRecord(ushort.Parse(strNewKeyTag), Enum.Parse<DnssecAlgorithm>(strNewAlgorithm), Enum.Parse<DnssecDigestType>(strNewDigestType), Convert.FromHexString(newDigest)));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsCAARecord(byte.Parse(flags), tag, value));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsCAARecord(byte.Parse(newFlags), newTag, newValue));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsANAMERecord(aname.TrimEnd('.')));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsANAMERecord(newAName.TrimEnd('.')));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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
                        NetProxyType proxyType = NetProxyType.None;
                        string proxyAddress = null;
                        ushort proxyPort = 0;
                        string proxyUsername = null;
                        string proxyPassword = null;

                        if (!newForwarder.Equals("this-server"))
                        {
                            string strDnssecValidation = request.QueryString["dnssecValidation"];
                            if (!string.IsNullOrEmpty(strDnssecValidation))
                                dnssecValidation = bool.Parse(strDnssecValidation);

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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecord(protocol, forwarder));
                        DnsResourceRecord newRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsForwarderRecord(newProtocol, newForwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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

                        DnsResourceRecord oldRecord = new DnsResourceRecord(domain, type, DnsClass.IN, 0, new DnsApplicationRecord(appName, classPath, recordData));
                        DnsResourceRecord newRecord = new DnsResourceRecord(newDomain, type, DnsClass.IN, ttl, new DnsApplicationRecord(appName, classPath, recordData));

                        if (disable)
                            newRecord.Disable();

                        if (!string.IsNullOrEmpty(comments))
                            newRecord.SetComments(comments);

                        _dnsWebService.DnsServer.AuthZoneManager.UpdateRecord(zoneName, oldRecord, newRecord);
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
