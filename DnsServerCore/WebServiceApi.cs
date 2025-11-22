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
using DnsServerCore.Dns;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        class WebServiceApi
        {
            #region variables

            static readonly char[] _domainTrimChars = new char[] { '\t', ' ', '.' };

            readonly DnsWebService _dnsWebService;
            readonly Uri _updateCheckUri;

            string _checkForUpdateJsonData;
            DateTime _checkForUpdateJsonDataUpdatedOn;
            const int CHECK_FOR_UPDATE_JSON_DATA_CACHE_TIME_SECONDS = 3600;

            #endregion

            #region constructor

            public WebServiceApi(DnsWebService dnsWebService, Uri updateCheckUri)
            {
                _dnsWebService = dnsWebService;
                _updateCheckUri = updateCheckUri;
            }

            #endregion

            #region private

            private async Task<string> GetCheckForUpdateJsonData()
            {
                if ((_checkForUpdateJsonData is null) || (DateTime.UtcNow > _checkForUpdateJsonDataUpdatedOn.AddSeconds(CHECK_FOR_UPDATE_JSON_DATA_CACHE_TIME_SECONDS)))
                {
                    HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                    handler.Proxy = _dnsWebService._dnsServer.Proxy;
                    handler.NetworkType = _dnsWebService._dnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default;
                    handler.DnsClient = _dnsWebService._dnsServer;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        _checkForUpdateJsonData = await http.GetStringAsync(_updateCheckUri);
                        _checkForUpdateJsonDataUpdatedOn = DateTime.UtcNow;
                    }
                }

                return _checkForUpdateJsonData;
            }

            #endregion

            #region public

            public async Task CheckForUpdateAsync(HttpContext context)
            {
                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                if (_updateCheckUri is null)
                {
                    jsonWriter.WriteBoolean("updateAvailable", false);
                    return;
                }

                try
                {
                    string jsonData = await GetCheckForUpdateJsonData();
                    using JsonDocument jsonDocument = JsonDocument.Parse(jsonData);
                    JsonElement jsonResponse = jsonDocument.RootElement;

                    string updateVersion = jsonResponse.GetProperty("updateVersion").GetString();
                    string updateTitle = jsonResponse.GetPropertyValue("updateTitle", null);
                    string updateMessage = jsonResponse.GetPropertyValue("updateMessage", null);
                    string downloadLink = jsonResponse.GetPropertyValue("downloadLink", null);
                    string instructionsLink = jsonResponse.GetPropertyValue("instructionsLink", null);
                    string changeLogLink = jsonResponse.GetPropertyValue("changeLogLink", null);

                    bool updateAvailable = new Version(updateVersion) > _dnsWebService._currentVersion;

                    jsonWriter.WriteBoolean("updateAvailable", updateAvailable);
                    jsonWriter.WriteString("updateVersion", updateVersion);
                    jsonWriter.WriteString("currentVersion", _dnsWebService.GetServerVersion());

                    if (updateAvailable)
                    {
                        jsonWriter.WriteString("updateTitle", updateTitle);
                        jsonWriter.WriteString("updateMessage", updateMessage);
                        jsonWriter.WriteString("downloadLink", downloadLink);
                        jsonWriter.WriteString("instructionsLink", instructionsLink);
                        jsonWriter.WriteString("changeLogLink", changeLogLink);
                    }

                    string strLog = "Check for update was done {updateAvailable: " + updateAvailable + "; updateVersion: " + updateVersion + ";";

                    if (!string.IsNullOrEmpty(updateTitle))
                        strLog += " updateTitle: " + updateTitle + ";";

                    if (!string.IsNullOrEmpty(updateMessage))
                        strLog += " updateMessage: " + updateMessage + ";";

                    if (!string.IsNullOrEmpty(downloadLink))
                        strLog += " downloadLink: " + downloadLink + ";";

                    if (!string.IsNullOrEmpty(instructionsLink))
                        strLog += " instructionsLink: " + instructionsLink + ";";

                    if (!string.IsNullOrEmpty(changeLogLink))
                        strLog += " changeLogLink: " + changeLogLink + ";";

                    strLog += "}";

                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), strLog);
                }
                catch (Exception ex)
                {
                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "Check for update was done {updateAvailable: False;}\r\n" + ex.ToString());

                    jsonWriter.WriteBoolean("updateAvailable", false);
                }
            }

            public async Task ResolveQueryAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DnsClient, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string server = request.GetQueryOrForm("server");
                string domain = request.GetQueryOrForm("domain").Trim(_domainTrimChars);
                DnsResourceRecordType type = request.GetQueryOrFormEnum<DnsResourceRecordType>("type");
                DnsTransportProtocol protocol = request.GetQueryOrFormEnum("protocol", DnsTransportProtocol.Udp);
                bool dnssecValidation = request.GetQueryOrForm("dnssec", bool.Parse, false);

                NetworkAddress eDnsClientSubnet = request.GetQueryOrForm("eDnsClientSubnet", NetworkAddress.Parse, null);
                if (eDnsClientSubnet is not null)
                {
                    switch (eDnsClientSubnet.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            if (eDnsClientSubnet.PrefixLength == 32)
                                eDnsClientSubnet = new NetworkAddress(eDnsClientSubnet.Address, 24);

                            break;

                        case AddressFamily.InterNetworkV6:
                            if (eDnsClientSubnet.PrefixLength == 128)
                                eDnsClientSubnet = new NetworkAddress(eDnsClientSubnet.Address, 56);

                            break;
                    }
                }

                bool importResponse = request.GetQueryOrForm("import", bool.Parse, false);
                NetProxy proxy = _dnsWebService._dnsServer.Proxy;
                bool preferIPv6 = _dnsWebService._dnsServer.PreferIPv6;
                ushort udpPayloadSize = _dnsWebService._dnsServer.UdpPayloadSize;
                bool randomizeName = false;
                bool qnameMinimization = _dnsWebService._dnsServer.QnameMinimization;
                const int RETRIES = 1;
                const int TIMEOUT = 10000;

                DnsDatagram dnsResponse;
                List<DnsDatagram> rawResponses = new List<DnsDatagram>();
                string dnssecErrorMessage = null;

                if (server.Equals("recursive-resolver", StringComparison.OrdinalIgnoreCase))
                {
                    if (type == DnsResourceRecordType.AXFR)
                        throw new DnsServerException("Cannot do zone transfer (AXFR) for 'recursive-resolver'.");

                    DnsQuestionRecord question;

                    if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                        question = new DnsQuestionRecord(address, DnsClass.IN);
                    else
                        question = new DnsQuestionRecord(domain, type, DnsClass.IN);

                    DnsCache dnsCache = new DnsCache();
                    dnsCache.MinimumRecordTtl = 0;
                    dnsCache.MaximumRecordTtl = 7 * 24 * 60 * 60;

                    try
                    {
                        dnsResponse = await TechnitiumLibrary.TaskExtensions.TimeoutAsync(async delegate (CancellationToken cancellationToken1)
                        {
                            return await DnsClient.RecursiveResolveAsync(question, dnsCache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, eDnsClientSubnet, RETRIES, TIMEOUT, rawResponses: rawResponses, cancellationToken: cancellationToken1);
                        }, DnsServer.RECURSIVE_RESOLUTION_TIMEOUT);
                    }
                    catch (DnsClientResponseDnssecValidationException ex)
                    {
                        if (ex.InnerException is DnsClientResponseDnssecValidationException ex1)
                            ex = ex1;

                        dnsResponse = ex.Response;
                        dnssecErrorMessage = ex.Message;
                        importResponse = false;
                    }
                }
                else if (server.Equals("system-dns", StringComparison.OrdinalIgnoreCase))
                {
                    DnsClient dnsClient = new DnsClient();

                    dnsClient.Proxy = proxy;
                    dnsClient.PreferIPv6 = preferIPv6;
                    dnsClient.RandomizeName = randomizeName;
                    dnsClient.Retries = RETRIES;
                    dnsClient.Timeout = TIMEOUT;
                    dnsClient.UdpPayloadSize = udpPayloadSize;
                    dnsClient.DnssecValidation = dnssecValidation;
                    dnsClient.EDnsClientSubnet = eDnsClientSubnet;

                    try
                    {
                        dnsResponse = await dnsClient.ResolveAsync(domain, type);
                    }
                    catch (DnsClientResponseDnssecValidationException ex)
                    {
                        if (ex.InnerException is DnsClientResponseDnssecValidationException ex1)
                            ex = ex1;

                        dnsResponse = ex.Response;
                        dnssecErrorMessage = ex.Message;
                        importResponse = false;
                    }
                }
                else
                {
                    if ((type == DnsResourceRecordType.AXFR) && (protocol == DnsTransportProtocol.Udp))
                        protocol = DnsTransportProtocol.Tcp;

                    NameServerAddress nameServer;

                    if (server.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                    {
                        switch (protocol)
                        {
                            case DnsTransportProtocol.Udp:
                                nameServer = _dnsWebService._dnsServer.ThisServer;
                                break;

                            case DnsTransportProtocol.Tcp:
                                nameServer = _dnsWebService._dnsServer.ThisServer.ChangeProtocol(DnsTransportProtocol.Tcp);
                                break;

                            case DnsTransportProtocol.Tls:
                                throw new DnsServerException("Cannot use DNS-over-TLS protocol for 'this-server'. Please use the TLS certificate domain name as the server.");

                            case DnsTransportProtocol.Https:
                                throw new DnsServerException("Cannot use DNS-over-HTTPS protocol for 'this-server'. Please use the TLS certificate domain name with a url as the server.");

                            case DnsTransportProtocol.Quic:
                                throw new DnsServerException("Cannot use DNS-over-QUIC protocol for 'this-server'. Please use the TLS certificate domain name as the server.");

                            default:
                                throw new NotSupportedException("DNS transport protocol is not supported: " + protocol.ToString());
                        }

                        proxy = null; //no proxy required for this server
                    }
                    else
                    {
                        nameServer = NameServerAddress.Parse(server);

                        if (nameServer.Protocol != protocol)
                            nameServer = nameServer.ChangeProtocol(protocol);

                        if (nameServer.IsIPEndPointStale)
                            await nameServer.ResolveIPAddressAsync(_dnsWebService._dnsServer, _dnsWebService._dnsServer.PreferIPv6);

                        if ((nameServer.DomainEndPoint is null) && ((protocol == DnsTransportProtocol.Udp) || (protocol == DnsTransportProtocol.Tcp)))
                        {
                            try
                            {
                                await nameServer.ResolveDomainNameAsync(_dnsWebService._dnsServer);
                            }
                            catch
                            { }
                        }
                    }

                    DnsClient dnsClient = new DnsClient(nameServer);

                    dnsClient.Proxy = proxy;
                    dnsClient.PreferIPv6 = preferIPv6;
                    dnsClient.RandomizeName = randomizeName;
                    dnsClient.Retries = RETRIES;
                    dnsClient.Timeout = TIMEOUT;
                    dnsClient.UdpPayloadSize = udpPayloadSize;
                    dnsClient.DnssecValidation = dnssecValidation;
                    dnsClient.EDnsClientSubnet = eDnsClientSubnet;

                    if (dnssecValidation)
                    {
                        if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress ptrIp))
                            domain = ptrIp.GetReverseDomain();

                        //load trust anchors into dns client if domain is locally hosted
                        _dnsWebService._dnsServer.AuthZoneManager.LoadTrustAnchorsTo(dnsClient, domain, type);
                    }

                    try
                    {
                        dnsResponse = await dnsClient.ResolveAsync(domain, type);
                    }
                    catch (DnsClientResponseDnssecValidationException ex)
                    {
                        if (ex.InnerException is DnsClientResponseDnssecValidationException ex1)
                            ex = ex1;

                        dnsResponse = ex.Response;
                        dnssecErrorMessage = ex.Message;
                        importResponse = false;
                    }

                    if (type == DnsResourceRecordType.AXFR)
                        dnsResponse = dnsResponse.Join();
                }

                if (importResponse)
                {
                    bool isZoneImport = false;

                    if (type == DnsResourceRecordType.AXFR)
                    {
                        isZoneImport = true;
                    }
                    else
                    {
                        foreach (DnsResourceRecord record in dnsResponse.Answer)
                        {
                            if (record.Type == DnsResourceRecordType.SOA)
                            {
                                if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                                    isZoneImport = true;

                                break;
                            }
                        }
                    }

                    AuthZoneInfo zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.FindAuthZoneInfo(domain);
                    if (
                        (zoneInfo is null) ||
                        ((zoneInfo.Type != AuthZoneType.Primary) && (zoneInfo.Type != AuthZoneType.Forwarder) && !zoneInfo.Name.Equals(domain, StringComparison.OrdinalIgnoreCase)) ||
                        (isZoneImport && !zoneInfo.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                       )
                    {
                        if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify))
                            throw new DnsWebServiceException("Access was denied.");

                        zoneInfo = _dnsWebService._dnsServer.AuthZoneManager.CreatePrimaryZone(domain);
                        if (zoneInfo is null)
                            throw new DnsServerException("Cannot import records: failed to create primary zone.");

                        //set permissions
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        _dnsWebService._authManager.SaveConfigFile();
                    }
                    else
                    {
                        if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, sessionUser, PermissionFlag.Modify))
                            throw new DnsWebServiceException("Access was denied.");

                        switch (zoneInfo.Type)
                        {
                            case AuthZoneType.Primary:
                                break;

                            case AuthZoneType.Forwarder:
                                if (type == DnsResourceRecordType.AXFR)
                                    throw new DnsServerException("Cannot import records via zone transfer: import zone must be of primary type.");

                                break;

                            default:
                                throw new DnsServerException("Cannot import records: import zone must be of primary or forwarder type.");
                        }
                    }

                    if (type == DnsResourceRecordType.AXFR)
                    {
                        _dnsWebService._dnsServer.AuthZoneManager.SyncZoneTransferRecords(zoneInfo.Name, dnsResponse.Answer);
                    }
                    else
                    {
                        List<DnsResourceRecord> importRecords = new List<DnsResourceRecord>(dnsResponse.Answer.Count + dnsResponse.Authority.Count);

                        foreach (DnsResourceRecord record in dnsResponse.Answer)
                        {
                            if (record.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneInfo.Name, StringComparison.OrdinalIgnoreCase) || (zoneInfo.Name.Length == 0))
                            {
                                record.RemoveExpiry();
                                record.Tag = null; //remove cache zone record info

                                importRecords.Add(record);

                                if (record.Type == DnsResourceRecordType.NS)
                                    record.SyncGlueRecords(dnsResponse.Additional);
                            }
                        }

                        foreach (DnsResourceRecord record in dnsResponse.Authority)
                        {
                            if (record.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneInfo.Name, StringComparison.OrdinalIgnoreCase) || (zoneInfo.Name.Length == 0))
                            {
                                record.RemoveExpiry();
                                record.Tag = null; //remove cache zone record info

                                importRecords.Add(record);

                                if (record.Type == DnsResourceRecordType.NS)
                                    record.SyncGlueRecords(dnsResponse.Additional);
                            }
                        }

                        _dnsWebService._dnsServer.AuthZoneManager.ImportRecords(zoneInfo.Name, importRecords, true, true);
                    }

                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DNS Client imported record(s) for authoritative zone {server: " + server + "; zone: " + zoneInfo.DisplayName + "; type: " + type + ";}");
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                if (dnssecErrorMessage is not null)
                    jsonWriter.WriteString("warningMessage", dnssecErrorMessage);

                jsonWriter.WritePropertyName("result");
                dnsResponse.SerializeTo(jsonWriter);

                jsonWriter.WritePropertyName("rawResponses");
                jsonWriter.WriteStartArray();

                for (int i = 0; i < rawResponses.Count; i++)
                    rawResponses[i].SerializeTo(jsonWriter);

                jsonWriter.WriteEndArray();
            }

            #endregion
        }
    }
}
