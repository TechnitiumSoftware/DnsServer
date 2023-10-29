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
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    class WebServiceApi
    {
        #region variables

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
                SocketsHttpHandler handler = new SocketsHttpHandler();
                handler.Proxy = _dnsWebService.DnsServer.Proxy;
                handler.UseProxy = _dnsWebService.DnsServer.Proxy is not null;
                handler.AutomaticDecompression = DecompressionMethods.All;

                using (HttpClient http = new HttpClient(new HttpClientNetworkHandler(handler, _dnsWebService.DnsServer.PreferIPv6 ? HttpClientNetworkType.PreferIPv6 : HttpClientNetworkType.Default, _dnsWebService.DnsServer)))
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

                _dnsWebService._log.Write(context.GetRemoteEndPoint(), strLog);
            }
            catch (Exception ex)
            {
                _dnsWebService._log.Write(context.GetRemoteEndPoint(), "Check for update was done {updateAvailable: False;}\r\n" + ex.ToString());

                jsonWriter.WriteBoolean("updateAvailable", false);
            }
        }

        public async Task ResolveQueryAsync(HttpContext context)
        {
            UserSession session = context.GetCurrentSession();

            if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DnsClient, session.User, PermissionFlag.View))
                throw new DnsWebServiceException("Access was denied.");

            HttpRequest request = context.Request;

            string server = request.GetQueryOrForm("server");
            string domain = request.GetQueryOrForm("domain").Trim(new char[] { '\t', ' ', '.' });
            DnsResourceRecordType type = request.GetQueryOrFormEnum<DnsResourceRecordType>("type");
            DnsTransportProtocol protocol = request.GetQueryOrFormEnum("protocol", DnsTransportProtocol.Udp);
            bool dnssecValidation = request.GetQueryOrForm("dnssec", bool.Parse, false);
            bool importResponse = request.GetQueryOrForm("import", bool.Parse, false);
            NetProxy proxy = _dnsWebService.DnsServer.Proxy;
            bool preferIPv6 = _dnsWebService.DnsServer.PreferIPv6;
            ushort udpPayloadSize = _dnsWebService.DnsServer.UdpPayloadSize;
            bool randomizeName = false;
            bool qnameMinimization = _dnsWebService.DnsServer.QnameMinimization;
            const int RETRIES = 1;
            const int TIMEOUT = 10000;

            DnsDatagram dnsResponse;
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
                    dnsResponse = await DnsClient.RecursiveResolveAsync(question, dnsCache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, false, dnssecValidation, null, RETRIES, TIMEOUT);
                }
                catch (DnsClientResponseDnssecValidationException ex)
                {
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

                try
                {
                    dnsResponse = await dnsClient.ResolveAsync(domain, type);
                }
                catch (DnsClientResponseDnssecValidationException ex)
                {
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
                            nameServer = _dnsWebService.DnsServer.ThisServer;
                            break;

                        case DnsTransportProtocol.Tcp:
                            nameServer = _dnsWebService.DnsServer.ThisServer.ChangeProtocol(DnsTransportProtocol.Tcp);
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
                    {
                        if (proxy is null)
                            await nameServer.ResolveIPAddressAsync(_dnsWebService.DnsServer, _dnsWebService.DnsServer.PreferIPv6);
                    }
                    else if ((nameServer.DomainEndPoint is null) && ((protocol == DnsTransportProtocol.Udp) || (protocol == DnsTransportProtocol.Tcp)))
                    {
                        try
                        {
                            await nameServer.ResolveDomainNameAsync(_dnsWebService.DnsServer);
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

                if (dnssecValidation)
                {
                    if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress ptrIp))
                        domain = ptrIp.GetReverseDomain();

                    //load trust anchors into dns client if domain is locally hosted
                    _dnsWebService.DnsServer.AuthZoneManager.LoadTrustAnchorsTo(dnsClient, domain, type);
                }

                try
                {
                    dnsResponse = await dnsClient.ResolveAsync(domain, type);
                }
                catch (DnsClientResponseDnssecValidationException ex)
                {
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

                AuthZoneInfo zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(domain);
                if ((zoneInfo is null) || ((zoneInfo.Type != AuthZoneType.Primary) && !zoneInfo.Name.Equals(domain, StringComparison.OrdinalIgnoreCase)) || (isZoneImport && !zoneInfo.Name.Equals(domain, StringComparison.OrdinalIgnoreCase)))
                {
                    if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                        throw new DnsWebServiceException("Access was denied.");

                    zoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreatePrimaryZone(domain, _dnsWebService.DnsServer.ServerDomain, false);
                    if (zoneInfo is null)
                        throw new DnsServerException("Cannot import records: failed to create primary zone.");

                    //set permissions
                    _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                    _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _dnsWebService._authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _dnsWebService._authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _dnsWebService._authManager.SaveConfigFile();
                }
                else
                {
                    if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
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
                    _dnsWebService.DnsServer.AuthZoneManager.SyncZoneTransferRecords(zoneInfo.Name, dnsResponse.Answer);
                }
                else
                {
                    List<DnsResourceRecord> importRecords = new List<DnsResourceRecord>(dnsResponse.Answer.Count + dnsResponse.Authority.Count);

                    foreach (DnsResourceRecord record in dnsResponse.Answer)
                    {
                        if (record.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneInfo.Name, StringComparison.OrdinalIgnoreCase) || (zoneInfo.Name.Length == 0))
                        {
                            record.RemoveExpiry();
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
                            importRecords.Add(record);

                            if (record.Type == DnsResourceRecordType.NS)
                                record.SyncGlueRecords(dnsResponse.Additional);
                        }
                    }

                    _dnsWebService.DnsServer.AuthZoneManager.ImportRecords(zoneInfo.Name, importRecords, true);
                }

                _dnsWebService._log.Write(context.GetRemoteEndPoint(), "[" + session.User.Username + "] DNS Client imported record(s) for authoritative zone {server: " + server + "; zone: " + zoneInfo.Name + "; type: " + type + ";}");

                _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
            }

            Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

            if (dnssecErrorMessage is not null)
                jsonWriter.WriteString("warningMessage", dnssecErrorMessage);

            jsonWriter.WritePropertyName("result");
            dnsResponse.SerializeTo(jsonWriter);
        }

        #endregion
    }
}
