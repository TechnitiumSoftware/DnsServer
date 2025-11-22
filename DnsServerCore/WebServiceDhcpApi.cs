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
using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        class WebServiceDhcpApi
        {
            #region variables

            static readonly char[] _commaSeparator = new char[] { ',' };

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceDhcpApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region public

            public void ListDhcpLeases(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                IReadOnlyDictionary<string, Scope> scopes = _dnsWebService._dhcpServer.Scopes;

                //sort by name
                List<Scope> sortedScopes = new List<Scope>(scopes.Count);

                foreach (KeyValuePair<string, Scope> entry in scopes)
                    sortedScopes.Add(entry.Value);

                sortedScopes.Sort();

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("leases");
                jsonWriter.WriteStartArray();

                foreach (Scope scope in sortedScopes)
                {
                    IReadOnlyDictionary<ClientIdentifierOption, Lease> leases = scope.Leases;

                    //sort by address
                    List<Lease> sortedLeases = new List<Lease>(leases.Count);

                    foreach (KeyValuePair<ClientIdentifierOption, Lease> entry in leases)
                        sortedLeases.Add(entry.Value);

                    sortedLeases.Sort();

                    foreach (Lease lease in sortedLeases)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("scope", scope.Name);
                        jsonWriter.WriteString("type", lease.Type.ToString());
                        jsonWriter.WriteString("hardwareAddress", BitConverter.ToString(lease.HardwareAddress));
                        jsonWriter.WriteString("clientIdentifier", lease.ClientIdentifier.ToString());
                        jsonWriter.WriteString("address", lease.Address.ToString());
                        jsonWriter.WriteString("hostName", lease.HostName);
                        jsonWriter.WriteString("leaseObtained", lease.LeaseObtained);
                        jsonWriter.WriteString("leaseExpires", lease.LeaseExpires);

                        jsonWriter.WriteEndObject();
                    }
                }

                jsonWriter.WriteEndArray();
            }

            public void ListDhcpScopes(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                IReadOnlyDictionary<string, Scope> scopes = _dnsWebService._dhcpServer.Scopes;

                //sort by name
                List<Scope> sortedScopes = new List<Scope>(scopes.Count);

                foreach (KeyValuePair<string, Scope> entry in scopes)
                    sortedScopes.Add(entry.Value);

                sortedScopes.Sort();

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("scopes");
                jsonWriter.WriteStartArray();

                foreach (Scope scope in sortedScopes)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteString("name", scope.Name);
                    jsonWriter.WriteBoolean("enabled", scope.Enabled);
                    jsonWriter.WriteString("startingAddress", scope.StartingAddress.ToString());
                    jsonWriter.WriteString("endingAddress", scope.EndingAddress.ToString());
                    jsonWriter.WriteString("subnetMask", scope.SubnetMask.ToString());
                    jsonWriter.WriteString("networkAddress", scope.NetworkAddress.ToString());
                    jsonWriter.WriteString("broadcastAddress", scope.BroadcastAddress.ToString());

                    if (scope.InterfaceAddress is not null)
                        jsonWriter.WriteString("interfaceAddress", scope.InterfaceAddress.ToString());

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            public void GetDhcpScope(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                string scopeName = context.Request.GetQueryOrForm("name");

                Scope scope = _dnsWebService._dhcpServer.GetScope(scopeName);
                if (scope is null)
                    throw new DnsWebServiceException("DHCP scope was not found: " + scopeName);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WriteString("name", scope.Name);
                jsonWriter.WriteString("startingAddress", scope.StartingAddress.ToString());
                jsonWriter.WriteString("endingAddress", scope.EndingAddress.ToString());
                jsonWriter.WriteString("subnetMask", scope.SubnetMask.ToString());
                jsonWriter.WriteNumber("leaseTimeDays", scope.LeaseTimeDays);
                jsonWriter.WriteNumber("leaseTimeHours", scope.LeaseTimeHours);
                jsonWriter.WriteNumber("leaseTimeMinutes", scope.LeaseTimeMinutes);
                jsonWriter.WriteNumber("offerDelayTime", scope.OfferDelayTime);

                jsonWriter.WriteBoolean("pingCheckEnabled", scope.PingCheckEnabled);
                jsonWriter.WriteNumber("pingCheckTimeout", scope.PingCheckTimeout);
                jsonWriter.WriteNumber("pingCheckRetries", scope.PingCheckRetries);

                if (!string.IsNullOrEmpty(scope.DomainName))
                    jsonWriter.WriteString("domainName", scope.DomainName);

                if (scope.DomainSearchList is not null)
                {
                    jsonWriter.WritePropertyName("domainSearchList");
                    jsonWriter.WriteStartArray();

                    foreach (string domainSearchString in scope.DomainSearchList)
                        jsonWriter.WriteStringValue(domainSearchString);

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteBoolean("dnsUpdates", scope.DnsUpdates);
                jsonWriter.WriteNumber("dnsTtl", scope.DnsTtl);

                if (scope.ServerAddress is not null)
                    jsonWriter.WriteString("serverAddress", scope.ServerAddress.ToString());

                if (scope.ServerHostName is not null)
                    jsonWriter.WriteString("serverHostName", scope.ServerHostName);

                if (scope.BootFileName is not null)
                    jsonWriter.WriteString("bootFileName", scope.BootFileName);

                if (scope.RouterAddress is not null)
                    jsonWriter.WriteString("routerAddress", scope.RouterAddress.ToString());

                jsonWriter.WriteBoolean("useThisDnsServer", scope.UseThisDnsServer);

                if (scope.DnsServers is not null)
                {
                    jsonWriter.WritePropertyName("dnsServers");
                    jsonWriter.WriteStartArray();

                    foreach (IPAddress dnsServer in scope.DnsServers)
                        jsonWriter.WriteStringValue(dnsServer.ToString());

                    jsonWriter.WriteEndArray();
                }

                if (scope.WinsServers is not null)
                {
                    jsonWriter.WritePropertyName("winsServers");
                    jsonWriter.WriteStartArray();

                    foreach (IPAddress winsServer in scope.WinsServers)
                        jsonWriter.WriteStringValue(winsServer.ToString());

                    jsonWriter.WriteEndArray();
                }

                if (scope.NtpServers is not null)
                {
                    jsonWriter.WritePropertyName("ntpServers");
                    jsonWriter.WriteStartArray();

                    foreach (IPAddress ntpServer in scope.NtpServers)
                        jsonWriter.WriteStringValue(ntpServer.ToString());

                    jsonWriter.WriteEndArray();
                }

                if (scope.NtpServerDomainNames is not null)
                {
                    jsonWriter.WritePropertyName("ntpServerDomainNames");
                    jsonWriter.WriteStartArray();

                    foreach (string ntpServerDomainName in scope.NtpServerDomainNames)
                        jsonWriter.WriteStringValue(ntpServerDomainName);

                    jsonWriter.WriteEndArray();
                }

                if (scope.StaticRoutes is not null)
                {
                    jsonWriter.WritePropertyName("staticRoutes");
                    jsonWriter.WriteStartArray();

                    foreach (ClasslessStaticRouteOption.Route route in scope.StaticRoutes)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("destination", route.Destination.ToString());
                        jsonWriter.WriteString("subnetMask", route.SubnetMask.ToString());
                        jsonWriter.WriteString("router", route.Router.ToString());

                        jsonWriter.WriteEndObject();
                    }

                    jsonWriter.WriteEndArray();
                }

                if (scope.VendorInfo is not null)
                {
                    jsonWriter.WritePropertyName("vendorInfo");
                    jsonWriter.WriteStartArray();

                    foreach (KeyValuePair<string, VendorSpecificInformationOption> entry in scope.VendorInfo)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("identifier", entry.Key);
                        jsonWriter.WriteString("information", BitConverter.ToString(entry.Value.Information).Replace('-', ':'));

                        jsonWriter.WriteEndObject();
                    }

                    jsonWriter.WriteEndArray();
                }

                if (scope.CAPWAPAcIpAddresses is not null)
                {
                    jsonWriter.WritePropertyName("capwapAcIpAddresses");
                    jsonWriter.WriteStartArray();

                    foreach (IPAddress acIpAddress in scope.CAPWAPAcIpAddresses)
                        jsonWriter.WriteStringValue(acIpAddress.ToString());

                    jsonWriter.WriteEndArray();
                }

                if (scope.TftpServerAddresses is not null)
                {
                    jsonWriter.WritePropertyName("tftpServerAddresses");
                    jsonWriter.WriteStartArray();

                    foreach (IPAddress address in scope.TftpServerAddresses)
                        jsonWriter.WriteStringValue(address.ToString());

                    jsonWriter.WriteEndArray();
                }

                if (scope.GenericOptions is not null)
                {
                    jsonWriter.WritePropertyName("genericOptions");
                    jsonWriter.WriteStartArray();

                    foreach (DhcpOption genericOption in scope.GenericOptions)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteNumber("code", (byte)genericOption.Code);
                        jsonWriter.WriteString("value", BitConverter.ToString(genericOption.RawValue).Replace('-', ':'));

                        jsonWriter.WriteEndObject();
                    }

                    jsonWriter.WriteEndArray();
                }

                if (scope.Exclusions is not null)
                {
                    jsonWriter.WritePropertyName("exclusions");
                    jsonWriter.WriteStartArray();

                    foreach (Exclusion exclusion in scope.Exclusions)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("startingAddress", exclusion.StartingAddress.ToString());
                        jsonWriter.WriteString("endingAddress", exclusion.EndingAddress.ToString());

                        jsonWriter.WriteEndObject();
                    }

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WritePropertyName("reservedLeases");
                jsonWriter.WriteStartArray();

                foreach (Lease reservedLease in scope.ReservedLeases)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteString("hostName", reservedLease.HostName);
                    jsonWriter.WriteString("hardwareAddress", BitConverter.ToString(reservedLease.HardwareAddress));
                    jsonWriter.WriteString("address", reservedLease.Address.ToString());
                    jsonWriter.WriteString("comments", reservedLease.Comments);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteBoolean("allowOnlyReservedLeases", scope.AllowOnlyReservedLeases);
                jsonWriter.WriteBoolean("blockLocallyAdministeredMacAddresses", scope.BlockLocallyAdministeredMacAddresses);
                jsonWriter.WriteBoolean("ignoreClientIdentifierOption", scope.IgnoreClientIdentifierOption);
            }

            public async Task SetDhcpScopeAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string scopeName = request.GetQueryOrForm("name");
                string strStartingAddress = request.QueryOrForm("startingAddress");
                string strEndingAddress = request.QueryOrForm("endingAddress");
                string strSubnetMask = request.QueryOrForm("subnetMask");

                bool scopeExists;
                Scope scope = _dnsWebService._dhcpServer.GetScope(scopeName);
                if (scope is null)
                {
                    //scope does not exists; create new scope
                    if (string.IsNullOrEmpty(strStartingAddress))
                        throw new DnsWebServiceException("Parameter 'startingAddress' missing.");

                    if (string.IsNullOrEmpty(strEndingAddress))
                        throw new DnsWebServiceException("Parameter 'endingAddress' missing.");

                    if (string.IsNullOrEmpty(strSubnetMask))
                        throw new DnsWebServiceException("Parameter 'subnetMask' missing.");

                    scopeExists = false;
                    scope = new Scope(scopeName, true, IPAddress.Parse(strStartingAddress), IPAddress.Parse(strEndingAddress), IPAddress.Parse(strSubnetMask), _dnsWebService._log, _dnsWebService._dhcpServer);
                    scope.IgnoreClientIdentifierOption = true;
                }
                else
                {
                    scopeExists = true;

                    IPAddress startingAddress = string.IsNullOrEmpty(strStartingAddress) ? scope.StartingAddress : IPAddress.Parse(strStartingAddress);
                    IPAddress endingAddress = string.IsNullOrEmpty(strEndingAddress) ? scope.EndingAddress : IPAddress.Parse(strEndingAddress);
                    IPAddress subnetMask = string.IsNullOrEmpty(strSubnetMask) ? scope.SubnetMask : IPAddress.Parse(strSubnetMask);

                    //validate scope address
                    foreach (KeyValuePair<string, Scope> entry in _dnsWebService._dhcpServer.Scopes)
                    {
                        Scope existingScope = entry.Value;

                        if (existingScope.Equals(scope))
                            continue;

                        if (existingScope.IsAddressInRange(startingAddress) || existingScope.IsAddressInRange(endingAddress))
                            throw new DhcpServerException("Scope with overlapping range already exists: " + existingScope.StartingAddress.ToString() + "-" + existingScope.EndingAddress.ToString());
                    }

                    scope.ChangeNetwork(startingAddress, endingAddress, subnetMask);
                }

                if (request.TryGetQueryOrForm("leaseTimeDays", ushort.Parse, out ushort leaseTimeDays))
                    scope.LeaseTimeDays = leaseTimeDays;

                if (request.TryGetQueryOrForm("leaseTimeHours", byte.Parse, out byte leaseTimeHours))
                    scope.LeaseTimeHours = leaseTimeHours;

                if (request.TryGetQueryOrForm("leaseTimeMinutes", byte.Parse, out byte leaseTimeMinutes))
                    scope.LeaseTimeMinutes = leaseTimeMinutes;

                if (request.TryGetQueryOrForm("offerDelayTime", ushort.Parse, out ushort offerDelayTime))
                    scope.OfferDelayTime = offerDelayTime;

                if (request.TryGetQueryOrForm("pingCheckEnabled", bool.Parse, out bool pingCheckEnabled))
                    scope.PingCheckEnabled = pingCheckEnabled;

                if (request.TryGetQueryOrForm("pingCheckTimeout", ushort.Parse, out ushort pingCheckTimeout))
                    scope.PingCheckTimeout = pingCheckTimeout;

                if (request.TryGetQueryOrForm("pingCheckRetries", byte.Parse, out byte pingCheckRetries))
                    scope.PingCheckRetries = pingCheckRetries;

                string domainName = request.QueryOrForm("domainName");
                if (domainName is not null)
                    scope.DomainName = domainName.Length == 0 ? null : domainName;

                string domainSearchList = request.QueryOrForm("domainSearchList");
                if (domainSearchList is not null)
                {
                    if (domainSearchList.Length == 0)
                        scope.DomainSearchList = null;
                    else
                        scope.DomainSearchList = domainSearchList.Split(_commaSeparator, StringSplitOptions.RemoveEmptyEntries);
                }

                if (request.TryGetQueryOrForm("dnsUpdates", bool.Parse, out bool dnsUpdates))
                    scope.DnsUpdates = dnsUpdates;

                if (request.TryGetQueryOrForm("dnsTtl", ZoneFile.ParseTtl, out uint dnsTtl))
                    scope.DnsTtl = dnsTtl;

                string serverAddress = request.QueryOrForm("serverAddress");
                if (serverAddress is not null)
                    scope.ServerAddress = serverAddress.Length == 0 ? null : IPAddress.Parse(serverAddress);

                string serverHostName = request.QueryOrForm("serverHostName");
                if (serverHostName is not null)
                    scope.ServerHostName = serverHostName.Length == 0 ? null : serverHostName;

                string bootFileName = request.QueryOrForm("bootFileName");
                if (bootFileName is not null)
                    scope.BootFileName = bootFileName.Length == 0 ? null : bootFileName;

                string routerAddress = request.QueryOrForm("routerAddress");
                if (routerAddress is not null)
                    scope.RouterAddress = routerAddress.Length == 0 ? null : IPAddress.Parse(routerAddress);

                if (request.TryGetQueryOrForm("useThisDnsServer", bool.Parse, out bool useThisDnsServer))
                    scope.UseThisDnsServer = useThisDnsServer;

                if (!scope.UseThisDnsServer)
                {
                    string dnsServers = request.QueryOrForm("dnsServers");
                    if (dnsServers is not null)
                    {
                        if (dnsServers.Length == 0)
                            scope.DnsServers = null;
                        else
                            scope.DnsServers = dnsServers.Split(IPAddress.Parse, ',');
                    }
                }

                string winsServers = request.QueryOrForm("winsServers");
                if (winsServers is not null)
                {
                    if (winsServers.Length == 0)
                        scope.WinsServers = null;
                    else
                        scope.WinsServers = winsServers.Split(IPAddress.Parse, ',');
                }

                string ntpServers = request.QueryOrForm("ntpServers");
                if (ntpServers is not null)
                {
                    if (ntpServers.Length == 0)
                        scope.NtpServers = null;
                    else
                        scope.NtpServers = ntpServers.Split(IPAddress.Parse, ',');
                }

                string ntpServerDomainNames = request.QueryOrForm("ntpServerDomainNames");
                if (ntpServerDomainNames is not null)
                {
                    if (ntpServerDomainNames.Length == 0)
                        scope.NtpServerDomainNames = null;
                    else
                        scope.NtpServerDomainNames = ntpServerDomainNames.Split(_commaSeparator, StringSplitOptions.RemoveEmptyEntries);
                }

                string strStaticRoutes = request.QueryOrForm("staticRoutes");
                if (strStaticRoutes is not null)
                {
                    if (strStaticRoutes.Length == 0)
                    {
                        scope.StaticRoutes = null;
                    }
                    else
                    {
                        string[] strStaticRoutesParts = strStaticRoutes.Split('|');
                        List<ClasslessStaticRouteOption.Route> staticRoutes = new List<ClasslessStaticRouteOption.Route>();

                        for (int i = 0; i < strStaticRoutesParts.Length; i += 3)
                            staticRoutes.Add(new ClasslessStaticRouteOption.Route(IPAddress.Parse(strStaticRoutesParts[i + 0]), IPAddress.Parse(strStaticRoutesParts[i + 1]), IPAddress.Parse(strStaticRoutesParts[i + 2])));

                        scope.StaticRoutes = staticRoutes;
                    }
                }

                string strVendorInfo = request.QueryOrForm("vendorInfo");
                if (strVendorInfo is not null)
                {
                    if (strVendorInfo.Length == 0)
                    {
                        scope.VendorInfo = null;
                    }
                    else
                    {
                        string[] strVendorInfoParts = strVendorInfo.Split('|');
                        Dictionary<string, VendorSpecificInformationOption> vendorInfo = new Dictionary<string, VendorSpecificInformationOption>();

                        for (int i = 0; i < strVendorInfoParts.Length; i += 2)
                            vendorInfo.Add(strVendorInfoParts[i + 0], new VendorSpecificInformationOption(strVendorInfoParts[i + 1]));

                        scope.VendorInfo = vendorInfo;
                    }
                }

                string capwapAcIpAddresses = request.QueryOrForm("capwapAcIpAddresses");
                if (capwapAcIpAddresses is not null)
                {
                    if (capwapAcIpAddresses.Length == 0)
                        scope.CAPWAPAcIpAddresses = null;
                    else
                        scope.CAPWAPAcIpAddresses = capwapAcIpAddresses.Split(IPAddress.Parse, ',');
                }

                string tftpServerAddresses = request.QueryOrForm("tftpServerAddresses");
                if (tftpServerAddresses is not null)
                {
                    if (tftpServerAddresses.Length == 0)
                        scope.TftpServerAddresses = null;
                    else
                        scope.TftpServerAddresses = tftpServerAddresses.Split(IPAddress.Parse, ',');
                }

                string strGenericOptions = request.QueryOrForm("genericOptions");
                if (strGenericOptions is not null)
                {
                    if (strGenericOptions.Length == 0)
                    {
                        scope.GenericOptions = null;
                    }
                    else
                    {
                        string[] strGenericOptionsParts = strGenericOptions.Split('|');
                        List<DhcpOption> genericOptions = new List<DhcpOption>();

                        for (int i = 0; i < strGenericOptionsParts.Length; i += 2)
                            genericOptions.Add(new DhcpOption((DhcpOptionCode)byte.Parse(strGenericOptionsParts[i + 0]), strGenericOptionsParts[i + 1]));

                        scope.GenericOptions = genericOptions;
                    }
                }

                string strExclusions = request.QueryOrForm("exclusions");
                if (strExclusions is not null)
                {
                    if (strExclusions.Length == 0)
                    {
                        scope.Exclusions = null;
                    }
                    else
                    {
                        string[] strExclusionsParts = strExclusions.Split('|');
                        List<Exclusion> exclusions = new List<Exclusion>();

                        for (int i = 0; i < strExclusionsParts.Length; i += 2)
                            exclusions.Add(new Exclusion(IPAddress.Parse(strExclusionsParts[i + 0]), IPAddress.Parse(strExclusionsParts[i + 1])));

                        scope.Exclusions = exclusions;
                    }
                }

                string strReservedLeases = request.QueryOrForm("reservedLeases");
                if (strReservedLeases is not null)
                {
                    if (strReservedLeases.Length == 0)
                    {
                        scope.ReservedLeases = null;
                    }
                    else
                    {
                        string[] strReservedLeaseParts = strReservedLeases.Split('|');
                        List<Lease> reservedLeases = new List<Lease>();

                        for (int i = 0; i < strReservedLeaseParts.Length; i += 4)
                            reservedLeases.Add(new Lease(LeaseType.Reserved, strReservedLeaseParts[i + 0], DhcpMessageHardwareAddressType.Ethernet, strReservedLeaseParts[i + 1], IPAddress.Parse(strReservedLeaseParts[i + 2]), strReservedLeaseParts[i + 3]));

                        scope.ReservedLeases = reservedLeases;
                    }
                }

                if (request.TryGetQueryOrForm("allowOnlyReservedLeases", bool.Parse, out bool allowOnlyReservedLeases))
                    scope.AllowOnlyReservedLeases = allowOnlyReservedLeases;

                if (request.TryGetQueryOrForm("blockLocallyAdministeredMacAddresses", bool.Parse, out bool blockLocallyAdministeredMacAddresses))
                    scope.BlockLocallyAdministeredMacAddresses = blockLocallyAdministeredMacAddresses;

                if (request.TryGetQueryOrForm("ignoreClientIdentifierOption", bool.Parse, out bool ignoreClientIdentifierOption))
                    scope.IgnoreClientIdentifierOption = ignoreClientIdentifierOption;

                if (scopeExists)
                {
                    _dnsWebService._dhcpServer.SaveScope(scopeName);

                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DHCP scope was updated successfully: " + scopeName);
                }
                else
                {
                    await _dnsWebService._dhcpServer.AddScopeAsync(scope);

                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DHCP scope was added successfully: " + scopeName);
                }

                if (request.TryGetQueryOrForm("newName", out string newName) && !newName.Equals(scopeName))
                {
                    _dnsWebService._dhcpServer.RenameScope(scopeName, newName);

                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DHCP scope was renamed successfully: '" + scopeName + "' to '" + newName + "'");
                }
            }

            public void AddReservedLease(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string scopeName = request.GetQueryOrForm("name");

                Scope scope = _dnsWebService._dhcpServer.GetScope(scopeName);
                if (scope is null)
                    throw new DnsWebServiceException("No such scope exists: " + scopeName);

                string hostName = request.QueryOrForm("hostName");
                string hardwareAddress = request.GetQueryOrForm("hardwareAddress");
                string strIpAddress = request.GetQueryOrForm("ipAddress");
                string comments = request.QueryOrForm("comments");

                Lease reservedLease = new Lease(LeaseType.Reserved, hostName, DhcpMessageHardwareAddressType.Ethernet, hardwareAddress, IPAddress.Parse(strIpAddress), comments);

                if (!scope.AddReservedLease(reservedLease))
                    throw new DnsWebServiceException("Failed to add reserved lease for scope: " + scopeName);

                _dnsWebService._dhcpServer.SaveScope(scopeName);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DHCP scope reserved lease was added successfully: " + scopeName);
            }

            public void RemoveReservedLease(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string scopeName = request.GetQueryOrForm("name");

                Scope scope = _dnsWebService._dhcpServer.GetScope(scopeName);
                if (scope is null)
                    throw new DnsWebServiceException("No such scope exists: " + scopeName);

                string hardwareAddress = request.GetQueryOrForm("hardwareAddress");

                if (!scope.RemoveReservedLease(hardwareAddress))
                    throw new DnsWebServiceException("Failed to remove reserved lease for scope: " + scopeName);

                _dnsWebService._dhcpServer.SaveScope(scopeName);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DHCP scope reserved lease was removed successfully: " + scopeName);
            }

            public async Task EnableDhcpScopeAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string scopeName = context.Request.GetQueryOrForm("name");

                await _dnsWebService._dhcpServer.EnableScopeAsync(scopeName, true);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DHCP scope was enabled successfully: " + scopeName);
            }

            public void DisableDhcpScope(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                string scopeName = context.Request.GetQueryOrForm("name");

                _dnsWebService._dhcpServer.DisableScope(scopeName, true);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DHCP scope was disabled successfully: " + scopeName);
            }

            public void DeleteDhcpScope(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                string scopeName = context.Request.GetQueryOrForm("name");

                _dnsWebService._dhcpServer.DeleteScope(scopeName);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DHCP scope was deleted successfully: " + scopeName);
            }

            public void RemoveDhcpLease(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string scopeName = request.GetQueryOrForm("name");

                Scope scope = _dnsWebService._dhcpServer.GetScope(scopeName);
                if (scope is null)
                    throw new DnsWebServiceException("DHCP scope does not exists: " + scopeName);

                string clientIdentifier = request.QueryOrForm("clientIdentifier");
                string hardwareAddress = request.QueryOrForm("hardwareAddress");

                if (!string.IsNullOrEmpty(clientIdentifier))
                    scope.RemoveLease(ClientIdentifierOption.Parse(clientIdentifier));
                else if (!string.IsNullOrEmpty(hardwareAddress))
                    scope.RemoveLease(hardwareAddress);
                else
                    throw new DnsWebServiceException("Parameter 'hardwareAddress' or 'clientIdentifier' missing. At least one of them must be specified.");

                _dnsWebService._dhcpServer.SaveScope(scopeName);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DHCP scope's lease was removed successfully: " + scopeName);
            }

            public void ConvertToReservedLease(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string scopeName = request.GetQueryOrForm("name");

                Scope scope = _dnsWebService._dhcpServer.GetScope(scopeName);
                if (scope == null)
                    throw new DnsWebServiceException("DHCP scope does not exists: " + scopeName);

                string clientIdentifier = request.QueryOrForm("clientIdentifier");
                string hardwareAddress = request.QueryOrForm("hardwareAddress");

                if (!string.IsNullOrEmpty(clientIdentifier))
                    scope.ConvertToReservedLease(ClientIdentifierOption.Parse(clientIdentifier));
                else if (!string.IsNullOrEmpty(hardwareAddress))
                    scope.ConvertToReservedLease(hardwareAddress);
                else
                    throw new DnsWebServiceException("Parameter 'hardwareAddress' or 'clientIdentifier' missing. At least one of them must be specified.");

                _dnsWebService._dhcpServer.SaveScope(scopeName);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DHCP scope's lease was reserved successfully: " + scopeName);
            }

            public void ConvertToDynamicLease(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string scopeName = request.GetQueryOrForm("name");

                Scope scope = _dnsWebService._dhcpServer.GetScope(scopeName);
                if (scope == null)
                    throw new DnsWebServiceException("DHCP scope does not exists: " + scopeName);

                string clientIdentifier = request.QueryOrForm("clientIdentifier");
                string hardwareAddress = request.QueryOrForm("hardwareAddress");

                if (!string.IsNullOrEmpty(clientIdentifier))
                    scope.ConvertToDynamicLease(ClientIdentifierOption.Parse(clientIdentifier));
                else if (!string.IsNullOrEmpty(hardwareAddress))
                    scope.ConvertToDynamicLease(hardwareAddress);
                else
                    throw new DnsWebServiceException("Parameter 'hardwareAddress' or 'clientIdentifier' missing. At least one of them must be specified.");

                _dnsWebService._dhcpServer.SaveScope(scopeName);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] DHCP scope's lease was unreserved successfully: " + scopeName);
            }

            #endregion
        }
    }
}
