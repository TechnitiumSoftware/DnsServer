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

using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;

namespace DnsServerCore
{
    class WebServiceDhcpApi
    {
        #region variables

        readonly DnsWebService _dnsWebService;

        #endregion

        #region constructor

        public WebServiceDhcpApi(DnsWebService dnsWebService)
        {
            _dnsWebService = dnsWebService;
        }

        #endregion

        #region public

        public void ListDhcpLeases(Utf8JsonWriter jsonWriter)
        {
            IReadOnlyDictionary<string, Scope> scopes = _dnsWebService.DhcpServer.Scopes;

            //sort by name
            List<Scope> sortedScopes = new List<Scope>(scopes.Count);

            foreach (KeyValuePair<string, Scope> entry in scopes)
                sortedScopes.Add(entry.Value);

            sortedScopes.Sort();

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

        public void ListDhcpScopes(Utf8JsonWriter jsonWriter)
        {
            IReadOnlyDictionary<string, Scope> scopes = _dnsWebService.DhcpServer.Scopes;

            //sort by name
            List<Scope> sortedScopes = new List<Scope>(scopes.Count);

            foreach (KeyValuePair<string, Scope> entry in scopes)
                sortedScopes.Add(entry.Value);

            sortedScopes.Sort();

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

        public void GetDhcpScope(HttpListenerRequest request, Utf8JsonWriter jsonWriter)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            Scope scope = _dnsWebService.DhcpServer.GetScope(scopeName);
            if (scope == null)
                throw new DnsWebServiceException("DHCP scope was not found: " + scopeName);

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
        }

        public async Task SetDhcpScopeAsync(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            string strStartingAddress = request.QueryString["startingAddress"];
            string strEndingAddress = request.QueryString["endingAddress"];
            string strSubnetMask = request.QueryString["subnetMask"];

            bool scopeExists;
            Scope scope = _dnsWebService.DhcpServer.GetScope(scopeName);
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
                scope = new Scope(scopeName, true, IPAddress.Parse(strStartingAddress), IPAddress.Parse(strEndingAddress), IPAddress.Parse(strSubnetMask), _dnsWebService.Log);
            }
            else
            {
                scopeExists = true;

                IPAddress startingAddress;
                if (string.IsNullOrEmpty(strStartingAddress))
                    startingAddress = scope.StartingAddress;
                else
                    startingAddress = IPAddress.Parse(strStartingAddress);

                IPAddress endingAddress;
                if (string.IsNullOrEmpty(strEndingAddress))
                    endingAddress = scope.EndingAddress;
                else
                    endingAddress = IPAddress.Parse(strEndingAddress);

                IPAddress subnetMask;
                if (string.IsNullOrEmpty(strSubnetMask))
                    subnetMask = scope.SubnetMask;
                else
                    subnetMask = IPAddress.Parse(strSubnetMask);

                //validate scope address
                foreach (KeyValuePair<string, Scope> entry in _dnsWebService.DhcpServer.Scopes)
                {
                    Scope existingScope = entry.Value;

                    if (existingScope.Equals(scope))
                        continue;

                    if (existingScope.IsAddressInRange(startingAddress) || existingScope.IsAddressInRange(endingAddress))
                        throw new DhcpServerException("Scope with overlapping range already exists: " + existingScope.StartingAddress.ToString() + "-" + existingScope.EndingAddress.ToString());
                }

                scope.ChangeNetwork(startingAddress, endingAddress, subnetMask);
            }

            string strLeaseTimeDays = request.QueryString["leaseTimeDays"];
            if (!string.IsNullOrEmpty(strLeaseTimeDays))
                scope.LeaseTimeDays = ushort.Parse(strLeaseTimeDays);

            string strLeaseTimeHours = request.QueryString["leaseTimeHours"];
            if (!string.IsNullOrEmpty(strLeaseTimeHours))
                scope.LeaseTimeHours = byte.Parse(strLeaseTimeHours);

            string strLeaseTimeMinutes = request.QueryString["leaseTimeMinutes"];
            if (!string.IsNullOrEmpty(strLeaseTimeMinutes))
                scope.LeaseTimeMinutes = byte.Parse(strLeaseTimeMinutes);

            string strOfferDelayTime = request.QueryString["offerDelayTime"];
            if (!string.IsNullOrEmpty(strOfferDelayTime))
                scope.OfferDelayTime = ushort.Parse(strOfferDelayTime);

            string strPingCheckEnabled = request.QueryString["pingCheckEnabled"];
            if (!string.IsNullOrEmpty(strPingCheckEnabled))
                scope.PingCheckEnabled = bool.Parse(strPingCheckEnabled);

            string strPingCheckTimeout = request.QueryString["pingCheckTimeout"];
            if (!string.IsNullOrEmpty(strPingCheckTimeout))
                scope.PingCheckTimeout = ushort.Parse(strPingCheckTimeout);

            string strPingCheckRetries = request.QueryString["pingCheckRetries"];
            if (!string.IsNullOrEmpty(strPingCheckRetries))
                scope.PingCheckRetries = byte.Parse(strPingCheckRetries);

            string strDomainName = request.QueryString["domainName"];
            if (strDomainName != null)
                scope.DomainName = strDomainName.Length == 0 ? null : strDomainName;

            string strDomainSearchList = request.QueryString["domainSearchList"];
            if (strDomainSearchList is not null)
            {
                if (strDomainSearchList.Length == 0)
                    scope.DomainSearchList = null;
                else
                    scope.DomainSearchList = strDomainSearchList.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            }

            string strDnsUpdates = request.QueryString["dnsUpdates"];
            if (!string.IsNullOrEmpty(strDnsUpdates))
                scope.DnsUpdates = bool.Parse(strDnsUpdates);

            string strDnsTtl = request.QueryString["dnsTtl"];
            if (!string.IsNullOrEmpty(strDnsTtl))
                scope.DnsTtl = uint.Parse(strDnsTtl);

            string strServerAddress = request.QueryString["serverAddress"];
            if (strServerAddress != null)
                scope.ServerAddress = strServerAddress.Length == 0 ? null : IPAddress.Parse(strServerAddress);

            string strServerHostName = request.QueryString["serverHostName"];
            if (strServerHostName != null)
                scope.ServerHostName = strServerHostName.Length == 0 ? null : strServerHostName;

            string strBootFileName = request.QueryString["bootFileName"];
            if (strBootFileName != null)
                scope.BootFileName = strBootFileName.Length == 0 ? null : strBootFileName;

            string strRouterAddress = request.QueryString["routerAddress"];
            if (strRouterAddress != null)
                scope.RouterAddress = strRouterAddress.Length == 0 ? null : IPAddress.Parse(strRouterAddress);

            string strUseThisDnsServer = request.QueryString["useThisDnsServer"];
            if (!string.IsNullOrEmpty(strUseThisDnsServer))
                scope.UseThisDnsServer = bool.Parse(strUseThisDnsServer);

            if (!scope.UseThisDnsServer)
            {
                string strDnsServers = request.QueryString["dnsServers"];
                if (strDnsServers != null)
                {
                    if (strDnsServers.Length == 0)
                    {
                        scope.DnsServers = null;
                    }
                    else
                    {
                        string[] strDnsServerParts = strDnsServers.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                        IPAddress[] dnsServers = new IPAddress[strDnsServerParts.Length];

                        for (int i = 0; i < strDnsServerParts.Length; i++)
                            dnsServers[i] = IPAddress.Parse(strDnsServerParts[i]);

                        scope.DnsServers = dnsServers;
                    }
                }
            }

            string strWinsServers = request.QueryString["winsServers"];
            if (strWinsServers != null)
            {
                if (strWinsServers.Length == 0)
                {
                    scope.WinsServers = null;
                }
                else
                {
                    string[] strWinsServerParts = strWinsServers.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    IPAddress[] winsServers = new IPAddress[strWinsServerParts.Length];

                    for (int i = 0; i < strWinsServerParts.Length; i++)
                        winsServers[i] = IPAddress.Parse(strWinsServerParts[i]);

                    scope.WinsServers = winsServers;
                }
            }

            string strNtpServers = request.QueryString["ntpServers"];
            if (strNtpServers != null)
            {
                if (strNtpServers.Length == 0)
                {
                    scope.NtpServers = null;
                }
                else
                {
                    string[] strNtpServerParts = strNtpServers.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    IPAddress[] ntpServers = new IPAddress[strNtpServerParts.Length];

                    for (int i = 0; i < strNtpServerParts.Length; i++)
                        ntpServers[i] = IPAddress.Parse(strNtpServerParts[i]);

                    scope.NtpServers = ntpServers;
                }
            }

            string strNtpServerDomainNames = request.QueryString["ntpServerDomainNames"];
            if (strNtpServerDomainNames is not null)
            {
                if (strNtpServerDomainNames.Length == 0)
                    scope.NtpServerDomainNames = null;
                else
                    scope.NtpServerDomainNames = strNtpServerDomainNames.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            }

            string strStaticRoutes = request.QueryString["staticRoutes"];
            if (strStaticRoutes != null)
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
                    {
                        staticRoutes.Add(new ClasslessStaticRouteOption.Route(IPAddress.Parse(strStaticRoutesParts[i + 0]), IPAddress.Parse(strStaticRoutesParts[i + 1]), IPAddress.Parse(strStaticRoutesParts[i + 2])));
                    }

                    scope.StaticRoutes = staticRoutes;
                }
            }

            string strVendorInfo = request.QueryString["vendorInfo"];
            if (strVendorInfo != null)
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

            string strCAPWAPAcIpAddresses = request.QueryString["capwapAcIpAddresses"];
            if (strCAPWAPAcIpAddresses is not null)
            {
                if (strCAPWAPAcIpAddresses.Length == 0)
                {
                    scope.CAPWAPAcIpAddresses = null;
                }
                else
                {
                    string[] strCAPWAPAcIpAddressesParts = strCAPWAPAcIpAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    IPAddress[] capwapAcIpAddresses = new IPAddress[strCAPWAPAcIpAddressesParts.Length];

                    for (int i = 0; i < strCAPWAPAcIpAddressesParts.Length; i++)
                        capwapAcIpAddresses[i] = IPAddress.Parse(strCAPWAPAcIpAddressesParts[i]);

                    scope.CAPWAPAcIpAddresses = capwapAcIpAddresses;
                }
            }

            string strTftpServerAddresses = request.QueryString["tftpServerAddresses"];
            if (strTftpServerAddresses is not null)
            {
                if (strTftpServerAddresses.Length == 0)
                {
                    scope.TftpServerAddresses = null;
                }
                else
                {
                    string[] strTftpServerAddressesParts = strTftpServerAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    IPAddress[] tftpServerAddresses = new IPAddress[strTftpServerAddressesParts.Length];

                    for (int i = 0; i < strTftpServerAddressesParts.Length; i++)
                        tftpServerAddresses[i] = IPAddress.Parse(strTftpServerAddressesParts[i]);

                    scope.TftpServerAddresses = tftpServerAddresses;
                }
            }

            string strGenericOptions = request.QueryString["genericOptions"];
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

            string strExclusions = request.QueryString["exclusions"];
            if (strExclusions != null)
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
                    {
                        exclusions.Add(new Exclusion(IPAddress.Parse(strExclusionsParts[i + 0]), IPAddress.Parse(strExclusionsParts[i + 1])));
                    }

                    scope.Exclusions = exclusions;
                }
            }

            string strReservedLeases = request.QueryString["reservedLeases"];
            if (strReservedLeases != null)
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
                    {
                        reservedLeases.Add(new Lease(LeaseType.Reserved, strReservedLeaseParts[i + 0], DhcpMessageHardwareAddressType.Ethernet, strReservedLeaseParts[i + 1], IPAddress.Parse(strReservedLeaseParts[i + 2]), strReservedLeaseParts[i + 3]));
                    }

                    scope.ReservedLeases = reservedLeases;
                }
            }

            string strAllowOnlyReservedLeases = request.QueryString["allowOnlyReservedLeases"];
            if (!string.IsNullOrEmpty(strAllowOnlyReservedLeases))
                scope.AllowOnlyReservedLeases = bool.Parse(strAllowOnlyReservedLeases);

            string strBlockLocallyAdministeredMacAddresses = request.QueryString["blockLocallyAdministeredMacAddresses"];
            if (!string.IsNullOrEmpty(strBlockLocallyAdministeredMacAddresses))
                scope.BlockLocallyAdministeredMacAddresses = bool.Parse(strBlockLocallyAdministeredMacAddresses);

            if (scopeExists)
            {
                _dnsWebService.DhcpServer.SaveScope(scopeName);

                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DHCP scope was updated successfully: " + scopeName);
            }
            else
            {
                await _dnsWebService.DhcpServer.AddScopeAsync(scope);

                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DHCP scope was added successfully: " + scopeName);
            }

            string newName = request.QueryString["newName"];
            if (!string.IsNullOrEmpty(newName) && !newName.Equals(scopeName))
            {
                _dnsWebService.DhcpServer.RenameScope(scopeName, newName);

                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DHCP scope was renamed successfully: '" + scopeName + "' to '" + newName + "'");
            }
        }

        public void AddReservedLease(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            Scope scope = _dnsWebService.DhcpServer.GetScope(scopeName);
            if (scope is null)
                throw new DnsWebServiceException("No such scope exists: " + scopeName);

            string hostName = request.QueryString["hostName"];

            string hardwareAddress = request.QueryString["hardwareAddress"];
            if (string.IsNullOrEmpty(hardwareAddress))
                throw new DnsWebServiceException("Parameter 'hardwareAddress' missing.");

            string strIpAddress = request.QueryString["ipAddress"];
            if (string.IsNullOrEmpty(strIpAddress))
                throw new DnsWebServiceException("Parameter 'ipAddress' missing.");

            string comments = request.QueryString["comments"];

            Lease reservedLease = new Lease(LeaseType.Reserved, hostName, DhcpMessageHardwareAddressType.Ethernet, hardwareAddress, IPAddress.Parse(strIpAddress), comments);

            if (!scope.AddReservedLease(reservedLease))
                throw new DnsWebServiceException("Failed to add reserved lease for scope: " + scopeName);

            _dnsWebService.DhcpServer.SaveScope(scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DHCP scope reserved lease was added successfully: " + scopeName);
        }

        public void RemoveReservedLease(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            Scope scope = _dnsWebService.DhcpServer.GetScope(scopeName);
            if (scope is null)
                throw new DnsWebServiceException("No such scope exists: " + scopeName);

            string hardwareAddress = request.QueryString["hardwareAddress"];
            if (string.IsNullOrEmpty(hardwareAddress))
                throw new DnsWebServiceException("Parameter 'hardwareAddress' missing.");

            if (!scope.RemoveReservedLease(hardwareAddress))
                throw new DnsWebServiceException("Failed to remove reserved lease for scope: " + scopeName);

            _dnsWebService.DhcpServer.SaveScope(scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DHCP scope reserved lease was removed successfully: " + scopeName);
        }

        public async Task EnableDhcpScopeAsync(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            await _dnsWebService.DhcpServer.EnableScopeAsync(scopeName, true);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DHCP scope was enabled successfully: " + scopeName);
        }

        public void DisableDhcpScope(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            _dnsWebService.DhcpServer.DisableScope(scopeName, true);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DHCP scope was disabled successfully: " + scopeName);
        }

        public void DeleteDhcpScope(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            _dnsWebService.DhcpServer.DeleteScope(scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DHCP scope was deleted successfully: " + scopeName);
        }

        public void RemoveDhcpLease(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            Scope scope = _dnsWebService.DhcpServer.GetScope(scopeName);
            if (scope is null)
                throw new DnsWebServiceException("DHCP scope does not exists: " + scopeName);

            string strClientIdentifier = request.QueryString["clientIdentifier"];
            string strHardwareAddress = request.QueryString["hardwareAddress"];

            if (!string.IsNullOrEmpty(strClientIdentifier))
                scope.RemoveLease(ClientIdentifierOption.Parse(strClientIdentifier));
            else if (!string.IsNullOrEmpty(strHardwareAddress))
                scope.RemoveLease(strHardwareAddress);
            else
                throw new DnsWebServiceException("Parameter 'hardwareAddress' or 'clientIdentifier' missing. At least one of them must be specified.");

            _dnsWebService.DhcpServer.SaveScope(scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DHCP scope's lease was removed successfully: " + scopeName);
        }

        public void ConvertToReservedLease(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            Scope scope = _dnsWebService.DhcpServer.GetScope(scopeName);
            if (scope == null)
                throw new DnsWebServiceException("DHCP scope does not exists: " + scopeName);

            string strClientIdentifier = request.QueryString["clientIdentifier"];
            string strHardwareAddress = request.QueryString["hardwareAddress"];

            if (!string.IsNullOrEmpty(strClientIdentifier))
                scope.ConvertToReservedLease(ClientIdentifierOption.Parse(strClientIdentifier));
            else if (!string.IsNullOrEmpty(strHardwareAddress))
                scope.ConvertToReservedLease(strHardwareAddress);
            else
                throw new DnsWebServiceException("Parameter 'hardwareAddress' or 'clientIdentifier' missing. At least one of them must be specified.");

            _dnsWebService.DhcpServer.SaveScope(scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DHCP scope's lease was reserved successfully: " + scopeName);
        }

        public void ConvertToDynamicLease(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            Scope scope = _dnsWebService.DhcpServer.GetScope(scopeName);
            if (scope == null)
                throw new DnsWebServiceException("DHCP scope does not exists: " + scopeName);

            string strClientIdentifier = request.QueryString["clientIdentifier"];
            string strHardwareAddress = request.QueryString["hardwareAddress"];

            if (!string.IsNullOrEmpty(strClientIdentifier))
                scope.ConvertToDynamicLease(ClientIdentifierOption.Parse(strClientIdentifier));
            else if (!string.IsNullOrEmpty(strHardwareAddress))
                scope.ConvertToDynamicLease(strHardwareAddress);
            else
                throw new DnsWebServiceException("Parameter 'hardwareAddress' or 'clientIdentifier' missing. At least one of them must be specified.");

            _dnsWebService.DhcpServer.SaveScope(scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).User.Username + "] DHCP scope's lease was unreserved successfully: " + scopeName);
        }

        #endregion
    }
}
