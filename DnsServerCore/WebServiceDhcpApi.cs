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

using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
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

        public void ListDhcpLeases(JsonTextWriter jsonWriter)
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

                    jsonWriter.WritePropertyName("scope");
                    jsonWriter.WriteValue(scope.Name);

                    jsonWriter.WritePropertyName("type");
                    jsonWriter.WriteValue(lease.Type.ToString());

                    jsonWriter.WritePropertyName("hardwareAddress");
                    jsonWriter.WriteValue(BitConverter.ToString(lease.HardwareAddress));

                    jsonWriter.WritePropertyName("address");
                    jsonWriter.WriteValue(lease.Address.ToString());

                    jsonWriter.WritePropertyName("hostName");
                    jsonWriter.WriteValue(lease.HostName);

                    jsonWriter.WritePropertyName("leaseObtained");
                    jsonWriter.WriteValue(lease.LeaseObtained);

                    jsonWriter.WritePropertyName("leaseExpires");
                    jsonWriter.WriteValue(lease.LeaseExpires);

                    jsonWriter.WriteEndObject();
                }
            }

            jsonWriter.WriteEndArray();
        }

        public void ListDhcpScopes(JsonTextWriter jsonWriter)
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

                jsonWriter.WritePropertyName("name");
                jsonWriter.WriteValue(scope.Name);

                jsonWriter.WritePropertyName("enabled");
                jsonWriter.WriteValue(scope.Enabled);

                jsonWriter.WritePropertyName("startingAddress");
                jsonWriter.WriteValue(scope.StartingAddress.ToString());

                jsonWriter.WritePropertyName("endingAddress");
                jsonWriter.WriteValue(scope.EndingAddress.ToString());

                jsonWriter.WritePropertyName("subnetMask");
                jsonWriter.WriteValue(scope.SubnetMask.ToString());

                jsonWriter.WritePropertyName("networkAddress");
                jsonWriter.WriteValue(scope.NetworkAddress.ToString());

                jsonWriter.WritePropertyName("broadcastAddress");
                jsonWriter.WriteValue(scope.BroadcastAddress.ToString());

                if (scope.InterfaceAddress != null)
                {
                    jsonWriter.WritePropertyName("interfaceAddress");
                    jsonWriter.WriteValue(scope.InterfaceAddress.ToString());
                }

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        public void GetDhcpScope(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            Scope scope = _dnsWebService.DhcpServer.GetScope(scopeName);
            if (scope == null)
                throw new DnsWebServiceException("DHCP scope was not found: " + scopeName);

            jsonWriter.WritePropertyName("name");
            jsonWriter.WriteValue(scope.Name);

            jsonWriter.WritePropertyName("startingAddress");
            jsonWriter.WriteValue(scope.StartingAddress.ToString());

            jsonWriter.WritePropertyName("endingAddress");
            jsonWriter.WriteValue(scope.EndingAddress.ToString());

            jsonWriter.WritePropertyName("subnetMask");
            jsonWriter.WriteValue(scope.SubnetMask.ToString());

            jsonWriter.WritePropertyName("leaseTimeDays");
            jsonWriter.WriteValue(scope.LeaseTimeDays);

            jsonWriter.WritePropertyName("leaseTimeHours");
            jsonWriter.WriteValue(scope.LeaseTimeHours);

            jsonWriter.WritePropertyName("leaseTimeMinutes");
            jsonWriter.WriteValue(scope.LeaseTimeMinutes);

            jsonWriter.WritePropertyName("offerDelayTime");
            jsonWriter.WriteValue(scope.OfferDelayTime);

            jsonWriter.WritePropertyName("pingCheckEnabled");
            jsonWriter.WriteValue(scope.PingCheckEnabled);

            jsonWriter.WritePropertyName("pingCheckTimeout");
            jsonWriter.WriteValue(scope.PingCheckTimeout);

            jsonWriter.WritePropertyName("pingCheckRetries");
            jsonWriter.WriteValue(scope.PingCheckRetries);

            if (!string.IsNullOrEmpty(scope.DomainName))
            {
                jsonWriter.WritePropertyName("domainName");
                jsonWriter.WriteValue(scope.DomainName);
            }

            jsonWriter.WritePropertyName("dnsTtl");
            jsonWriter.WriteValue(scope.DnsTtl);

            if (scope.ServerAddress != null)
            {
                jsonWriter.WritePropertyName("serverAddress");
                jsonWriter.WriteValue(scope.ServerAddress.ToString());
            }

            if (scope.ServerHostName != null)
            {
                jsonWriter.WritePropertyName("serverHostName");
                jsonWriter.WriteValue(scope.ServerHostName);
            }

            if (scope.BootFileName != null)
            {
                jsonWriter.WritePropertyName("bootFileName");
                jsonWriter.WriteValue(scope.BootFileName);
            }

            if (scope.RouterAddress != null)
            {
                jsonWriter.WritePropertyName("routerAddress");
                jsonWriter.WriteValue(scope.RouterAddress.ToString());
            }

            jsonWriter.WritePropertyName("useThisDnsServer");
            jsonWriter.WriteValue(scope.UseThisDnsServer);

            if (scope.DnsServers != null)
            {
                jsonWriter.WritePropertyName("dnsServers");
                jsonWriter.WriteStartArray();

                foreach (IPAddress dnsServer in scope.DnsServers)
                    jsonWriter.WriteValue(dnsServer.ToString());

                jsonWriter.WriteEndArray();
            }

            if (scope.WinsServers != null)
            {
                jsonWriter.WritePropertyName("winsServers");
                jsonWriter.WriteStartArray();

                foreach (IPAddress winsServer in scope.WinsServers)
                    jsonWriter.WriteValue(winsServer.ToString());

                jsonWriter.WriteEndArray();
            }

            if (scope.NtpServers != null)
            {
                jsonWriter.WritePropertyName("ntpServers");
                jsonWriter.WriteStartArray();

                foreach (IPAddress ntpServer in scope.NtpServers)
                    jsonWriter.WriteValue(ntpServer.ToString());

                jsonWriter.WriteEndArray();
            }

            if (scope.StaticRoutes != null)
            {
                jsonWriter.WritePropertyName("staticRoutes");
                jsonWriter.WriteStartArray();

                foreach (ClasslessStaticRouteOption.Route route in scope.StaticRoutes)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("destination");
                    jsonWriter.WriteValue(route.Destination.ToString());

                    jsonWriter.WritePropertyName("subnetMask");
                    jsonWriter.WriteValue(route.SubnetMask.ToString());

                    jsonWriter.WritePropertyName("router");
                    jsonWriter.WriteValue(route.Router.ToString());

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            if (scope.VendorInfo != null)
            {
                jsonWriter.WritePropertyName("vendorInfo");
                jsonWriter.WriteStartArray();

                foreach (KeyValuePair<string, VendorSpecificInformationOption> entry in scope.VendorInfo)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("identifier");
                    jsonWriter.WriteValue(entry.Key);

                    jsonWriter.WritePropertyName("information");
                    jsonWriter.WriteValue(entry.Value.ToString());

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            if (scope.Exclusions != null)
            {
                jsonWriter.WritePropertyName("exclusions");
                jsonWriter.WriteStartArray();

                foreach (Exclusion exclusion in scope.Exclusions)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WritePropertyName("startingAddress");
                    jsonWriter.WriteValue(exclusion.StartingAddress.ToString());

                    jsonWriter.WritePropertyName("endingAddress");
                    jsonWriter.WriteValue(exclusion.EndingAddress.ToString());

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("reservedLeases");
            jsonWriter.WriteStartArray();

            foreach (Lease reservedLease in scope.ReservedLeases)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("hostName");
                jsonWriter.WriteValue(reservedLease.HostName);

                jsonWriter.WritePropertyName("hardwareAddress");
                jsonWriter.WriteValue(BitConverter.ToString(reservedLease.HardwareAddress));

                jsonWriter.WritePropertyName("address");
                jsonWriter.WriteValue(reservedLease.Address.ToString());

                jsonWriter.WritePropertyName("comments");
                jsonWriter.WriteValue(reservedLease.Comments);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("allowOnlyReservedLeases");
            jsonWriter.WriteValue(scope.AllowOnlyReservedLeases);
        }

        public async Task SetDhcpScopeAsync(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            string newName = request.QueryString["newName"];
            if (!string.IsNullOrEmpty(newName) && !newName.Equals(scopeName))
            {
                _dnsWebService.DhcpServer.RenameScope(scopeName, newName);

                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DHCP scope was renamed successfully: '" + scopeName + "' to '" + newName + "'");

                scopeName = newName;
            }

            string strStartingAddress = request.QueryString["startingAddress"];
            if (string.IsNullOrEmpty(strStartingAddress))
                throw new DnsWebServiceException("Parameter 'startingAddress' missing.");

            string strEndingAddress = request.QueryString["endingAddress"];
            if (string.IsNullOrEmpty(strEndingAddress))
                throw new DnsWebServiceException("Parameter 'endingAddress' missing.");

            string strSubnetMask = request.QueryString["subnetMask"];
            if (string.IsNullOrEmpty(strSubnetMask))
                throw new DnsWebServiceException("Parameter 'subnetMask' missing.");

            bool scopeExists;
            Scope scope = _dnsWebService.DhcpServer.GetScope(scopeName);
            if (scope is null)
            {
                //scope does not exists; create new scope
                scopeExists = false;
                scope = new Scope(scopeName, true, IPAddress.Parse(strStartingAddress), IPAddress.Parse(strEndingAddress), IPAddress.Parse(strSubnetMask));
            }
            else
            {
                scopeExists = true;
                IPAddress startingAddress = IPAddress.Parse(strStartingAddress);
                IPAddress endingAddress = IPAddress.Parse(strEndingAddress);

                //validate scope address
                foreach (KeyValuePair<string, Scope> entry in _dnsWebService.DhcpServer.Scopes)
                {
                    Scope existingScope = entry.Value;

                    if (existingScope.Equals(scope))
                        continue;

                    if (existingScope.IsAddressInRange(startingAddress) || existingScope.IsAddressInRange(endingAddress))
                        throw new DhcpServerException("Scope with overlapping range already exists: " + existingScope.StartingAddress.ToString() + "-" + existingScope.EndingAddress.ToString());
                }

                scope.ChangeNetwork(startingAddress, endingAddress, IPAddress.Parse(strSubnetMask));
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
                    {
                        vendorInfo.Add(strVendorInfoParts[i + 0], new VendorSpecificInformationOption(strVendorInfoParts[i + 1]));
                    }

                    scope.VendorInfo = vendorInfo;
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

            if (scopeExists)
            {
                _dnsWebService.DhcpServer.SaveScope(scopeName);

                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DHCP scope was updated successfully: " + scopeName);
            }
            else
            {
                await _dnsWebService.DhcpServer.AddScopeAsync(scope);

                _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DHCP scope was added successfully: " + scopeName);
            }
        }

        public async Task EnableDhcpScopeAsync(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            if (!await _dnsWebService.DhcpServer.EnableScopeAsync(scopeName))
                throw new DnsWebServiceException("Failed to enable DHCP scope, please check logs for details: " + scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DHCP scope was enabled successfully: " + scopeName);
        }

        public void DisableDhcpScope(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            if (!_dnsWebService.DhcpServer.DisableScope(scopeName))
                throw new DnsWebServiceException("Failed to disable DHCP scope, please check logs for details: " + scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DHCP scope was disabled successfully: " + scopeName);
        }

        public void DeleteDhcpScope(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            _dnsWebService.DhcpServer.DeleteScope(scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DHCP scope was deleted successfully: " + scopeName);
        }

        public void RemoveDhcpLease(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            string strHardwareAddress = request.QueryString["hardwareAddress"];
            if (string.IsNullOrEmpty(strHardwareAddress))
                throw new DnsWebServiceException("Parameter 'hardwareAddress' missing.");

            _dnsWebService.DhcpServer.RemoveLease(scopeName, strHardwareAddress);
            _dnsWebService.DhcpServer.SaveScope(scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DHCP scope's lease was removed successfully: " + scopeName);
        }

        public void ConvertToReservedLease(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            Scope scope = _dnsWebService.DhcpServer.GetScope(scopeName);
            if (scope == null)
                throw new DnsWebServiceException("DHCP scope does not exists: " + scopeName);

            string strHardwareAddress = request.QueryString["hardwareAddress"];
            if (string.IsNullOrEmpty(strHardwareAddress))
                throw new DnsWebServiceException("Parameter 'hardwareAddress' missing.");

            scope.ConvertToReservedLease(strHardwareAddress);

            _dnsWebService.DhcpServer.SaveScope(scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DHCP scope's lease was reserved successfully: " + scopeName);
        }

        public void ConvertToDynamicLease(HttpListenerRequest request)
        {
            string scopeName = request.QueryString["name"];
            if (string.IsNullOrEmpty(scopeName))
                throw new DnsWebServiceException("Parameter 'name' missing.");

            Scope scope = _dnsWebService.DhcpServer.GetScope(scopeName);
            if (scope == null)
                throw new DnsWebServiceException("DHCP scope does not exists: " + scopeName);

            string strHardwareAddress = request.QueryString["hardwareAddress"];
            if (string.IsNullOrEmpty(strHardwareAddress))
                throw new DnsWebServiceException("Parameter 'hardwareAddress' missing.");

            scope.ConvertToDynamicLease(strHardwareAddress);

            _dnsWebService.DhcpServer.SaveScope(scopeName);

            _dnsWebService.Log.Write(DnsWebService.GetRequestRemoteEndPoint(request), "[" + _dnsWebService.GetSession(request).Username + "] DHCP scope's lease was unreserved successfully: " + scopeName);
        }

        #endregion
    }
}
