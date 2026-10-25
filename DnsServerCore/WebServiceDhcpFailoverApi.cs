/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        sealed class WebServiceDhcpFailoverApi
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceDhcpFailoverApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            private void WriteFailover(Utf8JsonWriter jsonWriter)
            {
                DhcpFailoverManager failover = _dnsWebService._dhcpFailoverManager;

                jsonWriter.WriteBoolean("enabled", failover.Enabled);
                jsonWriter.WriteString("role", failover.Role.ToString());
                jsonWriter.WriteString("partnerNodeName", failover.PartnerNodeName);

                jsonWriter.WriteString("partnerMode", failover.PartnerUrl is null ? "Cluster" : "Direct");
                jsonWriter.WriteString("partnerUrl", failover.PartnerUrl?.AbsoluteUri);
                jsonWriter.WriteBoolean("partnerApiTokenSet", failover.PartnerApiTokenSet); //token itself is never returned
                jsonWriter.WriteBoolean("partnerIgnoreCertificateErrors", failover.PartnerIgnoreCertificateErrors);

                ClusterManager clusterManagerForMode = _dnsWebService._clusterManager;
                jsonWriter.WriteBoolean("clusterInitialized", (clusterManagerForMode is not null) && clusterManagerForMode.ClusterInitialized);

                jsonWriter.WriteNumber("heartbeatIntervalSeconds", failover.HeartbeatIntervalSeconds);
                jsonWriter.WriteNumber("partnerDownDelaySeconds", failover.PartnerDownDelaySeconds);
                jsonWriter.WriteNumber("maxClientLeadTimeSeconds", failover.MaxClientLeadTimeSeconds);

                jsonWriter.WriteString("state", failover.State.ToString());
                jsonWriter.WriteString("stateChangedOn", failover.StateChangedOn);
                jsonWriter.WriteBoolean("serving", failover.IsServing);
                jsonWriter.WriteBoolean("partnerReachable", failover.PartnerReachable);

                if (failover.LastPartnerContact == default)
                    jsonWriter.WriteNull("lastPartnerContact");
                else
                    jsonWriter.WriteString("lastPartnerContact", failover.LastPartnerContact);

                if (failover.LastFullSync == default)
                    jsonWriter.WriteNull("lastFullSync");
                else
                    jsonWriter.WriteString("lastFullSync", failover.LastFullSync);

                if (failover.LastPartnerStatus is null)
                {
                    jsonWriter.WriteNull("partnerState");
                }
                else
                {
                    jsonWriter.WriteString("partnerState", failover.LastPartnerStatus.State);
                    jsonWriter.WriteBoolean("partnerServing", failover.LastPartnerStatus.Serving);
                }

                //list available partner nodes for UI
                jsonWriter.WriteStartArray("availablePartnerNodes");

                ClusterManager clusterManager = _dnsWebService._clusterManager;
                if ((clusterManager is not null) && clusterManager.ClusterInitialized)
                {
                    foreach (ClusterNode node in clusterManager.ClusterNodes.Values)
                    {
                        if (node.State != ClusterNodeState.Self)
                            jsonWriter.WriteStringValue(node.Name);
                    }
                }

                jsonWriter.WriteEndArray();
            }

            #endregion

            #region public

            public void GetFailover(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                WriteFailover(context.GetCurrentJsonWriter());
            }

            public void SetFailover(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;
                DhcpFailoverManager failover = _dnsWebService._dhcpFailoverManager;

                bool enabled = request.GetQueryOrForm("enabled", bool.Parse, failover.Enabled);
                DhcpFailoverRole role = request.GetQueryOrFormEnum("role", failover.Role);
                string partnerNodeName = request.GetQueryOrForm("partnerNodeName", failover.PartnerNodeName);
                ushort heartbeatIntervalSeconds = request.GetQueryOrForm("heartbeatIntervalSeconds", ushort.Parse, failover.HeartbeatIntervalSeconds);
                ushort partnerDownDelaySeconds = request.GetQueryOrForm("partnerDownDelaySeconds", ushort.Parse, failover.PartnerDownDelaySeconds);
                uint maxClientLeadTimeSeconds = request.GetQueryOrForm("maxClientLeadTimeSeconds", uint.Parse, failover.MaxClientLeadTimeSeconds);

                //partnerMode: Cluster (partner by cluster node name) or Direct (partner by URL + API token)
                string partnerMode = request.GetQueryOrForm("partnerMode", failover.PartnerUrl is null ? "Cluster" : "Direct");

                Uri partnerUrl = null;
                string partnerApiToken = null;
                bool partnerIgnoreCertificateErrors = false;

                if (partnerMode.Equals("Direct", StringComparison.OrdinalIgnoreCase))
                {
                    string partnerUrlValue = request.GetQueryOrForm("partnerUrl", failover.PartnerUrl?.AbsoluteUri);
                    if (string.IsNullOrWhiteSpace(partnerUrlValue))
                        throw new DnsWebServiceException("Parameter 'partnerUrl' missing.");

                    if (!Uri.TryCreate(partnerUrlValue.Trim(), UriKind.Absolute, out partnerUrl))
                        throw new DnsWebServiceException("Invalid partner URL: " + partnerUrlValue);

                    partnerApiToken = request.QueryOrForm("partnerApiToken"); //empty keeps saved token
                    partnerIgnoreCertificateErrors = request.GetQueryOrForm("partnerIgnoreCertificateErrors", bool.Parse, failover.PartnerIgnoreCertificateErrors);
                }

                failover.SetConfig(enabled, role, partnerNodeName, partnerUrl, partnerApiToken, partnerIgnoreCertificateErrors, heartbeatIntervalSeconds, partnerDownDelaySeconds, maxClientLeadTimeSeconds);

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] DHCP failover settings were updated (enabled: " + enabled + ", role: " + role.ToString() + ", partner: " + (partnerUrl is null ? partnerNodeName : partnerUrl.AbsoluteUri) + ").");

                WriteFailover(context.GetCurrentJsonWriter());
            }

            public void GetPartnerStatus(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                DhcpFailoverManager failover = _dnsWebService._dhcpFailoverManager;
                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WriteBoolean("enabled", failover.Enabled);
                jsonWriter.WriteString("role", failover.Role.ToString());
                jsonWriter.WriteString("state", failover.State.ToString());
                jsonWriter.WriteString("partnerNodeName", failover.PartnerNodeName);
                jsonWriter.WriteBoolean("serving", failover.IsServing);

                if (failover.Enabled && (failover.Role == DhcpFailoverRole.Primary))
                    jsonWriter.WriteString("settingsHash", _dnsWebService._dhcpServer.GetSettingsHash());
            }

            public async Task GetSnapshotAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                if (!_dnsWebService._dhcpFailoverManager.Enabled)
                    throw new DnsWebServiceException("DHCP failover is not enabled on this node.");

                using (MemoryStream mS = new MemoryStream())
                {
                    _dnsWebService._dhcpServer.WriteSnapshotTo(mS);
                    mS.Position = 0;

                    HttpResponse response = context.Response;

                    response.ContentType = "application/octet-stream";
                    response.ContentLength = mS.Length;

                    await using (Stream output = response.Body)
                    {
                        await mS.CopyToAsync(output);
                    }
                }
            }

            public async Task ApplyLeaseUpdatesAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                if (!_dnsWebService._dhcpFailoverManager.Enabled)
                    throw new DnsWebServiceException("DHCP failover is not enabled on this node.");

                using (MemoryStream mS = new MemoryStream())
                {
                    await context.Request.Body.CopyToAsync(mS);
                    mS.Position = 0;

                    int applied = _dnsWebService._dhcpServer.ApplyLeaseUpdates(mS);

                    Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                    jsonWriter.WriteNumber("applied", applied);
                }
            }

            #endregion
        }
    }
}
