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
using Microsoft.AspNetCore.Http;
using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        sealed class WebServiceClusterApi
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceClusterApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            private void WriteClusterState(Utf8JsonWriter jsonWriter, bool includeServerIpAddresses = false)
            {
                jsonWriter.WriteString("version", _dnsWebService.GetServerVersion());
                jsonWriter.WriteString("dnsServerDomain", _dnsWebService._dnsServer.ServerDomain);
                jsonWriter.WriteBoolean("clusterInitialized", _dnsWebService._clusterManager.ClusterInitialized);

                if (_dnsWebService._clusterManager.ClusterInitialized)
                {
                    jsonWriter.WriteString("clusterDomain", _dnsWebService._clusterManager.ClusterDomain);

                    jsonWriter.WriteNumber("heartbeatRefreshIntervalSeconds", _dnsWebService._clusterManager.HeartbeatRefreshIntervalSeconds);
                    jsonWriter.WriteNumber("heartbeatRetryIntervalSeconds", _dnsWebService._clusterManager.HeartBeatRetryIntervalSeconds);
                    jsonWriter.WriteNumber("configRefreshIntervalSeconds", _dnsWebService._clusterManager.ConfigRefreshIntervalSeconds);
                    jsonWriter.WriteNumber("configRetryIntervalSeconds", _dnsWebService._clusterManager.ConfigRetryIntervalSeconds);

                    WriteClusterNodes(jsonWriter);
                }

                if (includeServerIpAddresses)
                {
                    jsonWriter.WriteStartArray("serverIpAddresses");

                    foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (networkInterface.OperationalStatus != OperationalStatus.Up)
                            continue;

                        foreach (UnicastIPAddressInformation ip in networkInterface.GetIPProperties().UnicastAddresses)
                        {
                            if (IPAddress.IsLoopback(ip.Address))
                                continue;

                            switch (ip.Address.AddressFamily)
                            {
                                case AddressFamily.InterNetwork:
                                    jsonWriter.WriteStringValue(ip.Address.ToString());
                                    break;

                                case AddressFamily.InterNetworkV6:
                                    if (ip.Address.IsIPv6LinkLocal || ip.Address.IsIPv6Teredo)
                                        continue;

                                    jsonWriter.WriteStringValue(ip.Address.ToString());
                                    break;
                            }
                        }
                    }

                    jsonWriter.WriteEndArray();
                }
            }

            internal void WriteClusterNodes(Utf8JsonWriter jsonWriter)
            {
                List<ClusterNode> sortedClusterNodes = [.. _dnsWebService._clusterManager.ClusterNodes.Values];
                sortedClusterNodes.Sort();

                jsonWriter.WriteStartArray("clusterNodes");

                foreach (ClusterNode clusterNode in sortedClusterNodes)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteNumber("id", clusterNode.Id);
                    jsonWriter.WriteString("name", clusterNode.Name);
                    jsonWriter.WriteString("url", clusterNode.Url.OriginalString);

                    jsonWriter.WriteStartArray("ipAddresses");

                    foreach (IPAddress ipAddress in clusterNode.IPAddresses)
                        jsonWriter.WriteStringValue(ipAddress.ToString());

                    jsonWriter.WriteEndArray();

                    jsonWriter.WriteString("type", clusterNode.Type.ToString());
                    jsonWriter.WriteString("state", clusterNode.State.ToString());

                    if (clusterNode.State == ClusterNodeState.Self)
                    {
                        jsonWriter.WriteString("upSince", clusterNode.UpSince);

                        if (clusterNode.Type == ClusterNodeType.Secondary)
                        {
                            if (_dnsWebService._clusterManager.ConfigLastSynced != default)
                                jsonWriter.WriteString("configLastSynced", _dnsWebService._clusterManager.ConfigLastSynced);
                        }
                    }
                    else
                    {
                        if (clusterNode.UpSince != default)
                            jsonWriter.WriteString("upSince", clusterNode.UpSince);

                        if (clusterNode.LastSeen != default)
                            jsonWriter.WriteString("lastSeen", clusterNode.LastSeen);
                    }

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            private void EnableWebServiceTlsWithSelfSignedCertificate()
            {
                _dnsWebService._webServiceEnableTls = true;
                _dnsWebService._webServiceUseSelfSignedTlsCertificate = true;
                _dnsWebService._webServiceTlsCertificatePath = null;
                _dnsWebService._webServiceTlsCertificatePassword = null;

                _dnsWebService.CheckAndLoadSelfSignedCertificate(false, true);

                _dnsWebService.SaveConfigFile();
            }

            private void RestartWebService()
            {
                ThreadPool.QueueUserWorkItem(async delegate (object state)
                {
                    try
                    {
                        await Task.Delay(2000); //wait for the current HTTP response to be delivered before restarting web server

                        _dnsWebService._log.Write("Attempting to restart web service.");

                        await _dnsWebService.StopWebServiceAsync();
                        await _dnsWebService.StartWebServiceAsync(false);

                        _dnsWebService._log.Write("Web service was restarted successfully.");
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService._log.Write("Failed to restart web service.\r\n" + ex.ToString());
                        _dnsWebService._log.Write("Attempting to restart web service in HTTP only mode.");

                        try
                        {
                            await _dnsWebService.StopWebServiceAsync();
                            await _dnsWebService.StartWebServiceAsync(true);
                        }
                        catch (Exception ex2)
                        {
                            _dnsWebService._log.Write("Failed to restart web service in HTTP only mode.\r\n" + ex2.ToString());
                        }
                    }
                });
            }

            #endregion

            #region public

            public void GetClusterState(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool includeServerIpAddresses = request.GetQueryOrForm("includeServerIpAddresses", bool.Parse, false);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteClusterState(jsonWriter, includeServerIpAddresses);
            }

            public void InitializeCluster(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string clusterDomain = request.GetQueryOrForm("clusterDomain").TrimEnd('.');

                if (!request.TryGetQueryOrFormArray("primaryNodeIpAddresses", IPAddress.Parse, out IPAddress[] primaryNodeIpAddresses))
                    throw new DnsWebServiceException("Parameter 'primaryNodeIpAddresses' missing.");

                bool restartWebService = false;

                //enable TLS web service if not already enabled
                if (!_dnsWebService.IsWebServiceTlsEnabled)
                {
                    EnableWebServiceTlsWithSelfSignedCertificate();
                    restartWebService = true;
                }

                try
                {
                    _dnsWebService._clusterManager.InitializeCluster(clusterDomain, primaryNodeIpAddresses, context.GetCurrentSession());

                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Cluster (" + _dnsWebService._clusterManager.ClusterDomain + ") was initialized successfully.");

                    Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                    WriteClusterState(jsonWriter);
                }
                finally
                {
                    //restart TLS web service to apply HTTPS changes
                    if (restartWebService)
                        RestartWebService();
                }
            }

            public void DeleteCluster(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool forceDelete = request.GetQueryOrForm("forceDelete", bool.Parse, false);

                string clusterDomain = _dnsWebService._clusterManager.ClusterDomain;
                _dnsWebService._clusterManager.DeleteCluster(forceDelete);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Cluster (" + clusterDomain + ") was deleted successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteClusterState(jsonWriter);
            }

            public void JoinCluster(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                int secondaryNodeId = request.GetQueryOrForm("secondaryNodeId", int.Parse);
                Uri secondaryNodeUrl = new Uri(request.GetQueryOrForm("secondaryNodeUrl"));

                if (!request.TryGetQueryOrFormArray("secondaryNodeIpAddresses", IPAddress.Parse, out IPAddress[] secondaryNodeIpAddresses))
                    throw new DnsWebServiceException("Parameter 'secondaryNodeIpAddresses' missing.");

                X509Certificate2 secondaryNodeCertificate = X509CertificateLoader.LoadCertificate(Base64Url.DecodeFromChars(request.GetQueryOrForm("secondaryNodeCertificate")));

                ClusterNode secondaryNode = _dnsWebService._clusterManager.JoinCluster(secondaryNodeId, secondaryNodeUrl, secondaryNodeIpAddresses, secondaryNodeCertificate);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Secondary node '" + secondaryNode.ToString() + "' joined the Cluster (" + _dnsWebService._clusterManager.ClusterDomain + ") successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteClusterState(jsonWriter);
            }

            public async Task RemoveSecondaryNodeAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                int secondaryNodeId = request.GetQueryOrForm("secondaryNodeId", int.Parse);

                ClusterNode secondaryNode = await _dnsWebService._clusterManager.AskSecondaryNodeToLeaveClusterAsync(secondaryNodeId);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Secondary node '" + secondaryNode.ToString() + "' was asked to leave the Cluster (" + _dnsWebService._clusterManager.ClusterDomain + ") successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteClusterState(jsonWriter);
            }

            public void DeleteSecondaryNode(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                int secondaryNodeId = request.GetQueryOrForm("secondaryNodeId", int.Parse);

                ClusterNode secondaryNode = _dnsWebService._clusterManager.DeleteSecondaryNode(secondaryNodeId);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Secondary node '" + secondaryNode.ToString() + "' was deleted from the Cluster (" + _dnsWebService._clusterManager.ClusterDomain + ") successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteClusterState(jsonWriter);
            }

            public void UpdateSecondaryNode(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                int secondaryNodeId = request.GetQueryOrForm("secondaryNodeId", int.Parse);
                Uri secondaryNodeUrl = new Uri(request.GetQueryOrForm("secondaryNodeUrl"));

                if (!request.TryGetQueryOrFormArray("secondaryNodeIpAddresses", IPAddress.Parse, out IPAddress[] secondaryNodeIpAddresses))
                    throw new DnsWebServiceException("Parameter 'secondaryNodeIpAddresses' missing.");

                X509Certificate2 secondaryNodeCertificate = X509CertificateLoader.LoadCertificate(Base64Url.DecodeFromChars(request.GetQueryOrForm("secondaryNodeCertificate")));

                ClusterNode secondaryNode = _dnsWebService._clusterManager.UpdateSecondaryNode(secondaryNodeId, secondaryNodeUrl, secondaryNodeIpAddresses, secondaryNodeCertificate);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Secondary node '" + secondaryNode.ToString() + "' details were updated successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteClusterState(jsonWriter);
            }

            public async Task TransferConfigAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string ifModifiedSinceValue = request.Headers.IfModifiedSince;
                string includeZonesValue = request.QueryOrForm("includeZones");

                DateTime ifModifiedSince = string.IsNullOrEmpty(ifModifiedSinceValue) ? DateTime.UnixEpoch : DateTime.ParseExact(ifModifiedSinceValue, "R", CultureInfo.InvariantCulture);
                string[] includeZones = string.IsNullOrEmpty(includeZonesValue) ? null : includeZonesValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

                string tmpFile = Path.GetTempFileName();
                try
                {
                    await using (FileStream configZipStream = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        //create config zip file
                        await _dnsWebService._clusterManager.TransferConfigAsync(configZipStream, ifModifiedSince, includeZones);

                        //send config zip file
                        configZipStream.Position = 0;

                        HttpResponse response = context.Response;

                        response.ContentType = "application/zip";
                        response.ContentLength = configZipStream.Length;
                        response.Headers.LastModified = DateTime.UtcNow.ToString("R");
                        response.Headers.Append("Content-Disposition", "attachment; filename=\"config.zip\"");

                        await using (Stream output = response.Body)
                        {
                            await configZipStream.CopyToAsync(output);
                        }
                    }
                }
                finally
                {
                    try
                    {
                        File.Delete(tmpFile);
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService._log.Write(ex);
                    }
                }

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Server configuration was transferred successfully.");
            }

            public void SetClusterOptions(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                ushort heartbeatRefreshIntervalSeconds = request.GetQueryOrForm("heartbeatRefreshIntervalSeconds", ushort.Parse, _dnsWebService._clusterManager.HeartbeatRefreshIntervalSeconds);
                ushort heartbeatRetryIntervalSeconds = request.GetQueryOrForm("heartbeatRetryIntervalSeconds", ushort.Parse, _dnsWebService._clusterManager.HeartBeatRetryIntervalSeconds);
                ushort configRefreshIntervalSeconds = request.GetQueryOrForm("configRefreshIntervalSeconds", ushort.Parse, _dnsWebService._clusterManager.ConfigRefreshIntervalSeconds);
                ushort configRetryIntervalSeconds = request.GetQueryOrForm("configRetryIntervalSeconds", ushort.Parse, _dnsWebService._clusterManager.ConfigRetryIntervalSeconds);

                _dnsWebService._clusterManager.UpdateClusterOptions(heartbeatRefreshIntervalSeconds, heartbeatRetryIntervalSeconds, configRefreshIntervalSeconds, configRetryIntervalSeconds);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Cluster (" + _dnsWebService._clusterManager.ClusterDomain + ") options were updated successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteClusterState(jsonWriter);
            }

            public async Task InitializeAndJoinClusterAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                if (!request.TryGetQueryOrFormArray("secondaryNodeIpAddresses", IPAddress.Parse, out IPAddress[] secondaryNodeIpAddresses))
                    throw new DnsWebServiceException("Parameter 'secondaryNodeIpAddresses' missing.");

                Uri primaryNodeUrl = new Uri(request.GetQueryOrForm("primaryNodeUrl"));
                IPAddress primaryNodeIpAddress = request.GetQueryOrForm("primaryNodeIpAddress", IPAddress.Parse, null);
                string primaryNodeUsername = request.GetQueryOrForm("primaryNodeUsername");
                string primaryNodePassword = request.GetQueryOrForm("primaryNodePassword");
                string primaryNodeTotp = request.GetQueryOrForm("primaryNodeTotp", null);
                bool ignoreCertificateErrors = request.GetQueryOrForm("ignoreCertificateErrors", bool.Parse, false);

                bool restartWebService = false;

                //enable TLS web service if not already enabled
                if (!_dnsWebService.IsWebServiceTlsEnabled)
                {
                    EnableWebServiceTlsWithSelfSignedCertificate();
                    restartWebService = true;
                }

                try
                {
                    await _dnsWebService._clusterManager.InitializeAndJoinClusterAsync(secondaryNodeIpAddresses, primaryNodeUrl, primaryNodeUsername, primaryNodePassword, primaryNodeTotp, [primaryNodeIpAddress], ignoreCertificateErrors);

                    _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Joined the Cluster (" + _dnsWebService._clusterManager.ClusterDomain + ") as a Secondary node successfully.");

                    Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                    WriteClusterState(jsonWriter);
                }
                finally
                {
                    //restart TLS web service to apply HTTPS changes
                    if (restartWebService)
                        RestartWebService();
                }
            }

            public async Task LeaveClusterAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool forceLeave = request.GetQueryOrForm("forceLeave", bool.Parse, false);

                string clusterDomain = _dnsWebService._clusterManager.ClusterDomain;
                await _dnsWebService._clusterManager.LeaveClusterAsync(forceLeave);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Left the Cluster (" + clusterDomain + ") successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteClusterState(jsonWriter);
            }

            public async Task ConfigUpdateNotificationAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                int primaryNodeId = request.GetQueryOrForm("primaryNodeId", int.Parse);
                Uri primaryNodeUrl = new Uri(request.GetQueryOrForm("primaryNodeUrl"));

                if (!request.TryGetQueryOrFormArray("primaryNodeIpAddresses", IPAddress.Parse, out IPAddress[] primaryNodeIpAddresses))
                    throw new DnsWebServiceException("Parameter 'primaryNodeIpAddresses' missing.");

                //update primary node
                ClusterNode primaryNode = await _dnsWebService._clusterManager.UpdatePrimaryNodeAsync(primaryNodeUrl, primaryNodeIpAddresses, primaryNodeId);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Notification for configuration update was received. Primary node '" + primaryNode.ToString() + "' details were updated successfully.");
            }

            public void ResyncCluster(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._clusterManager.TriggerResyncForConfig();

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Resync for configuration and Cluster Secondary zones was triggered successfully.");
            }

            public async Task UpdatePrimaryNodeAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                Uri primaryNodeUrl = new Uri(request.GetQueryOrForm("primaryNodeUrl"));

                if (!request.TryGetQueryOrFormArray("primaryNodeIpAddresses", IPAddress.Parse, out IPAddress[] primaryNodeIpAddresses))
                    primaryNodeIpAddresses = null;

                //update primary node
                ClusterNode primaryNode = await _dnsWebService._clusterManager.UpdatePrimaryNodeAsync(primaryNodeUrl, primaryNodeIpAddresses);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] Primary node '" + primaryNode.ToString() + "' details were updated successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteClusterState(jsonWriter);
            }

            public async Task PromoteToPrimaryNodeAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool forceDeletePrimary = request.GetQueryOrForm("forceDeletePrimary", bool.Parse, false);

                //promote to primary node
                await _dnsWebService._clusterManager.PromoteToPrimaryNodeAsync(forceDeletePrimary);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] This Secondary node was promoted to be a Primary node for the Cluster successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteClusterState(jsonWriter);
            }

            public void UpdateSelfNodeIPAddress(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Administration, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                if (!request.TryGetQueryOrFormArray("ipAddresses", IPAddress.Parse, out IPAddress[] ipAddresses))
                    throw new DnsWebServiceException("Parameter 'ipAddresses' missing.");

                //update self node IP address
                ClusterNode selfNode = _dnsWebService._clusterManager.UpdateSelfNodeIPAddresses(ipAddresses);

                _dnsWebService._log.Write(context.GetRemoteEndPoint(_dnsWebService._webServiceRealIpHeader), "[" + sessionUser.Username + "] " + selfNode.Type.ToString() + " node '" + selfNode.ToString() + "' IP address was updated successfully.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteClusterState(jsonWriter);
            }

            #endregion
        }
    }
}
