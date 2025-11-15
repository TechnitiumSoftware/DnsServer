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
using DnsServerCore.HttpApi;
using DnsServerCore.HttpApi.Models;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;

namespace DnsServerCore.Cluster
{
    enum ClusterNodeType : byte
    {
        Unknown = 0,
        Primary = 1,
        Secondary = 2
    }

    enum ClusterNodeState : byte
    {
        Unknown = 0,
        Self = 1,
        Connected = 2,
        Unreachable = 3
    }

    class ClusterNode : IComparable<ClusterNode>, IDisposable
    {
        #region variables

        readonly ClusterManager _clusterManager;

        readonly int _id;
        Uri _url;
        IReadOnlyList<IPAddress> _ipAddresses;
        ClusterNodeType _type;
        ClusterNodeState _state;

        DateTime _upSince;
        DateTime _lastSeen;
        HttpApiClient _apiClient;

        Timer _heartbeatTimer;
        const int HEARTBEAT_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        public ClusterNode(ClusterManager clusterManager, ClusterInfo.ClusterNodeInfo nodeInfo)
        {
            _clusterManager = clusterManager;

            _id = nodeInfo.Id;
            _url = nodeInfo.Url;
            _ipAddresses = nodeInfo.IPAddresses.Convert(IPAddress.Parse);
            _type = Enum.Parse<ClusterNodeType>(nodeInfo.Type, true);

            if (_type == ClusterNodeType.Primary)
            {
                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected; //since this info was received from primary node
            }
            else
            {
                _state = ClusterNodeState.Unknown;
            }
        }

        public ClusterNode(ClusterManager clusterManager, int id, Uri url, IReadOnlyList<IPAddress> ipAddresses, ClusterNodeType type, ClusterNodeState state)
        {
            if (url.OriginalString.Length > 255)
                throw new ArgumentException("Cluster node URL length must be less than 255 bytes.", nameof(url));

            if (!url.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Cluster node URL must use HTTPS scheme.", nameof(url));

            if (ipAddresses.Count > 10)
                throw new ArgumentException("Cluster node cannot have more than 10 IP addresses.", nameof(ipAddresses));

            _clusterManager = clusterManager;

            _id = id;
            _url = url;
            _ipAddresses = ipAddresses;
            _type = type;
            _state = state;
        }

        public ClusterNode(ClusterManager clusterManager, BinaryReader bR)
        {
            _clusterManager = clusterManager;

            int version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                    _id = bR.ReadInt32();
                    _url = new Uri(bR.ReadShortString());

                    if (version >= 2)
                    {
                        int count = bR.ReadByte();
                        IPAddress[] ipAddresses = new IPAddress[count];

                        for (int i = 0; i < count; i++)
                            ipAddresses[i] = IPAddressExtensions.ReadFrom(bR);

                        _ipAddresses = ipAddresses;
                    }
                    else
                    {
                        _ipAddresses = [IPAddressExtensions.ReadFrom(bR)];
                    }

                    _type = (ClusterNodeType)bR.ReadByte();
                    _state = (ClusterNodeState)bR.ReadByte();
                    break;

                default:
                    throw new InvalidDataException("Cluster Node version not supported.");
            }

            if (_state != ClusterNodeState.Self)
                _state = ClusterNodeState.Unknown;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _heartbeatTimer?.Dispose();

            if (_apiClient is not null)
            {
                ThreadPool.QueueUserWorkItem(async delegate (object state)
                {
                    try
                    {
                        await Task.Delay(2000); //give some time for any in-progress API calls to complete
                        _apiClient?.Dispose();
                    }
                    catch
                    { }
                });
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        #endregion

        #region private

        private HttpApiClient GetApiClient()
        {
            if (_state == ClusterNodeState.Self)
                throw new InvalidOperationException();

            if (_apiClient is null)
            {
                _apiClient = new HttpApiClient(_url, _clusterManager.DnsWebService.DnsServer.Proxy, _clusterManager.DnsWebService.DnsServer.PreferIPv6, false, new InternalDnsClient(_clusterManager.DnsWebService.DnsServer, this));

                UserSession clusterApiToken = null;

                foreach (UserSession session in _clusterManager.DnsWebService.AuthManager.Sessions)
                {
                    if ((session.Type == UserSessionType.ApiToken) && (session.TokenName == _clusterManager.ClusterDomain))
                    {
                        clusterApiToken = session;
                        break;
                    }
                }

                if (clusterApiToken is null)
                    throw new InvalidOperationException("No API token was found for the Cluster domain.");

                _apiClient.UseApiToken(clusterApiToken.User.Username, clusterApiToken.Token);
            }

            return _apiClient;
        }

        private async void HeartbeatTimerCallbackAsync(object state)
        {
            bool success = true;

            try
            {
                ClusterInfo clusterInfo = await GetClusterStateAsync();

                if (_type == ClusterNodeType.Primary)
                    _clusterManager.UpdateClusterFromPrimaryNode(clusterInfo); //update cluster nodes from primary node response

                //update up since time
                foreach (ClusterInfo.ClusterNodeInfo clusterNodeInfo in clusterInfo.ClusterNodes)
                {
                    if (clusterNodeInfo.Name.Equals(Name, StringComparison.OrdinalIgnoreCase))
                    {
                        _upSince = clusterNodeInfo.UpSince ?? default;
                        break;
                    }
                }
            }
            catch (TaskCanceledException)
            {
                //ignore
            }
            catch (Exception ex)
            {
                success = false;
                _clusterManager.DnsWebService.LogManager.Write("Heartbeat failed for " + _type.ToString() + " node '" + ToString() + "'.\r\n" + ex.ToString());
            }
            finally
            {
                try
                {
                    _heartbeatTimer?.Change(success ? _clusterManager.HeartbeatRefreshIntervalSeconds * 1000 : _clusterManager.HeartBeatRetryIntervalSeconds * 1000, Timeout.Infinite);
                }
                catch (ObjectDisposedException)
                { }
            }
        }

        #endregion

        #region public

        public void PromoteToPrimaryNode()
        {
            _type = ClusterNodeType.Primary;
        }

        public void UpdateSelfNodeIPAddresses(IReadOnlyList<IPAddress> ipAddresses)
        {
            if (_state != ClusterNodeState.Self)
                throw new InvalidOperationException();

            if (ipAddresses.Count > 10)
                throw new ArgumentException("Cluster node cannot have more than 10 IP addresses.", nameof(ipAddresses));

            _ipAddresses = ipAddresses;
        }

        public void UpdateSelfNodeUrl()
        {
            if (_state != ClusterNodeState.Self)
                throw new InvalidOperationException();

            Uri url = new Uri($"https://{_clusterManager.DnsWebService.DnsServer.ServerDomain}:{_clusterManager.DnsWebService.WebServiceTlsPort}/");

            if (url.OriginalString.Length > 255)
                throw new ArgumentException("Cluster node URL length must be less than 255 bytes.", nameof(url));

            if (!url.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Cluster node URL must use HTTPS scheme.", nameof(url));

            _url = url;
        }

        public void UpdateNode(Uri url, IReadOnlyList<IPAddress> ipAddresses)
        {
            if (url.OriginalString.Length > 255)
                throw new ArgumentException("Cluster node URL length must be less than 255 bytes.", nameof(url));

            if (!url.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Cluster node URL must use HTTPS scheme.", nameof(url));

            if (ipAddresses.Count > 10)
                throw new ArgumentException("Cluster node cannot have more than 10 IP addresses.", nameof(ipAddresses));

            bool changed = false;

            if (!_url.Equals(url))
            {
                _url = url;
                changed = true;
            }

            if (!_ipAddresses.HasSameItems(ipAddresses))
            {
                _ipAddresses = ipAddresses;
                changed = true;
            }

            if (changed && (_apiClient is not null))
            {
                _apiClient.Dispose();
                _apiClient = null;
            }
        }

        public void UpdateNode(ClusterInfo.ClusterNodeInfo nodeInfo)
        {
            if (nodeInfo.Id != _id)
                throw new InvalidOperationException();

            bool changed = false;

            if (!_url.Equals(nodeInfo.Url))
            {
                _url = nodeInfo.Url;
                changed = true;
            }

            IReadOnlyList<IPAddress> ipAddresses = nodeInfo.IPAddresses.Convert(IPAddress.Parse);
            if (!_ipAddresses.HasSameItems(ipAddresses))
            {
                _ipAddresses = ipAddresses;
                changed = true;
            }

            _type = Enum.Parse<ClusterNodeType>(nodeInfo.Type, true);

            if (changed && (_apiClient is not null))
            {
                _apiClient.Dispose();
                _apiClient = null;
            }
        }

        public void InitializeHeartbeatTimer()
        {
            if (_state == ClusterNodeState.Self)
                throw new InvalidOperationException();

            if (_heartbeatTimer is null)
            {
                _heartbeatTimer = new Timer(HeartbeatTimerCallbackAsync);

                //for Primary node use configured refresh interval since config transfer already syncs the cluster state
                _heartbeatTimer.Change(_type == ClusterNodeType.Primary ? _clusterManager.HeartbeatRefreshIntervalSeconds * 1000 : HEARTBEAT_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        public void UpdateHeartbeatTimer()
        {
            if (_state == ClusterNodeState.Self)
                throw new InvalidOperationException();

            _heartbeatTimer?.Change(_clusterManager.HeartbeatRefreshIntervalSeconds * 1000, Timeout.Infinite);
        }

        public async Task<DashboardStats> GetDashboardStatsAsync(DashboardStatsType type = DashboardStatsType.LastHour, bool utcFormat = false, string acceptLanguage = "en-US,en;q=0.5", bool dontTrimQueryTypeData = false, DateTime startDate = default, DateTime endDate = default, CancellationToken cancellationToken = default)
        {
            HttpApiClient apiClient = GetApiClient();

            try
            {
                DashboardStats stats = await apiClient.GetDashboardStatsAsync(type, utcFormat, acceptLanguage, dontTrimQueryTypeData, startDate, endDate, cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;

                return stats;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public async Task<DashboardStats> GetDashboardTopStatsAsync(DashboardTopStatsType statsType, int limit = 1000, DashboardStatsType type = DashboardStatsType.LastHour, DateTime startDate = default, DateTime endDate = default, CancellationToken cancellationToken = default)
        {
            HttpApiClient apiClient = GetApiClient();

            try
            {
                DashboardStats stats = await apiClient.GetDashboardTopStatsAsync(statsType, limit, type, startDate, endDate, cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;

                return stats;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public async Task SetClusterSettingsAsync(IReadOnlyDictionary<string, string> clusterParameters, CancellationToken cancellationToken = default)
        {
            if (_type != ClusterNodeType.Primary)
                throw new InvalidOperationException();

            HttpApiClient apiClient = GetApiClient();

            try
            {
                await apiClient.SetClusterSettingsAsync(clusterParameters, cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public async Task ForceUpdateBlockListsAsync(CancellationToken cancellationToken = default)
        {
            HttpApiClient apiClient = GetApiClient();

            try
            {
                await apiClient.ForceUpdateBlockListsAsync(cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public async Task TemporaryDisableBlockingAsync(int minutes, CancellationToken cancellationToken = default)
        {
            HttpApiClient apiClient = GetApiClient();

            try
            {
                await apiClient.TemporaryDisableBlockingAsync(minutes, cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public async Task<ClusterInfo> GetClusterStateAsync(CancellationToken cancellationToken = default)
        {
            HttpApiClient apiClient = GetApiClient();

            try
            {
                ClusterInfo clusterInfo = await apiClient.GetClusterStateAsync(false, true, cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;

                return clusterInfo;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public async Task<ClusterInfo> DeleteClusterAsync(bool forceDelete = false, CancellationToken cancellationToken = default)
        {
            if (_type != ClusterNodeType.Primary)
                throw new InvalidOperationException();

            HttpApiClient apiClient = GetApiClient();

            try
            {
                ClusterInfo clusterInfo = await apiClient.DeleteClusterAsync(forceDelete, cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Unreachable; //node is deleted, so mark as unreachable

                return clusterInfo;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public async Task NotifySecondaryNodeAsync(ClusterNode primaryNode, CancellationToken cancellationToken = default)
        {
            if (_type != ClusterNodeType.Secondary)
                throw new InvalidOperationException();

            HttpApiClient apiClient = GetApiClient();

            try
            {
                await apiClient.NotifySecondaryNodeAsync(primaryNode.Id, primaryNode._url, primaryNode._ipAddresses, cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;

                _clusterManager.DnsWebService.LogManager.Write("DNS Server successfully notified Secondary node '" + ToString() + "' for server configuration changes.");
            }
            catch (Exception ex)
            {
                _state = ClusterNodeState.Unreachable;

                _clusterManager.DnsWebService.LogManager.Write("DNS Server failed to notify Secondary node '" + ToString() + "' for server configuration changes.\r\n" + ex.ToString());
            }
        }

        public async Task SyncConfigAsync(IReadOnlyCollection<string> includeZones = null, CancellationToken cancellationToken = default)
        {
            if (_type != ClusterNodeType.Primary)
                throw new InvalidOperationException();

            HttpApiClient apiClient = GetApiClient();

            try
            {
                await _clusterManager.SyncConfigFromAsync(apiClient, includeZones, cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public async Task AskSecondaryNodeToLeaveClusterAsync(CancellationToken cancellationToken = default)
        {
            if (_type != ClusterNodeType.Secondary)
                throw new InvalidOperationException();

            HttpApiClient apiClient = GetApiClient();

            try
            {
                _ = await apiClient.LeaveClusterAsync(cancellationToken: cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public async Task DeleteSecondaryNodeAsync(ClusterNode secondaryNode, CancellationToken cancellationToken = default)
        {
            if (_type != ClusterNodeType.Primary)
                throw new InvalidOperationException();

            if (secondaryNode.Type != ClusterNodeType.Secondary)
                throw new InvalidOperationException();

            HttpApiClient apiClient = GetApiClient();

            try
            {
                await apiClient.DeleteSecondaryNodeAsync(secondaryNode._id, cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public async Task<ClusterInfo> UpdateSecondaryNodeAsync(ClusterNode secondaryNode, X509Certificate2 secondaryNodeCertificate, CancellationToken cancellationToken = default)
        {
            if (_type != ClusterNodeType.Primary)
                throw new InvalidOperationException();

            if (secondaryNode.Type != ClusterNodeType.Secondary)
                throw new InvalidOperationException();

            HttpApiClient apiClient = GetApiClient();

            try
            {
                ClusterInfo clusterInfo = await apiClient.UpdateSecondaryNodeAsync(secondaryNode._id, secondaryNode._url, secondaryNode._ipAddresses, secondaryNodeCertificate, cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;

                return clusterInfo;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public async Task ProxyRequest(HttpContext context, string username, CancellationToken cancellationToken = default)
        {
            HttpApiClient apiClient = GetApiClient();

            try
            {
                await apiClient.ProxyRequest(context, username, cancellationToken);

                _lastSeen = DateTime.UtcNow;
                _state = ClusterNodeState.Connected;
            }
            catch
            {
                _state = ClusterNodeState.Unreachable;
                throw;
            }
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)2); //version
            bW.Write(_id);
            bW.WriteShortString(_url.OriginalString);

            bW.Write(Convert.ToByte(_ipAddresses.Count));

            foreach (IPAddress ipAddress in _ipAddresses)
                ipAddress.WriteTo(bW);

            bW.Write((byte)_type);
            bW.Write((byte)_state);
        }

        public override string ToString()
        {
            return _url.Host.ToLowerInvariant() + " (" + _ipAddresses.Join() + ")";
        }

        public int CompareTo(ClusterNode other)
        {
            return _url.Host.CompareTo(other._url.Host);
        }

        #endregion

        #region properties

        public int Id
        { get { return _id; } }

        public string Name
        { get { return _url.Host.ToLowerInvariant(); } }

        public Uri Url
        { get { return _url; } }

        public IReadOnlyList<IPAddress> IPAddresses
        { get { return _ipAddresses; } }

        public ClusterNodeType Type
        { get { return _type; } }

        public ClusterNodeState State
        { get { return _state; } }

        public DateTime UpSince
        {
            get
            {
                if (_state == ClusterNodeState.Self)
                    return _clusterManager.DnsWebService.UpTimeStamp;

                return _upSince;
            }
        }

        public DateTime LastSeen
        { get { return _lastSeen; } }

        #endregion
    }
}
