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

using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using DnsServerCore.HttpApi;
using DnsServerCore.HttpApi.Models;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Cluster
{
    enum DhcpFailoverRole : byte
    {
        Primary = 1,
        Standby = 2
    }

    enum DhcpFailoverState : byte
    {
        Disabled = 0,
        Startup = 1,
        Normal = 2,
        CommunicationsInterrupted = 3,
        PartnerDown = 4,
        Recovering = 5
    }

    //Hot-standby DHCP failover between two Cluster nodes.
    //The Primary serves clients and replicates every lease change to the Standby. The Standby stays passive, mirrors
    //the Primary's scopes and leases, and starts serving (with leases limited to the max client lead time) when the
    //Primary has been unreachable for the partner down delay. On recovery the Primary merges the Standby's leases
    //before serving and the Standby hands back control.
    sealed class DhcpFailoverManager : IDhcpFailoverHandler, IDisposable
    {
        #region variables

        const ushort DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 5;
        const ushort DEFAULT_PARTNER_DOWN_DELAY_SECONDS = 30;
        const uint DEFAULT_MAX_CLIENT_LEAD_TIME_SECONDS = 1800;

        const int LEASE_UPDATE_TIMER_INTERVAL = 500;
        const int MAX_LEASE_UPDATES_PER_REQUEST = 1000;
        const int MAX_PENDING_LEASE_UPDATES = 10000;
        const int FULL_SYNC_INTERVAL_SECONDS = 300;

        readonly DnsWebService _dnsWebService;
        readonly DhcpServer _dhcpServer;

        bool _enabled;
        DhcpFailoverRole _role = DhcpFailoverRole.Primary;
        string _partnerNodeName; //cluster node name, or host of partner URL in direct mode

        //direct mode: partner reached by URL and API token without a Cluster
        Uri _partnerUrl;
        string _partnerApiToken;
        bool _partnerIgnoreCertificateErrors;
        DirectDhcpFailoverPartner _directPartner;

        ushort _heartbeatIntervalSeconds = DEFAULT_HEARTBEAT_INTERVAL_SECONDS;
        ushort _partnerDownDelaySeconds = DEFAULT_PARTNER_DOWN_DELAY_SECONDS;
        uint _maxClientLeadTimeSeconds = DEFAULT_MAX_CLIENT_LEAD_TIME_SECONDS;

        volatile DhcpFailoverState _state = DhcpFailoverState.Disabled;
        DateTime _stateChangedOn = DateTime.UtcNow;
        DateTime _lastPartnerContact;
        DhcpFailoverStatus _lastPartnerStatus;
        bool _partnerReachable;

        //standby sync tracking
        string _syncedPrimarySettingsHash;
        DateTime _lastFullSync;
        readonly Dictionary<string, string> _appliedSettingsHashes = new Dictionary<string, string>();

        readonly ConcurrentQueue<(string, Lease, bool)> _pendingLeaseUpdates = new ConcurrentQueue<(string, Lease, bool)>();

        readonly Timer _heartbeatTimer;
        readonly Timer _leaseUpdateTimer;
        readonly SemaphoreSlim _leaseUpdateLock = new SemaphoreSlim(1, 1);

        #endregion

        #region constructor

        public DhcpFailoverManager(DnsWebService dnsWebService, DhcpServer dhcpServer)
        {
            _dnsWebService = dnsWebService;
            _dhcpServer = dhcpServer;

            _heartbeatTimer = new Timer(HeartbeatTimerCallbackAsync);
            _leaseUpdateTimer = new Timer(LeaseUpdateTimerCallbackAsync);

            LoadConfigFile();

            if (_enabled)
                SetState(DhcpFailoverState.Startup);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _heartbeatTimer?.Dispose();
            _leaseUpdateTimer?.Dispose();
            _directPartner?.Dispose();

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        #endregion

        #region config

        private string ConfigFile
        { get { return Path.Combine(_dnsWebService.ConfigFolder, "dhcp-failover.config"); } }

        private void LoadConfigFile()
        {
            try
            {
                if (!File.Exists(ConfigFile))
                    return;

                using (FileStream fS = new FileStream(ConfigFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader bR = new BinaryReader(fS);

                    if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DF")
                        throw new InvalidDataException("DHCP failover config file format is invalid.");

                    byte version = bR.ReadByte();
                    switch (version)
                    {
                        case 1:
                        case 2:
                            _enabled = bR.ReadBoolean();
                            _role = (DhcpFailoverRole)bR.ReadByte();

                            _partnerNodeName = fS.ReadShortString();
                            if (string.IsNullOrEmpty(_partnerNodeName))
                                _partnerNodeName = null;

                            _heartbeatIntervalSeconds = bR.ReadUInt16();
                            _partnerDownDelaySeconds = bR.ReadUInt16();
                            _maxClientLeadTimeSeconds = bR.ReadUInt32();

                            if (version >= 2)
                            {
                                string partnerUrl = bR.ReadString();
                                _partnerUrl = (partnerUrl.Length == 0) ? null : new Uri(partnerUrl);

                                _partnerApiToken = bR.ReadString();
                                if (_partnerApiToken.Length == 0)
                                    _partnerApiToken = null;

                                _partnerIgnoreCertificateErrors = bR.ReadBoolean();
                            }

                            break;

                        default:
                            throw new InvalidDataException("DHCP failover config version not supported.");
                    }
                }

                _dnsWebService.LogManager.Write("DHCP failover config file was loaded: " + ConfigFile);
            }
            catch (Exception ex)
            {
                _enabled = false;
                _dnsWebService.LogManager.Write("DHCP failover failed to load config file: " + ConfigFile, ex);
            }
        }

        private void SaveConfigFile()
        {
            string tmpConfigFile = Path.Combine(_dnsWebService.ConfigFolder, "dhcp-failover.tmp");

            using (FileStream fS = new FileStream(tmpConfigFile, FileMode.Create, FileAccess.Write))
            {
                BinaryWriter bW = new BinaryWriter(fS);

                bW.Write(Encoding.ASCII.GetBytes("DF"));
                bW.Write((byte)2); //version

                bW.Write(_enabled);
                bW.Write((byte)_role);

                if (_partnerNodeName is null)
                    bW.Write((byte)0);
                else
                    fS.WriteShortString(_partnerNodeName);

                bW.Write(_heartbeatIntervalSeconds);
                bW.Write(_partnerDownDelaySeconds);
                bW.Write(_maxClientLeadTimeSeconds);

                bW.Write(_partnerUrl is null ? "" : _partnerUrl.AbsoluteUri);
                bW.Write(_partnerApiToken ?? "");
                bW.Write(_partnerIgnoreCertificateErrors);

                bW.Flush();
            }

            File.Move(tmpConfigFile, ConfigFile, true);

            _dnsWebService.LogManager.Write("DHCP failover config file was saved: " + ConfigFile);
        }

        #endregion

        #region private

        private void Log(string message)
        {
            _dnsWebService.LogManager.Write("DHCP failover: " + message);
        }

        private void SetState(DhcpFailoverState state)
        {
            if (_state == state)
                return;

            DhcpFailoverState oldState = _state;

            _state = state;
            _stateChangedOn = DateTime.UtcNow;

            if (state != DhcpFailoverState.Disabled)
                Log("state changed from " + oldState.ToString() + " to " + state.ToString() + " (" + _role.ToString() + ", serving: " + IsServing + ").");
        }

        private IDhcpFailoverPartner GetPartner()
        {
            if (_partnerUrl is not null)
            {
                if (_partnerApiToken is null)
                    return null;

                if (_directPartner is null)
                    _directPartner = new DirectDhcpFailoverPartner(_dnsWebService, _partnerUrl, _partnerApiToken, _partnerIgnoreCertificateErrors);

                return _directPartner;
            }

            ClusterManager clusterManager = _dnsWebService.ClusterManager;

            if ((clusterManager is null) || !clusterManager.ClusterInitialized || (_partnerNodeName is null))
                return null;

            if (!clusterManager.TryGetClusterNode(_partnerNodeName, out ClusterNode partnerNode))
                return null;

            if (partnerNode.State == ClusterNodeState.Self)
                return null;

            return partnerNode;
        }

        private string GetSelfNodeName()
        {
            ClusterManager clusterManager = _dnsWebService.ClusterManager;

            if ((_partnerUrl is null) && (clusterManager is not null) && clusterManager.ClusterInitialized)
                return clusterManager.GetSelfNode().Name;

            return _dnsWebService.DnsServer.ServerDomain;
        }

        private async void HeartbeatTimerCallbackAsync(object state)
        {
            try
            {
                if (!_enabled)
                    return;

                IDhcpFailoverPartner partnerNode = GetPartner();
                DhcpFailoverStatus partnerStatus = null;

                if (partnerNode is not null)
                {
                    try
                    {
                        using (CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Max(5, _heartbeatIntervalSeconds * 2))))
                        {
                            partnerStatus = await partnerNode.GetDhcpFailoverStatusAsync(GetSelfNodeName(), cts.Token);
                        }

                        //in direct mode the partner knows this node by whatever address it was given, so names are not compared
                        bool partnerNameMismatch = (_partnerUrl is null) && !GetSelfNodeName().Equals(partnerStatus.PartnerNodeName, StringComparison.OrdinalIgnoreCase);

                        if (!partnerStatus.Enabled || (partnerStatus.Role == _role.ToString()) || partnerNameMismatch)
                        {
                            if (_partnerReachable || (_lastPartnerStatus is null))
                                Log("partner node '" + _partnerNodeName + "' is reachable but is not configured as the failover partner of this node (enabled: " + partnerStatus.Enabled + ", role: " + partnerStatus.Role + ", partner: " + partnerStatus.PartnerNodeName + ").");

                            _lastPartnerStatus = partnerStatus;
                            partnerStatus = null;

                            //partner is alive and may be serving on its own; never escalate to partner down for a reachable node
                            _lastPartnerContact = DateTime.UtcNow;
                        }
                    }
                    catch (Exception ex) when (IsPartnerAnswerError(ex))
                    {
                        //partner answered (e.g. rejected token, failover disabled) so it is alive; never take over from a live partner
                        if (_partnerReachable || (_lastPartnerStatus is null))
                            _dnsWebService.LogManager.Write("DHCP failover: partner '" + _partnerNodeName + "' is reachable but rejected the request; check the partner API token and settings. Not taking over while the partner is alive.", ex);

                        _lastPartnerContact = DateTime.UtcNow;
                    }
                    catch (Exception ex)
                    {
                        if (_partnerReachable)
                            _dnsWebService.LogManager.Write("DHCP failover: heartbeat failed for partner node '" + _partnerNodeName + "'.", ex);
                    }
                }

                if (partnerStatus is null)
                {
                    _partnerReachable = false;
                    OnPartnerUnreachable();
                }
                else
                {
                    if (!_partnerReachable)
                        Log("partner node '" + _partnerNodeName + "' is reachable (state: " + partnerStatus.State + ").");

                    _partnerReachable = true;
                    _lastPartnerContact = DateTime.UtcNow;
                    _lastPartnerStatus = partnerStatus;

                    await OnPartnerReachableAsync(partnerNode, partnerStatus);
                }
            }
            catch (Exception ex)
            {
                _dnsWebService.LogManager.Write(ex);
            }
            finally
            {
                try
                {
                    if (_enabled)
                        _heartbeatTimer.Change(_heartbeatIntervalSeconds * 1000, Timeout.Infinite);
                }
                catch (ObjectDisposedException)
                { }
            }
        }

        private static bool IsPartnerAnswerError(Exception ex)
        {
            //errors that can only happen when the partner's web service actually responded
            if (ex is HttpApiClientException)
                return true; //includes invalid token responses

            if ((ex is HttpRequestException httpEx) && (httpEx.StatusCode is not null))
                return true;

            return false;
        }

        private void OnPartnerUnreachable()
        {
            switch (_role)
            {
                case DhcpFailoverRole.Primary:
                    //primary keeps serving
                    SetState(DhcpFailoverState.CommunicationsInterrupted);
                    break;

                case DhcpFailoverRole.Standby:
                    switch (_state)
                    {
                        case DhcpFailoverState.Startup:
                            _lastPartnerContact = DateTime.UtcNow; //start counting partner down delay from startup
                            SetState(DhcpFailoverState.CommunicationsInterrupted);
                            break;

                        case DhcpFailoverState.Normal:
                            SetState(DhcpFailoverState.CommunicationsInterrupted);
                            break;

                        case DhcpFailoverState.CommunicationsInterrupted:
                            if (DateTime.UtcNow >= _lastPartnerContact.AddSeconds(_partnerDownDelaySeconds))
                            {
                                Log("partner node '" + _partnerNodeName + "' was unreachable for " + _partnerDownDelaySeconds + " seconds; taking over DHCP service.");
                                SetState(DhcpFailoverState.PartnerDown);
                            }

                            break;
                    }

                    break;
            }
        }

        private async Task OnPartnerReachableAsync(IDhcpFailoverPartner partnerNode, DhcpFailoverStatus partnerStatus)
        {
            switch (_role)
            {
                case DhcpFailoverRole.Primary:
                    if ((_state == DhcpFailoverState.Startup) || (_state == DhcpFailoverState.Recovering) || partnerStatus.Serving)
                    {
                        //standby may have issued leases; merge them before (or while) serving
                        DhcpFailoverState previousState = _state;

                        if (_state == DhcpFailoverState.Startup)
                            SetState(DhcpFailoverState.Recovering);

                        try
                        {
                            await PullSnapshotAsync(partnerNode, false);
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService.LogManager.Write("DHCP failover: failed to merge leases from partner node '" + _partnerNodeName + "'.", ex);

                            if (previousState == DhcpFailoverState.Startup)
                                SetState(DhcpFailoverState.CommunicationsInterrupted); //serve anyway; do not block service at startup

                            return;
                        }
                    }

                    SetState(DhcpFailoverState.Normal);
                    break;

                case DhcpFailoverRole.Standby:
                    if ((partnerStatus.State == nameof(DhcpFailoverState.Startup)) || (partnerStatus.State == nameof(DhcpFailoverState.Recovering)))
                    {
                        //primary is recovering and will pull our leases; keep current state until it serves
                        if (_state == DhcpFailoverState.Startup)
                            SetState(DhcpFailoverState.CommunicationsInterrupted);

                        return;
                    }

                    if (!partnerStatus.Serving)
                        return; //unexpected; wait for primary to serve

                    if (_state == DhcpFailoverState.PartnerDown)
                    {
                        //hand back control: push all our leases to primary first so none are lost
                        try
                        {
                            await SendAllLeasesAsync(partnerNode);
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService.LogManager.Write("DHCP failover: failed to send leases to partner node '" + _partnerNodeName + "'; continuing to serve.", ex);
                            return;
                        }

                        Log("partner node '" + _partnerNodeName + "' is serving again; handing back DHCP service.");
                    }

                    bool forceFullSync = _state != DhcpFailoverState.Normal;

                    SetState(DhcpFailoverState.Normal);

                    if (forceFullSync || (partnerStatus.SettingsHash != _syncedPrimarySettingsHash) || (DateTime.UtcNow >= _lastFullSync.AddSeconds(FULL_SYNC_INTERVAL_SECONDS)))
                    {
                        try
                        {
                            await PullSnapshotAsync(partnerNode, true);

                            _syncedPrimarySettingsHash = partnerStatus.SettingsHash;
                            _lastFullSync = DateTime.UtcNow;
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService.LogManager.Write("DHCP failover: failed to sync scopes from partner node '" + _partnerNodeName + "'.", ex);
                        }
                    }

                    break;
            }
        }

        private async Task PullSnapshotAsync(IDhcpFailoverPartner partnerNode, bool configAuthority)
        {
            using (MemoryStream mS = new MemoryStream())
            {
                using (CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(60)))
                {
                    await using (Stream stream = await partnerNode.GetDhcpFailoverSnapshotAsync(cts.Token))
                    {
                        await stream.CopyToAsync(mS, cts.Token);
                    }
                }

                mS.Position = 0;

                await _dhcpServer.ApplySnapshotAsync(mS, configAuthority, _appliedSettingsHashes);
            }

            if (configAuthority)
                Log("scopes and leases were synced from partner node '" + _partnerNodeName + "'.");
            else
                Log("leases were merged from partner node '" + _partnerNodeName + "'.");
        }

        private async Task SendAllLeasesAsync(IDhcpFailoverPartner partnerNode)
        {
            List<(string, Lease, bool)> leaseUpdates = new List<(string, Lease, bool)>();

            foreach (KeyValuePair<string, Scope> scope in _dhcpServer.Scopes)
            {
                foreach (KeyValuePair<ClientIdentifierOption, Lease> lease in scope.Value.Leases)
                    leaseUpdates.Add((scope.Key, lease.Value, false));
            }

            for (int i = 0; i < leaseUpdates.Count; i += MAX_LEASE_UPDATES_PER_REQUEST)
                await SendLeaseUpdatesAsync(partnerNode, leaseUpdates.GetRange(i, Math.Min(MAX_LEASE_UPDATES_PER_REQUEST, leaseUpdates.Count - i)));
        }

        private static async Task SendLeaseUpdatesAsync(IDhcpFailoverPartner partnerNode, IReadOnlyCollection<(string, Lease, bool)> leaseUpdates)
        {
            byte[] buffer;

            using (MemoryStream mS = new MemoryStream())
            {
                DhcpServer.WriteLeaseUpdatesTo(mS, leaseUpdates);
                buffer = mS.ToArray();
            }

            using (CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
            {
                await partnerNode.SendDhcpFailoverLeaseUpdatesAsync(buffer, cts.Token);
            }
        }

        private async void LeaseUpdateTimerCallbackAsync(object state)
        {
            if (!await _leaseUpdateLock.WaitAsync(0))
                return;

            try
            {
                if (_pendingLeaseUpdates.IsEmpty)
                    return;

                IDhcpFailoverPartner partnerNode = GetPartner();

                if ((partnerNode is null) || !_partnerReachable)
                {
                    //partner is down; it will resync when it comes back
                    _pendingLeaseUpdates.Clear();
                    return;
                }

                List<(string, Lease, bool)> leaseUpdates = new List<(string, Lease, bool)>();

                while ((leaseUpdates.Count < MAX_LEASE_UPDATES_PER_REQUEST) && _pendingLeaseUpdates.TryDequeue(out (string, Lease, bool) leaseUpdate))
                    leaseUpdates.Add(leaseUpdate);

                try
                {
                    await SendLeaseUpdatesAsync(partnerNode, leaseUpdates);
                }
                catch (Exception ex)
                {
                    _dnsWebService.LogManager.Write("DHCP failover: failed to send " + leaseUpdates.Count + " lease update(s) to partner node '" + _partnerNodeName + "'; will retry.", ex);

                    //retry on next tick; receiver ignores updates older than its own copy so reordering is safe
                    //queue gets cleared once heartbeat marks the partner unreachable
                    foreach ((string, Lease, bool) leaseUpdate in leaseUpdates)
                    {
                        if (_pendingLeaseUpdates.Count >= MAX_PENDING_LEASE_UPDATES)
                            break;

                        _pendingLeaseUpdates.Enqueue(leaseUpdate);
                    }
                }
            }
            catch (Exception ex)
            {
                _dnsWebService.LogManager.Write(ex);
            }
            finally
            {
                _leaseUpdateLock.Release();

                try
                {
                    if (!_pendingLeaseUpdates.IsEmpty)
                        _leaseUpdateTimer.Change(LEASE_UPDATE_TIMER_INTERVAL, Timeout.Infinite);
                }
                catch (ObjectDisposedException)
                { }
            }
        }

        #endregion

        #region IDhcpFailoverHandler

        public void OnLeaseChanged(string scopeName, Lease lease, bool removed)
        {
            if (!_enabled || !IsServing)
                return;

            if (_pendingLeaseUpdates.Count >= MAX_PENDING_LEASE_UPDATES)
                return; //partner too far behind; periodic full sync will fix it

            _pendingLeaseUpdates.Enqueue((scopeName, lease, removed));

            try
            {
                _leaseUpdateTimer.Change(LEASE_UPDATE_TIMER_INTERVAL, Timeout.Infinite);
            }
            catch (ObjectDisposedException)
            { }
        }

        public bool IsServing
        {
            get
            {
                if (!_enabled)
                    return true;

                switch (_role)
                {
                    case DhcpFailoverRole.Primary:
                        return (_state == DhcpFailoverState.Normal) || (_state == DhcpFailoverState.CommunicationsInterrupted);

                    case DhcpFailoverRole.Standby:
                        return _state == DhcpFailoverState.PartnerDown;

                    default:
                        return false;
                }
            }
        }

        public uint LeaseTimeLimit
        {
            get
            {
                if (_enabled && (_role == DhcpFailoverRole.Standby) && (_state == DhcpFailoverState.PartnerDown))
                    return _maxClientLeadTimeSeconds;

                return 0;
            }
        }

        #endregion

        #region public

        public void Start()
        {
            if (_enabled)
                _heartbeatTimer.Change(0, Timeout.Infinite);
        }

        public void SetConfig(bool enabled, DhcpFailoverRole role, string partnerNodeName, Uri partnerUrl, string partnerApiToken, bool partnerIgnoreCertificateErrors, ushort heartbeatIntervalSeconds, ushort partnerDownDelaySeconds, uint maxClientLeadTimeSeconds)
        {
            //partnerUrl set: direct mode without a Cluster; partnerApiToken null keeps the saved token
            if (partnerUrl is not null)
            {
                if (!partnerUrl.IsAbsoluteUri || ((partnerUrl.Scheme != Uri.UriSchemeHttps) && (partnerUrl.Scheme != Uri.UriSchemeHttp)))
                    throw new DnsWebServiceException("The partner URL must be an absolute http:// or https:// URL of the partner's web console, for example https://dns2.home.lan:53443/");

                if (string.IsNullOrWhiteSpace(partnerApiToken))
                    partnerApiToken = _partnerApiToken;

                if (enabled && string.IsNullOrWhiteSpace(partnerApiToken))
                    throw new DnsWebServiceException("An API token created on the partner node is required for direct mode.");

                partnerNodeName = partnerUrl.Host.ToLowerInvariant();
            }
            else if (enabled)
            {
                ClusterManager clusterManager = _dnsWebService.ClusterManager;

                if ((clusterManager is null) || !clusterManager.ClusterInitialized)
                    throw new DnsWebServiceException("No Cluster is initialized on this node. Use direct mode with the partner's URL and an API token, or initialize a Cluster.");

                if (string.IsNullOrWhiteSpace(partnerNodeName))
                    throw new DnsWebServiceException("Parameter 'partnerNodeName' missing.");

                if (!clusterManager.TryGetClusterNode(partnerNodeName, out ClusterNode partnerNode))
                    throw new DnsWebServiceException("No such node exists in the Cluster by name: " + partnerNodeName);

                if (partnerNode.State == ClusterNodeState.Self)
                    throw new DnsWebServiceException("The failover partner node cannot be this node.");

                partnerNodeName = partnerNode.Name;
            }

            if (heartbeatIntervalSeconds < 1)
                throw new ArgumentOutOfRangeException(nameof(heartbeatIntervalSeconds), "Heartbeat interval must be at least 1 second.");

            if (partnerDownDelaySeconds < heartbeatIntervalSeconds * 2)
                throw new ArgumentOutOfRangeException(nameof(partnerDownDelaySeconds), "Partner down delay must be at least twice the heartbeat interval.");

            if (maxClientLeadTimeSeconds < 60)
                throw new ArgumentOutOfRangeException(nameof(maxClientLeadTimeSeconds), "Max client lead time must be at least 60 seconds.");

            if (partnerUrl is null)
                partnerApiToken = null; //cluster mode uses the Cluster API token

            bool partnerConnectionChanged = !Equals(_partnerUrl, partnerUrl) || (_partnerApiToken != partnerApiToken) || (_partnerIgnoreCertificateErrors != partnerIgnoreCertificateErrors);
            bool restart = (_enabled != enabled) || (_role != role) || !string.Equals(_partnerNodeName, partnerNodeName, StringComparison.OrdinalIgnoreCase) || partnerConnectionChanged;

            if (partnerConnectionChanged)
            {
                DirectDhcpFailoverPartner oldDirectPartner = _directPartner;
                _directPartner = null;

                if (oldDirectPartner is not null)
                {
                    //give any in-flight call time to finish before disposing
                    _ = Task.Delay(5000).ContinueWith(delegate { oldDirectPartner.Dispose(); });
                }
            }

            _partnerUrl = partnerUrl;
            _partnerApiToken = string.IsNullOrWhiteSpace(partnerApiToken) ? null : partnerApiToken;
            _partnerIgnoreCertificateErrors = partnerIgnoreCertificateErrors;

            _enabled = enabled;
            _role = role;
            _partnerNodeName = string.IsNullOrWhiteSpace(partnerNodeName) ? null : partnerNodeName;
            _heartbeatIntervalSeconds = heartbeatIntervalSeconds;
            _partnerDownDelaySeconds = partnerDownDelaySeconds;
            _maxClientLeadTimeSeconds = maxClientLeadTimeSeconds;

            SaveConfigFile();

            if (restart)
            {
                _pendingLeaseUpdates.Clear();
                _partnerReachable = false;
                _lastPartnerStatus = null;
                _syncedPrimarySettingsHash = null;
                _lastFullSync = default;
                _appliedSettingsHashes.Clear();

                if (_enabled)
                {
                    SetState(DhcpFailoverState.Startup);
                    _heartbeatTimer.Change(0, Timeout.Infinite);
                }
                else
                {
                    _heartbeatTimer.Change(Timeout.Infinite, Timeout.Infinite);
                    SetState(DhcpFailoverState.Disabled);
                    Log("disabled; this node now serves DHCP independently.");
                }
            }
        }

        public bool IsPartnerNode(string nodeName)
        {
            return _enabled && (_partnerNodeName is not null) && _partnerNodeName.Equals(nodeName, StringComparison.OrdinalIgnoreCase);
        }

        #endregion

        #region properties

        public bool Enabled
        { get { return _enabled; } }

        public DhcpFailoverRole Role
        { get { return _role; } }

        public DhcpFailoverState State
        { get { return _state; } }

        public DateTime StateChangedOn
        { get { return _stateChangedOn; } }

        public string PartnerNodeName
        { get { return _partnerNodeName; } }

        public Uri PartnerUrl
        { get { return _partnerUrl; } }

        public bool PartnerApiTokenSet
        { get { return _partnerApiToken is not null; } }

        public bool PartnerIgnoreCertificateErrors
        { get { return _partnerIgnoreCertificateErrors; } }

        public bool PartnerReachable
        { get { return _partnerReachable; } }

        public DateTime LastPartnerContact
        { get { return _lastPartnerContact; } }

        public DhcpFailoverStatus LastPartnerStatus
        { get { return _lastPartnerStatus; } }

        public DateTime LastFullSync
        { get { return _lastFullSync; } }

        public ushort HeartbeatIntervalSeconds
        { get { return _heartbeatIntervalSeconds; } }

        public ushort PartnerDownDelaySeconds
        { get { return _partnerDownDelaySeconds; } }

        public uint MaxClientLeadTimeSeconds
        { get { return _maxClientLeadTimeSeconds; } }

        #endregion
    }
}
