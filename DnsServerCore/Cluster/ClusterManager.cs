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
using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using DnsServerCore.HttpApi;
using DnsServerCore.HttpApi.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Cluster
{
    sealed class ClusterManager : IDisposable
    {
        #region variables

        const ushort HEARTBEAT_REFRESH_INTERVAL_SECONDS = 30;
        const ushort HEARTBEAT_RETRY_INTERVAL_SECONDS = 10;
        const ushort CONFIG_REFRESH_INTERVAL_SECONDS = 900;
        const ushort CONFIG_RETRY_INTERVAL_SECONDS = 60;

        readonly DnsWebService _dnsWebService;

        string _clusterDomain;
        ushort _heartbeatRefreshIntervalSeconds;
        ushort _heartbeatRetryIntervalSeconds;
        ushort _configRefreshIntervalSeconds;
        ushort _configRetryIntervalSeconds;
        DateTime _configLastSynced;

        IReadOnlyDictionary<int, ClusterNode> _clusterNodes;

        readonly SemaphoreSlim _configRefreshLock = new SemaphoreSlim(1, 1);
        readonly Timer _configRefreshTimer;
        bool _configRefreshTimerTriggered;
        IReadOnlyCollection<string> _configRefreshIncludeZones;
        const int CONFIG_REFRESH_TIMER_INTERVAL = 5000;

        readonly Timer _notifyAllSecondaryNodesTimer;
        bool _notifyAllSecondaryNodesTimerTriggered;
        const int NOTIFY_ALL_SECONDARY_NODES_TIMER_INTERVAL = 5000;

        readonly Timer _clusterUpdateForSecondaryNodeChangesTimer;
        bool _clusterUpdateForSecondaryNodeChangesTimerTriggered;
        const int CLUSTER_UPDATE_FOR_SECONDARY_NODE_CHANGES_TIMER_INTERVAL = 5000;

        readonly object _saveLock = new object();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        volatile int _recordUpdateForMemberZonesId;

        #endregion

        #region constructor

        public ClusterManager(DnsWebService dnsWebService)
        {
            _dnsWebService = dnsWebService;

            _configRefreshTimer = new Timer(ConfigRefreshTimerCallbackAsync);
            _notifyAllSecondaryNodesTimer = new Timer(NotifyAllSecondaryNodesTimerCallbackAsync);
            _clusterUpdateForSecondaryNodeChangesTimer = new Timer(ClusterUpdateForSecondaryNodeChangesTimerCallbackAsync);

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveConfigFileInternal();
                            _pendingSave = false;
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService.LogManager.Write(ex);

                            //set timer to retry again
                            _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                        }
                    }
                }
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _configRefreshTimer?.Dispose();
            _notifyAllSecondaryNodesTimer?.Dispose();
            _clusterUpdateForSecondaryNodeChangesTimer?.Dispose();

            DisposeAllNodes();

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave)
                {
                    try
                    {
                        SaveConfigFileInternal();
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService.LogManager.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            _configRefreshLock?.Dispose();

            _disposed = true;
        }

        #endregion

        #region config

        public void LoadConfigFile()
        {
            string configFile = Path.Combine(_dnsWebService.ConfigFolder, "cluster.config");

            try
            {
                DisposeAllNodes(); //dispose existing nodes, if any

                using (FileStream fS = new FileStream(configFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS);
                }

                InitializeHeartbeatTimerFor(_clusterNodes);
                UpdateConfigRefreshTimer();

                _dnsWebService.LogManager.Write("DNS Server Cluster config file was loaded: " + configFile);
            }
            catch (FileNotFoundException)
            {
                //do nothing
            }
            catch (Exception ex)
            {
                _dnsWebService.LogManager.Write("DNS Server encountered an error while loading the Cluster config file: " + configFile + "\r\n" + ex.ToString());
            }
        }

        public void LoadConfig(Stream s)
        {
            lock (_saveLock)
            {
                DisposeAllNodes(); //dispose existing nodes, if any

                ReadConfigFrom(s);

                InitializeHeartbeatTimerFor(_clusterNodes);
                UpdateConfigRefreshTimer();

                //save config file
                SaveConfigFileInternal();

                if (_pendingSave)
                {
                    _pendingSave = false;
                    _saveTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
        }

        private void UpdateConfigRefreshTimer(int refreshInterval = CONFIG_REFRESH_TIMER_INTERVAL)
        {
            //ensure that the new refresh interval is applied using lock
            _configRefreshLock.Wait();
            try
            {
                if (ClusterInitialized && (GetSelfNode().Type == ClusterNodeType.Secondary))
                    _configRefreshTimer.Change(refreshInterval, Timeout.Infinite); //start config refresh timer only for secondary nodes
                else
                    _configRefreshTimer.Change(Timeout.Infinite, Timeout.Infinite);
            }
            finally
            {
                _configRefreshLock.Release();
            }
        }

        private void StopConfigRefreshTimer()
        {
            //ensure that the timer is stopped using lock
            _configRefreshLock.Wait();
            try
            {
                _configRefreshTimer.Change(Timeout.Infinite, Timeout.Infinite);
            }
            finally
            {
                _configRefreshLock.Release();
            }
        }

        private void SaveConfigFileInternal()
        {
            if (!ClusterInitialized)
                throw new InvalidOperationException();

            string configFile = Path.Combine(_dnsWebService.ConfigFolder, "cluster.config");

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize config
                WriteConfigTo(mS);

                //write config
                mS.Position = 0;

                using (FileStream fS = new FileStream(configFile, FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _dnsWebService.LogManager.Write("DNS Server Cluster config file was saved: " + configFile);
        }

        public void SaveConfigFile()
        {
            if (!ClusterInitialized)
                throw new InvalidOperationException();

            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void UnloadAndDeleteConfigFile()
        {
            StopConfigRefreshTimer();

            DisposeAllNodes(); //dispose existing nodes, if any

            lock (_saveLock)
            {
                //unload
                _clusterDomain = null;
                _configLastSynced = default;
                _clusterNodes = null;

                //delete config file
                string configFile = Path.Combine(_dnsWebService.ConfigFolder, "cluster.config");

                try
                {
                    if (File.Exists(configFile))
                    {
                        File.Delete(configFile);

                        _dnsWebService.LogManager.Write("DNS Server Cluster config file was deleted: " + configFile);
                    }
                }
                catch (Exception ex)
                {
                    _dnsWebService.LogManager.Write("DNS Server encountered an error while deleting the Cluster config file: " + configFile + "\r\n" + ex.ToString());
                }

                if (_pendingSave)
                {
                    _pendingSave = false;
                    _saveTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
        }

        private void ReadConfigFrom(Stream s)
        {
            BinaryReader bR = new BinaryReader(s);

            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "CL") //format
                throw new InvalidDataException("DNS Server Cluster config file format is invalid.");

            int version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    _clusterDomain = bR.ReadString();
                    _heartbeatRefreshIntervalSeconds = bR.ReadUInt16();
                    _heartbeatRetryIntervalSeconds = bR.ReadUInt16();
                    _configRefreshIntervalSeconds = bR.ReadUInt16();
                    _configRetryIntervalSeconds = bR.ReadUInt16();
                    _configLastSynced = bR.ReadDateTime();

                    Dictionary<int, ClusterNode> clusterNodes = null;
                    int count = bR.ReadByte();

                    if (count > 0)
                    {
                        clusterNodes = new Dictionary<int, ClusterNode>(count);

                        for (int i = 0; i < count; i++)
                        {
                            ClusterNode node = new ClusterNode(this, bR);
                            clusterNodes.TryAdd(node.Id, node);
                        }
                    }

                    _clusterNodes = clusterNodes;
                    break;

                default:
                    throw new InvalidDataException("DNS Server Cluster config version not supported.");
            }
        }

        private void WriteConfigTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("CL")); //format
            bW.Write((byte)1); //version

            bW.Write(_clusterDomain);
            bW.Write(_heartbeatRefreshIntervalSeconds);
            bW.Write(_heartbeatRetryIntervalSeconds);
            bW.Write(_configRefreshIntervalSeconds);
            bW.Write(_configRetryIntervalSeconds);
            bW.Write(_configLastSynced);

            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            if (clusterNodes is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(clusterNodes.Count));

                foreach (KeyValuePair<int, ClusterNode> node in clusterNodes)
                    node.Value.WriteTo(bW);
            }
        }

        #endregion

        #region private

        private void DisposeAllNodes()
        {
            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            if (clusterNodes is not null)
            {
                foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                    clusterNode.Value.Dispose();
            }
        }

        private static void InitializeHeartbeatTimerFor(IReadOnlyDictionary<int, ClusterNode> clusterNodes)
        {
            //start heartbeat timers for all nodes except self node
            foreach (KeyValuePair<int, ClusterNode> node in clusterNodes)
            {
                if (node.Value.State == ClusterNodeState.Self)
                    continue;

                node.Value.InitializeHeartbeatTimer();
            }
        }

        private void UpdateHeartbeatTimerForAllClusterNodes()
        {
            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            if (clusterNodes is not null)
            {
                foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                {
                    if (clusterNode.Value.State == ClusterNodeState.Self)
                        continue;

                    clusterNode.Value.UpdateHeartbeatTimer();
                }
            }
        }

        private void DeleteAllClusterConfig()
        {
            //delete cluster catalog zone
            string clusterCatalogDomain = "cluster-catalog." + _clusterDomain;

            AuthZoneInfo clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain);
            if (clusterCatalogZoneInfo is not null)
            {
                if (_dnsWebService.DnsServer.AuthZoneManager.DeleteZone(clusterCatalogZoneInfo, true))
                    _dnsWebService.AuthManager.RemoveAllPermissions(PermissionSection.Zones, clusterCatalogDomain);
            }

            //remove TSIG key for cluster catalog zone
            {
                IReadOnlyDictionary<string, TsigKey> existingKeys = _dnsWebService.DnsServer.TsigKeys;
                if (existingKeys is not null)
                {
                    Dictionary<string, TsigKey> updatedKeys = new Dictionary<string, TsigKey>(existingKeys);
                    updatedKeys.Remove(clusterCatalogDomain);

                    _dnsWebService.DnsServer.TsigKeys = updatedKeys;
                }
            }

            //delete cluster API token
            {
                foreach (UserSession session in _dnsWebService.AuthManager.Sessions)
                {
                    if ((session.Type == UserSessionType.ApiToken) && (session.TokenName == _clusterDomain))
                        _dnsWebService.AuthManager.DeleteSession(session.Token);
                }
            }

            //finalize
            if (_dnsWebService.DnsServer.ServerDomain.EndsWith("." + _clusterDomain, StringComparison.OrdinalIgnoreCase))
                _dnsWebService.DnsServer.ServerDomain = _dnsWebService.DnsServer.ServerDomain.Substring(0, _dnsWebService.DnsServer.ServerDomain.Length - (_clusterDomain.Length + 1));

            //save all changes
            _dnsWebService.DnsServer.SaveConfigFile();
            _dnsWebService.AuthManager.SaveConfigFile();

            UnloadAndDeleteConfigFile();
        }

        #endregion

        #region primary node

        public void InitializeCluster(string clusterDomain, IReadOnlyList<IPAddress> primaryNodeIpAddresses, UserSession session)
        {
            if (ClusterInitialized)
                throw new DnsServerException("Failed to initialize Cluster: the Cluster is already initialized.");

            if (!_dnsWebService.IsWebServiceTlsEnabled)
                throw new InvalidOperationException();

            clusterDomain = clusterDomain.ToLowerInvariant();

            //create self node
            string serverDomain = _dnsWebService.DnsServer.ServerDomain;
            if (!serverDomain.EndsWith("." + clusterDomain, StringComparison.OrdinalIgnoreCase))
            {
                int x = serverDomain.IndexOf('.');
                if (x < 0)
                    serverDomain = serverDomain + "." + clusterDomain;
                else
                    serverDomain = string.Concat(serverDomain.AsSpan(0, x), ".", clusterDomain);
            }

            Uri primaryNodeUrl = new Uri($"https://{serverDomain}:{_dnsWebService.WebServiceTlsPort}/");

            ClusterNode selfPrimaryNode = new ClusterNode(this, RandomNumberGenerator.GetInt32(int.MaxValue), primaryNodeUrl, primaryNodeIpAddresses, ClusterNodeType.Primary, ClusterNodeState.Self);

            //create cluster primary zone
            AuthZoneInfo clusterZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterDomain);
            if (clusterZoneInfo is null)
            {
                clusterZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreatePrimaryZone(clusterDomain);
                if (clusterZoneInfo is null)
                    throw new DnsServerException($"Failed to initialize Cluster: failed to create the Cluster zone '{clusterDomain}'. Please try again.");
            }
            else if (clusterZoneInfo.Type != AuthZoneType.Primary)
            {
                throw new DnsServerException($"Failed to initialize Cluster: the zone '{clusterZoneInfo.Name}' already exists and is not a Primary zone. Please delete the existing zone or use a different Cluster domain name.");
            }

            //create cluster catalog zone
            string clusterCatalogDomain = "cluster-catalog." + clusterDomain;

            AuthZoneInfo clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain);
            if (clusterCatalogZoneInfo is null)
            {
                clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreateCatalogZone(clusterCatalogDomain);
                if (clusterCatalogZoneInfo is null)
                    throw new DnsServerException($"Failed to initialize Cluster: failed to create the Cluster Catalog zone '{clusterCatalogDomain}'. Please try again.");
            }
            else if (clusterCatalogZoneInfo.Type != AuthZoneType.Catalog)
            {
                throw new DnsServerException($"Failed to initialize Cluster: the zone '{clusterCatalogZoneInfo.Name}' already exists and is not a Catalog zone. Please delete the existing zone or use a different Cluster domain name.");
            }

            //set cluster primary zone permissions
            _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, clusterZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, clusterZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.View);

            //set cluster catalog zone permissions
            _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, clusterCatalogZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, clusterCatalogZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.View);

            //ensure cluster zone is a member of cluster catalog zone
            if (clusterZoneInfo.CatalogZoneName is null)
                _dnsWebService.DnsServer.AuthZoneManager.AddCatalogMemberZone(clusterCatalogZoneInfo.Name, clusterZoneInfo);
            else if (!clusterZoneInfo.CatalogZoneName.Equals(clusterCatalogZoneInfo.Name, StringComparison.OrdinalIgnoreCase))
                _dnsWebService.DnsServer.AuthZoneManager.ChangeCatalogMemberZoneOwnership(clusterZoneInfo, clusterCatalogZoneInfo.Name);

            //sign cluster zone
            if (clusterZoneInfo.ApexZone.DnssecStatus == AuthZoneDnssecStatus.Unsigned)
            {
                DnssecPrivateKey kskPrivateKey = DnssecPrivateKey.Create(DnssecAlgorithm.ECDSAP256SHA256, DnssecPrivateKeyType.KeySigningKey);
                DnssecPrivateKey zskPrivateKey = DnssecPrivateKey.Create(DnssecAlgorithm.ECDSAP256SHA256, DnssecPrivateKeyType.ZoneSigningKey);
                zskPrivateKey.RolloverDays = 90;

                _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZone(clusterZoneInfo.Name, kskPrivateKey, zskPrivateKey, 3600, false);
            }

            //create TSIG key for cluster catalog zone if it does not exist
            {
                IReadOnlyDictionary<string, TsigKey> existingKeys = _dnsWebService.DnsServer.TsigKeys;
                if (existingKeys is null)
                {
                    Dictionary<string, TsigKey> updatedKeys = new Dictionary<string, TsigKey>();
                    updatedKeys[clusterCatalogDomain] = new TsigKey(clusterCatalogDomain, TsigAlgorithm.HMAC_SHA256);

                    _dnsWebService.DnsServer.TsigKeys = updatedKeys;
                }
                else if (!existingKeys.ContainsKey(clusterCatalogDomain))
                {
                    Dictionary<string, TsigKey> updatedKeys = new Dictionary<string, TsigKey>(existingKeys);
                    updatedKeys[clusterCatalogDomain] = new TsigKey(clusterCatalogDomain, TsigAlgorithm.HMAC_SHA256);

                    _dnsWebService.DnsServer.TsigKeys = updatedKeys;
                }
            }

            //create cluster API token if it does not exist
            {
                List<UserSession> userSessions = _dnsWebService.AuthManager.GetSessions(session.User);
                bool apiTokenExists = false;

                foreach (UserSession existingSession in userSessions)
                {
                    if ((existingSession.Type == UserSessionType.ApiToken) && (existingSession.TokenName == clusterZoneInfo.Name))
                    {
                        apiTokenExists = true;
                        break;
                    }
                }

                if (!apiTokenExists)
                    _dnsWebService.AuthManager.CreateApiToken(clusterZoneInfo.Name, session.User.Username, session.LastSeenRemoteAddress, session.LastSeenUserAgent);
            }

            //dispose existing nodes, if any
            DisposeAllNodes();

            //initialize cluster
            _clusterNodes = new Dictionary<int, ClusterNode>(1)
            {
                [selfPrimaryNode.Id] = selfPrimaryNode
            };

            _clusterDomain = clusterZoneInfo.Name;
            _heartbeatRefreshIntervalSeconds = HEARTBEAT_REFRESH_INTERVAL_SECONDS;
            _heartbeatRetryIntervalSeconds = HEARTBEAT_RETRY_INTERVAL_SECONDS;
            _configRefreshIntervalSeconds = CONFIG_REFRESH_INTERVAL_SECONDS;
            _configRetryIntervalSeconds = CONFIG_RETRY_INTERVAL_SECONDS;

            //update cluster primary zone and save zone file
            RemoveAllClusterPrimaryZoneNSRecords(); //remove all existing NS records
            AddClusterPrimaryZoneRecordsFor(selfPrimaryNode, _dnsWebService.WebServiceTlsCertificate);

            //update cluster catalog zone ACLs, TSIG key name and save zone file
            UpdateClusterCatalogZoneOptions(clusterCatalogZoneInfo);

            //finalize
            _dnsWebService.DnsServer.ServerDomain = selfPrimaryNode.Name;

            //save all changes
            _dnsWebService.DnsServer.SaveConfigFile();
            _dnsWebService.AuthManager.SaveConfigFile();
            SaveConfigFile();
        }

        public void DeleteCluster(bool forceDelete)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to delete Cluster: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to delete Cluster: only a Primary node can delete the Cluster.");

            if (!forceDelete && (_clusterNodes.Count > 1))
                throw new DnsServerException("Failed to delete Cluster: please remove all Secondary nodes before deleting the Cluster.");

            DeleteAllClusterConfig();
        }

        public ClusterNode JoinCluster(int secondaryNodeId, Uri secondaryNodeUrl, IReadOnlyList<IPAddress> secondaryNodeIpAddresses, X509Certificate2 secondaryNodeCertificate)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to add Secondary node: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to add Secondary node: only a Primary node can add a Secondary node to the Cluster.");

            string secondaryNodeDomain = secondaryNodeUrl.Host.ToLowerInvariant();

            if (!secondaryNodeDomain.EndsWith("." + _clusterDomain, StringComparison.OrdinalIgnoreCase))
                throw new DnsServerException("Failed to add Secondary node: the Secondary node domain name must be a subdomain of the Cluster domain name.");

            IReadOnlyDictionary<int, ClusterNode> existingClusterNodes = _clusterNodes;

            //validate for duplicate names
            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
            {
                if (existingClusterNode.Value.Name.Equals(secondaryNodeUrl.Host, StringComparison.OrdinalIgnoreCase))
                    throw new DnsServerException("Failed to add Secondary node: the Secondary node's domain name already exists in the Cluster. Please try again after changing the Secondary DNS Server's domain name.");
            }

            //add secondary node to cluster nodes
            ClusterNode secondaryNode = new ClusterNode(this, secondaryNodeId, secondaryNodeUrl, secondaryNodeIpAddresses, ClusterNodeType.Secondary, ClusterNodeState.Unknown);
            Dictionary<int, ClusterNode> updatedClusterNodes = new Dictionary<int, ClusterNode>(existingClusterNodes.Count + 1);

            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
                updatedClusterNodes[existingClusterNode.Value.Id] = existingClusterNode.Value;

            if (!updatedClusterNodes.TryAdd(secondaryNode.Id, secondaryNode))
                throw new DnsServerException("Failed to add Secondary node: node ID already exists in the Cluster. Please try again.");

            if (updatedClusterNodes.Count > 255)
                throw new DnsServerException("Failed to add Secondary node: a maximum of 255 nodes are supported by the Cluster.");

            IReadOnlyDictionary<int, ClusterNode> originalValue = Interlocked.CompareExchange(ref _clusterNodes, updatedClusterNodes, existingClusterNodes);
            if (!ReferenceEquals(originalValue, existingClusterNodes))
                throw new DnsServerException("Failed to add Secondary node: please try again.");

            secondaryNode.InitializeHeartbeatTimer();

            //update cluster zone and save zone file
            AddClusterPrimaryZoneRecordsFor(secondaryNode, secondaryNodeCertificate);

            //update cluster catalog zone ACLs and save zone file
            UpdateClusterCatalogZoneOptions();

            //save all changes
            SaveConfigFile();

            //notify all secondary nodes
            TriggerNotifyAllSecondaryNodes();

            //trigger NS and SOA update for member zones
            TriggerRecordUpdateForClusterCatalogMemberZones();

            return secondaryNode;
        }

        public async Task<ClusterNode> AskSecondaryNodeToLeaveClusterAsync(int secondaryNodeId)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to ask Secondary node to leave: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to ask Secondary node to leave: only a Primary node can ask a Secondary node to leave the Cluster.");

            //find existing secondary node
            if (!_clusterNodes.TryGetValue(secondaryNodeId, out ClusterNode secondaryNode))
                throw new DnsServerException("Failed to ask Secondary node to leave: the specified node does not exist in the Cluster.");

            if (secondaryNode.Type == ClusterNodeType.Primary)
                throw new DnsServerException("Failed to ask Secondary node to leave: the specified node is the Cluster Primary node and cannot be removed.");

            //ask secondary node to leave the cluster
            await secondaryNode.AskSecondaryNodeToLeaveClusterAsync();

            return secondaryNode;
        }

        public ClusterNode DeleteSecondaryNode(int secondaryNodeId)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to delete Secondary node: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to delete Secondary node: only a Primary node can delete a Secondary node from the Cluster.");

            //find existing secondary node
            IReadOnlyDictionary<int, ClusterNode> existingClusterNodes = _clusterNodes;

            if (!existingClusterNodes.TryGetValue(secondaryNodeId, out ClusterNode secondaryNode))
                throw new DnsServerException("Failed to delete Secondary node: the specified node does not exist in the Cluster.");

            if (secondaryNode.Type == ClusterNodeType.Primary)
                throw new DnsServerException("Failed to delete Secondary node: the specified node is the Cluster Primary node and cannot be deleted.");

            //delete secondary node from cluster nodes
            Dictionary<int, ClusterNode> updatedClusterNodes = new Dictionary<int, ClusterNode>(existingClusterNodes.Count - 1);

            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
            {
                if (existingClusterNode.Key == secondaryNodeId)
                    continue;

                updatedClusterNodes[existingClusterNode.Key] = existingClusterNode.Value;
            }

            IReadOnlyDictionary<int, ClusterNode> originalValue = Interlocked.CompareExchange(ref _clusterNodes, updatedClusterNodes, existingClusterNodes);
            if (!ReferenceEquals(originalValue, existingClusterNodes))
                throw new InvalidOperationException("Failed to delete Secondary node: please try again.");

            secondaryNode.Dispose();

            //update cluster zone and save zone file
            RemoveClusterPrimaryZoneRecordsFor(secondaryNode);

            //update cluster catalog zone ACLs and save zone file
            UpdateClusterCatalogZoneOptions();

            //save all changes
            SaveConfigFile();

            //notify all secondary nodes
            TriggerNotifyAllSecondaryNodes();

            //trigger NS and SOA update for member zones
            TriggerRecordUpdateForClusterCatalogMemberZones();

            return secondaryNode;
        }

        public ClusterNode UpdateSecondaryNode(int secondaryNodeId, Uri secondaryNodeUrl, IReadOnlyList<IPAddress> secondaryNodeIpAddresses, X509Certificate2 secondaryNodeCertificate)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to update Secondary node: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to update Secondary node: only a Primary node can update a Secondary node's details in the Cluster.");

            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;

            if (!clusterNodes.TryGetValue(secondaryNodeId, out ClusterNode secondaryNode))
                throw new DnsServerException("Failed to update Secondary node: the specified node does not exist in the Cluster.");

            if (secondaryNode.Type != ClusterNodeType.Secondary)
                throw new DnsServerException("Failed to update Secondary node: the specified node to update must be a Secondary node.");

            //validate for duplicate names
            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
            {
                if (clusterNode.Key == secondaryNodeId)
                    continue; //skip self

                if (clusterNode.Value.Name.Equals(secondaryNodeUrl.Host, StringComparison.OrdinalIgnoreCase))
                    throw new DnsServerException("Failed to update Secondary node: the Secondary node's domain name already exists in the Cluster. Please try again after changing the Secondary DNS Server's domain name.");
            }

            bool secondaryNodeDomainChanged = !secondaryNode.Name.Equals(secondaryNodeUrl.Host, StringComparison.OrdinalIgnoreCase);

            //update cluster zone to remove existing records for secondary node
            RemoveClusterPrimaryZoneRecordsFor(secondaryNode);

            //update secondary node URL and IP address
            secondaryNode.UpdateNode(secondaryNodeUrl, secondaryNodeIpAddresses);

            //update cluster zone to add updated records for secondary node and save zone file
            AddClusterPrimaryZoneRecordsFor(secondaryNode, secondaryNodeCertificate);

            //update cluster catalog zone ACLs and save zone file
            UpdateClusterCatalogZoneOptions();

            //save all changes
            SaveConfigFile();

            //notify all secondary nodes
            TriggerNotifyAllSecondaryNodes();

            //trigger NS and SOA update for member zones only if secondary node domain name has changed
            if (secondaryNodeDomainChanged)
                TriggerRecordUpdateForClusterCatalogMemberZones();

            return secondaryNode;
        }

        public Task TransferConfigAsync(Stream zipStream, DateTime ifModifiedSince, IReadOnlyCollection<string> includeZones)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to transfer configuration: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to transfer configuration: only the Primary node can transfer the configuration.");

            return _dnsWebService.BackupConfigAsync(zipStream: zipStream,
                                                    authConfig: true,
                                                    clusterConfig: false,
                                                    webServiceSettings: false,
                                                    dnsSettings: true,
                                                    logSettings: false,
                                                    zones: true,
                                                    allowedZones: true,
                                                    blockedZones: true,
                                                    blockLists: true,
                                                    apps: true,
                                                    scopes: false,
                                                    stats: false,
                                                    logs: false,
                                                    isConfigTransfer: true,
                                                    ifModifiedSince: ifModifiedSince,
                                                    includeZones: includeZones);
        }

        public void UpdateClusterOptions(ushort heartbeatRefreshIntervalSeconds, ushort heartbeatRetryIntervalSeconds, ushort configRefreshIntervalSeconds, ushort configRetryIntervalSeconds)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to update Cluster options: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to update Cluster options: only the Primary node can update the Cluster options.");

            if ((heartbeatRefreshIntervalSeconds < 10) || (heartbeatRefreshIntervalSeconds > 300))
                throw new ArgumentOutOfRangeException(nameof(heartbeatRefreshIntervalSeconds));

            if ((heartbeatRetryIntervalSeconds < 10) || (heartbeatRetryIntervalSeconds > 300))
                throw new ArgumentOutOfRangeException(nameof(heartbeatRetryIntervalSeconds));

            if ((configRefreshIntervalSeconds < 30) || (configRefreshIntervalSeconds > 3600))
                throw new ArgumentOutOfRangeException(nameof(configRefreshIntervalSeconds));

            if ((configRetryIntervalSeconds < 30) || (configRetryIntervalSeconds > 3600))
                throw new ArgumentOutOfRangeException(nameof(configRetryIntervalSeconds));

            if (configRefreshIntervalSeconds <= heartbeatRefreshIntervalSeconds)
                throw new ArgumentException("Failed to update Cluster options: The config refresh interval must be greater than the heartbeat refresh interval.");

            bool changed = false;

            if (_heartbeatRefreshIntervalSeconds != heartbeatRefreshIntervalSeconds)
            {
                _heartbeatRefreshIntervalSeconds = heartbeatRefreshIntervalSeconds;
                changed = true;
            }

            if (_heartbeatRetryIntervalSeconds != heartbeatRetryIntervalSeconds)
            {
                _heartbeatRetryIntervalSeconds = heartbeatRetryIntervalSeconds;
                changed = true;
            }

            if (_configRefreshIntervalSeconds != configRefreshIntervalSeconds)
            {
                _configRefreshIntervalSeconds = configRefreshIntervalSeconds;
                changed = true;
            }

            if (_configRetryIntervalSeconds != configRetryIntervalSeconds)
            {
                _configRetryIntervalSeconds = configRetryIntervalSeconds;
                changed = true;
            }

            if (changed)
            {
                //apply new interval to all cluster nodes immediately
                UpdateHeartbeatTimerForAllClusterNodes();

                //save changes
                SaveConfigFile();

                //trigger notify to all secondary nodes
                TriggerNotifyAllSecondaryNodes();
            }
        }

        private void RemoveAllClusterPrimaryZoneNSRecords()
        {
            //remove all existing NS records
            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(_clusterDomain, _clusterDomain, DnsResourceRecordType.NS);
        }

        private void RemoveClusterPrimaryZoneRecordsFor(ClusterNode node)
        {
            //remove NS record
            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(_clusterDomain, _clusterDomain, DnsResourceRecordType.NS, new DnsNSRecordData(node.Name));

            //remove A/AAAA records
            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(_clusterDomain, node.Name, DnsResourceRecordType.A);
            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(_clusterDomain, node.Name, DnsResourceRecordType.AAAA);

            //remove PTR record
            foreach (IPAddress ipAddress in node.IPAddresses)
            {
                string ptrDomain = Zone.GetReverseZone(ipAddress, ipAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
                _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(ptrDomain, ptrDomain, DnsResourceRecordType.PTR, new DnsPTRRecordData(node.Name));
            }

            //remove TLSA DANE-EE record
            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(_clusterDomain, $"_{node.Url.Port}._tcp.{node.Name}", DnsResourceRecordType.TLSA);

            //save zone file
            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(_clusterDomain);
        }

        private void AddClusterPrimaryZoneRecordsFor(ClusterNode node, X509Certificate2 certificate)
        {
            const string recordComments = "Cluster managed record. Do not update or delete.";

            if (node.Type == ClusterNodeType.Primary)
            {
                //update SOA record
                IReadOnlyList<DnsResourceRecord> existingSoaRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(_clusterDomain, _clusterDomain, DnsResourceRecordType.SOA);
                DnsResourceRecord existingSoaRecord = existingSoaRecords[0];
                DnsSOARecordData existingSoa = existingSoaRecord.RDATA as DnsSOARecordData;

                DnsSOARecordData newSoa = new DnsSOARecordData(node.Name, existingSoa.ResponsiblePerson, existingSoa.Serial, existingSoa.Refresh, existingSoa.Retry, existingSoa.Expire, existingSoa.Minimum);
                DnsResourceRecord newSoaRecord = new DnsResourceRecord(_clusterDomain, DnsResourceRecordType.SOA, DnsClass.IN, existingSoaRecord.TTL, newSoa);

                _dnsWebService.DnsServer.AuthZoneManager.SetRecord(_clusterDomain, newSoaRecord);
            }

            //add NS record
            DnsResourceRecord nsRecord = new DnsResourceRecord(_clusterDomain, DnsResourceRecordType.NS, DnsClass.IN, 60, new DnsNSRecordData(node.Name));

            GenericRecordInfo nsRecordInfo = nsRecord.GetAuthGenericRecordInfo();
            nsRecordInfo.LastModified = DateTime.UtcNow;
            nsRecordInfo.Comments = recordComments;

            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(_clusterDomain, nsRecord);

            //set A/AAAA record
            List<DnsResourceRecord> addressRecords = new List<DnsResourceRecord>(node.IPAddresses.Count);

            foreach (IPAddress ipAddress in node.IPAddresses)
            {
                DnsResourceRecord record;

                switch (ipAddress.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        record = new DnsResourceRecord(node.Name, DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(ipAddress));
                        break;

                    case AddressFamily.InterNetworkV6:
                        record = new DnsResourceRecord(node.Name, DnsResourceRecordType.AAAA, DnsClass.IN, 60, new DnsAAAARecordData(ipAddress));
                        break;

                    default:
                        throw new InvalidOperationException();
                }

                GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();
                recordInfo.LastModified = DateTime.UtcNow;
                recordInfo.Comments = recordComments;

                addressRecords.Add(record);
            }

            _dnsWebService.DnsServer.AuthZoneManager.SetRecords(_clusterDomain, addressRecords);

            //set PTR record
            foreach (IPAddress ipAddress in node.IPAddresses)
            {
                string ptrDomain = Zone.GetReverseZone(ipAddress, ipAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);

                AuthZoneInfo reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
                if (reverseZoneInfo is not null)
                {
                    if (!reverseZoneInfo.Internal && (reverseZoneInfo.Type == AuthZoneType.Primary))
                    {
                        DnsResourceRecord ptrRecord = new DnsResourceRecord(ptrDomain, DnsResourceRecordType.PTR, DnsClass.IN, 60, new DnsPTRRecordData(node.Name));

                        GenericRecordInfo ptrRecordInfo = ptrRecord.GetAuthGenericRecordInfo();
                        ptrRecordInfo.LastModified = DateTime.UtcNow;
                        ptrRecordInfo.Comments = recordComments;

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(reverseZoneInfo.Name, ptrRecord);
                    }
                }
            }

            //set TLSA DANE-EE record
            DnsResourceRecord tlsaRecord = new DnsResourceRecord($"_{node.Url.Port}._tcp.{node.Name}", DnsResourceRecordType.TLSA, DnsClass.IN, 60, new DnsTLSARecordData(DnsTLSACertificateUsage.DANE_EE, DnsTLSASelector.SPKI, DnsTLSAMatchingType.SHA2_256, certificate));

            GenericRecordInfo tlsaRecordInfo = tlsaRecord.GetAuthGenericRecordInfo();
            tlsaRecordInfo.LastModified = DateTime.UtcNow;
            tlsaRecordInfo.Comments = recordComments;

            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(_clusterDomain, tlsaRecord);

            //save zone file
            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(_clusterDomain);
        }

        public void UpdateClusterRecordsFor(AuthZoneInfo zoneInfo)
        {
            if (zoneInfo.Type != AuthZoneType.Primary)
                throw new InvalidOperationException();

            //set NS records for cluster
            IReadOnlyList<DnsResourceRecord> existingNSRecords = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.NS);
            uint ttl;

            if (existingNSRecords.Count > 0)
                ttl = existingNSRecords[0].TTL;
            else
                ttl = _dnsWebService.DnsServer.AuthZoneManager.DefaultRecordTtl;

            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            DnsResourceRecord[] nsRecords = new DnsResourceRecord[clusterNodes.Count];
            int i = 0;

            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                nsRecords[i++] = new DnsResourceRecord(zoneInfo.Name, DnsResourceRecordType.NS, DnsClass.IN, ttl, new DnsNSRecordData(clusterNode.Value.Name));

            //set NS record
            _dnsWebService.DnsServer.AuthZoneManager.SetRecords(zoneInfo.Name, nsRecords);

            //ensure correct SOA primary name server
            IReadOnlyList<DnsResourceRecord> existingSoaRecords = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.SOA);
            if (existingSoaRecords.Count > 0)
            {
                DnsResourceRecord existingSoaRecord = existingSoaRecords[0];
                DnsSOARecordData existingSoa = existingSoaRecord.RDATA as DnsSOARecordData;

                //set SOA record
                _dnsWebService.DnsServer.AuthZoneManager.SetRecords(zoneInfo.Name, [new DnsResourceRecord(zoneInfo.Name, DnsResourceRecordType.SOA, DnsClass.IN, existingSoaRecord.TTL, new DnsSOARecordData(_dnsWebService.DnsServer.ServerDomain, existingSoa.ResponsiblePerson, existingSoa.Serial, existingSoa.Refresh, existingSoa.Retry, existingSoa.Expire, existingSoa.Minimum))]);
            }
        }

        private void TriggerRecordUpdateForClusterCatalogMemberZones()
        {
            int id = RandomNumberGenerator.GetInt32(int.MaxValue);
            _recordUpdateForMemberZonesId = id;

            ThreadPool.QueueUserWorkItem(delegate (object state)
            {
                try
                {
                    //get cluster catalog zone info
                    AuthZoneInfo clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo("cluster-catalog." + _clusterDomain);
                    if ((clusterCatalogZoneInfo is null) || (clusterCatalogZoneInfo.Type != AuthZoneType.Catalog))
                        throw new InvalidOperationException();

                    //get all member zone names for cluster catalog zone
                    IReadOnlyCollection<string> memberZoneNames = (clusterCatalogZoneInfo.ApexZone as CatalogZone).GetAllMemberZoneNames();

                    foreach (string memberZoneName in memberZoneNames)
                    {
                        if (_recordUpdateForMemberZonesId != id)
                            return; //stop current update since another update has been triggered

                        //get member zone info
                        AuthZoneInfo memberZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(memberZoneName);
                        if ((memberZoneInfo is null) || (memberZoneInfo.Type != AuthZoneType.Primary))
                            continue; //process is only for primary zones

                        //update NS and SOA records for the member zone
                        UpdateClusterRecordsFor(memberZoneInfo);

                        //save zone file
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(memberZoneName);
                    }

                    _dnsWebService.LogManager.Write("The Cluster Catalog member zones NS and SOA records were successfully updated to reflect the Cluster changes.");
                }
                catch (Exception ex)
                {
                    _dnsWebService.LogManager.Write(ex);
                }
            });
        }

        private void UpdateClusterCatalogZoneOptions()
        {
            string clusterCatalogDomain = "cluster-catalog." + _clusterDomain;

            AuthZoneInfo clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain);
            if (clusterCatalogZoneInfo is null)
                throw new InvalidOperationException();

            UpdateClusterCatalogZoneOptions(clusterCatalogZoneInfo);
        }

        private void UpdateClusterCatalogZoneOptions(AuthZoneInfo clusterCatalogZoneInfo)
        {
            //set cluster catalog zone options for Zone Transfer ACLs and notify addresses
            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;

            List<NetworkAccessControl> zoneTransferACL = new List<NetworkAccessControl>(clusterNodes.Count * 2);
            List<IPAddress> notifyNameServers = new List<IPAddress>(clusterNodes.Count * 2);

            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
            {
                if (clusterNode.Value.Type == ClusterNodeType.Primary)
                    continue;

                foreach (IPAddress ipAddress in clusterNode.Value.IPAddresses)
                    zoneTransferACL.Add(new NetworkAccessControl(ipAddress, 32));

                notifyNameServers.AddRange(clusterNode.Value.IPAddresses);
            }

            clusterCatalogZoneInfo.ZoneTransferNetworkACL = zoneTransferACL;
            clusterCatalogZoneInfo.NotifyNameServers = notifyNameServers;

            clusterCatalogZoneInfo.ZoneTransfer = AuthZoneTransfer.UseSpecifiedNetworkACL;
            clusterCatalogZoneInfo.Notify = AuthZoneNotify.SpecifiedNameServers;

            //set cluster catalog zone options for zone transfer TSIG key names
            IReadOnlySet<string> existingKeyNames = clusterCatalogZoneInfo.ZoneTransferTsigKeyNames;
            if (existingKeyNames is null)
            {
                HashSet<string> updatedKeyNames = [clusterCatalogZoneInfo.Name];

                clusterCatalogZoneInfo.ZoneTransferTsigKeyNames = updatedKeyNames;
            }
            else if (!existingKeyNames.Contains(clusterCatalogZoneInfo.Name))
            {
                HashSet<string> updatedKeyNames = [.. existingKeyNames, clusterCatalogZoneInfo.Name];

                clusterCatalogZoneInfo.ZoneTransferTsigKeyNames = updatedKeyNames;
            }

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(clusterCatalogZoneInfo.Name);
        }

        public void TriggerNotifyAllSecondaryNodesIfPrimarySelfNode()
        {
            if (GetSelfNode().Type == ClusterNodeType.Primary)
                TriggerNotifyAllSecondaryNodes();
        }

        public void TriggerNotifyAllSecondaryNodes(int notifyInterval = NOTIFY_ALL_SECONDARY_NODES_TIMER_INTERVAL)
        {
            if (_notifyAllSecondaryNodesTimerTriggered)
                return;

            _notifyAllSecondaryNodesTimer.Change(notifyInterval, Timeout.Infinite);
            _notifyAllSecondaryNodesTimerTriggered = true;
        }

        private async void NotifyAllSecondaryNodesTimerCallbackAsync(object state)
        {
            try
            {
                IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
                ClusterNode primaryNode = null;

                foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                {
                    if (clusterNode.Value.Type == ClusterNodeType.Primary)
                    {
                        primaryNode = clusterNode.Value;
                        break;
                    }
                }

                if ((primaryNode is null) || (primaryNode.State != ClusterNodeState.Self))
                    throw new InvalidOperationException();

                List<Task> tasks = new List<Task>(clusterNodes.Count);

                foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                {
                    if (clusterNode.Value.Type == ClusterNodeType.Primary)
                        continue; //skip primary cluster node

                    tasks.Add(clusterNode.Value.NotifySecondaryNodeAsync(primaryNode));
                }

                await Task.WhenAll(tasks); //notify node call does error logging
            }
            catch (Exception ex)
            {
                _dnsWebService.LogManager.Write(ex);
            }
            finally
            {
                _notifyAllSecondaryNodesTimerTriggered = false;
            }
        }

        #endregion

        #region secondary node

        public async Task InitializeAndJoinClusterAsync(IReadOnlyList<IPAddress> secondaryNodeIpAddresses, Uri primaryNodeUrl, string primaryNodeUsername, string primaryNodePassword, string primaryNodeTotp = null, IReadOnlyList<IPAddress> primaryNodeIpAddresses = null, bool ignoreCertificateErrors = false, CancellationToken cancellationToken = default)
        {
            if (ClusterInitialized)
                throw new DnsServerException("Failed to join Cluster: the Cluster is already initialized.");

            if (!_dnsWebService.IsWebServiceTlsEnabled)
                throw new InvalidOperationException();

            if (primaryNodeIpAddresses is null)
            {
                try
                {
                    IReadOnlyList<IPAddress> ipAddresses = await DnsClient.ResolveIPAsync(_dnsWebService.DnsServer, primaryNodeUrl.Host, _dnsWebService.DnsServer.PreferIPv6, cancellationToken);
                    if (ipAddresses.Count < 1)
                        throw new DnsServerException($"The domain name '{primaryNodeUrl.Host}' does not have an A/AAAA record configured.");

                    primaryNodeIpAddresses = ipAddresses;
                }
                catch (Exception ex)
                {
                    throw new DnsServerException($"Failed to join Cluster: the Primary node domain name '{primaryNodeUrl.Host}' could not be resolved to an IP address. Please specify the Primary node IP address manually.", ex);
                }
            }

            //login to primary node API
            using HttpApiClient primaryNodeApiClient = new HttpApiClient(primaryNodeUrl, _dnsWebService.DnsServer.Proxy, _dnsWebService.DnsServer.PreferIPv6, ignoreCertificateErrors, new InternalDnsClient(_dnsWebService.DnsServer, primaryNodeIpAddresses));

            try
            {
                _ = await primaryNodeApiClient.LoginAsync(primaryNodeUsername, primaryNodePassword, primaryNodeTotp, false, cancellationToken);
            }
            catch (TwoFactorAuthRequiredHttpApiClientException ex)
            {
                throw new TwoFactorAuthRequiredWebServiceException("Failed to join Cluster: two-factor authentication is required by the Primary node user account.", ex);
            }

            try
            {
                //get cluster info
                ClusterInfo primaryNodeClusterInfo = await primaryNodeApiClient.GetClusterStateAsync(cancellationToken: cancellationToken);

                //do validations
                if (!primaryNodeClusterInfo.ClusterInitialized)
                    throw new DnsServerException("Failed to join Cluster: the Primary node does not have a Cluster initialized.");

                string clusterCatalogDomain = "cluster-catalog." + primaryNodeClusterInfo.ClusterDomain;

                if (_dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain) is not null)
                    throw new DnsServerException($"Failed to join Cluster: the zone '{clusterCatalogDomain}' already exists. Please delete the '{clusterCatalogDomain}' zone and try again.");

                if (_dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(primaryNodeClusterInfo.ClusterDomain) is not null)
                    throw new DnsServerException($"Failed to join Cluster: the zone '{primaryNodeClusterInfo.ClusterDomain}' already exists. Please delete the '{primaryNodeClusterInfo.ClusterDomain}' zone and try again.");

                //create self node
                string serverDomain = _dnsWebService.DnsServer.ServerDomain;
                if (!serverDomain.EndsWith("." + primaryNodeClusterInfo.ClusterDomain, StringComparison.OrdinalIgnoreCase))
                {
                    int x = serverDomain.IndexOf('.');
                    if (x < 0)
                        serverDomain = serverDomain + "." + primaryNodeClusterInfo.ClusterDomain;
                    else
                        serverDomain = string.Concat(serverDomain.AsSpan(0, x), ".", primaryNodeClusterInfo.ClusterDomain);
                }

                Uri secondaryNodeUrl = new Uri($"https://{serverDomain}:{_dnsWebService.WebServiceTlsPort}/");

                ClusterNode selfSecondaryNode = new ClusterNode(this, RandomNumberGenerator.GetInt32(int.MaxValue), secondaryNodeUrl, secondaryNodeIpAddresses, ClusterNodeType.Secondary, ClusterNodeState.Self);

                //join cluster
                primaryNodeClusterInfo = await primaryNodeApiClient.JoinClusterAsync(selfSecondaryNode.Id, secondaryNodeUrl, secondaryNodeIpAddresses, _dnsWebService.WebServiceTlsCertificate, cancellationToken);

                //initialize cluster
                Dictionary<int, ClusterNode> clusterNodes = new Dictionary<int, ClusterNode>(primaryNodeClusterInfo.ClusterNodes.Count + 1);

                clusterNodes[selfSecondaryNode.Id] = selfSecondaryNode;

                foreach (ClusterInfo.ClusterNodeInfo nodeInfo in primaryNodeClusterInfo.ClusterNodes)
                {
                    if (nodeInfo.Id == selfSecondaryNode.Id)
                        continue; //skip self node

                    ClusterNode node = new ClusterNode(this, nodeInfo);
                    clusterNodes[node.Id] = node;
                }

                DisposeAllNodes(); //dispose existing nodes, if any

                _clusterNodes = clusterNodes;

                _clusterDomain = primaryNodeClusterInfo.ClusterDomain;
                _heartbeatRefreshIntervalSeconds = primaryNodeClusterInfo.HeartbeatRefreshIntervalSeconds;
                _heartbeatRetryIntervalSeconds = primaryNodeClusterInfo.HeartbeatRetryIntervalSeconds;
                _configRefreshIntervalSeconds = primaryNodeClusterInfo.ConfigRefreshIntervalSeconds;
                _configRetryIntervalSeconds = primaryNodeClusterInfo.ConfigRetryIntervalSeconds;

                try
                {
                    //sync entire config from primary node first to get TSIG keys for secondary catalog zone transfer
                    _configLastSynced = DateTime.UnixEpoch; //reset last sync time to ensure full sync
                    await SyncConfigFromAsync(primaryNodeApiClient, cancellationToken: cancellationToken);

                    //create cluster secondary catalog zone
                    AuthZoneInfo clusterSecondaryCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreateSecondaryCatalogZone(clusterCatalogDomain, primaryNodeIpAddresses.Convert(delegate (IPAddress ipAddress) { return new NameServerAddress(ipAddress); }), DnsTransportProtocol.Tcp, clusterCatalogDomain);
                    if (clusterSecondaryCatalogZoneInfo is null)
                        throw new DnsServerException($"Failed to join Cluster: the zone '{clusterCatalogDomain}' already exists. Please delete the '{clusterCatalogDomain}' zone and try again.");

                    //set cluster secondary catalog zone permissions
                    _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, clusterSecondaryCatalogZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, clusterSecondaryCatalogZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.View);
                }
                catch
                {
                    try
                    {
                        await primaryNodeApiClient.DeleteSecondaryNodeAsync(selfSecondaryNode.Id, cancellationToken);
                    }
                    catch
                    { }

                    DeleteAllClusterConfig();
                    throw;
                }

                //initialize heartbeat timer for all nodes here since config sync and zone transfers needs to occur first for DANE validation to work
                InitializeHeartbeatTimerFor(clusterNodes);

                //start config refresh timer to refresh as per config refresh interval as config was just synced
                UpdateConfigRefreshTimer(_configRefreshIntervalSeconds * 1000);

                //finalize
                _dnsWebService.DnsServer.ServerDomain = selfSecondaryNode.Name;

                //save all changes
                _dnsWebService.DnsServer.SaveConfigFile();
                _dnsWebService.AuthManager.SaveConfigFile();
                SaveConfigFile();
            }
            finally
            {
                try
                {
                    //logout from primary node
                    await primaryNodeApiClient.LogoutAsync(cancellationToken);
                }
                catch
                { }
            }
        }

        public async Task LeaveClusterAsync(bool forceLeave)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to leave Cluster: the Cluster is not initialized.");

            ClusterNode primaryNode = GetPrimaryNode();

            if (primaryNode.State == ClusterNodeState.Self)
                throw new DnsServerException("Failed to leave Cluster: a Primary self node cannot leave the Cluster.");

            ClusterNode secondaryNode = GetSelfNode();

            if (secondaryNode.Type != ClusterNodeType.Secondary)
                throw new DnsServerException("Failed to leave Cluster: only Secondary nodes can leave the Cluster.");

            if (!forceLeave)
            {
                //delete self node from cluster on primary node
                await primaryNode.DeleteSecondaryNodeAsync(secondaryNode);
            }

            //delete all cluster config
            DeleteAllClusterConfig();
        }

        public async Task<ClusterNode> UpdatePrimaryNodeAsync(Uri primaryNodeUrl, IReadOnlyList<IPAddress> primaryNodeIpAddresses = null, int primaryNodeId = -1, CancellationToken cancellationToken = default)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to update Primary node: the Cluster is not initialized.");

            if (primaryNodeIpAddresses is null)
            {
                try
                {
                    IReadOnlyList<IPAddress> ipAddresses = await DnsClient.ResolveIPAsync(_dnsWebService.DnsServer, primaryNodeUrl.Host, _dnsWebService.DnsServer.PreferIPv6, cancellationToken);
                    if (ipAddresses.Count < 1)
                        throw new DnsServerException($"The domain name '{primaryNodeUrl.Host}' does not have an A/AAAA record configured.");

                    primaryNodeIpAddresses = ipAddresses;
                }
                catch (Exception ex)
                {
                    throw new DnsServerException($"Failed to update Primary node: the Primary node domain name '{primaryNodeUrl.Host}' could not be resolved to an IP address.", ex);
                }
            }

            ClusterNode primaryNode;

            if (primaryNodeId < 0)
                primaryNode = GetPrimaryNode();
            else if (!_clusterNodes.TryGetValue(primaryNodeId, out primaryNode))
                throw new DnsServerException("Failed to update Primary node: the specified Primary node ID does not exists in the Cluster.");

            if (primaryNode.State == ClusterNodeState.Self)
                throw new DnsServerException("Failed to update Primary node: the specified node is the self node and cannot be updated this way.");

            if (primaryNode.Type == ClusterNodeType.Secondary)
            {
                //secondary node was promoted to primary node
                ClusterNode formerPrimaryNode = GetPrimaryNode();

                //dispose former primary node immediately to stop heartbeat
                formerPrimaryNode.Dispose();

                //remove former primary node from cluster nodes
                IReadOnlyDictionary<int, ClusterNode> existingClusterNodes = _clusterNodes;
                Dictionary<int, ClusterNode> updatedClusterNodes = new Dictionary<int, ClusterNode>(existingClusterNodes.Count - 1);

                foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
                {
                    if (existingClusterNode.Key == formerPrimaryNode.Id)
                        continue;

                    updatedClusterNodes[existingClusterNode.Key] = existingClusterNode.Value;
                }

                //update cluster nodes
                _clusterNodes = updatedClusterNodes;

                //promote secondary node to primary immediately
                primaryNode.PromoteToPrimaryNode();

                //ensure to save changes
                SaveConfigFile();
            }

            //validate for duplicate names
            foreach (KeyValuePair<int, ClusterNode> clusterNode in _clusterNodes)
            {
                if (clusterNode.Key == primaryNode.Id)
                    continue; //skip self

                if (clusterNode.Value.Name.Equals(primaryNodeUrl.Host, StringComparison.OrdinalIgnoreCase))
                    throw new DnsServerException("Failed to update Primary node: the Primary node's domain name already exists in the Cluster. Please try again after changing the Primary DNS Server's domain name.");
            }

            //get cluster secondary catalog zone
            string clusterCatalogDomain = "cluster-catalog." + _clusterDomain;

            AuthZoneInfo clusterSecondaryCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain);
            if (clusterSecondaryCatalogZoneInfo is null)
                throw new DnsServerException($"Failed to update Primary node: the Cluster Secondary Catalog zone '{clusterCatalogDomain}' does not exists.");

            //update primary node
            primaryNode.UpdateNode(primaryNodeUrl, primaryNodeIpAddresses);

            //update cluster catalog zone's primary name server
            clusterSecondaryCatalogZoneInfo.PrimaryNameServerAddresses = primaryNodeIpAddresses.Convert(delegate (IPAddress ipAddress) { return new NameServerAddress(ipAddress); });

            //save all changes
            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(clusterSecondaryCatalogZoneInfo.Name);
            SaveConfigFile();

            //trigger config and zone refresh
            TriggerRefreshForConfig(CONFIG_REFRESH_TIMER_INTERVAL);

            return primaryNode;
        }

        public void TriggerRefreshForConfig(IReadOnlyCollection<string> configRefreshIncludeZones = null)
        {
            //do validation
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to refresh configuration: the Cluster is not initialized.");

            ClusterNode primaryNode = GetPrimaryNode();

            if (primaryNode.State == ClusterNodeState.Self)
                throw new DnsServerException("Failed to refresh configuration: only Secondary nodes can sync configuration from Primary nodes.");

            TriggerRefreshForConfig(CONFIG_REFRESH_TIMER_INTERVAL, configRefreshIncludeZones);
        }

        public void TriggerResyncForConfig()
        {
            //do validation
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to resync configuration: the Cluster is not initialized.");

            ClusterNode primaryNode = GetPrimaryNode();

            if (primaryNode.State == ClusterNodeState.Self)
                throw new DnsServerException("Failed to resync configuration: only Secondary nodes can sync configuration from Primary nodes.");

            _configLastSynced = DateTime.UnixEpoch; //to ensure complete config resync

            //trigger immediate config refresh
            TriggerRefreshForConfig(0);
        }

        private void TriggerRefreshForConfig(int refreshInterval, IReadOnlyCollection<string> configRefreshIncludeZones = null)
        {
            _configRefreshLock.Wait();
            try
            {
                if (configRefreshIncludeZones is not null)
                {
                    if (_configRefreshIncludeZones is null)
                        _configRefreshIncludeZones = configRefreshIncludeZones;
                    else
                        _configRefreshIncludeZones = [.. _configRefreshIncludeZones, .. configRefreshIncludeZones];
                }

                if (_configRefreshTimerTriggered)
                    return;

                _configRefreshTimer.Change(refreshInterval, Timeout.Infinite);
                _configRefreshTimerTriggered = true;
            }
            finally
            {
                _configRefreshLock.Release();
            }
        }

        private async void ConfigRefreshTimerCallbackAsync(object state)
        {
            bool success = false;

            await _configRefreshLock.WaitAsync();
            try
            {
                ClusterNode primaryNode = GetPrimaryNode();

                if (primaryNode.State == ClusterNodeState.Self)
                    throw new InvalidOperationException();

                //update cluster options
                UpdateClusterFromPrimaryNode(await primaryNode.GetClusterStateAsync());

                //sync config from primary node
                await primaryNode.SyncConfigAsync(_configRefreshIncludeZones);

                success = true;
            }
            catch (Exception ex)
            {
                _dnsWebService.LogManager.Write("Failed to sync server configuration from the Primary node.\r\n" + ex.ToString());
            }
            finally
            {
                if (success)
                {
                    _configRefreshTimerTriggered = false;
                    _configRefreshIncludeZones = null;
                }

                try
                {
                    _configRefreshTimer.Change(success ? _configRefreshIntervalSeconds * 1000 : _configRetryIntervalSeconds * 1000, Timeout.Infinite);
                }
                catch (ObjectDisposedException)
                { }

                try
                {
                    _configRefreshLock.Release();
                }
                catch (ObjectDisposedException)
                { }
            }
        }

        public async Task SyncConfigFromAsync(HttpApiClient primaryNodeApiClient, IReadOnlyCollection<string> includeZones = null, CancellationToken cancellationToken = default)
        {
            string tmpFile = Path.GetTempFileName();
            try
            {
                await using (FileStream configZipStream = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //get config from primary node
                    (Stream, DateTime) response = await primaryNodeApiClient.TransferConfigFromPrimaryNodeAsync(_configLastSynced, includeZones, cancellationToken);

                    await using (Stream stream = response.Item1)
                    {
                        await stream.CopyToAsync(configZipStream, cancellationToken);
                    }

                    //dynamically load config
                    configZipStream.Position = 0;

                    await _dnsWebService.RestoreConfigAsync(zipStream: configZipStream,
                                                            authConfig: true,
                                                            clusterConfig: false,
                                                            webServiceSettings: false,
                                                            dnsSettings: true,
                                                            logSettings: false,
                                                            zones: true,
                                                            allowedZones: true,
                                                            blockedZones: true,
                                                            blockLists: true,
                                                            apps: true,
                                                            scopes: false,
                                                            stats: false,
                                                            logs: false,
                                                            deleteExistingFiles: false,
                                                            isConfigTransfer: true);

                    _configLastSynced = response.Item2;

                    //save config
                    SaveConfigFile();
                }

                _dnsWebService.LogManager.Write("Server configuration was synced from the Primary node successfully.");
            }
            finally
            {
                try
                {
                    File.Delete(tmpFile);
                }
                catch (Exception ex)
                {
                    _dnsWebService.LogManager.Write(ex);
                }
            }
        }

        private void TriggerClusterUpdateForSecondaryNodeChanges()
        {
            if (_clusterUpdateForSecondaryNodeChangesTimerTriggered)
                return;

            _clusterUpdateForSecondaryNodeChangesTimer.Change(CLUSTER_UPDATE_FOR_SECONDARY_NODE_CHANGES_TIMER_INTERVAL, Timeout.Infinite);
            _clusterUpdateForSecondaryNodeChangesTimerTriggered = true;
        }

        private async void ClusterUpdateForSecondaryNodeChangesTimerCallbackAsync(object state)
        {
            try
            {
                ClusterNode primaryNode = GetPrimaryNode();

                if (primaryNode.State == ClusterNodeState.Self)
                    throw new InvalidOperationException();

                ClusterNode secondaryNode = GetSelfNode();

                if (secondaryNode.Type != ClusterNodeType.Secondary)
                    throw new InvalidOperationException();

                UpdateClusterFromPrimaryNode(await primaryNode.UpdateSecondaryNodeAsync(secondaryNode, _dnsWebService.WebServiceTlsCertificate));

                _dnsWebService.LogManager.Write("DNS Server updated this Secondary node's details on the Primary node successfully.");
            }
            catch (Exception ex)
            {
                _dnsWebService.LogManager.Write("DNS Server failed to update this Secondary node's details on the Primary node." + ex.ToString());
            }
            finally
            {
                _clusterUpdateForSecondaryNodeChangesTimerTriggered = false;
            }
        }

        public void UpdateClusterFromPrimaryNode(ClusterInfo primaryNodeClusterInfo)
        {
            IReadOnlyDictionary<int, ClusterNode> existingClusterNodes = _clusterNodes;

            //validation
            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
            {
                if (existingClusterNode.Value.Type == ClusterNodeType.Primary)
                {
                    if (existingClusterNode.Value.State == ClusterNodeState.Self)
                        throw new InvalidOperationException(); //this is a self primary node itself

                    break;
                }
            }

            List<ClusterNode> clusterNodesToAdd = new List<ClusterNode>();
            List<ClusterNode> clusterNodesToRemove = new List<ClusterNode>();

            foreach (ClusterInfo.ClusterNodeInfo clusterNodeInfo in primaryNodeClusterInfo.ClusterNodes)
            {
                if (existingClusterNodes.TryGetValue(clusterNodeInfo.Id, out ClusterNode existingClusterNode))
                {
                    if (existingClusterNode.State == ClusterNodeState.Self)
                        continue; //skip self node

                    //update existing cluster node
                    existingClusterNode.UpdateNode(clusterNodeInfo);
                }
                else
                {
                    //add new cluster node
                    clusterNodesToAdd.Add(new ClusterNode(this, clusterNodeInfo));
                }
            }

            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
            {
                bool found = false;

                foreach (ClusterInfo.ClusterNodeInfo clusterNodeInfo in primaryNodeClusterInfo.ClusterNodes)
                {
                    if (existingClusterNode.Key == clusterNodeInfo.Id)
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    clusterNodesToRemove.Add(existingClusterNode.Value);
            }

            bool saveConfig = false;

            if ((clusterNodesToAdd.Count > 0) || (clusterNodesToRemove.Count > 0))
            {
                Dictionary<int, ClusterNode> updatedClusterNodes = new Dictionary<int, ClusterNode>(existingClusterNodes.Count + clusterNodesToAdd.Count - clusterNodesToRemove.Count);

                foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
                {
                    if (clusterNodesToRemove.Contains(existingClusterNode.Value))
                        continue; //skip removed node

                    updatedClusterNodes[existingClusterNode.Key] = existingClusterNode.Value;
                }

                foreach (ClusterNode clusterNode in clusterNodesToAdd)
                    updatedClusterNodes[clusterNode.Id] = clusterNode;

                //verify if node is part of the cluster
                {
                    bool foundSelfNode = false;

                    foreach (KeyValuePair<int, ClusterNode> clusterNode in updatedClusterNodes)
                    {
                        if (clusterNode.Value.State == ClusterNodeState.Self)
                        {
                            foundSelfNode = true;
                            break;
                        }
                    }

                    if (!foundSelfNode)
                    {
                        //this node is not part of the cluster anymore
                        //delete all cluster config
                        DeleteAllClusterConfig();

                        _dnsWebService.LogManager.Write("Failed to sync Cluster config: this Secondary node is not part of the Cluster anymore.");
                        return;
                    }
                }

                //dispose all removed nodes
                foreach (ClusterNode removedNodes in clusterNodesToRemove)
                    removedNodes.Dispose();

                _clusterNodes = updatedClusterNodes;

                InitializeHeartbeatTimerFor(updatedClusterNodes);
                saveConfig = true;
            }

            if (primaryNodeClusterInfo.HeartbeatRefreshIntervalSeconds != _heartbeatRefreshIntervalSeconds)
            {
                _heartbeatRefreshIntervalSeconds = primaryNodeClusterInfo.HeartbeatRefreshIntervalSeconds;
                UpdateHeartbeatTimerForAllClusterNodes(); //apply new interval to all cluster nodes immediately
                saveConfig = true;
            }

            if (primaryNodeClusterInfo.HeartbeatRetryIntervalSeconds != _heartbeatRetryIntervalSeconds)
            {
                _heartbeatRetryIntervalSeconds = primaryNodeClusterInfo.HeartbeatRetryIntervalSeconds;
                saveConfig = true;
            }

            if (primaryNodeClusterInfo.ConfigRefreshIntervalSeconds != _configRefreshIntervalSeconds)
            {
                _configRefreshIntervalSeconds = primaryNodeClusterInfo.ConfigRefreshIntervalSeconds;
                UpdateConfigRefreshTimer(_configRefreshIntervalSeconds * 1000); //apply new interval to config refresh timer immediately
                saveConfig = true;
            }

            if (primaryNodeClusterInfo.ConfigRetryIntervalSeconds != _configRetryIntervalSeconds)
            {
                _configRetryIntervalSeconds = primaryNodeClusterInfo.ConfigRetryIntervalSeconds;
                saveConfig = true;
            }

            //save changes
            if (saveConfig)
                SaveConfigFile();
        }

        public async Task PromoteToPrimaryNodeAsync(bool forceDeletePrimary)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to promote to Primary node: the Cluster is not initialized.");

            //do validation
            ClusterNode selfNewPrimaryNode = GetSelfNode();
            if (selfNewPrimaryNode.Type != ClusterNodeType.Secondary)
                throw new DnsServerException("Failed to promote to Primary node: only Secondary nodes can be promoted to Primary nodes.");

            string clusterCatalogDomain = "cluster-catalog." + _clusterDomain;

            AuthZoneInfo clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain);
            if (clusterCatalogZoneInfo is null)
                throw new DnsServerException("Failed to promote to Primary node: the Cluster Secondary Catalog zone does not exist.");

            AuthZoneInfo clusterZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(_clusterDomain);
            if (clusterZoneInfo is null)
                throw new DnsServerException("Failed to promote to Primary node: the Cluster Secondary zone does not exist.");

            //stop cluster config refresh timer
            StopConfigRefreshTimer();

            //resync config and delete current primary node from the cluster immediately
            ClusterNode existingPrimaryNode = GetPrimaryNode();

            if (!forceDeletePrimary)
            {
                //resync complete config from current primary node to ensure all data is synced
                _configLastSynced = DateTime.UnixEpoch; //to ensure complete config resync
                await existingPrimaryNode.SyncConfigAsync();

                //delete current cluster primary node
                await existingPrimaryNode.DeleteClusterAsync(true);
            }

            //dispose primary node immediately to stop heartbeat
            existingPrimaryNode.Dispose();

            //remove primary node from cluster nodes
            IReadOnlyDictionary<int, ClusterNode> existingClusterNodes = _clusterNodes;
            Dictionary<int, ClusterNode> updatedClusterNodes = new Dictionary<int, ClusterNode>(existingClusterNodes.Count - 1);

            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
            {
                if (existingClusterNode.Key == existingPrimaryNode.Id)
                    continue;

                updatedClusterNodes[existingClusterNode.Key] = existingClusterNode.Value;
            }

            //update cluster nodes
            _clusterNodes = updatedClusterNodes;

            //promote self node to primary immediately
            selfNewPrimaryNode.PromoteToPrimaryNode();

            //convert cluster secondary catalog zone to catalog zone along with all its member zones
            if (clusterCatalogZoneInfo.Type == AuthZoneType.SecondaryCatalog)
                clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.ConvertZoneTypeTo(clusterCatalogZoneInfo.Name, AuthZoneType.Catalog);

            //get converted primary cluster zone info
            clusterZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(_clusterDomain);
            if (clusterZoneInfo is null)
                throw new DnsServerException("Failed to promote to Primary node: the Cluster Primary zone does not exist.");

            //sign cluster zone in case when DNSSEC private keys were not available during ConvertZoneTypeTo() operation
            if (clusterZoneInfo.ApexZone.DnssecStatus == AuthZoneDnssecStatus.Unsigned)
            {
                DnssecPrivateKey kskPrivateKey = DnssecPrivateKey.Create(DnssecAlgorithm.ECDSAP256SHA256, DnssecPrivateKeyType.KeySigningKey);
                DnssecPrivateKey zskPrivateKey = DnssecPrivateKey.Create(DnssecAlgorithm.ECDSAP256SHA256, DnssecPrivateKeyType.ZoneSigningKey);
                zskPrivateKey.RolloverDays = 90;

                _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZone(clusterZoneInfo.Name, kskPrivateKey, zskPrivateKey, 3600, false);
            }

            //remove old primary node records from cluster primary zone and save zone file
            if (existingPrimaryNode is not null)
                RemoveClusterPrimaryZoneRecordsFor(existingPrimaryNode);

            //update cluster primary zone for new primary node
            AddClusterPrimaryZoneRecordsFor(selfNewPrimaryNode, _dnsWebService.WebServiceTlsCertificate);

            //update cluster catalog zone ACLs, TSIG key name and save zone file
            UpdateClusterCatalogZoneOptions(clusterCatalogZoneInfo);

            //save all changes
            SaveConfigFile();

            //notify all secondary nodes as a primary node immediately
            TriggerNotifyAllSecondaryNodes(0);

            //trigger NS and SOA update for member zones
            TriggerRecordUpdateForClusterCatalogMemberZones();
        }

        #endregion

        #region public

        public ClusterNode GetPrimaryNode()
        {
            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            if (clusterNodes is null)
                throw new InvalidOperationException();

            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
            {
                if (clusterNode.Value.Type == ClusterNodeType.Primary)
                    return clusterNode.Value;
            }

            throw new InvalidOperationException();
        }

        public ClusterNode GetSelfNode()
        {
            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            if (clusterNodes is null)
                throw new InvalidOperationException();

            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
            {
                if (clusterNode.Value.State == ClusterNodeState.Self)
                    return clusterNode.Value;
            }

            throw new InvalidOperationException();
        }

        public bool TryGetClusterNode(string nodeName, out ClusterNode clusterNode)
        {
            foreach (KeyValuePair<int, ClusterNode> node in _clusterNodes)
            {
                if (node.Value.Name.Equals(nodeName, StringComparison.OrdinalIgnoreCase))
                {
                    clusterNode = node.Value;
                    return true;
                }
            }

            clusterNode = null;
            return false;
        }

        public bool IsClusterPrimaryZone(string zoneName)
        {
            return (zoneName is not null) && zoneName.Equals(_clusterDomain, StringComparison.OrdinalIgnoreCase);
        }

        public bool IsClusterCatalogZone(string zoneName)
        {
            return (zoneName is not null) && zoneName.Equals("cluster-catalog." + _clusterDomain, StringComparison.OrdinalIgnoreCase);
        }

        public ClusterNode UpdateSelfNodeIPAddresses(IReadOnlyList<IPAddress> ipAddresses)
        {
            ClusterNode selfNode = GetSelfNode();

            switch (selfNode.Type)
            {
                case ClusterNodeType.Primary:
                    //update cluster zone to remove current self node records
                    RemoveClusterPrimaryZoneRecordsFor(selfNode);

                    //update self node
                    selfNode.UpdateSelfNodeIPAddresses(ipAddresses);

                    //update cluster zone to add updated self node records
                    AddClusterPrimaryZoneRecordsFor(selfNode, _dnsWebService.WebServiceTlsCertificate);

                    //update cluster catalog zone ACLs and save zone file
                    UpdateClusterCatalogZoneOptions();

                    //save all changes
                    SaveConfigFile();

                    //notify all secondary nodes immediately
                    TriggerNotifyAllSecondaryNodes(0);
                    break;

                case ClusterNodeType.Secondary:
                    //update self node
                    selfNode.UpdateSelfNodeIPAddresses(ipAddresses);

                    //save all changes
                    SaveConfigFile();

                    //trigger cluster node update on primary node
                    TriggerClusterUpdateForSecondaryNodeChanges();
                    break;
            }

            return selfNode;
        }

        public void UpdateSelfNodeUrlAndCertificate()
        {
            ClusterNode selfNode = GetSelfNode();

            //validation
            foreach (KeyValuePair<int, ClusterNode> clusterNode in _clusterNodes)
            {
                if (clusterNode.Key == selfNode.Id)
                    continue; //skip self

                if (clusterNode.Value.Name.Equals(_dnsWebService.DnsServer.ServerDomain, StringComparison.OrdinalIgnoreCase))
                    throw new DnsServerException("Failed to update self node URL: the node's domain name already exists in the Cluster. Please try again after changing the DNS Server's domain name.");
            }

            switch (selfNode.Type)
            {
                case ClusterNodeType.Primary:
                    //update cluster zone to remove current self node records
                    RemoveClusterPrimaryZoneRecordsFor(selfNode);

                    //update self node
                    selfNode.UpdateSelfNodeUrl();

                    //update cluster zone to add updated self node records
                    AddClusterPrimaryZoneRecordsFor(selfNode, _dnsWebService.WebServiceTlsCertificate);

                    //save all changes
                    SaveConfigFile();

                    _dnsWebService.LogManager.Write("Primary node '" + selfNode.ToString() + "' URL was updated successfully.");

                    //notify all secondary nodes
                    TriggerNotifyAllSecondaryNodes();
                    break;

                case ClusterNodeType.Secondary:
                    //update self node
                    selfNode.UpdateSelfNodeUrl();

                    //save all changes
                    SaveConfigFile();

                    _dnsWebService.LogManager.Write("Secondary node '" + selfNode.ToString() + "' URL was updated successfully.");

                    //trigger cluster node update on primary node
                    TriggerClusterUpdateForSecondaryNodeChanges();
                    break;
            }
        }

        #endregion

        #region properties

        public DnsWebService DnsWebService
        { get { return _dnsWebService; } }

        public bool ClusterInitialized
        {
            get
            {
                IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;

                return (clusterNodes is not null) && (clusterNodes.Count > 0);
            }
        }

        public string ClusterDomain
        { get { return _clusterDomain; } }

        public ushort HeartbeatRefreshIntervalSeconds
        { get { return _heartbeatRefreshIntervalSeconds; } }

        public ushort HeartBeatRetryIntervalSeconds
        { get { return _heartbeatRetryIntervalSeconds; } }

        public ushort ConfigRefreshIntervalSeconds
        { get { return _configRefreshIntervalSeconds; } }

        public ushort ConfigRetryIntervalSeconds
        { get { return _configRetryIntervalSeconds; } }

        public DateTime ConfigLastSynced
        { get { return _configLastSynced; } }

        public IReadOnlyDictionary<int, ClusterNode> ClusterNodes
        { get { return _clusterNodes; } }

        #endregion
    }
}
