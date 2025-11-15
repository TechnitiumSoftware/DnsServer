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
using DnsServerCore.Dhcp;
using DnsServerCore.Dns;
using DnsServerCore.Dns.Applications;
using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.Zones;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ClientConnection;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore
{
    public sealed partial class DnsWebService : IAsyncDisposable, IDisposable
    {
        #region variables

        readonly static char[] commaSeparator = new char[] { ',' };

        readonly Version _currentVersion;
        readonly DateTime _uptimestamp = DateTime.UtcNow;
        readonly string _appFolder;
        readonly string _configFolder;

        readonly LogManager _log;
        readonly AuthManager _authManager;

        readonly WebServiceApi _api;
        readonly WebServiceDashboardApi _dashboardApi;
        readonly WebServiceZonesApi _zonesApi;
        readonly WebServiceOtherZonesApi _otherZonesApi;
        readonly WebServiceAppsApi _appsApi;
        readonly WebServiceSettingsApi _settingsApi;
        readonly WebServiceDhcpApi _dhcpApi;
        readonly WebServiceAuthApi _authApi;
        readonly WebServiceClusterApi _clusterApi;
        readonly WebServiceLogsApi _logsApi;

        WebApplication _webService;

        ClusterManager _clusterManager;
        DnsServer _dnsServer;
        DhcpServer _dhcpServer;

        //web service
        IReadOnlyList<IPAddress> _webServiceLocalAddresses = [IPAddress.Any, IPAddress.IPv6Any];
        int _webServiceHttpPort = 5380;
        int _webServiceTlsPort = 53443;
        bool _webServiceEnableTls;
        bool _webServiceEnableHttp3;
        bool _webServiceHttpToTlsRedirect;
        bool _webServiceUseSelfSignedTlsCertificate;
        string _webServiceTlsCertificatePath;
        string _webServiceTlsCertificatePassword;
        string _webServiceRealIpHeader = "X-Real-IP";

        Timer _tlsCertificateUpdateTimer;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

        DateTime _webServiceCertificateLastModifiedOn;
        SslServerAuthenticationOptions _webServiceSslServerAuthenticationOptions;

        List<string> _configDisabledZones;

        readonly object _saveLock = new object();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        bool _isRunning;

        #endregion

        #region constructor

        public DnsWebService(string configFolder = null, Uri updateCheckUri = null)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();

            _currentVersion = assembly.GetName().Version;
            _appFolder = Path.GetDirectoryName(assembly.Location);

            if (configFolder is null)
                _configFolder = Path.Combine(_appFolder, "config");
            else
                _configFolder = configFolder;

            Directory.CreateDirectory(_configFolder);
            Directory.CreateDirectory(Path.Combine(_configFolder, "blocklists"));
            Directory.CreateDirectory(Path.Combine(_configFolder, "zones"));

            _log = new LogManager(_configFolder);
            _authManager = new AuthManager(_configFolder, _log);

            _api = new WebServiceApi(this, updateCheckUri);
            _dashboardApi = new WebServiceDashboardApi(this);
            _zonesApi = new WebServiceZonesApi(this);
            _otherZonesApi = new WebServiceOtherZonesApi(this);
            _appsApi = new WebServiceAppsApi(this);
            _settingsApi = new WebServiceSettingsApi(this);
            _dhcpApi = new WebServiceDhcpApi(this);
            _authApi = new WebServiceAuthApi(this);
            _clusterApi = new WebServiceClusterApi(this);
            _logsApi = new WebServiceLogsApi(this);

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
                            _log.Write(ex);

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

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
                return;

            StopTlsCertificateUpdateTimer();

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
                        _log.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            await StopAsync();

            _authManager?.Dispose();
            _log?.Dispose();

            _disposed = true;
        }

        public void Dispose()
        {
            DisposeAsync().Sync();
        }

        #endregion

        #region config

        private void LoadConfigFile()
        {
            string webServiceConfigFile = Path.Combine(_configFolder, "webservice.config");

            try
            {
                using (FileStream fS = new FileStream(webServiceConfigFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS);
                }

                _log.Write("Web Service config file was loaded: " + webServiceConfigFile);
            }
            catch (FileNotFoundException)
            {
                TryLoadOldConfigFile();

                CreateForwarderZoneToDisableDnssecForNTP();

                //web service
                string strWebServiceLocalAddresses = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES");
                if (!string.IsNullOrEmpty(strWebServiceLocalAddresses))
                    _webServiceLocalAddresses = strWebServiceLocalAddresses.Split(IPAddress.Parse, commaSeparator);

                string strWebServiceHttpPort = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_PORT");
                if (!string.IsNullOrEmpty(strWebServiceHttpPort))
                    _webServiceHttpPort = int.Parse(strWebServiceHttpPort);

                string webServiceTlsPort = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTPS_PORT");
                if (!string.IsNullOrEmpty(webServiceTlsPort))
                    _webServiceTlsPort = int.Parse(webServiceTlsPort);

                UdpClientConnection.SocketPoolExcludedPorts = [(ushort)_webServiceTlsPort];

                string webServiceEnableTls = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS");
                if (!string.IsNullOrEmpty(webServiceEnableTls))
                    _webServiceEnableTls = bool.Parse(webServiceEnableTls);

                string webServiceUseSelfSignedTlsCertificate = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_USE_SELF_SIGNED_CERT");
                if (!string.IsNullOrEmpty(webServiceUseSelfSignedTlsCertificate))
                    _webServiceUseSelfSignedTlsCertificate = bool.Parse(webServiceUseSelfSignedTlsCertificate);

                string webServiceTlsCertificatePath = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_TLS_CERTIFICATE_PATH");
                if (!string.IsNullOrEmpty(webServiceTlsCertificatePath))
                    _webServiceTlsCertificatePath = webServiceTlsCertificatePath;

                string webServiceTlsCertificatePassword = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_TLS_CERTIFICATE_PASSWORD");
                if (!string.IsNullOrEmpty(webServiceTlsCertificatePassword))
                    _webServiceTlsCertificatePassword = webServiceTlsCertificatePassword;

                string webServiceHttpToTlsRedirect = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_TO_TLS_REDIRECT");
                if (!string.IsNullOrEmpty(webServiceHttpToTlsRedirect))
                    _webServiceHttpToTlsRedirect = bool.Parse(webServiceHttpToTlsRedirect);

                SaveConfigFileInternal();
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading Web Service config file: " + webServiceConfigFile + "\r\n" + ex.ToString());
                _log.Write("Note: You may try deleting the Web Service config file to fix this issue. However, you will lose Web Service settings but, other data wont be affected.");
                throw;
            }
        }

        public void LoadConfig(Stream s)
        {
            lock (_saveLock)
            {
                ReadConfigFrom(s);

                SaveConfigFileInternal();

                if (_pendingSave)
                {
                    _pendingSave = false;
                    _saveTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
        }

        private void CreateForwarderZoneToDisableDnssecForNTP()
        {
            if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                //adding a conditional forwarder zone for disabling DNSSEC validation for ntp.org so that systems with no real-time clock can sync time
                string ntpDomain = "ntp.org";
                string fwdRecordComments = "This forwarder zone was automatically created to disable DNSSEC validation for ntp.org to allow systems with no real-time clock (e.g. Raspberry Pi) to sync time via NTP when booting.";
                if (_dnsServer.AuthZoneManager.CreateForwarderZone(ntpDomain, DnsTransportProtocol.Udp, "this-server", false, DnsForwarderRecordProxyType.DefaultProxy, null, 0, null, null, fwdRecordComments) is not null)
                {
                    //set permissions
                    _authManager.SetPermission(PermissionSection.Zones, ntpDomain, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _authManager.SetPermission(PermissionSection.Zones, ntpDomain, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _authManager.SaveConfigFile();
                }
            }
        }

        private void SaveConfigFileInternal()
        {
            string configFile = Path.Combine(_configFolder, "webservice.config");

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

            _log.Write("Web Service config file was saved: " + configFile);
        }

        public void SaveConfigFile()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void InspectAndFixZonePermissions()
        {
            Permission permission = _authManager.GetPermission(PermissionSection.Zones);
            if (permission is null)
                throw new DnsWebServiceException("Failed to read 'Zones' permissions: auth.config file is probably corrupt.");

            IReadOnlyDictionary<string, Permission> subItemPermissions = permission.SubItemPermissions;

            //remove ghost permissions
            foreach (KeyValuePair<string, Permission> subItemPermission in subItemPermissions)
            {
                string zoneName = subItemPermission.Key;

                if (_dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName) is null)
                    permission.RemoveAllSubItemPermissions(zoneName); //no such zone exists; remove permissions
            }

            //add missing admin permissions
            IReadOnlyList<AuthZoneInfo> zones = _dnsServer.AuthZoneManager.GetAllZones();
            Group admins = _authManager.GetGroup(Group.ADMINISTRATORS);
            if (admins is null)
                throw new DnsWebServiceException("Failed to find 'Administrators' group: auth.config file is probably corrupt.");

            Group dnsAdmins = _authManager.GetGroup(Group.DNS_ADMINISTRATORS);
            if (dnsAdmins is null)
                throw new DnsWebServiceException("Failed to find 'DNS Administrators' group: auth.config file is probably corrupt.");

            foreach (AuthZoneInfo zone in zones)
            {
                if (zone.Internal)
                {
                    _authManager.SetPermission(PermissionSection.Zones, zone.Name, admins, PermissionFlag.View);
                    _authManager.SetPermission(PermissionSection.Zones, zone.Name, dnsAdmins, PermissionFlag.View);
                }
                else
                {
                    _authManager.SetPermission(PermissionSection.Zones, zone.Name, admins, PermissionFlag.ViewModifyDelete);
                    _authManager.SetPermission(PermissionSection.Zones, zone.Name, dnsAdmins, PermissionFlag.ViewModifyDelete);
                }
            }

            _authManager.SaveConfigFile();
        }

        private void ReadConfigFrom(Stream s)
        {
            BinaryReader bR = new BinaryReader(s);

            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "WC") //format
                throw new InvalidDataException("Web Service config file format is invalid.");

            int version = bR.ReadByte();
            if (version > 1)
                throw new InvalidDataException("Web Service config version not supported.");

            _webServiceHttpPort = bR.ReadInt32();
            _webServiceTlsPort = bR.ReadInt32();

            {
                IPAddress[] webServiceLocalAddresses;

                int count = bR.ReadByte();
                if (count > 0)
                {
                    IPAddress[] localAddresses = new IPAddress[count];

                    for (int i = 0; i < count; i++)
                        localAddresses[i] = IPAddressExtensions.ReadFrom(bR);

                    webServiceLocalAddresses = localAddresses;
                }
                else
                {
                    webServiceLocalAddresses = [IPAddress.Any, IPAddress.IPv6Any];
                }

                _webServiceLocalAddresses = webServiceLocalAddresses;
            }

            _webServiceEnableTls = bR.ReadBoolean();
            _webServiceEnableHttp3 = bR.ReadBoolean();
            _webServiceHttpToTlsRedirect = bR.ReadBoolean();
            _webServiceUseSelfSignedTlsCertificate = bR.ReadBoolean();

            _webServiceTlsCertificatePath = bR.ReadShortString();
            _webServiceTlsCertificatePassword = bR.ReadShortString();

            if (_webServiceTlsCertificatePath.Length == 0)
                _webServiceTlsCertificatePath = null;

            if (_webServiceTlsCertificatePath is null)
            {
                StopTlsCertificateUpdateTimer();
            }
            else
            {
                string webServiceTlsCertificateAbsolutePath = ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                try
                {
                    LoadWebServiceTlsCertificate(webServiceTlsCertificateAbsolutePath, _webServiceTlsCertificatePassword);
                }
                catch (Exception ex)
                {
                    _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + webServiceTlsCertificateAbsolutePath + "\r\n" + ex.ToString());
                }

                StartTlsCertificateUpdateTimer();
            }

            CheckAndLoadSelfSignedCertificate(false, false);

            _webServiceRealIpHeader = bR.ReadShortString();
        }

        private void WriteConfigTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("WC")); //format
            bW.Write((byte)1); //version

            bW.Write(_webServiceHttpPort);
            bW.Write(_webServiceTlsPort);

            {
                bW.Write(Convert.ToByte(_webServiceLocalAddresses.Count));

                foreach (IPAddress localAddress in _webServiceLocalAddresses)
                    localAddress.WriteTo(bW);
            }

            bW.Write(_webServiceEnableTls);
            bW.Write(_webServiceEnableHttp3);
            bW.Write(_webServiceHttpToTlsRedirect);
            bW.Write(_webServiceUseSelfSignedTlsCertificate);

            if (_webServiceTlsCertificatePath is null)
                bW.WriteShortString(string.Empty);
            else
                bW.WriteShortString(_webServiceTlsCertificatePath);

            if (_webServiceTlsCertificatePassword is null)
                bW.WriteShortString(string.Empty);
            else
                bW.WriteShortString(_webServiceTlsCertificatePassword);

            bW.WriteShortString(_webServiceRealIpHeader);
        }

        #endregion

        #region backup and restore config

        internal async Task BackupConfigAsync(Stream zipStream, bool authConfig, bool clusterConfig, bool webServiceSettings, bool dnsSettings, bool logSettings, bool zones, bool allowedZones, bool blockedZones, bool blockLists, bool apps, bool scopes, bool stats, bool logs, bool isConfigTransfer = false, DateTime ifModifiedSince = default, IReadOnlyCollection<string> includeZones = null)
        {
            using (ZipArchive backupZip = new ZipArchive(zipStream, ZipArchiveMode.Create, true, Encoding.UTF8))
            {
                if (authConfig)
                {
                    string authConfigFile = Path.Combine(_configFolder, "auth.config");

                    if (File.Exists(authConfigFile) && (File.GetLastWriteTimeUtc(authConfigFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(authConfigFile, "auth.config");
                }

                if (clusterConfig && !isConfigTransfer)
                {
                    string clusterConfigFile = Path.Combine(_configFolder, "cluster.config");

                    if (File.Exists(clusterConfigFile))
                        backupZip.CreateEntryFromFile(clusterConfigFile, "cluster.config");
                }

                if (webServiceSettings && !isConfigTransfer)
                {
                    string webServiceConfigFile = Path.Combine(_configFolder, "webservice.config");

                    if (File.Exists(webServiceConfigFile) && (File.GetLastWriteTimeUtc(webServiceConfigFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(webServiceConfigFile, "webservice.config");

                    //backup web service cert
                    if (!isConfigTransfer && !string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                    {
                        string webServiceTlsCertificatePath = ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                        if (File.Exists(webServiceTlsCertificatePath) && webServiceTlsCertificatePath.StartsWith(_configFolder, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                        {
                            string entryName = ConvertToRelativePath(webServiceTlsCertificatePath).Replace('\\', '/');
                            backupZip.CreateEntryFromFile(webServiceTlsCertificatePath, entryName);
                        }
                    }
                }

                if (dnsSettings)
                {
                    string dnsConfigFile = Path.Combine(_configFolder, "dns.config");

                    if (File.Exists(dnsConfigFile) && (File.GetLastWriteTimeUtc(dnsConfigFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(dnsConfigFile, "dns.config");

                    //backup optional protocols cert
                    if (!isConfigTransfer && !string.IsNullOrEmpty(_dnsServer.DnsTlsCertificatePath))
                    {
                        string dnsTlsCertificatePath = ConvertToAbsolutePath(_dnsServer.DnsTlsCertificatePath);

                        if (File.Exists(dnsTlsCertificatePath) && dnsTlsCertificatePath.StartsWith(_configFolder, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                        {
                            string entryName = ConvertToRelativePath(dnsTlsCertificatePath).Replace('\\', '/');
                            backupZip.CreateEntryFromFile(dnsTlsCertificatePath, entryName);
                        }
                    }
                }

                if (logSettings && !isConfigTransfer)
                {
                    string logConfigFile = Path.Combine(_configFolder, "log.config");

                    if (File.Exists(logConfigFile) && (File.GetLastWriteTimeUtc(logConfigFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(logConfigFile, "log.config");
                }

                if (zones)
                {
                    if (isConfigTransfer)
                    {
                        //backup Primary zone DNSSEC private keys that are member zone of the cluster catalog zone
                        AuthZoneInfo clusterCatalogZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo("cluster-catalog." + _clusterManager.ClusterDomain);
                        if ((clusterCatalogZoneInfo is not null) && (clusterCatalogZoneInfo.Type == AuthZoneType.Catalog))
                        {
                            IReadOnlyCollection<string> memberZoneNames = (clusterCatalogZoneInfo.ApexZone as CatalogZone).GetAllMemberZoneNames();

                            foreach (string memberZoneName in memberZoneNames)
                            {
                                AuthZoneInfo memberZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(memberZoneName);
                                if (memberZoneInfo is null)
                                    continue; //no such zone exists; ignore

                                if (memberZoneInfo.Type != AuthZoneType.Primary)
                                    continue; //not a Primary zone; ignore

                                if (memberZoneInfo.ApexZone.DnssecStatus == AuthZoneDnssecStatus.Unsigned)
                                    continue; //not a DNSSEC signed zone; ignore

                                IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys = memberZoneInfo.DnssecPrivateKeys;
                                bool includePrivateKeys = false;

                                if ((includeZones is not null) && includeZones.Contains(memberZoneInfo.Name))
                                {
                                    includePrivateKeys = true;
                                }
                                else
                                {
                                    foreach (DnssecPrivateKey dnssecPrivateKey in dnssecPrivateKeys)
                                    {
                                        if (dnssecPrivateKey.StateChangedOn > ifModifiedSince)
                                        {
                                            //found a changed key
                                            includePrivateKeys = true;
                                            break;
                                        }
                                    }
                                }

                                if (includePrivateKeys)
                                {
                                    using (MemoryStream mS = new MemoryStream(4096))
                                    {
                                        AuthZoneInfo.WriteDnssecPrivateKeysTo(dnssecPrivateKeys, new BinaryWriter(mS));

                                        mS.Position = 0;

                                        //create zip entry
                                        ZipArchiveEntry entry = backupZip.CreateEntry("zones/" + memberZoneName + ".keys", CompressionLevel.Optimal);
                                        await using (Stream entryStream = entry.Open())
                                        {
                                            await mS.CopyToAsync(entryStream);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        //backup zone files
                        string[] zoneFiles = Directory.GetFiles(Path.Combine(_configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);
                        foreach (string zoneFile in zoneFiles)
                        {
                            string entryName = "zones/" + Path.GetFileName(zoneFile);
                            backupZip.CreateEntryFromFile(zoneFile, entryName);
                        }
                    }
                }

                if (allowedZones)
                {
                    string allowedZonesFile = Path.Combine(_configFolder, "allowed.config");

                    if (File.Exists(allowedZonesFile) && (File.GetLastWriteTimeUtc(allowedZonesFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(allowedZonesFile, "allowed.config");
                }

                if (blockedZones)
                {
                    string blockedZonesFile = Path.Combine(_configFolder, "blocked.config");

                    if (File.Exists(blockedZonesFile) && (File.GetLastWriteTimeUtc(blockedZonesFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(blockedZonesFile, "blocked.config");
                }

                if (blockLists)
                {
                    string blockListConfigFile = Path.Combine(_configFolder, "blocklist.config");

                    if (File.Exists(blockListConfigFile) && (File.GetLastWriteTimeUtc(blockListConfigFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(blockListConfigFile, "blocklist.config");

                    string[] blockListFiles = Directory.GetFiles(Path.Combine(_configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);
                    foreach (string blockListFile in blockListFiles)
                    {
                        if (File.GetLastWriteTimeUtc(blockListFile) > ifModifiedSince)
                        {
                            string entryName = "blocklists/" + Path.GetFileName(blockListFile);
                            backupZip.CreateEntryFromFile(blockListFile, entryName);
                        }
                    }
                }

                if (apps)
                {
                    if (isConfigTransfer)
                    {
                        string[] appDirectories = Directory.GetDirectories(Path.Combine(_configFolder, "apps"), "*", SearchOption.TopDirectoryOnly);
                        foreach (string appDirectory in appDirectories)
                        {
                            string applicationName = Path.GetFileName(appDirectory);
                            string applicationZipFile = Path.Combine(appDirectory, applicationName + ".zip");
                            string configFile = Path.Combine(appDirectory, "dnsApp.config");
                            bool fileAdded = false;

                            if (File.Exists(applicationZipFile) && (File.GetLastWriteTimeUtc(applicationZipFile) > ifModifiedSince))
                            {
                                string entryName = "apps/" + applicationName + "/" + applicationName + ".zip";
                                backupZip.CreateEntryFromFile(applicationZipFile, entryName);
                                fileAdded = true;
                            }

                            if (File.Exists(configFile) && (File.GetLastWriteTimeUtc(configFile) > ifModifiedSince))
                            {
                                string entryName = "apps/" + applicationName + "/dnsApp.config";
                                backupZip.CreateEntryFromFile(configFile, entryName);
                                fileAdded = true;
                            }

                            if (!fileAdded)
                                _ = backupZip.CreateEntry("apps/" + applicationName + "/.exists", CompressionLevel.Optimal);
                        }
                    }
                    else
                    {
                        string[] appFiles = Directory.GetFiles(Path.Combine(_configFolder, "apps"), "*", SearchOption.AllDirectories);
                        foreach (string appFile in appFiles)
                        {
                            string entryName = appFile.Substring(_configFolder.Length);

                            if (Path.DirectorySeparatorChar != '/')
                                entryName = entryName.Replace(Path.DirectorySeparatorChar, '/');

                            entryName = entryName.TrimStart('/');

                            await CreateBackupEntryFromSharedFileAsync(backupZip, appFile, entryName);
                        }
                    }
                }

                if (scopes && !isConfigTransfer)
                {
                    string[] scopeFiles = Directory.GetFiles(Path.Combine(_configFolder, "scopes"), "*.scope", SearchOption.TopDirectoryOnly);
                    foreach (string scopeFile in scopeFiles)
                    {
                        string entryName = "scopes/" + Path.GetFileName(scopeFile);
                        backupZip.CreateEntryFromFile(scopeFile, entryName);
                    }
                }

                if (stats && !isConfigTransfer)
                {
                    string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);
                    foreach (string hourlyStatsFile in hourlyStatsFiles)
                    {
                        string entryName = "stats/" + Path.GetFileName(hourlyStatsFile);
                        backupZip.CreateEntryFromFile(hourlyStatsFile, entryName);
                    }

                    string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);
                    foreach (string dailyStatsFile in dailyStatsFiles)
                    {
                        string entryName = "stats/" + Path.GetFileName(dailyStatsFile);
                        backupZip.CreateEntryFromFile(dailyStatsFile, entryName);
                    }
                }

                if (logs && !isConfigTransfer)
                {
                    string[] logFiles = Directory.GetFiles(_log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);
                    foreach (string logFile in logFiles)
                    {
                        string entryName = "logs/" + Path.GetFileName(logFile);

                        if (logFile.Equals(_log.CurrentLogFile, StringComparison.OrdinalIgnoreCase))
                        {
                            await CreateBackupEntryFromSharedFileAsync(backupZip, logFile, entryName);
                        }
                        else
                        {
                            backupZip.CreateEntryFromFile(logFile, entryName);
                        }
                    }
                }
            }
        }

        internal async Task RestoreConfigAsync(Stream zipStream, bool authConfig, bool clusterConfig, bool webServiceSettings, bool dnsSettings, bool logSettings, bool zones, bool allowedZones, bool blockedZones, bool blockLists, bool apps, bool scopes, bool stats, bool logs, bool deleteExistingFiles, UserSession implantSession = null, bool isConfigTransfer = false)
        {
            using (ZipArchive backupZip = new ZipArchive(zipStream, ZipArchiveMode.Read, false, Encoding.UTF8))
            {
                if (logSettings && !isConfigTransfer)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("log.config");
                    if (entry is not null)
                    {
                        //dynamically load and apply logger config
                        await using (Stream stream = entry.Open())
                        {
                            _log.LoadConfig(stream);
                        }
                    }
                }

                if (logs && !isConfigTransfer)
                {
                    _log.BulkManipulateLogFiles(delegate ()
                    {
                        if (deleteExistingFiles)
                        {
                            //delete existing log files
                            string[] logFiles = Directory.GetFiles(_log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);

                            foreach (string logFile in logFiles)
                            {
                                try
                                {
                                    File.Delete(logFile);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }

                        //extract log files from backup
                        foreach (ZipArchiveEntry entry in backupZip.Entries)
                        {
                            if (entry.FullName.StartsWith("logs/"))
                            {
                                try
                                {
                                    entry.ExtractToFile(Path.Combine(_log.LogFolderAbsolutePath, entry.Name), true);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }
                    });
                }

                if (authConfig)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("auth.config");
                    if (entry is not null)
                    {
                        //dynamically load and apply auth config
                        await using (Stream stream = entry.Open())
                        {
                            _authManager.LoadConfig(stream, isConfigTransfer, implantSession);
                        }
                    }
                }

                if (clusterConfig && !isConfigTransfer)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("cluster.config");
                    if (entry is not null)
                    {
                        //dynamically load and apply cluster config
                        await using (Stream stream = entry.Open())
                        {
                            _clusterManager.LoadConfig(stream);
                        }
                    }
                }

                if ((webServiceSettings || dnsSettings) && !isConfigTransfer)
                {
                    //extract any certs
                    foreach (ZipArchiveEntry certEntry in backupZip.Entries)
                    {
                        if (certEntry.FullName.StartsWith("apps/"))
                            continue;

                        if (certEntry.FullName.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase) || certEntry.FullName.EndsWith(".p12", StringComparison.OrdinalIgnoreCase))
                        {
                            string certFile = Path.Combine(_configFolder, certEntry.FullName);

                            try
                            {
                                Directory.CreateDirectory(Path.GetDirectoryName(certFile));

                                certEntry.ExtractToFile(certFile, true);
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }
                }

                if (webServiceSettings && !isConfigTransfer)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("webservice.config");
                    if (entry is not null)
                    {
                        //dynamically load and apply web service config
                        await using (Stream stream = entry.Open())
                        {
                            LoadConfig(stream);
                        }
                    }
                }

                if (dnsSettings)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("dns.config");
                    if (entry is not null)
                    {
                        //dynamically load and apply DNS settings config
                        await using (Stream stream = entry.Open())
                        {
                            _dnsServer.LoadConfig(stream, isConfigTransfer);
                        }
                    }
                }

                if (zones)
                {
                    if (isConfigTransfer)
                    {
                        //backup DNSSEC private keys into Secondary zones that are member zone of the secondary cluster catalog zone
                        AuthZoneInfo secondaryClusterCatalogZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo("cluster-catalog." + _clusterManager.ClusterDomain);
                        if ((secondaryClusterCatalogZoneInfo is not null) && (secondaryClusterCatalogZoneInfo.Type == AuthZoneType.SecondaryCatalog))
                        {
                            HashSet<string> memberZoneNames = new HashSet<string>((secondaryClusterCatalogZoneInfo.ApexZone as SecondaryCatalogZone).GetAllMemberZoneNames());

                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (!entry.FullName.StartsWith("zones/") || !entry.FullName.EndsWith(".keys", StringComparison.Ordinal))
                                    continue;

                                string memberZoneName = Path.GetFileNameWithoutExtension(entry.Name);

                                AuthZoneInfo memberZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(memberZoneName);
                                if (memberZoneInfo is null)
                                    continue; //no such zone exists; ignore

                                if (memberZoneInfo.Type != AuthZoneType.Secondary)
                                    continue; //not a Secondary zone; ignore

                                SecondaryZone memberZone = memberZoneInfo.ApexZone as SecondaryZone;

                                if (memberZoneNames.Contains(memberZoneName))
                                {
                                    //read DNSSEC private keys
                                    IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys;

                                    await using (Stream s = entry.Open())
                                    {
                                        dnssecPrivateKeys = AuthZoneInfo.ReadDnssecPrivateKeysFrom(new BinaryReader(s));
                                    }

                                    //backup DNSSEC private keys
                                    memberZone.DnssecPrivateKeys = dnssecPrivateKeys;
                                    _dnsServer.AuthZoneManager.SaveZoneFile(memberZoneInfo.Name);
                                }
                                else
                                {
                                    //not a member zone of the secondary cluster catalog zone
                                    if (memberZone.DnssecPrivateKeys is not null)
                                    {
                                        //found old backup keys; remove them
                                        memberZone.DnssecPrivateKeys = null;
                                        _dnsServer.AuthZoneManager.SaveZoneFile(memberZoneInfo.Name);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        //restore zones
                        if (deleteExistingFiles)
                        {
                            //delete existing zone files
                            string[] zoneFiles = Directory.GetFiles(Path.Combine(_configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);

                            foreach (string zoneFile in zoneFiles)
                            {
                                try
                                {
                                    File.Delete(zoneFile);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }

                        //extract zone files from backup
                        foreach (ZipArchiveEntry entry in backupZip.Entries)
                        {
                            if (entry.FullName.StartsWith("zones/"))
                            {
                                try
                                {
                                    entry.ExtractToFile(Path.Combine(_configFolder, "zones", entry.Name), true);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }

                        //reload zones
                        _dnsServer.AuthZoneManager.LoadAllZoneFiles();
                        InspectAndFixZonePermissions();
                    }
                }

                if (allowedZones)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("allowed.config");
                    if (entry is not null)
                    {
                        //dynamically load and apply allowed zones config
                        await using (Stream stream = entry.Open())
                        {
                            _dnsServer.AllowedZoneManager.LoadAllowedZone(stream);
                        }
                    }
                }

                if (blockedZones)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("blocked.config");
                    if (entry is not null)
                    {
                        //dynamically load and apply blocked zones config
                        await using (Stream stream = entry.Open())
                        {
                            _dnsServer.BlockedZoneManager.LoadBlockedZone(stream);
                        }
                    }
                }

                if (blockLists)
                {
                    if (deleteExistingFiles)
                    {
                        //delete existing block list files
                        string[] blockListFiles = Directory.GetFiles(Path.Combine(_configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);

                        foreach (string blockListFile in blockListFiles)
                        {
                            try
                            {
                                File.Delete(blockListFile);
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }

                    //extract block list files from backup
                    foreach (ZipArchiveEntry entry in backupZip.Entries)
                    {
                        if (entry.FullName.StartsWith("blocklists/"))
                        {
                            try
                            {
                                entry.ExtractToFile(Path.Combine(_configFolder, "blocklists", entry.Name), true);
                            }
                            catch (IOException)
                            {
                                //ignore since file may be loading in another thread
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }

                    ZipArchiveEntry blockListConfigEntry = backupZip.GetEntry("blocklist.config");
                    if (blockListConfigEntry is not null)
                    {
                        //dynamically load and apply block list config
                        await using (Stream stream = blockListConfigEntry.Open())
                        {
                            _dnsServer.BlockListZoneManager.LoadConfig(stream, isConfigTransfer);
                        }
                    }
                }

                if (apps)
                {
                    if (isConfigTransfer)
                    {
                        //install or update app from zip
                        foreach (ZipArchiveEntry entry in backupZip.Entries)
                        {
                            if (!entry.FullName.StartsWith("apps/"))
                                continue;

                            string[] fullNameParts = entry.FullName.Split('/');
                            if (fullNameParts.Length < 3)
                                continue;

                            string applicationName = fullNameParts[1];
                            string applicationZipFile = fullNameParts[2];

                            if (!applicationZipFile.Equals(applicationName + ".zip", StringComparison.Ordinal))
                                continue;

                            if (_dnsServer.DnsApplicationManager.Applications.TryGetValue(applicationName, out _))
                            {
                                //update existing app
                                await using (Stream s = entry.Open())
                                {
                                    await _dnsServer.DnsApplicationManager.UpdateApplicationAsync(applicationName, s);
                                }
                            }
                            else
                            {
                                //install new app
                                await using (Stream s = entry.Open())
                                {
                                    await _dnsServer.DnsApplicationManager.InstallApplicationAsync(applicationName, s);
                                }
                            }
                        }

                        //update app config
                        foreach (ZipArchiveEntry entry in backupZip.Entries)
                        {
                            if (!entry.FullName.StartsWith("apps/"))
                                continue;

                            string[] fullNameParts = entry.FullName.Split('/');
                            if (fullNameParts.Length < 3)
                                continue;

                            string applicationName = fullNameParts[1];
                            string configFile = fullNameParts[2];

                            if (!configFile.Equals("dnsApp.config", StringComparison.Ordinal))
                                continue;

                            if (_dnsServer.DnsApplicationManager.Applications.TryGetValue(applicationName, out DnsApplication application))
                            {
                                string config;

                                await using (Stream s = entry.Open())
                                {
                                    using (StreamReader sR = new StreamReader(s, true))
                                    {
                                        config = await sR.ReadToEndAsync();
                                    }
                                }

                                try
                                {
                                    await application.SetConfigAsync(config);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }

                        //remove apps that are not in the zip file
                        HashSet<string> existingApplications = new HashSet<string>();

                        foreach (ZipArchiveEntry entry in backupZip.Entries)
                        {
                            if (!entry.FullName.StartsWith("apps/"))
                                continue;

                            string[] fullNameParts = entry.FullName.Split('/');
                            if (fullNameParts.Length < 2)
                                continue;

                            string applicationName = fullNameParts[1];

                            existingApplications.Add(applicationName);
                        }

                        foreach (KeyValuePair<string, DnsApplication> application in _dnsServer.DnsApplicationManager.Applications)
                        {
                            if (!existingApplications.Contains(application.Key))
                                _dnsServer.DnsApplicationManager.UninstallApplication(application.Key);
                        }
                    }
                    else
                    {
                        //unload apps
                        _dnsServer.DnsApplicationManager.UnloadAllApplications();

                        if (deleteExistingFiles)
                        {
                            //delete existing apps
                            string appFolder = Path.Combine(_configFolder, "apps");
                            if (Directory.Exists(appFolder))
                            {
                                try
                                {
                                    Directory.Delete(appFolder, true);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }

                            //create apps folder
                            Directory.CreateDirectory(appFolder);
                        }

                        //extract apps files from backup
                        foreach (ZipArchiveEntry entry in backupZip.Entries)
                        {
                            if (entry.FullName.StartsWith("apps/"))
                            {
                                string entryPath = entry.FullName;

                                if (Path.DirectorySeparatorChar != '/')
                                    entryPath = entryPath.Replace('/', '\\');

                                string filePath = Path.Combine(_configFolder, entryPath);

                                Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                                try
                                {
                                    entry.ExtractToFile(filePath, true);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }

                        //reload apps
                        await _dnsServer.DnsApplicationManager.LoadAllApplicationsAsync();
                    }
                }

                if (scopes && !isConfigTransfer)
                {
                    //stop dhcp server
                    _dhcpServer.Stop();

                    try
                    {
                        if (deleteExistingFiles)
                        {
                            //delete existing scope files
                            string[] scopeFiles = Directory.GetFiles(Path.Combine(_configFolder, "scopes"), "*.scope", SearchOption.TopDirectoryOnly);

                            foreach (string scopeFile in scopeFiles)
                            {
                                try
                                {
                                    File.Delete(scopeFile);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }

                        //extract scope files from backup
                        foreach (ZipArchiveEntry entry in backupZip.Entries)
                        {
                            if (entry.FullName.StartsWith("scopes/"))
                            {
                                try
                                {
                                    entry.ExtractToFile(Path.Combine(_configFolder, "scopes", entry.Name), true);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }
                    }
                    finally
                    {
                        //start dhcp server
                        _dhcpServer.Start();
                    }
                }

                if (stats && !isConfigTransfer)
                {
                    if (deleteExistingFiles)
                    {
                        //delete existing stats files
                        string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);

                        foreach (string hourlyStatsFile in hourlyStatsFiles)
                        {
                            try
                            {
                                File.Delete(hourlyStatsFile);
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }

                        string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);

                        foreach (string dailyStatsFile in dailyStatsFiles)
                        {
                            try
                            {
                                File.Delete(dailyStatsFile);
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }

                    //extract stats files from backup
                    foreach (ZipArchiveEntry entry in backupZip.Entries)
                    {
                        if (entry.FullName.StartsWith("stats/"))
                        {
                            try
                            {
                                entry.ExtractToFile(Path.Combine(_configFolder, "stats", entry.Name), true);
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }

                    //reload stats
                    _dnsServer.StatsManager.ReloadStats();
                }
            }
        }

        private static async Task CreateBackupEntryFromSharedFileAsync(ZipArchive backupZip, string sourceFileName, string entryName)
        {
            await using (FileStream fS = new FileStream(sourceFileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                ZipArchiveEntry entry = backupZip.CreateEntry(entryName);

                DateTime lastWrite = File.GetLastWriteTime(sourceFileName);

                // If file to be archived has an invalid last modified time, use the first datetime representable in the Zip timestamp format
                // (midnight on January 1, 1980):
                if (lastWrite.Year < 1980 || lastWrite.Year > 2107)
                    lastWrite = new DateTime(1980, 1, 1, 0, 0, 0);

                entry.LastWriteTime = lastWrite;

                await using (Stream sE = entry.Open())
                {
                    await fS.CopyToAsync(sE);
                }
            }
        }

        #endregion

        #region internal

        private string ConvertToRelativePath(string path)
        {
            if (path.StartsWith(_configFolder, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                path = path.Substring(_configFolder.Length).TrimStart(Path.DirectorySeparatorChar);

            return path;
        }

        private string ConvertToAbsolutePath(string path)
        {
            if (path is null)
                return null;

            if (Path.IsPathRooted(path))
                return path;

            return Path.Combine(_configFolder, path);
        }

        #endregion

        #region server version

        private string GetServerVersion()
        {
            return GetCleanVersion(_currentVersion);
        }

        private static string GetCleanVersion(Version version)
        {
            string strVersion = version.Major + "." + version.Minor;

            if (version.Build > 0)
                strVersion += "." + version.Build;

            if (version.Revision > 0)
                strVersion += "." + version.Revision;

            return strVersion;
        }

        #endregion

        #region web service

        private async Task TryStartWebServiceAsync(IReadOnlyList<IPAddress> oldWebServiceLocalAddresses, int oldWebServiceHttpPort, int oldWebServiceTlsPort)
        {
            try
            {
                _webServiceLocalAddresses = WebUtilities.GetValidKestrelLocalAddresses(_webServiceLocalAddresses);

                await StartWebServiceAsync(false);
                return;
            }
            catch (Exception ex)
            {
                _log.Write("Web Service failed to start: " + ex.ToString());
            }

            _log.Write("Attempting to revert Web Service end point changes ...");

            try
            {
                _webServiceLocalAddresses = WebUtilities.GetValidKestrelLocalAddresses(oldWebServiceLocalAddresses);
                _webServiceHttpPort = oldWebServiceHttpPort;
                _webServiceTlsPort = oldWebServiceTlsPort;

                await StartWebServiceAsync(false);

                SaveConfigFileInternal(); //save reverted changes
                return;
            }
            catch (Exception ex2)
            {
                _log.Write("Web Service failed to start: " + ex2.ToString());
            }

            _log.Write("Attempting to start Web Service on ANY (0.0.0.0) fallback address...");

            try
            {
                _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any };

                await StartWebServiceAsync(true);
                return;
            }
            catch (Exception ex3)
            {
                _log.Write("Web Service failed to start: " + ex3.ToString());
            }

            _log.Write("Attempting to start Web Service on loopback (127.0.0.1) fallback address...");

            _webServiceLocalAddresses = new IPAddress[] { IPAddress.Loopback };

            await StartWebServiceAsync(true);
        }

        private async Task StartWebServiceAsync(bool httpOnlyMode)
        {
            WebApplicationBuilder builder = WebApplication.CreateBuilder();

            builder.Environment.ContentRootFileProvider = new PhysicalFileProvider(_appFolder)
            {
                UseActivePolling = true,
                UsePollingFileWatcher = true
            };

            builder.Environment.WebRootFileProvider = new PhysicalFileProvider(Path.Combine(_appFolder, "www"))
            {
                UseActivePolling = true,
                UsePollingFileWatcher = true
            };

            builder.WebHost.ConfigureKestrel(delegate (WebHostBuilderContext context, KestrelServerOptions serverOptions)
            {
                //http
                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                    serverOptions.Listen(webServiceLocalAddress, _webServiceHttpPort);

                //https
                if (!httpOnlyMode && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                {
                    foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                    {
                        serverOptions.Listen(webServiceLocalAddress, _webServiceTlsPort, delegate (ListenOptions listenOptions)
                        {
                            if (_webServiceEnableHttp3)
                                listenOptions.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
                            else if (IsHttp2Supported())
                                listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
                            else
                                listenOptions.Protocols = HttpProtocols.Http1;

                            listenOptions.UseHttps(delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object state, CancellationToken cancellationToken)
                            {
                                return ValueTask.FromResult(_webServiceSslServerAuthenticationOptions);
                            }, null);
                        });
                    }
                }

                serverOptions.AddServerHeader = false;
                serverOptions.Limits.MaxRequestBodySize = int.MaxValue;
            });

            builder.Services.Configure(delegate (FormOptions options)
            {
                options.MultipartBodyLengthLimit = int.MaxValue;
            });

            builder.Logging.ClearProviders();

            _webService = builder.Build();

            if (_webServiceHttpToTlsRedirect && !httpOnlyMode && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                _webService.Use(WebServiceHttpsRedirectionMiddleware);

            _webService.UseDefaultFiles();
            _webService.UseStaticFiles(new StaticFileOptions()
            {
                OnPrepareResponse = delegate (StaticFileResponseContext ctx)
                {
                    ctx.Context.Response.Headers["X-Robots-Tag"] = "noindex, nofollow";
                    ctx.Context.Response.Headers.CacheControl = "no-cache";
                },
                ServeUnknownFileTypes = true
            });

            ConfigureWebServiceRoutes();

            try
            {
                await _webService.StartAsync();

                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                {
                    _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceHttpPort), "Http", "Web Service was bound successfully.");

                    if (!httpOnlyMode && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                        _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceTlsPort), "Https", "Web Service was bound successfully.");
                }
            }
            catch
            {
                await StopWebServiceAsync();

                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                {
                    _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceHttpPort), "Http", "Web Service failed to bind.");

                    if (!httpOnlyMode && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                        _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceTlsPort), "Https", "Web Service failed to bind.");
                }

                throw;
            }
        }

        private async Task StopWebServiceAsync()
        {
            if (_webService is not null)
            {
                await _webService.DisposeAsync();
                _webService = null;
            }
        }

        private bool IsHttp2Supported()
        {
            if (_webServiceEnableHttp3)
                return true;

            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                    return Environment.OSVersion.Version.Major >= 10; //http/2 supported on Windows Server 2016/Windows 10 or later

                case PlatformID.Unix:
                    return true; //http/2 supported on Linux with OpenSSL 1.0.2 or later (for example, Ubuntu 16.04 or later)

                default:
                    return false;
            }
        }

        private void ConfigureWebServiceRoutes()
        {
            _webService.UseExceptionHandler(WebServiceExceptionHandler);

            _webService.Use(WebServiceApiMiddleware);

            _webService.UseRouting();

            //user auth
            _webService.MapGetAndPost("/api/user/login", delegate (HttpContext context) { return _authApi.LoginAsync(context, UserSessionType.Standard); });
            _webService.MapGetAndPost("/api/user/createToken", delegate (HttpContext context) { return _authApi.LoginAsync(context, UserSessionType.ApiToken); });
            _webService.MapGetAndPost("/api/user/logout", _authApi.Logout);

            //user
            _webService.MapGetAndPost("/api/user/session/get", _authApi.GetCurrentSessionDetails);
            _webService.MapGetAndPost("/api/user/session/delete", delegate (HttpContext context) { _authApi.DeleteSession(context, false); });
            _webService.MapGetAndPost("/api/user/changePassword", _authApi.ChangePasswordAsync);
            _webService.MapGetAndPost("/api/user/2fa/init", _authApi.Initialize2FA);
            _webService.MapGetAndPost("/api/user/2fa/enable", _authApi.Enable2FA);
            _webService.MapGetAndPost("/api/user/2fa/disable", _authApi.Disable2FA);
            _webService.MapGetAndPost("/api/user/profile/get", _authApi.GetProfile);
            _webService.MapGetAndPost("/api/user/profile/set", _authApi.SetProfile);
            _webService.MapGetAndPost("/api/user/checkForUpdate", _api.CheckForUpdateAsync);

            //dashboard
            _webService.MapGetAndPost("/api/dashboard/stats/get", _dashboardApi.GetStats);
            _webService.MapGetAndPost("/api/dashboard/stats/getTop", _dashboardApi.GetTopStats);
            _webService.MapGetAndPost("/api/dashboard/stats/deleteAll", _logsApi.DeleteAllStats);

            //zones
            _webService.MapGetAndPost("/api/zones/list", _zonesApi.ListZones);
            _webService.MapGetAndPost("/api/zones/catalogs/list", _zonesApi.ListCatalogZones);
            _webService.MapGetAndPost("/api/zones/create", _zonesApi.CreateZoneAsync);
            _webService.MapGetAndPost("/api/zones/import", _zonesApi.ImportZoneAsync);
            _webService.MapGetAndPost("/api/zones/export", _zonesApi.ExportZoneAsync);
            _webService.MapGetAndPost("/api/zones/clone", _zonesApi.CloneZone);
            _webService.MapGetAndPost("/api/zones/convert", _zonesApi.ConvertZone);
            _webService.MapGetAndPost("/api/zones/enable", _zonesApi.EnableZone);
            _webService.MapGetAndPost("/api/zones/disable", _zonesApi.DisableZone);
            _webService.MapGetAndPost("/api/zones/delete", _zonesApi.DeleteZone);
            _webService.MapGetAndPost("/api/zones/resync", _zonesApi.ResyncZone);
            _webService.MapGetAndPost("/api/zones/options/get", _zonesApi.GetZoneOptions);
            _webService.MapGetAndPost("/api/zones/options/set", _zonesApi.SetZoneOptions);
            _webService.MapGetAndPost("/api/zones/permissions/get", delegate (HttpContext context) { _authApi.GetPermissionDetails(context, PermissionSection.Zones); });
            _webService.MapGetAndPost("/api/zones/permissions/set", delegate (HttpContext context) { _authApi.SetPermissionsDetails(context, PermissionSection.Zones); });
            _webService.MapGetAndPost("/api/zones/dnssec/sign", _zonesApi.SignPrimaryZone);
            _webService.MapGetAndPost("/api/zones/dnssec/unsign", _zonesApi.UnsignPrimaryZone);
            _webService.MapGetAndPost("/api/zones/dnssec/viewDS", _zonesApi.GetPrimaryZoneDsInfo);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/get", _zonesApi.GetPrimaryZoneDnssecProperties);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/convertToNSEC", _zonesApi.ConvertPrimaryZoneToNSEC);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/convertToNSEC3", _zonesApi.ConvertPrimaryZoneToNSEC3);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/updateNSEC3Params", _zonesApi.UpdatePrimaryZoneNSEC3Parameters);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/updateDnsKeyTtl", _zonesApi.UpdatePrimaryZoneDnssecDnsKeyTtl);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/generatePrivateKey", _zonesApi.AddPrimaryZoneDnssecPrivateKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/addPrivateKey", _zonesApi.AddPrimaryZoneDnssecPrivateKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/updatePrivateKey", _zonesApi.UpdatePrimaryZoneDnssecPrivateKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/deletePrivateKey", _zonesApi.DeletePrimaryZoneDnssecPrivateKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/publishAllPrivateKeys", _zonesApi.PublishAllGeneratedPrimaryZoneDnssecPrivateKeys);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/rolloverDnsKey", _zonesApi.RolloverPrimaryZoneDnsKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/retireDnsKey", _zonesApi.RetirePrimaryZoneDnsKeyAsync);
            _webService.MapGetAndPost("/api/zones/records/add", _zonesApi.AddRecord);
            _webService.MapGetAndPost("/api/zones/records/get", _zonesApi.GetRecords);
            _webService.MapGetAndPost("/api/zones/records/update", _zonesApi.UpdateRecord);
            _webService.MapGetAndPost("/api/zones/records/delete", _zonesApi.DeleteRecord);

            //cache
            _webService.MapGetAndPost("/api/cache/list", _otherZonesApi.ListCachedZones);
            _webService.MapGetAndPost("/api/cache/delete", _otherZonesApi.DeleteCachedZone);
            _webService.MapGetAndPost("/api/cache/flush", _otherZonesApi.FlushCache);

            //allowed
            _webService.MapGetAndPost("/api/allowed/list", _otherZonesApi.ListAllowedZones);
            _webService.MapGetAndPost("/api/allowed/add", _otherZonesApi.AllowZone);
            _webService.MapGetAndPost("/api/allowed/delete", _otherZonesApi.DeleteAllowedZone);
            _webService.MapGetAndPost("/api/allowed/flush", _otherZonesApi.FlushAllowedZone);
            _webService.MapGetAndPost("/api/allowed/import", _otherZonesApi.ImportAllowedZones);
            _webService.MapGetAndPost("/api/allowed/export", _otherZonesApi.ExportAllowedZonesAsync);

            //blocked
            _webService.MapGetAndPost("/api/blocked/list", _otherZonesApi.ListBlockedZones);
            _webService.MapGetAndPost("/api/blocked/add", _otherZonesApi.BlockZone);
            _webService.MapGetAndPost("/api/blocked/delete", _otherZonesApi.DeleteBlockedZone);
            _webService.MapGetAndPost("/api/blocked/flush", _otherZonesApi.FlushBlockedZone);
            _webService.MapGetAndPost("/api/blocked/import", _otherZonesApi.ImportBlockedZones);
            _webService.MapGetAndPost("/api/blocked/export", _otherZonesApi.ExportBlockedZonesAsync);

            //apps
            _webService.MapGetAndPost("/api/apps/list", _appsApi.ListInstalledAppsAsync);
            _webService.MapGetAndPost("/api/apps/listStoreApps", _appsApi.ListStoreApps);
            _webService.MapGetAndPost("/api/apps/downloadAndInstall", _appsApi.DownloadAndInstallAppAsync);
            _webService.MapGetAndPost("/api/apps/downloadAndUpdate", _appsApi.DownloadAndUpdateAppAsync);
            _webService.MapPost("/api/apps/install", _appsApi.InstallAppAsync);
            _webService.MapPost("/api/apps/update", _appsApi.UpdateAppAsync);
            _webService.MapGetAndPost("/api/apps/uninstall", _appsApi.UninstallApp);
            _webService.MapGetAndPost("/api/apps/config/get", _appsApi.GetAppConfigAsync);
            _webService.MapGetAndPost("/api/apps/config/set", _appsApi.SetAppConfigAsync);

            //dns client
            _webService.MapGetAndPost("/api/dnsClient/resolve", _api.ResolveQueryAsync);

            //settings
            _webService.MapGetAndPost("/api/settings/get", _settingsApi.GetDnsSettings);
            _webService.MapGetAndPost("/api/settings/set", _settingsApi.SetDnsSettingsAsync);
            _webService.MapGetAndPost("/api/settings/getTsigKeyNames", _settingsApi.GetTsigKeyNames);
            _webService.MapGetAndPost("/api/settings/forceUpdateBlockLists", _settingsApi.ForceUpdateBlockLists);
            _webService.MapGetAndPost("/api/settings/temporaryDisableBlocking", _settingsApi.TemporaryDisableBlocking);
            _webService.MapGetAndPost("/api/settings/backup", _settingsApi.BackupSettingsAsync);
            _webService.MapPost("/api/settings/restore", _settingsApi.RestoreSettingsAsync);

            //dhcp
            _webService.MapGetAndPost("/api/dhcp/leases/list", _dhcpApi.ListDhcpLeases);
            _webService.MapGetAndPost("/api/dhcp/leases/remove", _dhcpApi.RemoveDhcpLease);
            _webService.MapGetAndPost("/api/dhcp/leases/convertToReserved", _dhcpApi.ConvertToReservedLease);
            _webService.MapGetAndPost("/api/dhcp/leases/convertToDynamic", _dhcpApi.ConvertToDynamicLease);
            _webService.MapGetAndPost("/api/dhcp/scopes/list", _dhcpApi.ListDhcpScopes);
            _webService.MapGetAndPost("/api/dhcp/scopes/get", _dhcpApi.GetDhcpScope);
            _webService.MapGetAndPost("/api/dhcp/scopes/set", _dhcpApi.SetDhcpScopeAsync);
            _webService.MapGetAndPost("/api/dhcp/scopes/addReservedLease", _dhcpApi.AddReservedLease);
            _webService.MapGetAndPost("/api/dhcp/scopes/removeReservedLease", _dhcpApi.RemoveReservedLease);
            _webService.MapGetAndPost("/api/dhcp/scopes/enable", _dhcpApi.EnableDhcpScopeAsync);
            _webService.MapGetAndPost("/api/dhcp/scopes/disable", _dhcpApi.DisableDhcpScope);
            _webService.MapGetAndPost("/api/dhcp/scopes/delete", _dhcpApi.DeleteDhcpScope);

            //administration
            _webService.MapGetAndPost("/api/admin/sessions/list", _authApi.ListSessions);
            _webService.MapGetAndPost("/api/admin/sessions/createToken", _authApi.CreateApiToken);
            _webService.MapGetAndPost("/api/admin/sessions/delete", delegate (HttpContext context) { _authApi.DeleteSession(context, true); });
            _webService.MapGetAndPost("/api/admin/users/list", _authApi.ListUsers);
            _webService.MapGetAndPost("/api/admin/users/create", _authApi.CreateUser);
            _webService.MapGetAndPost("/api/admin/users/get", _authApi.GetUserDetails);
            _webService.MapGetAndPost("/api/admin/users/set", _authApi.SetUserDetails);
            _webService.MapGetAndPost("/api/admin/users/delete", _authApi.DeleteUser);
            _webService.MapGetAndPost("/api/admin/groups/list", _authApi.ListGroups);
            _webService.MapGetAndPost("/api/admin/groups/create", _authApi.CreateGroup);
            _webService.MapGetAndPost("/api/admin/groups/get", _authApi.GetGroupDetails);
            _webService.MapGetAndPost("/api/admin/groups/set", _authApi.SetGroupDetails);
            _webService.MapGetAndPost("/api/admin/groups/delete", _authApi.DeleteGroup);
            _webService.MapGetAndPost("/api/admin/permissions/list", _authApi.ListPermissions);
            _webService.MapGetAndPost("/api/admin/permissions/get", delegate (HttpContext context) { _authApi.GetPermissionDetails(context, PermissionSection.Unknown); });
            _webService.MapGetAndPost("/api/admin/permissions/set", delegate (HttpContext context) { _authApi.SetPermissionsDetails(context, PermissionSection.Unknown); });
            _webService.MapGetAndPost("/api/admin/cluster/state", _clusterApi.GetClusterState);
            _webService.MapGetAndPost("/api/admin/cluster/init", _clusterApi.InitializeCluster);
            _webService.MapGetAndPost("/api/admin/cluster/primary/delete", _clusterApi.DeleteCluster);
            _webService.MapGetAndPost("/api/admin/cluster/primary/join", _clusterApi.JoinCluster);
            _webService.MapGetAndPost("/api/admin/cluster/primary/removeSecondary", _clusterApi.RemoveSecondaryNodeAsync);
            _webService.MapGetAndPost("/api/admin/cluster/primary/deleteSecondary", _clusterApi.DeleteSecondaryNode);
            _webService.MapGetAndPost("/api/admin/cluster/primary/updateSecondary", _clusterApi.UpdateSecondaryNode);
            _webService.MapGetAndPost("/api/admin/cluster/primary/transferConfig", _clusterApi.TransferConfigAsync);
            _webService.MapGetAndPost("/api/admin/cluster/primary/setOptions", _clusterApi.SetClusterOptions);
            _webService.MapGetAndPost("/api/admin/cluster/initJoin", _clusterApi.InitializeAndJoinClusterAsync);
            _webService.MapGetAndPost("/api/admin/cluster/secondary/leave", _clusterApi.LeaveClusterAsync);
            _webService.MapGetAndPost("/api/admin/cluster/secondary/notify", _clusterApi.ConfigUpdateNotificationAsync);
            _webService.MapGetAndPost("/api/admin/cluster/secondary/resync", _clusterApi.ResyncCluster);
            _webService.MapGetAndPost("/api/admin/cluster/secondary/updatePrimary", _clusterApi.UpdatePrimaryNodeAsync);
            _webService.MapGetAndPost("/api/admin/cluster/secondary/promote", _clusterApi.PromoteToPrimaryNodeAsync);
            _webService.MapGetAndPost("/api/admin/cluster/updateIpAddress", _clusterApi.UpdateSelfNodeIPAddress);

            //logs
            _webService.MapGetAndPost("/api/logs/list", _logsApi.ListLogs);
            _webService.MapGetAndPost("/api/logs/download", _logsApi.DownloadLogAsync);
            _webService.MapGetAndPost("/api/logs/delete", _logsApi.DeleteLog);
            _webService.MapGetAndPost("/api/logs/deleteAll", _logsApi.DeleteAllLogs);
            _webService.MapGetAndPost("/api/logs/query", _logsApi.QueryLogsAsync);
            _webService.MapGetAndPost("/api/logs/export", _logsApi.ExportLogsAsync);

            //fallback
            _webService.MapFallback("/api/{*path}", delegate (HttpContext context)
            {
                //mark api fallback
                context.Items["apiFallback"] = string.Empty;
            });
        }

        private static ClusterNodeType GetClusterNodeTypeForPath(string path)
        {
            switch (path)
            {
                case "/api/user/createToken":
                case "/api/user/changePassword":
                case "/api/user/2fa/init":
                case "/api/user/2fa/enable":
                case "/api/user/2fa/disable":
                case "/api/user/profile/set":

                case "/api/allowed/add":
                case "/api/allowed/delete":
                case "/api/allowed/flush":
                case "/api/allowed/import":

                case "/api/blocked/add":
                case "/api/blocked/delete":
                case "/api/blocked/flush":
                case "/api/blocked/import":

                case "/api/apps/downloadAndInstall":
                case "/api/apps/downloadAndUpdate":
                case "/api/apps/install":
                case "/api/apps/update":
                case "/api/apps/uninstall":
                case "/api/apps/config/set":

                case "/api/admin/sessions/createToken":
                case "/api/admin/users/create":
                case "/api/admin/users/set":
                case "/api/admin/users/delete":
                case "/api/admin/groups/create":
                case "/api/admin/groups/set":
                case "/api/admin/groups/delete":
                    return ClusterNodeType.Primary; //this api can be called only on primary node

                case "/api/user/login":
                case "/api/user/logout":
                case "/api/user/session/get":
                case "/api/user/session/delete":
                    return ClusterNodeType.Secondary; //this api must be called on current node

                default:
                    return ClusterNodeType.Unknown; //this api can be called on any specified node
            }
        }

        private Task WebServiceHttpsRedirectionMiddleware(HttpContext context, RequestDelegate next)
        {
            if (context.Request.IsHttps)
                return next(context);

            context.Response.Redirect("https://" + (context.Request.Host.HasValue ? context.Request.Host.Host : _dnsServer.ServerDomain) + (_webServiceTlsPort == 443 ? "" : ":" + _webServiceTlsPort) + context.Request.Path + (context.Request.QueryString.HasValue ? context.Request.QueryString.Value : ""), false, true);
            return Task.CompletedTask;
        }

        private async Task WebServiceApiMiddleware(HttpContext context, RequestDelegate next)
        {
            HttpRequest request = context.Request;

            if (_clusterManager.ClusterInitialized)
            {
                ClusterNodeType pathNodeType = GetClusterNodeTypeForPath(request.Path);
                switch (pathNodeType)
                {
                    case ClusterNodeType.Primary:
                        //this api can be called only on primary node
                        ClusterNode selfNode = _clusterManager.GetSelfNode();
                        if (selfNode.Type == ClusterNodeType.Secondary)
                        {
                            //validate user session before proxying request
                            if (!TryGetSession(context, out UserSession session))
                                throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                            //proxy to primary node
                            ClusterNode primaryNode = _clusterManager.GetPrimaryNode();
                            await primaryNode.ProxyRequest(context, session.User.Username);
                            return;
                        }

                        break;

                    case ClusterNodeType.Secondary:
                        //this api must be called on current node
                        break;

                    default:
                        //this api can be called on any specified node
                        string nodeName = request.GetQueryOrForm("node", null);
                        if (!string.IsNullOrEmpty(nodeName) && (nodeName != "cluster"))
                        {
                            if (!_clusterManager.TryGetClusterNode(nodeName, out ClusterNode node))
                                throw new DnsWebServiceException("No such node exists in the Cluster by name: " + nodeName);

                            if (node.State != ClusterNodeState.Self)
                            {
                                //validate user session before proxying request
                                if (!TryGetSession(context, out UserSession session))
                                    throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                                //proxy request to the specified cluster node
                                await node.ProxyRequest(context, session.User.Username);
                                return;
                            }
                        }

                        break;
                }
            }

            bool needsJsonResponseObject;

            switch (request.Path)
            {
                case "/api/user/login":
                case "/api/user/createToken":
                case "/api/user/logout":
                    needsJsonResponseObject = false;
                    break;

                case "/api/user/session/get":
                    {
                        if (!TryGetSession(context, out UserSession session))
                            throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                        context.Items["session"] = session;

                        needsJsonResponseObject = false;
                    }
                    break;

                case "/api/zones/export":
                case "/api/allowed/export":
                case "/api/blocked/export":
                case "/api/settings/backup":
                case "/api/logs/download":
                case "/api/logs/export":
                case "/api/admin/cluster/primary/transferConfig":
                    {
                        if (!TryGetSession(context, out UserSession session))
                            throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                        context.Items["session"] = session;

                        await next(context);
                    }
                    return;

                default:
                    if (request.Path.Value.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!TryGetSession(context, out UserSession session))
                            throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                        context.Items["session"] = session;
                        needsJsonResponseObject = true;
                    }
                    else
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        context.Response.ContentLength = 0;
                        return;
                    }

                    break;
            }

            using (MemoryStream mS = new MemoryStream(4096))
            {
                Utf8JsonWriter jsonWriter = new Utf8JsonWriter(mS);
                context.Items["jsonWriter"] = jsonWriter;

                jsonWriter.WriteStartObject();

                if (needsJsonResponseObject)
                {
                    jsonWriter.WritePropertyName("response");
                    jsonWriter.WriteStartObject();

                    await next(context);

                    jsonWriter.WriteEndObject();
                }
                else
                {
                    await next(context);
                }

                jsonWriter.WriteString("server", _dnsServer.ServerDomain);
                jsonWriter.WriteString("status", "ok");

                jsonWriter.WriteEndObject();
                jsonWriter.Flush();

                mS.Position = 0;

                HttpResponse response = context.Response;

                object apiFallback = context.Items["apiFallback"]; //check api fallback mark
                if (apiFallback is null)
                {
                    response.StatusCode = StatusCodes.Status200OK;
                    response.ContentType = "application/json; charset=utf-8";
                    response.ContentLength = mS.Length;

                    await mS.CopyToAsync(response.Body);
                }
                else
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    context.Response.ContentLength = 0;
                }
            }
        }

        private void WebServiceExceptionHandler(IApplicationBuilder exceptionHandlerApp)
        {
            exceptionHandlerApp.Run(async delegate (HttpContext context)
            {
                IExceptionHandlerPathFeature exceptionHandlerPathFeature = context.Features.Get<IExceptionHandlerPathFeature>();
                if (exceptionHandlerPathFeature.Path.StartsWith("/api/"))
                {
                    Exception ex = exceptionHandlerPathFeature.Error;

                    context.Response.StatusCode = StatusCodes.Status200OK;
                    context.Response.ContentType = "application/json; charset=utf-8";

                    await using (Utf8JsonWriter jsonWriter = new Utf8JsonWriter(context.Response.Body))
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("server", _dnsServer.ServerDomain);

                        if (ex is TwoFactorAuthRequiredWebServiceException)
                        {
                            jsonWriter.WriteString("status", "2fa-required");
                            jsonWriter.WriteString("errorMessage", ex.Message);
                        }
                        else if (ex is InvalidTokenWebServiceException)
                        {
                            jsonWriter.WriteString("status", "invalid-token");
                            jsonWriter.WriteString("errorMessage", ex.Message);
                        }
                        else
                        {
                            _log.Write(context.GetRemoteEndPoint(_webServiceRealIpHeader), ex);

                            jsonWriter.WriteString("status", "error");
                            jsonWriter.WriteString("errorMessage", ex.Message);
                            jsonWriter.WriteString("stackTrace", ex.StackTrace);

                            if (ex.InnerException is not null)
                                jsonWriter.WriteString("innerErrorMessage", ex.InnerException.Message);
                        }

                        jsonWriter.WriteEndObject();
                    }
                }
            });
        }

        private bool TryGetSession(HttpContext context, out UserSession session)
        {
            string token = context.Request.GetQueryOrForm("token");
            session = _authManager.GetSession(token);
            if ((session is null) || session.User.Disabled)
                return false;

            if (session.HasExpired())
            {
                _authManager.DeleteSession(session.Token);
                _authManager.SaveConfigFile();
                return false;
            }

            IPEndPoint remoteEP = context.GetRemoteEndPoint(_webServiceRealIpHeader);

            session.UpdateLastSeen(remoteEP.Address, context.Request.Headers.UserAgent);
            return true;
        }

        private User GetSessionUser(HttpContext context, bool standardOnly = false)
        {
            UserSession session = context.GetCurrentSession();

            if ((session.Type == UserSessionType.ApiToken) && _clusterManager.ClusterInitialized && session.TokenName.Equals(_clusterManager.ClusterDomain, StringComparison.OrdinalIgnoreCase))
            {
                //proxy call from cluster node 
                string username = context.Request.GetQueryOrForm("user");

                User user = _authManager.GetUser(username);
                if (user is null)
                    throw new DnsWebServiceException("No such user exists: " + username);

                return user;
            }
            else
            {
                if (standardOnly && (session.Type != UserSessionType.Standard))
                    throw new DnsWebServiceException("Access was denied.");

                return session.User;
            }
        }

        #endregion

        #region tls

        private void StartTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer is null)
            {
                _tlsCertificateUpdateTimer = new Timer(delegate (object state)
                {
                    if (!string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                    {
                        string webServiceTlsCertificatePath = ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                        try
                        {
                            FileInfo fileInfo = new FileInfo(webServiceTlsCertificatePath);

                            if (fileInfo.Exists && (fileInfo.LastWriteTimeUtc != _webServiceCertificateLastModifiedOn))
                            {
                                LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);

                                if (_clusterManager.ClusterInitialized)
                                    _clusterManager.UpdateSelfNodeUrlAndCertificate();
                            }
                        }
                        catch (Exception ex)
                        {
                            _log.Write("DNS Server encountered an error while updating Web Service TLS Certificate: " + webServiceTlsCertificatePath + "\r\n" + ex.ToString());
                        }
                    }
                }, null, TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL, TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL);
            }
        }

        private void StopTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer is not null)
            {
                _tlsCertificateUpdateTimer.Dispose();
                _tlsCertificateUpdateTimer = null;
            }
        }

        private void LoadWebServiceTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword)
        {
            FileInfo fileInfo = new FileInfo(tlsCertificatePath);

            if (!fileInfo.Exists)
                throw new ArgumentException("Web Service TLS certificate file does not exists: " + tlsCertificatePath);

            switch (Path.GetExtension(tlsCertificatePath).ToLowerInvariant())
            {
                case ".pfx":
                case ".p12":
                    break;

                default:
                    throw new ArgumentException("Web Service TLS certificate file must be PKCS #12 formatted with .pfx or .p12 extension: " + tlsCertificatePath);
            }

            X509Certificate2Collection certificateCollection = X509CertificateLoader.LoadPkcs12CollectionFromFile(tlsCertificatePath, tlsCertificatePassword, X509KeyStorageFlags.PersistKeySet);
            X509Certificate2 serverCertificate = null;

            foreach (X509Certificate2 certificate in certificateCollection)
            {
                if (certificate.HasPrivateKey)
                {
                    serverCertificate = certificate;
                    break;
                }
            }

            if (serverCertificate is null)
                throw new ArgumentException("Web Service TLS certificate file must contain a certificate with private key.");

            List<SslApplicationProtocol> applicationProtocols = new List<SslApplicationProtocol>();

            if (_webServiceEnableHttp3)
                applicationProtocols.Add(new SslApplicationProtocol("h3"));

            if (IsHttp2Supported())
                applicationProtocols.Add(new SslApplicationProtocol("h2"));

            applicationProtocols.Add(new SslApplicationProtocol("http/1.1"));

            _webServiceSslServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = applicationProtocols,
                ServerCertificateContext = SslStreamCertificateContext.Create(serverCertificate, certificateCollection, false)
            };

            _webServiceCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

            _log.Write("Web Service TLS certificate was loaded: " + tlsCertificatePath);
        }

        private void RemoveWebServiceTlsCertificate()
        {
            _webServiceSslServerAuthenticationOptions = null;

            _webServiceTlsCertificatePath = null;
            _webServiceTlsCertificatePassword = null;

            StopTlsCertificateUpdateTimer();
        }

        public void SetWebServiceTlsCertificate(string webServiceTlsCertificatePath, string webServiceTlsCertificatePassword)
        {
            if (string.IsNullOrWhiteSpace(webServiceTlsCertificatePath))
                throw new ArgumentException("Web service TLS certificate path cannot be null or empty.", nameof(webServiceTlsCertificatePath));

            if (webServiceTlsCertificatePath.Length > 255)
                throw new ArgumentException("Web service TLS certificate path length cannot exceed 255 characters.", nameof(webServiceTlsCertificatePath));

            if (webServiceTlsCertificatePassword?.Length > 255)
                throw new ArgumentException("Web service TLS certificate password length cannot exceed 255 characters.", nameof(webServiceTlsCertificatePassword));

            webServiceTlsCertificatePath = ConvertToAbsolutePath(webServiceTlsCertificatePath);

            try
            {
                LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, webServiceTlsCertificatePassword);
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading Web Service TLS Certificate: " + webServiceTlsCertificatePath + "\r\n" + ex.ToString());
            }

            _webServiceTlsCertificatePath = ConvertToRelativePath(webServiceTlsCertificatePath);
            _webServiceTlsCertificatePassword = webServiceTlsCertificatePassword;

            StartTlsCertificateUpdateTimer();
        }

        private void CheckAndLoadSelfSignedCertificate(bool generateNew, bool throwException)
        {
            string selfSignedCertificateFilePath = Path.Combine(_configFolder, "self-signed-cert.pfx");

            if (_webServiceUseSelfSignedTlsCertificate)
            {
                string oldSelfSignedCertificateFilePath = Path.Combine(_configFolder, "cert.pfx");

                if (!oldSelfSignedCertificateFilePath.Equals(ConvertToAbsolutePath(_webServiceTlsCertificatePath), Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) && File.Exists(oldSelfSignedCertificateFilePath) && !File.Exists(selfSignedCertificateFilePath))
                    File.Move(oldSelfSignedCertificateFilePath, selfSignedCertificateFilePath);

                if (generateNew || !File.Exists(selfSignedCertificateFilePath))
                {
                    RSA rsa = RSA.Create(2048);
                    CertificateRequest req = new CertificateRequest("cn=" + _dnsServer.ServerDomain, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
                    bool sanAdded = false;

                    foreach (IPAddress localAddress in _webServiceLocalAddresses)
                    {
                        if (localAddress.Equals(IPAddress.IPv6Any) || localAddress.Equals(IPAddress.Any))
                            continue;

                        san.AddIpAddress(localAddress);
                        sanAdded = true;
                    }

                    if (sanAdded)
                        req.CertificateExtensions.Add(san.Build());

                    X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(5));

                    File.WriteAllBytes(selfSignedCertificateFilePath, cert.Export(X509ContentType.Pkcs12, null as string));
                }

                if (_webServiceEnableTls && string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                {
                    try
                    {
                        LoadWebServiceTlsCertificate(selfSignedCertificateFilePath, null);

                        if (!generateNew)
                        {
                            if (_webServiceSslServerAuthenticationOptions.ServerCertificateContext.TargetCertificate.NotAfter < DateTime.UtcNow.AddYears(1))
                            {
                                _log.Write("Web Service TLS self signed certificate is nearing expiration and will be regenerated.");
                                CheckAndLoadSelfSignedCertificate(true, throwException); //force generate new cert

                                if (_clusterManager.ClusterInitialized)
                                    _clusterManager.UpdateSelfNodeUrlAndCertificate();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading self signed Web Service TLS certificate: " + selfSignedCertificateFilePath + "\r\n" + ex.ToString());

                        if (throwException)
                            throw;
                    }
                }
            }
            else
            {
                File.Delete(selfSignedCertificateFilePath);
            }
        }

        #endregion

        #region quic

        private static void ValidateQuicSupport(string protocolName = "DNS-over-QUIC")
        {
#pragma warning disable CA2252 // This API requires opting into preview features
#pragma warning disable CA1416 // Validate platform compatibility

            if (!QuicConnection.IsSupported)
                throw new DnsWebServiceException(protocolName + " is supported only on Windows 11, Windows Server 2022, and Linux. On Linux, you must install 'libmsquic' manually.");

#pragma warning restore CA1416 // Validate platform compatibility
#pragma warning restore CA2252 // This API requires opting into preview features
        }

        private static bool IsQuicSupported()
        {
#pragma warning disable CA2252 // This API requires opting into preview features
#pragma warning disable CA1416 // Validate platform compatibility

            return QuicConnection.IsSupported;

#pragma warning restore CA1416 // Validate platform compatibility
#pragma warning restore CA2252 // This API requires opting into preview features
        }

        #endregion

        #region secondary catalog zones

        private void AuthZoneManager_SecondaryCatalogZoneAdded(object sender, SecondaryCatalogEventArgs e)
        {
            AuthZoneInfo secondaryCatalogZoneInfo = new AuthZoneInfo(sender as ApexZone);
            AuthZoneInfo memberZoneInfo = e.ZoneInfo;

            //clone user/group permissions from source zone
            Permission sourceZonePermissions = _authManager.GetPermission(PermissionSection.Zones, secondaryCatalogZoneInfo.Name);

            foreach (KeyValuePair<User, PermissionFlag> userPermission in sourceZonePermissions.UserPermissions)
                _authManager.SetPermission(PermissionSection.Zones, memberZoneInfo.Name, userPermission.Key, userPermission.Value);

            foreach (KeyValuePair<Group, PermissionFlag> groupPermissions in sourceZonePermissions.GroupPermissions)
                _authManager.SetPermission(PermissionSection.Zones, memberZoneInfo.Name, groupPermissions.Key, groupPermissions.Value);

            //set default permissions
            _authManager.SetPermission(PermissionSection.Zones, memberZoneInfo.Name, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _authManager.SetPermission(PermissionSection.Zones, memberZoneInfo.Name, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _authManager.SaveConfigFile();

            //sync dnssec private keys for secondary members zone when it is a cluster secondary catalog zone
            if (_clusterManager.ClusterInitialized && (memberZoneInfo.Type == AuthZoneType.Secondary) && secondaryCatalogZoneInfo.Name.Equals("cluster-catalog." + _clusterManager.ClusterDomain, StringComparison.OrdinalIgnoreCase))
                _clusterManager.TriggerRefreshForConfig([memberZoneInfo.Name]);

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zone
            _dnsServer.CacheZoneManager.DeleteZone(memberZoneInfo.Name);
        }

        private void AuthZoneManager_SecondaryCatalogZoneRemoved(object sender, SecondaryCatalogEventArgs e)
        {
            _authManager.RemoveAllPermissions(PermissionSection.Zones, e.ZoneInfo.Name);
            _authManager.SaveConfigFile();

            //delete cache for this zone to allow rebuilding cache data without using the current zone
            _dnsServer.CacheZoneManager.DeleteZone(e.ZoneInfo.Name);
        }

        #endregion

        #region public

        public async Task StartAsync(bool throwIfBindFails = false)
        {
            if (_disposed)
                ObjectDisposedException.ThrowIf(_disposed, this);

            if (_isRunning)
                throw new DnsWebServiceException("The DNS web service is already running.");

            try
            {
                //init dns server
                _dnsServer = new DnsServer(_configFolder, Path.Combine(_appFolder, "dohwww"), _log);

                //init dhcp server
                _dhcpServer = new DhcpServer(Path.Combine(_configFolder, "scopes"), _log);
                _dhcpServer.DnsServer = _dnsServer;
                _dhcpServer.AuthManager = _authManager;

                //load web service config file
                LoadConfigFile();

                //load dns config file
                _dnsServer.LoadConfigFile();

                //load all dns applications
                await _dnsServer.DnsApplicationManager.LoadAllApplicationsAsync();

                //load all zones files
                _dnsServer.AuthZoneManager.SecondaryCatalogZoneAdded += AuthZoneManager_SecondaryCatalogZoneAdded;
                _dnsServer.AuthZoneManager.SecondaryCatalogZoneRemoved += AuthZoneManager_SecondaryCatalogZoneRemoved;
                _dnsServer.AuthZoneManager.LoadAllZoneFiles();
                InspectAndFixZonePermissions();

                //disable zones from old config format
                if (_configDisabledZones != null)
                {
                    foreach (string domain in _configDisabledZones)
                    {
                        AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
                        if (zoneInfo is not null)
                        {
                            zoneInfo.Disabled = true;
                            _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                        }
                    }
                }

                //load allowed zone and blocked zone files
                _dnsServer.AllowedZoneManager.LoadAllowedZoneFile();
                _dnsServer.BlockedZoneManager.LoadBlockedZoneFile();
                _dnsServer.BlockListZoneManager.LoadConfigFile();

                //init cluster manager
                _clusterManager = new ClusterManager(this);

                //load cluster config file
                _clusterManager.LoadConfigFile();

                //start web service
                if (throwIfBindFails)
                    await StartWebServiceAsync(false);
                else
                    await TryStartWebServiceAsync([IPAddress.Any, IPAddress.IPv6Any], 5380, 53443);

                //start dns and dhcp
                await _dnsServer.StartAsync(throwIfBindFails);
                _dhcpServer.Start();

                _log.Write("DNS Server (v" + _currentVersion.ToString() + ") was started successfully.");
                _isRunning = true;
            }
            catch (Exception ex)
            {
                _log.Write("Failed to start DNS Server (v" + _currentVersion.ToString() + ")\r\n" + ex.ToString());
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning || _disposed)
                return;

            try
            {
                //stop cluster manager
                _clusterManager?.Dispose();

                //stop web service
                await StopWebServiceAsync();

                //stop dhcp
                _dhcpServer?.Dispose();

                //stop dns & save cache to disk
                if (_dnsServer is not null)
                    await _dnsServer.DisposeAsync();

                _log.Write("DNS Server (v" + _currentVersion.ToString() + ") was stopped successfully.");
                _isRunning = false;
            }
            catch (Exception ex)
            {
                _log.Write("Failed to stop DNS Server (v" + _currentVersion.ToString() + ")\r\n" + ex.ToString());
                throw;
            }
        }

        #endregion

        #region properties

        public DnsServer DnsServer
        { get { return _dnsServer; } }

        public DateTime UpTimeStamp
        { get { return _uptimestamp; } }

        public string ConfigFolder
        { get { return _configFolder; } }

        public int WebServiceHttpPort
        { get { return _webServiceHttpPort; } }

        public int WebServiceTlsPort
        { get { return _webServiceTlsPort; } }

        internal bool IsWebServiceTlsEnabled
        {
            get
            {
                return _webServiceEnableTls && (_webServiceUseSelfSignedTlsCertificate || !string.IsNullOrEmpty(_webServiceTlsCertificatePath)) && (_webServiceSslServerAuthenticationOptions is not null);
            }
        }

        internal X509Certificate2 WebServiceTlsCertificate
        {
            get
            {
                if (_webServiceSslServerAuthenticationOptions is null)
                    return null;

                return _webServiceSslServerAuthenticationOptions.ServerCertificateContext.TargetCertificate;
            }
        }

        internal AuthManager AuthManager
        { get { return _authManager; } }

        internal LogManager LogManager
        { get { return _log; } }

        #endregion
    }
}
