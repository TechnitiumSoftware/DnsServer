/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using DnsServerCore.Dns;
using DnsServerCore.Dns.ZoneManagers;
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
using System.Net;
using System.Net.Mail;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
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
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    public sealed class DnsWebService : IAsyncDisposable, IDisposable
    {
        #region variables

        readonly static char[] commaSeparator = new char[] { ',' };

        internal readonly Version _currentVersion;
        internal readonly DateTime _uptimestamp = DateTime.UtcNow;
        readonly string _appFolder;
        internal readonly string _configFolder;

        internal readonly LogManager _log;
        internal readonly AuthManager _authManager;

        readonly WebServiceApi _api;
        readonly WebServiceDashboardApi _dashboardApi;
        internal readonly WebServiceZonesApi _zonesApi;
        readonly WebServiceOtherZonesApi _otherZonesApi;
        internal readonly WebServiceAppsApi _appsApi;
        readonly WebServiceSettingsApi _settingsApi;
        readonly WebServiceDhcpApi _dhcpApi;
        readonly WebServiceAuthApi _authApi;
        readonly WebServiceLogsApi _logsApi;

        WebApplication _webService;
        X509Certificate2Collection _webServiceCertificateCollection;
        SslServerAuthenticationOptions _webServiceSslServerAuthenticationOptions;

        DnsServer _dnsServer;
        DhcpServer _dhcpServer;

        //web service
        internal IReadOnlyList<IPAddress> _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };
        internal int _webServiceHttpPort = 5380;
        internal int _webServiceTlsPort = 53443;
        internal bool _webServiceEnableTls;
        internal bool _webServiceEnableHttp3;
        internal bool _webServiceHttpToTlsRedirect;
        internal bool _webServiceUseSelfSignedTlsCertificate;
        internal string _webServiceTlsCertificatePath;
        internal string _webServiceTlsCertificatePassword;
        DateTime _webServiceTlsCertificateLastModifiedOn;

        //optional protocols
        internal string _dnsTlsCertificatePath;
        internal string _dnsTlsCertificatePassword;
        DateTime _dnsTlsCertificateLastModifiedOn;

        //cache
        internal bool _saveCache = true;

        Timer _tlsCertificateUpdateTimer;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

        List<string> _configDisabledZones;

        readonly object _saveLock = new object();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 10000;

        #endregion

        #region constructor

        public DnsWebService(string configFolder = null, Uri updateCheckUri = null, Uri appStoreUri = null)
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
            _appsApi = new WebServiceAppsApi(this, appStoreUri);
            _settingsApi = new WebServiceSettingsApi(this);
            _dhcpApi = new WebServiceDhcpApi(this);
            _authApi = new WebServiceAuthApi(this);
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

            if (_appsApi is not null)
                _appsApi.Dispose();

            if (_settingsApi is not null)
                _settingsApi.Dispose();

            if (_authManager is not null)
                _authManager.Dispose();

            if (_log is not null)
                _log.Dispose();

            _disposed = true;
        }

        public void Dispose()
        {
            DisposeAsync().Sync();
        }

        #endregion

        #region internal

        internal string ConvertToRelativePath(string path)
        {
            if (path.StartsWith(_configFolder, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                path = path.Substring(_configFolder.Length).TrimStart(Path.DirectorySeparatorChar);

            return path;
        }

        internal string ConvertToAbsolutePath(string path)
        {
            if (path is null)
                return null;

            if (Path.IsPathRooted(path))
                return path;

            return Path.Combine(_configFolder, path);
        }

        #endregion

        #region server version

        internal string GetServerVersion()
        {
            return GetCleanVersion(_currentVersion);
        }

        internal static string GetCleanVersion(Version version)
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

        internal async Task TryStartWebServiceAsync(IReadOnlyList<IPAddress> oldWebServiceLocalAddresses, int oldWebServiceHttpPort, int oldWebServiceTlsPort)
        {
            try
            {
                _webServiceLocalAddresses = DnsServer.GetValidKestralLocalAddresses(_webServiceLocalAddresses);

                await StartWebServiceAsync(_webServiceLocalAddresses, _webServiceHttpPort, _webServiceTlsPort, false);
                return;
            }
            catch (Exception ex)
            {
                _log.Write("Web Service failed to start: " + ex.ToString());
            }

            _log.Write("Attempting to revert Web Service end point changes ...");

            try
            {
                _webServiceLocalAddresses = DnsServer.GetValidKestralLocalAddresses(oldWebServiceLocalAddresses);
                _webServiceHttpPort = oldWebServiceHttpPort;
                _webServiceTlsPort = oldWebServiceTlsPort;

                await StartWebServiceAsync(_webServiceLocalAddresses, _webServiceHttpPort, _webServiceTlsPort, false);

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

                await StartWebServiceAsync(_webServiceLocalAddresses, _webServiceHttpPort, _webServiceTlsPort, false);
                return;
            }
            catch (Exception ex3)
            {
                _log.Write("Web Service failed to start: " + ex3.ToString());
            }

            _log.Write("Attempting to start Web Service on loopback (127.0.0.1) fallback address...");

            _webServiceLocalAddresses = new IPAddress[] { IPAddress.Loopback };

            await StartWebServiceAsync(_webServiceLocalAddresses, _webServiceHttpPort, _webServiceTlsPort, true);
        }

        private async Task StartWebServiceAsync(IReadOnlyList<IPAddress> webServiceLocalAddresses, int webServiceHttpPort, int webServiceTlsPort, bool safeMode)
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
                foreach (IPAddress webServiceLocalAddress in webServiceLocalAddresses)
                    serverOptions.Listen(webServiceLocalAddress, webServiceHttpPort);

                //https
                if (!safeMode && _webServiceEnableTls && (_webServiceCertificateCollection is not null))
                {
                    foreach (IPAddress webServiceLocalAddress in webServiceLocalAddresses)
                    {
                        serverOptions.Listen(webServiceLocalAddress, webServiceTlsPort, delegate (ListenOptions listenOptions)
                        {
                            listenOptions.Protocols = _webServiceEnableHttp3 ? HttpProtocols.Http1AndHttp2AndHttp3 : HttpProtocols.Http1AndHttp2;
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

            if (_webServiceHttpToTlsRedirect && !safeMode && _webServiceEnableTls && (_webServiceCertificateCollection is not null))
                _webService.Use(WebServiceHttpsRedirectionMiddleware);

            _webService.UseDefaultFiles();
            _webService.UseStaticFiles(new StaticFileOptions()
            {
                OnPrepareResponse = delegate (StaticFileResponseContext ctx)
                {
                    ctx.Context.Response.Headers["X-Robots-Tag"] = "noindex, nofollow";
                    ctx.Context.Response.Headers.CacheControl = "private, max-age=300";
                },
                ServeUnknownFileTypes = true
            });

            ConfigureWebServiceRoutes();

            try
            {
                await _webService.StartAsync();

                foreach (IPAddress webServiceLocalAddress in webServiceLocalAddresses)
                {
                    _log?.Write(new IPEndPoint(webServiceLocalAddress, webServiceHttpPort), "Http", "Web Service was bound successfully.");

                    if (!safeMode && _webServiceEnableTls && (_webServiceCertificateCollection is not null))
                        _log?.Write(new IPEndPoint(webServiceLocalAddress, webServiceTlsPort), "Https", "Web Service was bound successfully.");
                }
            }
            catch
            {
                await StopWebServiceAsync();

                foreach (IPAddress webServiceLocalAddress in webServiceLocalAddresses)
                {
                    _log?.Write(new IPEndPoint(webServiceLocalAddress, webServiceHttpPort), "Http", "Web Service failed to bind.");

                    if (!safeMode && _webServiceEnableTls && (_webServiceCertificateCollection is not null))
                        _log?.Write(new IPEndPoint(webServiceLocalAddress, webServiceTlsPort), "Https", "Web Service failed to bind.");
                }

                throw;
            }
        }

        internal async Task StopWebServiceAsync()
        {
            if (_webService is not null)
            {
                await _webService.DisposeAsync();
                _webService = null;
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
            _webService.MapGetAndPost("/api/user/changePassword", _authApi.ChangePassword);
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
            _webService.MapGetAndPost("/api/zones/dnssec/properties/generatePrivateKey", _zonesApi.GenerateAndAddPrimaryZoneDnssecPrivateKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/updatePrivateKey", _zonesApi.UpdatePrimaryZoneDnssecPrivateKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/deletePrivateKey", _zonesApi.DeletePrimaryZoneDnssecPrivateKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/publishAllPrivateKeys", _zonesApi.PublishAllGeneratedPrimaryZoneDnssecPrivateKeys);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/rolloverDnsKey", _zonesApi.RolloverPrimaryZoneDnsKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/retireDnsKey", _zonesApi.RetirePrimaryZoneDnsKey);
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
            _webService.MapGetAndPost("/api/settings/set", _settingsApi.SetDnsSettings);
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

            //logs
            _webService.MapGetAndPost("/api/logs/list", _logsApi.ListLogs);
            _webService.MapGetAndPost("/api/logs/download", _logsApi.DownloadLogAsync);
            _webService.MapGetAndPost("/api/logs/delete", _logsApi.DeleteLog);
            _webService.MapGetAndPost("/api/logs/deleteAll", _logsApi.DeleteAllLogs);
            _webService.MapGetAndPost("/api/logs/query", _logsApi.QueryLogsAsync);
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
            bool needsJsonResponseObject;

            switch (context.Request.Path)
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
                    {
                        if (!TryGetSession(context, out UserSession session))
                            throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                        context.Items["session"] = session;

                        await next(context);
                    }
                    return;

                default:
                    {
                        if (!TryGetSession(context, out UserSession session))
                            throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                        context.Items["session"] = session;
                        needsJsonResponseObject = true;
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

                jsonWriter.WriteString("status", "ok");

                jsonWriter.WriteEndObject();
                jsonWriter.Flush();

                mS.Position = 0;

                HttpResponse response = context.Response;

                response.StatusCode = StatusCodes.Status200OK;
                response.ContentType = "application/json; charset=utf-8";
                response.ContentLength = mS.Length;

                await mS.CopyToAsync(response.Body);
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

                        if (ex is InvalidTokenWebServiceException)
                        {
                            jsonWriter.WriteString("status", "invalid-token");
                            jsonWriter.WriteString("errorMessage", ex.Message);
                        }
                        else
                        {
                            jsonWriter.WriteString("status", "error");
                            jsonWriter.WriteString("errorMessage", ex.Message);
                            jsonWriter.WriteString("stackTrace", ex.StackTrace);

                            if (ex.InnerException is not null)
                                jsonWriter.WriteString("innerErrorMessage", ex.InnerException.Message);
                        }

                        jsonWriter.WriteEndObject();
                    }

                    _log.Write(context.GetRemoteEndPoint(), ex);
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

            IPEndPoint remoteEP = context.GetRemoteEndPoint();

            session.UpdateLastSeen(remoteEP.Address, context.Request.Headers.UserAgent);
            return true;
        }

        #endregion

        #region tls

        internal void StartTlsCertificateUpdateTimer()
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

                            if (fileInfo.Exists && (fileInfo.LastWriteTimeUtc != _webServiceTlsCertificateLastModifiedOn))
                                LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                        }
                        catch (Exception ex)
                        {
                            _log.Write("DNS Server encountered an error while updating Web Service TLS Certificate: " + webServiceTlsCertificatePath + "\r\n" + ex.ToString());
                        }
                    }

                    if (!string.IsNullOrEmpty(_dnsTlsCertificatePath))
                    {
                        string dnsTlsCertificatePath = ConvertToAbsolutePath(_dnsTlsCertificatePath);

                        try
                        {
                            FileInfo fileInfo = new FileInfo(dnsTlsCertificatePath);

                            if (fileInfo.Exists && (fileInfo.LastWriteTimeUtc != _dnsTlsCertificateLastModifiedOn))
                                LoadDnsTlsCertificate(dnsTlsCertificatePath, _dnsTlsCertificatePassword);
                        }
                        catch (Exception ex)
                        {
                            _log.Write("DNS Server encountered an error while updating DNS Server TLS Certificate: " + dnsTlsCertificatePath + "\r\n" + ex.ToString());
                        }
                    }

                }, null, TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL, TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL);
            }
        }

        internal void StopTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer is not null)
            {
                _tlsCertificateUpdateTimer.Dispose();
                _tlsCertificateUpdateTimer = null;
            }
        }

        internal void LoadWebServiceTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword)
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

            X509Certificate2Collection certificateCollection = new X509Certificate2Collection();
            certificateCollection.Import(tlsCertificatePath, tlsCertificatePassword, X509KeyStorageFlags.PersistKeySet);

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

            _webServiceCertificateCollection = certificateCollection;

            _webServiceSslServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ServerCertificateContext = SslStreamCertificateContext.Create(serverCertificate, _webServiceCertificateCollection, false)
            };

            _webServiceTlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

            _log.Write("Web Service TLS certificate was loaded: " + tlsCertificatePath);
        }

        internal void LoadDnsTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword)
        {
            FileInfo fileInfo = new FileInfo(tlsCertificatePath);

            if (!fileInfo.Exists)
                throw new ArgumentException("DNS Server TLS certificate file does not exists: " + tlsCertificatePath);

            switch (Path.GetExtension(tlsCertificatePath).ToLowerInvariant())
            {
                case ".pfx":
                case ".p12":
                    break;

                default:
                    throw new ArgumentException("DNS Server TLS certificate file must be PKCS #12 formatted with .pfx or .p12 extension: " + tlsCertificatePath);
            }

            X509Certificate2Collection certificateCollection = new X509Certificate2Collection();
            certificateCollection.Import(tlsCertificatePath, tlsCertificatePassword, X509KeyStorageFlags.PersistKeySet);

            _dnsServer.CertificateCollection = certificateCollection;
            _dnsTlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

            _log.Write("DNS Server TLS certificate was loaded: " + tlsCertificatePath);
        }

        internal void SelfSignedCertCheck(bool generateNew, bool throwException)
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
                    X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(5));

                    File.WriteAllBytes(selfSignedCertificateFilePath, cert.Export(X509ContentType.Pkcs12, null as string));
                }

                if (_webServiceEnableTls && string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                {
                    try
                    {
                        LoadWebServiceTlsCertificate(selfSignedCertificateFilePath, null);
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

        internal static void ValidateQuicSupport(string protocolName = "DNS-over-QUIC")
        {
#pragma warning disable CA2252 // This API requires opting into preview features
#pragma warning disable CA1416 // Validate platform compatibility

            if (!QuicConnection.IsSupported)
                throw new DnsWebServiceException(protocolName + " is supported only on Windows 11, Windows Server 2022, and Linux. On Linux, you must install 'libmsquic' manually.");

#pragma warning restore CA1416 // Validate platform compatibility
#pragma warning restore CA2252 // This API requires opting into preview features
        }

        internal static bool IsQuicSupported()
        {
#pragma warning disable CA2252 // This API requires opting into preview features
#pragma warning disable CA1416 // Validate platform compatibility

            return QuicConnection.IsSupported;

#pragma warning restore CA1416 // Validate platform compatibility
#pragma warning restore CA2252 // This API requires opting into preview features
        }

        #endregion

        #region config

        internal void LoadConfigFile()
        {
            string configFile = Path.Combine(_configFolder, "dns.config");

            try
            {
                int version;

                using (FileStream fS = new FileStream(configFile, FileMode.Open, FileAccess.Read))
                {
                    version = ReadConfigFrom(new BinaryReader(fS));
                }

                _log.Write("DNS Server config file was loaded: " + configFile);

                if (version <= 27)
                    SaveConfigFileInternal(); //save as new config version to avoid loading old version next time
            }
            catch (FileNotFoundException)
            {
                _log.Write("DNS Server config file was not found: " + configFile);
                _log.Write("DNS Server is restoring default config file.");

                //general
                string serverDomain = Environment.GetEnvironmentVariable("DNS_SERVER_DOMAIN");
                if (!string.IsNullOrEmpty(serverDomain))
                    _dnsServer.ServerDomain = serverDomain;

                _appsApi.EnableAutomaticUpdate = true;

                string strPreferIPv6 = Environment.GetEnvironmentVariable("DNS_SERVER_PREFER_IPV6");
                if (!string.IsNullOrEmpty(strPreferIPv6))
                    _dnsServer.PreferIPv6 = bool.Parse(strPreferIPv6);

                _dnsServer.DnssecValidation = true;
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

                string webServiceEnableTls = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS");
                if (!string.IsNullOrEmpty(webServiceEnableTls))
                    _webServiceEnableTls = bool.Parse(webServiceEnableTls);

                string webServiceUseSelfSignedTlsCertificate = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_USE_SELF_SIGNED_CERT");
                if (!string.IsNullOrEmpty(webServiceUseSelfSignedTlsCertificate))
                    _webServiceUseSelfSignedTlsCertificate = bool.Parse(webServiceUseSelfSignedTlsCertificate);

                //optional protocols
                string strDnsOverHttp = Environment.GetEnvironmentVariable("DNS_SERVER_OPTIONAL_PROTOCOL_DNS_OVER_HTTP");
                if (!string.IsNullOrEmpty(strDnsOverHttp))
                    _dnsServer.EnableDnsOverHttp = bool.Parse(strDnsOverHttp);

                //recursion
                string strRecursion = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION");
                if (!string.IsNullOrEmpty(strRecursion))
                    _dnsServer.Recursion = Enum.Parse<DnsServerRecursion>(strRecursion, true);
                else
                    _dnsServer.Recursion = DnsServerRecursion.AllowOnlyForPrivateNetworks; //default for security reasons

                string strRecursionNetworkACL = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION_NETWORK_ACL");
                if (!string.IsNullOrEmpty(strRecursionNetworkACL))
                {
                    _dnsServer.RecursionNetworkACL = strRecursionNetworkACL.Split(NetworkAccessControl.Parse, ',');
                }
                else
                {
                    NetworkAddress[] recursionDeniedNetworks = null;
                    NetworkAddress[] recursionAllowedNetworks = null;

                    string strRecursionDeniedNetworks = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION_DENIED_NETWORKS");
                    if (!string.IsNullOrEmpty(strRecursionDeniedNetworks))
                        recursionDeniedNetworks = strRecursionDeniedNetworks.Split(NetworkAddress.Parse, ',');

                    string strRecursionAllowedNetworks = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION_ALLOWED_NETWORKS");
                    if (!string.IsNullOrEmpty(strRecursionAllowedNetworks))
                        recursionAllowedNetworks = strRecursionAllowedNetworks.Split(NetworkAddress.Parse, ',');

                    _dnsServer.RecursionNetworkACL = AuthZoneInfo.ConvertDenyAllowToACL(recursionDeniedNetworks, recursionAllowedNetworks);
                }

                _dnsServer.RandomizeName = false; //default false to allow resolving from bad name servers
                _dnsServer.QnameMinimization = true; //default true to enable privacy feature
                _dnsServer.NsRevalidation = false; //default false to allow resolving misconfigured zones

                //cache
                _dnsServer.CacheZoneManager.MaximumEntries = 10000;

                //blocking
                string strEnableBlocking = Environment.GetEnvironmentVariable("DNS_SERVER_ENABLE_BLOCKING");
                if (!string.IsNullOrEmpty(strEnableBlocking))
                    _dnsServer.EnableBlocking = bool.Parse(strEnableBlocking);

                string strAllowTxtBlockingReport = Environment.GetEnvironmentVariable("DNS_SERVER_ALLOW_TXT_BLOCKING_REPORT");
                if (!string.IsNullOrEmpty(strAllowTxtBlockingReport))
                    _dnsServer.AllowTxtBlockingReport = bool.Parse(strAllowTxtBlockingReport);

                string strBlockListUrls = Environment.GetEnvironmentVariable("DNS_SERVER_BLOCK_LIST_URLS");
                if (!string.IsNullOrEmpty(strBlockListUrls))
                {
                    string[] strBlockListUrlList = strBlockListUrls.Split(commaSeparator, StringSplitOptions.RemoveEmptyEntries);

                    foreach (string strBlockListUrl in strBlockListUrlList)
                    {
                        if (strBlockListUrl.StartsWith('!'))
                        {
                            Uri allowListUrl = new Uri(strBlockListUrl.Substring(1));

                            if (!_dnsServer.BlockListZoneManager.AllowListUrls.Contains(allowListUrl))
                                _dnsServer.BlockListZoneManager.AllowListUrls.Add(allowListUrl);
                        }
                        else
                        {
                            Uri blockListUrl = new Uri(strBlockListUrl);

                            if (!_dnsServer.BlockListZoneManager.BlockListUrls.Contains(blockListUrl))
                                _dnsServer.BlockListZoneManager.BlockListUrls.Add(blockListUrl);
                        }
                    }
                }

                //proxy & forwarders
                string strForwarders = Environment.GetEnvironmentVariable("DNS_SERVER_FORWARDERS");
                if (!string.IsNullOrEmpty(strForwarders))
                {
                    DnsTransportProtocol forwarderProtocol;

                    string strForwarderProtocol = Environment.GetEnvironmentVariable("DNS_SERVER_FORWARDER_PROTOCOL");
                    if (string.IsNullOrEmpty(strForwarderProtocol))
                    {
                        forwarderProtocol = DnsTransportProtocol.Udp;
                    }
                    else
                    {
                        forwarderProtocol = Enum.Parse<DnsTransportProtocol>(strForwarderProtocol, true);
                        if (forwarderProtocol == DnsTransportProtocol.HttpsJson)
                            forwarderProtocol = DnsTransportProtocol.Https;
                    }

                    _dnsServer.Forwarders = strForwarders.Split(delegate (string value)
                    {
                        NameServerAddress forwarder = NameServerAddress.Parse(value);

                        if (forwarder.Protocol != forwarderProtocol)
                            forwarder = forwarder.ChangeProtocol(forwarderProtocol);

                        return forwarder;
                    }, ',');
                }

                //logging
                _dnsServer.ResolverLogManager = _log;

                string strUseLocalTime = Environment.GetEnvironmentVariable("DNS_SERVER_LOG_USING_LOCAL_TIME");
                if (!string.IsNullOrEmpty(strUseLocalTime))
                    _log.UseLocalTime = bool.Parse(strUseLocalTime);

                _dnsServer.StatsManager.EnableInMemoryStats = false;

                SaveConfigFileInternal();
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading config file: " + configFile + "\r\n" + ex.ToString());
                _log.Write("Note: You may try deleting the config file to fix this issue. However, you will lose DNS settings but, zone data wont be affected.");
                throw;
            }

            //exclude web service TLS port to prevent socket pool from occupying it
            UdpClientConnection.SocketPoolExcludedPorts = new int[] { _webServiceTlsPort };
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
            string configFile = Path.Combine(_configFolder, "dns.config");

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize config
                WriteConfigTo(new BinaryWriter(mS));

                //write config
                mS.Position = 0;

                using (FileStream fS = new FileStream(configFile, FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _log.Write("DNS Server config file was saved: " + configFile);
        }

        internal void SaveConfigFile()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        internal void InspectAndFixZonePermissions()
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

        private int ReadConfigFrom(BinaryReader bR)
        {
            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DS") //format
                throw new InvalidDataException("DNS Server config file format is invalid.");

            int version = bR.ReadByte();

            if ((version >= 28) && (version <= 37))
            {
                ReadConfigFrom(bR, version);
            }
            else if ((version >= 2) && (version <= 27))
            {
                ReadOldConfigFrom(bR, version);

                //new default settings
                DnsClientConnection.IPv4SourceAddresses = null;
                DnsClientConnection.IPv6SourceAddresses = null;
                _appsApi.EnableAutomaticUpdate = true;
                _webServiceEnableHttp3 = _webServiceEnableTls && IsQuicSupported();
                _dnsServer.EnableDnsOverHttp3 = _dnsServer.EnableDnsOverHttps && IsQuicSupported();
                _dnsServer.ResponsiblePersonInternal = null;
                _dnsServer.AuthZoneManager.UseSoaSerialDateScheme = false;
                _dnsServer.ZoneTransferAllowedNetworks = null;
                _dnsServer.NotifyAllowedNetworks = null;
                _dnsServer.EDnsClientSubnet = false;
                _dnsServer.EDnsClientSubnetIPv4PrefixLength = 24;
                _dnsServer.EDnsClientSubnetIPv6PrefixLength = 56;
                _dnsServer.EDnsClientSubnetIpv4Override = null;
                _dnsServer.EDnsClientSubnetIpv6Override = null;
                _dnsServer.QpmLimitBypassList = null;
                _dnsServer.BlockingBypassList = null;
                _dnsServer.ResolverConcurrency = 2;
                _dnsServer.CacheZoneManager.ServeStaleAnswerTtl = CacheZoneManager.SERVE_STALE_ANSWER_TTL;
                _dnsServer.CacheZoneManager.ServeStaleResetTtl = CacheZoneManager.SERVE_STALE_RESET_TTL;
                _dnsServer.ServeStaleMaxWaitTime = DnsServer.SERVE_STALE_MAX_WAIT_TIME;
                _dnsServer.ConcurrentForwarding = true;
                _dnsServer.ResolverLogManager = _log;
                _dnsServer.StatsManager.EnableInMemoryStats = false;
            }
            else
            {
                throw new InvalidDataException("DNS Server config version not supported.");
            }

            return version;
        }

        private void ReadConfigFrom(BinaryReader bR, int version)
        {
            //web service
            {
                _webServiceHttpPort = bR.ReadInt32();
                _webServiceTlsPort = bR.ReadInt32();

                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        IPAddress[] localAddresses = new IPAddress[count];

                        for (int i = 0; i < count; i++)
                            localAddresses[i] = IPAddressExtensions.ReadFrom(bR);

                        _webServiceLocalAddresses = localAddresses;
                    }
                    else
                    {
                        _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };
                    }
                }

                _webServiceEnableTls = bR.ReadBoolean();

                if (version >= 33)
                    _webServiceEnableHttp3 = bR.ReadBoolean();
                else
                    _webServiceEnableHttp3 = _webServiceEnableTls && IsQuicSupported();

                _webServiceHttpToTlsRedirect = bR.ReadBoolean();
                _webServiceUseSelfSignedTlsCertificate = bR.ReadBoolean();

                _webServiceTlsCertificatePath = bR.ReadShortString();
                _webServiceTlsCertificatePassword = bR.ReadShortString();

                if (_webServiceTlsCertificatePath.Length == 0)
                    _webServiceTlsCertificatePath = null;

                if (_webServiceTlsCertificatePath is not null)
                {
                    string webServiceTlsCertificatePath = ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                    try
                    {
                        LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + webServiceTlsCertificatePath + "\r\n" + ex.ToString());
                    }

                    StartTlsCertificateUpdateTimer();
                }

                SelfSignedCertCheck(false, false);
            }

            //dns
            {
                //general
                _dnsServer.ServerDomain = bR.ReadShortString();

                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        IPEndPoint[] localEndPoints = new IPEndPoint[count];

                        for (int i = 0; i < count; i++)
                            localEndPoints[i] = (IPEndPoint)EndPointExtensions.ReadFrom(bR);

                        _dnsServer.LocalEndPoints = localEndPoints;
                    }
                    else
                    {
                        _dnsServer.LocalEndPoints = new IPEndPoint[] { new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53) };
                    }
                }

                if (version >= 34)
                {
                    DnsClientConnection.IPv4SourceAddresses = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                    DnsClientConnection.IPv6SourceAddresses = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                }
                else
                {
                    DnsClientConnection.IPv4SourceAddresses = null;
                    DnsClientConnection.IPv6SourceAddresses = null;
                }

                _zonesApi.DefaultRecordTtl = bR.ReadUInt32();

                if (version >= 36)
                {
                    string rp = bR.ReadString();
                    if (rp.Length == 0)
                        _dnsServer.ResponsiblePersonInternal = null;
                    else
                        _dnsServer.ResponsiblePersonInternal = new MailAddress(rp);
                }
                else
                {
                    _dnsServer.ResponsiblePersonInternal = null;
                }

                if (version >= 33)
                {
                    _dnsServer.AuthZoneManager.UseSoaSerialDateScheme = bR.ReadBoolean();
                    _dnsServer.ZoneTransferAllowedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                }
                else
                {
                    _dnsServer.AuthZoneManager.UseSoaSerialDateScheme = false;
                    _dnsServer.ZoneTransferAllowedNetworks = null;
                }

                if (version >= 34)
                    _dnsServer.NotifyAllowedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                else
                    _dnsServer.NotifyAllowedNetworks = null;

                _appsApi.EnableAutomaticUpdate = bR.ReadBoolean();

                _dnsServer.PreferIPv6 = bR.ReadBoolean();
                _dnsServer.UdpPayloadSize = bR.ReadUInt16();
                _dnsServer.DnssecValidation = bR.ReadBoolean();

                if (version >= 29)
                {
                    _dnsServer.EDnsClientSubnet = bR.ReadBoolean();
                    _dnsServer.EDnsClientSubnetIPv4PrefixLength = bR.ReadByte();
                    _dnsServer.EDnsClientSubnetIPv6PrefixLength = bR.ReadByte();
                }
                else
                {
                    _dnsServer.EDnsClientSubnet = false;
                    _dnsServer.EDnsClientSubnetIPv4PrefixLength = 24;
                    _dnsServer.EDnsClientSubnetIPv6PrefixLength = 56;
                }

                if (version >= 35)
                {
                    if (bR.ReadBoolean())
                        _dnsServer.EDnsClientSubnetIpv4Override = NetworkAddress.ReadFrom(bR);
                    else
                        _dnsServer.EDnsClientSubnetIpv4Override = null;

                    if (bR.ReadBoolean())
                        _dnsServer.EDnsClientSubnetIpv6Override = NetworkAddress.ReadFrom(bR);
                    else
                        _dnsServer.EDnsClientSubnetIpv6Override = null;
                }
                else
                {
                    _dnsServer.EDnsClientSubnetIpv4Override = null;
                    _dnsServer.EDnsClientSubnetIpv6Override = null;
                }

                _dnsServer.QpmLimitRequests = bR.ReadInt32();
                _dnsServer.QpmLimitErrors = bR.ReadInt32();
                _dnsServer.QpmLimitSampleMinutes = bR.ReadInt32();
                _dnsServer.QpmLimitIPv4PrefixLength = bR.ReadInt32();
                _dnsServer.QpmLimitIPv6PrefixLength = bR.ReadInt32();

                if (version >= 34)
                    _dnsServer.QpmLimitBypassList = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                else
                    _dnsServer.QpmLimitBypassList = null;

                _dnsServer.ClientTimeout = bR.ReadInt32();
                if (version < 34)
                {
                    if (_dnsServer.ClientTimeout == 4000)
                        _dnsServer.ClientTimeout = 2000;
                }

                _dnsServer.TcpSendTimeout = bR.ReadInt32();
                _dnsServer.TcpReceiveTimeout = bR.ReadInt32();

                if (version >= 30)
                {
                    _dnsServer.QuicIdleTimeout = bR.ReadInt32();
                    _dnsServer.QuicMaxInboundStreams = bR.ReadInt32();
                    _dnsServer.ListenBacklog = bR.ReadInt32();
                }
                else
                {
                    _dnsServer.QuicIdleTimeout = 60000;
                    _dnsServer.QuicMaxInboundStreams = 100;
                    _dnsServer.ListenBacklog = 100;
                }

                //optional protocols
                if (version >= 32)
                {
                    _dnsServer.EnableDnsOverUdpProxy = bR.ReadBoolean();
                    _dnsServer.EnableDnsOverTcpProxy = bR.ReadBoolean();
                }
                else
                {
                    _dnsServer.EnableDnsOverUdpProxy = false;
                    _dnsServer.EnableDnsOverTcpProxy = false;
                }

                _dnsServer.EnableDnsOverHttp = bR.ReadBoolean();
                _dnsServer.EnableDnsOverTls = bR.ReadBoolean();
                _dnsServer.EnableDnsOverHttps = bR.ReadBoolean();

                if (version >= 37)
                    _dnsServer.EnableDnsOverHttp3 = bR.ReadBoolean();
                else
                    _dnsServer.EnableDnsOverHttp3 = _dnsServer.EnableDnsOverHttps && IsQuicSupported();

                if (version >= 32)
                {
                    _dnsServer.EnableDnsOverQuic = bR.ReadBoolean();

                    _dnsServer.DnsOverUdpProxyPort = bR.ReadInt32();
                    _dnsServer.DnsOverTcpProxyPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpPort = bR.ReadInt32();
                    _dnsServer.DnsOverTlsPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpsPort = bR.ReadInt32();
                    _dnsServer.DnsOverQuicPort = bR.ReadInt32();
                }
                else if (version >= 31)
                {
                    _dnsServer.EnableDnsOverQuic = bR.ReadBoolean();

                    _dnsServer.DnsOverHttpPort = bR.ReadInt32();
                    _dnsServer.DnsOverTlsPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpsPort = bR.ReadInt32();
                    _dnsServer.DnsOverQuicPort = bR.ReadInt32();
                }
                else if (version >= 30)
                {
                    _ = bR.ReadBoolean(); //removed EnableDnsOverHttpPort80 value
                    _dnsServer.EnableDnsOverQuic = bR.ReadBoolean();

                    _dnsServer.DnsOverHttpPort = bR.ReadInt32();
                    _dnsServer.DnsOverTlsPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpsPort = bR.ReadInt32();
                    _dnsServer.DnsOverQuicPort = bR.ReadInt32();
                }
                else
                {
                    _dnsServer.EnableDnsOverQuic = false;

                    _dnsServer.DnsOverUdpProxyPort = 538;
                    _dnsServer.DnsOverTcpProxyPort = 538;

                    if (_dnsServer.EnableDnsOverHttps)
                    {
                        _dnsServer.EnableDnsOverHttp = true;
                        _dnsServer.DnsOverHttpPort = 80;
                    }
                    else if (_dnsServer.EnableDnsOverHttp)
                    {
                        _dnsServer.DnsOverHttpPort = 8053;
                    }
                    else
                    {
                        _dnsServer.DnsOverHttpPort = 80;
                    }

                    _dnsServer.DnsOverTlsPort = 853;
                    _dnsServer.DnsOverHttpsPort = 443;
                    _dnsServer.DnsOverQuicPort = 853;
                }

                _dnsTlsCertificatePath = bR.ReadShortString();
                _dnsTlsCertificatePassword = bR.ReadShortString();

                if (_dnsTlsCertificatePath.Length == 0)
                    _dnsTlsCertificatePath = null;

                if (_dnsTlsCertificatePath != null)
                {
                    string dnsTlsCertificatePath = ConvertToAbsolutePath(_dnsTlsCertificatePath);

                    try
                    {
                        LoadDnsTlsCertificate(dnsTlsCertificatePath, _dnsTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading DNS Server TLS certificate: " + dnsTlsCertificatePath + "\r\n" + ex.ToString());
                    }

                    StartTlsCertificateUpdateTimer();
                }

                //tsig
                {
                    int count = bR.ReadByte();
                    Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(count);

                    for (int i = 0; i < count; i++)
                    {
                        string keyName = bR.ReadShortString();
                        string sharedSecret = bR.ReadShortString();
                        TsigAlgorithm algorithm = (TsigAlgorithm)bR.ReadByte();

                        tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, algorithm));
                    }

                    _dnsServer.TsigKeys = tsigKeys;
                }

                //recursion
                _dnsServer.Recursion = (DnsServerRecursion)bR.ReadByte();

                if (version >= 37)
                {
                    _dnsServer.RecursionNetworkACL = AuthZoneInfo.ReadNetworkACLFrom(bR);
                }
                else
                {
                    NetworkAddress[] recursionDeniedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                    NetworkAddress[] recursionAllowedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                    _dnsServer.RecursionNetworkACL = AuthZoneInfo.ConvertDenyAllowToACL(recursionDeniedNetworks, recursionAllowedNetworks);
                }

                _dnsServer.RandomizeName = bR.ReadBoolean();
                _dnsServer.QnameMinimization = bR.ReadBoolean();
                _dnsServer.NsRevalidation = bR.ReadBoolean();

                _dnsServer.ResolverRetries = bR.ReadInt32();
                _dnsServer.ResolverTimeout = bR.ReadInt32();

                if (version >= 37)
                    _dnsServer.ResolverConcurrency = bR.ReadInt32();
                else
                    _dnsServer.ResolverConcurrency = 2;

                _dnsServer.ResolverMaxStackCount = bR.ReadInt32();

                //cache
                if (version >= 30)
                    _saveCache = bR.ReadBoolean();
                else
                    _saveCache = true;

                _dnsServer.ServeStale = bR.ReadBoolean();
                _dnsServer.CacheZoneManager.ServeStaleTtl = bR.ReadUInt32();

                if (version >= 36)
                {
                    _dnsServer.CacheZoneManager.ServeStaleAnswerTtl = bR.ReadUInt32();
                    _dnsServer.CacheZoneManager.ServeStaleResetTtl = bR.ReadUInt32();
                    _dnsServer.ServeStaleMaxWaitTime = bR.ReadInt32();
                }
                else
                {
                    _dnsServer.CacheZoneManager.ServeStaleAnswerTtl = CacheZoneManager.SERVE_STALE_ANSWER_TTL;
                    _dnsServer.CacheZoneManager.ServeStaleResetTtl = CacheZoneManager.SERVE_STALE_RESET_TTL;
                    _dnsServer.ServeStaleMaxWaitTime = DnsServer.SERVE_STALE_MAX_WAIT_TIME;
                }

                _dnsServer.CacheZoneManager.MaximumEntries = bR.ReadInt64();
                _dnsServer.CacheZoneManager.MinimumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.MaximumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.NegativeRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.FailureRecordTtl = bR.ReadUInt32();

                _dnsServer.CachePrefetchEligibility = bR.ReadInt32();
                _dnsServer.CachePrefetchTrigger = bR.ReadInt32();
                _dnsServer.CachePrefetchSampleIntervalInMinutes = bR.ReadInt32();
                _dnsServer.CachePrefetchSampleEligibilityHitsPerHour = bR.ReadInt32();

                //blocking
                _dnsServer.EnableBlocking = bR.ReadBoolean();
                _dnsServer.AllowTxtBlockingReport = bR.ReadBoolean();

                if (version >= 33)
                    _dnsServer.BlockingBypassList = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                else
                    _dnsServer.BlockingBypassList = null;

                _dnsServer.BlockingType = (DnsServerBlockingType)bR.ReadByte();

                {
                    //read custom blocking addresses
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                        List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

                        for (int i = 0; i < count; i++)
                        {
                            IPAddress customAddress = IPAddressExtensions.ReadFrom(bR);

                            switch (customAddress.AddressFamily)
                            {
                                case AddressFamily.InterNetwork:
                                    dnsARecords.Add(new DnsARecordData(customAddress));
                                    break;

                                case AddressFamily.InterNetworkV6:
                                    dnsAAAARecords.Add(new DnsAAAARecordData(customAddress));
                                    break;
                            }
                        }

                        _dnsServer.CustomBlockingARecords = dnsARecords;
                        _dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                    }
                    else
                    {
                        _dnsServer.CustomBlockingARecords = null;
                        _dnsServer.CustomBlockingAAAARecords = null;
                    }
                }

                {
                    //read block list urls
                    int count = bR.ReadByte();

                    _dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                    _dnsServer.BlockListZoneManager.BlockListUrls.Clear();

                    for (int i = 0; i < count; i++)
                    {
                        string listUrl = bR.ReadShortString();

                        if (listUrl.StartsWith('!'))
                            _dnsServer.BlockListZoneManager.AllowListUrls.Add(new Uri(listUrl.Substring(1)));
                        else
                            _dnsServer.BlockListZoneManager.BlockListUrls.Add(new Uri(listUrl));
                    }

                    _settingsApi.BlockListUpdateIntervalHours = bR.ReadInt32();
                    _settingsApi.BlockListLastUpdatedOn = bR.ReadDateTime();
                }

                //proxy & forwarders
                NetProxyType proxyType = (NetProxyType)bR.ReadByte();
                if (proxyType != NetProxyType.None)
                {
                    string address = bR.ReadShortString();
                    int port = bR.ReadInt32();
                    NetworkCredential credential = null;

                    if (bR.ReadBoolean()) //credential set
                        credential = new NetworkCredential(bR.ReadShortString(), bR.ReadShortString());

                    _dnsServer.Proxy = NetProxy.CreateProxy(proxyType, address, port, credential);

                    int count = bR.ReadByte();
                    List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(count);

                    for (int i = 0; i < count; i++)
                        bypassList.Add(new NetProxyBypassItem(bR.ReadShortString()));

                    _dnsServer.Proxy.BypassList = bypassList;
                }
                else
                {
                    _dnsServer.Proxy = null;
                }

                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NameServerAddress[] forwarders = new NameServerAddress[count];

                        for (int i = 0; i < count; i++)
                        {
                            forwarders[i] = new NameServerAddress(bR);

                            if (forwarders[i].Protocol == DnsTransportProtocol.HttpsJson)
                                forwarders[i] = forwarders[i].ChangeProtocol(DnsTransportProtocol.Https);
                        }

                        _dnsServer.Forwarders = forwarders;
                    }
                    else
                    {
                        _dnsServer.Forwarders = null;
                    }
                }

                if (version >= 37)
                    _dnsServer.ConcurrentForwarding = bR.ReadBoolean();
                else
                    _dnsServer.ConcurrentForwarding = true;

                _dnsServer.ForwarderRetries = bR.ReadInt32();
                _dnsServer.ForwarderTimeout = bR.ReadInt32();
                _dnsServer.ForwarderConcurrency = bR.ReadInt32();

                //logging
                if (version >= 33)
                {
                    if (bR.ReadBoolean()) //ignore resolver logs
                        _dnsServer.ResolverLogManager = null;
                    else
                        _dnsServer.ResolverLogManager = _log;
                }
                else
                {
                    _dnsServer.ResolverLogManager = _log;
                }

                if (bR.ReadBoolean()) //log all queries
                    _dnsServer.QueryLogManager = _log;
                else
                    _dnsServer.QueryLogManager = null;

                if (version >= 34)
                    _dnsServer.StatsManager.EnableInMemoryStats = bR.ReadBoolean();
                else
                    _dnsServer.StatsManager.EnableInMemoryStats = false;

                _dnsServer.StatsManager.MaxStatFileDays = bR.ReadInt32();
            }

            if ((_webServiceTlsCertificatePath == null) && (_dnsTlsCertificatePath == null))
                StopTlsCertificateUpdateTimer();
        }

        private void ReadOldConfigFrom(BinaryReader bR, int version)
        {
            _dnsServer.ServerDomain = bR.ReadShortString();
            _webServiceHttpPort = bR.ReadInt32();

            if (version >= 13)
            {
                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        IPAddress[] localAddresses = new IPAddress[count];

                        for (int i = 0; i < count; i++)
                            localAddresses[i] = IPAddressExtensions.ReadFrom(bR);

                        _webServiceLocalAddresses = localAddresses;
                    }
                    else
                    {
                        _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };
                    }
                }

                _webServiceTlsPort = bR.ReadInt32();
                _webServiceEnableTls = bR.ReadBoolean();
                _webServiceHttpToTlsRedirect = bR.ReadBoolean();
                _webServiceTlsCertificatePath = bR.ReadShortString();
                _webServiceTlsCertificatePassword = bR.ReadShortString();

                if (_webServiceTlsCertificatePath.Length == 0)
                    _webServiceTlsCertificatePath = null;

                if (_webServiceTlsCertificatePath != null)
                {
                    string webServiceTlsCertificatePath = ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                    try
                    {
                        LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + webServiceTlsCertificatePath + "\r\n" + ex.ToString());
                    }

                    StartTlsCertificateUpdateTimer();
                }
            }
            else
            {
                _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };

                _webServiceTlsPort = 53443;
                _webServiceEnableTls = false;
                _webServiceHttpToTlsRedirect = false;
                _webServiceTlsCertificatePath = string.Empty;
                _webServiceTlsCertificatePassword = string.Empty;
            }

            _dnsServer.PreferIPv6 = bR.ReadBoolean();

            if (bR.ReadBoolean()) //logQueries
                _dnsServer.QueryLogManager = _log;

            if (version >= 14)
                _dnsServer.StatsManager.MaxStatFileDays = bR.ReadInt32();
            else
                _dnsServer.StatsManager.MaxStatFileDays = 0;

            if (version >= 17)
            {
                _dnsServer.Recursion = (DnsServerRecursion)bR.ReadByte();

                NetworkAddress[] recursionDeniedNetworks = null;
                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NetworkAddress[] networks = new NetworkAddress[count];

                        for (int i = 0; i < count; i++)
                            networks[i] = NetworkAddress.ReadFrom(bR);

                        recursionDeniedNetworks = networks;
                    }
                    else
                    {
                        recursionDeniedNetworks = null;
                    }
                }

                NetworkAddress[] recursionAllowedNetworks = null;
                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NetworkAddress[] networks = new NetworkAddress[count];

                        for (int i = 0; i < count; i++)
                            networks[i] = NetworkAddress.ReadFrom(bR);

                        recursionAllowedNetworks = networks;
                    }
                    else
                    {
                        recursionAllowedNetworks = null;
                    }
                }

                _dnsServer.RecursionNetworkACL = AuthZoneInfo.ConvertDenyAllowToACL(recursionDeniedNetworks, recursionAllowedNetworks);
            }
            else
            {
                bool allowRecursion = bR.ReadBoolean();
                bool allowRecursionOnlyForPrivateNetworks;

                if (version >= 4)
                    allowRecursionOnlyForPrivateNetworks = bR.ReadBoolean();
                else
                    allowRecursionOnlyForPrivateNetworks = true; //default true for security reasons

                if (allowRecursion)
                {
                    if (allowRecursionOnlyForPrivateNetworks)
                        _dnsServer.Recursion = DnsServerRecursion.AllowOnlyForPrivateNetworks;
                    else
                        _dnsServer.Recursion = DnsServerRecursion.Allow;
                }
                else
                {
                    _dnsServer.Recursion = DnsServerRecursion.Deny;
                }
            }

            if (version >= 12)
                _dnsServer.RandomizeName = bR.ReadBoolean();
            else
                _dnsServer.RandomizeName = false; //default false to allow resolving from bad name servers

            if (version >= 15)
                _dnsServer.QnameMinimization = bR.ReadBoolean();
            else
                _dnsServer.QnameMinimization = true; //default true to enable privacy feature

            if (version >= 20)
            {
                _dnsServer.QpmLimitRequests = bR.ReadInt32();
                _dnsServer.QpmLimitErrors = bR.ReadInt32();
                _dnsServer.QpmLimitSampleMinutes = bR.ReadInt32();
                _dnsServer.QpmLimitIPv4PrefixLength = bR.ReadInt32();
                _dnsServer.QpmLimitIPv6PrefixLength = bR.ReadInt32();
            }
            else if (version >= 17)
            {
                _dnsServer.QpmLimitRequests = bR.ReadInt32();
                _dnsServer.QpmLimitSampleMinutes = bR.ReadInt32();
                _ = bR.ReadInt32(); //read obsolete value _dnsServer.QpmLimitSamplingIntervalInMinutes
            }
            else
            {
                _dnsServer.QpmLimitRequests = 0;
                _dnsServer.QpmLimitErrors = 0;
                _dnsServer.QpmLimitSampleMinutes = 1;
                _dnsServer.QpmLimitIPv4PrefixLength = 24;
                _dnsServer.QpmLimitIPv6PrefixLength = 56;
            }

            if (version >= 13)
            {
                _dnsServer.ServeStale = bR.ReadBoolean();
                _dnsServer.CacheZoneManager.ServeStaleTtl = bR.ReadUInt32();
            }
            else
            {
                _dnsServer.ServeStale = true;
                _dnsServer.CacheZoneManager.ServeStaleTtl = CacheZoneManager.SERVE_STALE_TTL;
            }

            if (version >= 9)
            {
                _dnsServer.CachePrefetchEligibility = bR.ReadInt32();
                _dnsServer.CachePrefetchTrigger = bR.ReadInt32();
                _dnsServer.CachePrefetchSampleIntervalInMinutes = bR.ReadInt32();
                _dnsServer.CachePrefetchSampleEligibilityHitsPerHour = bR.ReadInt32();
            }
            else
            {
                _dnsServer.CachePrefetchEligibility = 2;
                _dnsServer.CachePrefetchTrigger = 9;
                _dnsServer.CachePrefetchSampleIntervalInMinutes = 5;
                _dnsServer.CachePrefetchSampleEligibilityHitsPerHour = 30;
            }

            NetProxyType proxyType = (NetProxyType)bR.ReadByte();
            if (proxyType != NetProxyType.None)
            {
                string address = bR.ReadShortString();
                int port = bR.ReadInt32();
                NetworkCredential credential = null;

                if (bR.ReadBoolean()) //credential set
                    credential = new NetworkCredential(bR.ReadShortString(), bR.ReadShortString());

                _dnsServer.Proxy = NetProxy.CreateProxy(proxyType, address, port, credential);

                if (version >= 10)
                {
                    int count = bR.ReadByte();
                    List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(count);

                    for (int i = 0; i < count; i++)
                        bypassList.Add(new NetProxyBypassItem(bR.ReadShortString()));

                    _dnsServer.Proxy.BypassList = bypassList;
                }
                else
                {
                    _dnsServer.Proxy.BypassList = null;
                }
            }
            else
            {
                _dnsServer.Proxy = null;
            }

            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    NameServerAddress[] forwarders = new NameServerAddress[count];

                    for (int i = 0; i < count; i++)
                    {
                        forwarders[i] = new NameServerAddress(bR);
                        if (forwarders[i].Protocol == DnsTransportProtocol.HttpsJson)
                            forwarders[i] = forwarders[i].ChangeProtocol(DnsTransportProtocol.Https);
                    }

                    _dnsServer.Forwarders = forwarders;
                }
                else
                {
                    _dnsServer.Forwarders = null;
                }
            }

            if (version <= 10)
            {
                DnsTransportProtocol forwarderProtocol = (DnsTransportProtocol)bR.ReadByte();
                if (forwarderProtocol == DnsTransportProtocol.HttpsJson)
                    forwarderProtocol = DnsTransportProtocol.Https;

                if (_dnsServer.Forwarders != null)
                {
                    List<NameServerAddress> forwarders = new List<NameServerAddress>();

                    foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                    {
                        if (forwarder.Protocol == forwarderProtocol)
                            forwarders.Add(forwarder);
                        else
                            forwarders.Add(forwarder.ChangeProtocol(forwarderProtocol));
                    }

                    _dnsServer.Forwarders = forwarders;
                }
            }

            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    if (version > 2)
                    {
                        for (int i = 0; i < count; i++)
                        {
                            string username = bR.ReadShortString();
                            string passwordHash = bR.ReadShortString();

                            if (username.Equals("admin", StringComparison.OrdinalIgnoreCase))
                            {
                                _authManager.LoadOldConfig(passwordHash, true);
                                break;
                            }
                        }
                    }
                    else
                    {
                        for (int i = 0; i < count; i++)
                        {
                            string username = bR.ReadShortString();
                            string password = bR.ReadShortString();

                            if (username.Equals("admin", StringComparison.OrdinalIgnoreCase))
                            {
                                _authManager.LoadOldConfig(password, false);
                                break;
                            }
                        }
                    }
                }
            }

            if (version <= 6)
            {
                int count = bR.ReadInt32();
                _configDisabledZones = new List<string>(count);

                for (int i = 0; i < count; i++)
                {
                    string domain = bR.ReadShortString();
                    _configDisabledZones.Add(domain);
                }
            }

            if (version >= 18)
                _dnsServer.EnableBlocking = bR.ReadBoolean();
            else
                _dnsServer.EnableBlocking = true;

            if (version >= 18)
                _dnsServer.BlockingType = (DnsServerBlockingType)bR.ReadByte();
            else if (version >= 16)
                _dnsServer.BlockingType = bR.ReadBoolean() ? DnsServerBlockingType.NxDomain : DnsServerBlockingType.AnyAddress;
            else
                _dnsServer.BlockingType = DnsServerBlockingType.AnyAddress;

            if (version >= 18)
            {
                //read custom blocking addresses
                int count = bR.ReadByte();
                if (count > 0)
                {
                    List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                    List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

                    for (int i = 0; i < count; i++)
                    {
                        IPAddress customAddress = IPAddressExtensions.ReadFrom(bR);

                        switch (customAddress.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                dnsARecords.Add(new DnsARecordData(customAddress));
                                break;

                            case AddressFamily.InterNetworkV6:
                                dnsAAAARecords.Add(new DnsAAAARecordData(customAddress));
                                break;
                        }
                    }

                    _dnsServer.CustomBlockingARecords = dnsARecords;
                    _dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                }
                else
                {
                    _dnsServer.CustomBlockingARecords = null;
                    _dnsServer.CustomBlockingAAAARecords = null;
                }
            }
            else
            {
                _dnsServer.CustomBlockingARecords = null;
                _dnsServer.CustomBlockingAAAARecords = null;
            }

            if (version > 4)
            {
                //read block list urls
                int count = bR.ReadByte();

                _dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                _dnsServer.BlockListZoneManager.BlockListUrls.Clear();

                for (int i = 0; i < count; i++)
                {
                    string listUrl = bR.ReadShortString();

                    if (listUrl.StartsWith('!'))
                        _dnsServer.BlockListZoneManager.AllowListUrls.Add(new Uri(listUrl.Substring(1)));
                    else
                        _dnsServer.BlockListZoneManager.BlockListUrls.Add(new Uri(listUrl));
                }

                _settingsApi.BlockListLastUpdatedOn = bR.ReadDateTime();

                if (version >= 13)
                    _settingsApi.BlockListUpdateIntervalHours = bR.ReadInt32();
            }
            else
            {
                _dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                _dnsServer.BlockListZoneManager.BlockListUrls.Clear();
                _settingsApi.BlockListLastUpdatedOn = DateTime.MinValue;
                _settingsApi.BlockListUpdateIntervalHours = 24;
            }

            if (version >= 11)
            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    IPEndPoint[] localEndPoints = new IPEndPoint[count];

                    for (int i = 0; i < count; i++)
                        localEndPoints[i] = (IPEndPoint)EndPointExtensions.ReadFrom(bR);

                    _dnsServer.LocalEndPoints = localEndPoints;
                }
                else
                {
                    _dnsServer.LocalEndPoints = new IPEndPoint[] { new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53) };
                }
            }
            else if (version >= 6)
            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    IPEndPoint[] localEndPoints = new IPEndPoint[count];

                    for (int i = 0; i < count; i++)
                        localEndPoints[i] = new IPEndPoint(IPAddressExtensions.ReadFrom(bR), 53);

                    _dnsServer.LocalEndPoints = localEndPoints;
                }
                else
                {
                    _dnsServer.LocalEndPoints = new IPEndPoint[] { new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53) };
                }
            }
            else
            {
                _dnsServer.LocalEndPoints = new IPEndPoint[] { new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53) };
            }

            if (version >= 8)
            {
                _dnsServer.EnableDnsOverHttp = bR.ReadBoolean();
                _dnsServer.EnableDnsOverTls = bR.ReadBoolean();
                _dnsServer.EnableDnsOverHttps = bR.ReadBoolean();
                _dnsTlsCertificatePath = bR.ReadShortString();
                _dnsTlsCertificatePassword = bR.ReadShortString();

                if (_dnsTlsCertificatePath.Length == 0)
                    _dnsTlsCertificatePath = null;

                if (_dnsTlsCertificatePath != null)
                {
                    string dnsTlsCertificatePath = ConvertToAbsolutePath(_dnsTlsCertificatePath);

                    try
                    {
                        LoadDnsTlsCertificate(dnsTlsCertificatePath, _dnsTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading DNS Server TLS certificate: " + dnsTlsCertificatePath + "\r\n" + ex.ToString());
                    }

                    StartTlsCertificateUpdateTimer();
                }
            }
            else
            {
                _dnsServer.EnableDnsOverHttp = false;
                _dnsServer.EnableDnsOverTls = false;
                _dnsServer.EnableDnsOverHttps = false;
                _dnsTlsCertificatePath = string.Empty;
                _dnsTlsCertificatePassword = string.Empty;
            }

            if (version >= 19)
            {
                _dnsServer.CacheZoneManager.MinimumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.MaximumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.NegativeRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.FailureRecordTtl = bR.ReadUInt32();
            }
            else
            {
                _dnsServer.CacheZoneManager.MinimumRecordTtl = CacheZoneManager.MINIMUM_RECORD_TTL;
                _dnsServer.CacheZoneManager.MaximumRecordTtl = CacheZoneManager.MAXIMUM_RECORD_TTL;
                _dnsServer.CacheZoneManager.NegativeRecordTtl = CacheZoneManager.NEGATIVE_RECORD_TTL;
                _dnsServer.CacheZoneManager.FailureRecordTtl = CacheZoneManager.FAILURE_RECORD_TTL;
            }

            if (version >= 21)
            {
                int count = bR.ReadByte();
                Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(count);

                for (int i = 0; i < count; i++)
                {
                    string keyName = bR.ReadShortString();
                    string sharedSecret = bR.ReadShortString();
                    TsigAlgorithm algorithm = (TsigAlgorithm)bR.ReadByte();

                    tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, algorithm));
                }

                _dnsServer.TsigKeys = tsigKeys;
            }
            else if (version >= 20)
            {
                int count = bR.ReadByte();
                Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(count);

                for (int i = 0; i < count; i++)
                {
                    string keyName = bR.ReadShortString();
                    string sharedSecret = bR.ReadShortString();

                    tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, TsigAlgorithm.HMAC_SHA256));
                }

                _dnsServer.TsigKeys = tsigKeys;
            }
            else
            {
                _dnsServer.TsigKeys = null;
            }

            if (version >= 22)
                _dnsServer.NsRevalidation = bR.ReadBoolean();
            else
                _dnsServer.NsRevalidation = false; //default false to allow resolving misconfigured zones

            if (version >= 23)
            {
                _dnsServer.AllowTxtBlockingReport = bR.ReadBoolean();
                _zonesApi.DefaultRecordTtl = bR.ReadUInt32();
            }
            else
            {
                _dnsServer.AllowTxtBlockingReport = true;
                _zonesApi.DefaultRecordTtl = 3600;
            }

            if (version >= 24)
            {
                _webServiceUseSelfSignedTlsCertificate = bR.ReadBoolean();

                SelfSignedCertCheck(false, false);
            }
            else
            {
                _webServiceUseSelfSignedTlsCertificate = false;
            }

            if (version >= 25)
                _dnsServer.UdpPayloadSize = bR.ReadUInt16();
            else
                _dnsServer.UdpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE;

            if (version >= 26)
            {
                _dnsServer.DnssecValidation = bR.ReadBoolean();

                _dnsServer.ResolverRetries = bR.ReadInt32();
                _dnsServer.ResolverTimeout = bR.ReadInt32();
                _dnsServer.ResolverMaxStackCount = bR.ReadInt32();

                _dnsServer.ForwarderRetries = bR.ReadInt32();
                _dnsServer.ForwarderTimeout = bR.ReadInt32();
                _dnsServer.ForwarderConcurrency = bR.ReadInt32();

                _dnsServer.ClientTimeout = bR.ReadInt32();
                if (_dnsServer.ClientTimeout == 4000)
                    _dnsServer.ClientTimeout = 2000;

                _dnsServer.TcpSendTimeout = bR.ReadInt32();
                _dnsServer.TcpReceiveTimeout = bR.ReadInt32();
            }
            else
            {
                _dnsServer.DnssecValidation = true;
                CreateForwarderZoneToDisableDnssecForNTP();

                _dnsServer.ResolverRetries = 2;
                _dnsServer.ResolverTimeout = 1500;
                _dnsServer.ResolverMaxStackCount = 16;

                _dnsServer.ForwarderRetries = 3;
                _dnsServer.ForwarderTimeout = 2000;
                _dnsServer.ForwarderConcurrency = 2;

                _dnsServer.ClientTimeout = 2000;
                _dnsServer.TcpSendTimeout = 10000;
                _dnsServer.TcpReceiveTimeout = 10000;
            }

            if (version >= 27)
                _dnsServer.CacheZoneManager.MaximumEntries = bR.ReadInt32();
            else
                _dnsServer.CacheZoneManager.MaximumEntries = 10000;
        }

        private void WriteConfigTo(BinaryWriter bW)
        {
            bW.Write(Encoding.ASCII.GetBytes("DS")); //format
            bW.Write((byte)37); //version

            //web service
            {
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
            }

            //dns
            {
                //general
                bW.WriteShortString(_dnsServer.ServerDomain);

                {
                    bW.Write(Convert.ToByte(_dnsServer.LocalEndPoints.Count));

                    foreach (IPEndPoint localEP in _dnsServer.LocalEndPoints)
                        localEP.WriteTo(bW);
                }

                AuthZoneInfo.WriteNetworkAddressesTo(DnsClientConnection.IPv4SourceAddresses, bW);
                AuthZoneInfo.WriteNetworkAddressesTo(DnsClientConnection.IPv6SourceAddresses, bW);

                bW.Write(_zonesApi.DefaultRecordTtl);

                if (_dnsServer.ResponsiblePersonInternal is null)
                    bW.WriteShortString("");
                else
                    bW.WriteShortString(_dnsServer.ResponsiblePersonInternal.Address);

                bW.Write(_dnsServer.AuthZoneManager.UseSoaSerialDateScheme);

                AuthZoneInfo.WriteNetworkAddressesTo(_dnsServer.ZoneTransferAllowedNetworks, bW);
                AuthZoneInfo.WriteNetworkAddressesTo(_dnsServer.NotifyAllowedNetworks, bW);

                bW.Write(_appsApi.EnableAutomaticUpdate);

                bW.Write(_dnsServer.PreferIPv6);
                bW.Write(_dnsServer.UdpPayloadSize);
                bW.Write(_dnsServer.DnssecValidation);

                bW.Write(_dnsServer.EDnsClientSubnet);
                bW.Write(_dnsServer.EDnsClientSubnetIPv4PrefixLength);
                bW.Write(_dnsServer.EDnsClientSubnetIPv6PrefixLength);

                if (_dnsServer.EDnsClientSubnetIpv4Override is null)
                {
                    bW.Write(false);
                }
                else
                {
                    bW.Write(true);
                    _dnsServer.EDnsClientSubnetIpv4Override.WriteTo(bW);
                }

                if (_dnsServer.EDnsClientSubnetIpv6Override is null)
                {
                    bW.Write(false);
                }
                else
                {
                    bW.Write(true);
                    _dnsServer.EDnsClientSubnetIpv6Override.WriteTo(bW);
                }

                bW.Write(_dnsServer.QpmLimitRequests);
                bW.Write(_dnsServer.QpmLimitErrors);
                bW.Write(_dnsServer.QpmLimitSampleMinutes);
                bW.Write(_dnsServer.QpmLimitIPv4PrefixLength);
                bW.Write(_dnsServer.QpmLimitIPv6PrefixLength);

                AuthZoneInfo.WriteNetworkAddressesTo(_dnsServer.QpmLimitBypassList, bW);

                bW.Write(_dnsServer.ClientTimeout);
                bW.Write(_dnsServer.TcpSendTimeout);
                bW.Write(_dnsServer.TcpReceiveTimeout);
                bW.Write(_dnsServer.QuicIdleTimeout);
                bW.Write(_dnsServer.QuicMaxInboundStreams);
                bW.Write(_dnsServer.ListenBacklog);

                //optional protocols
                bW.Write(_dnsServer.EnableDnsOverUdpProxy);
                bW.Write(_dnsServer.EnableDnsOverTcpProxy);
                bW.Write(_dnsServer.EnableDnsOverHttp);
                bW.Write(_dnsServer.EnableDnsOverTls);
                bW.Write(_dnsServer.EnableDnsOverHttps);
                bW.Write(_dnsServer.EnableDnsOverHttp3);
                bW.Write(_dnsServer.EnableDnsOverQuic);

                bW.Write(_dnsServer.DnsOverUdpProxyPort);
                bW.Write(_dnsServer.DnsOverTcpProxyPort);
                bW.Write(_dnsServer.DnsOverHttpPort);
                bW.Write(_dnsServer.DnsOverTlsPort);
                bW.Write(_dnsServer.DnsOverHttpsPort);
                bW.Write(_dnsServer.DnsOverQuicPort);

                if (_dnsTlsCertificatePath == null)
                    bW.WriteShortString(string.Empty);
                else
                    bW.WriteShortString(_dnsTlsCertificatePath);

                if (_dnsTlsCertificatePassword == null)
                    bW.WriteShortString(string.Empty);
                else
                    bW.WriteShortString(_dnsTlsCertificatePassword);

                //tsig
                if (_dnsServer.TsigKeys is null)
                {
                    bW.Write((byte)0);
                }
                else
                {
                    bW.Write(Convert.ToByte(_dnsServer.TsigKeys.Count));

                    foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsServer.TsigKeys)
                    {
                        bW.WriteShortString(tsigKey.Key);
                        bW.WriteShortString(tsigKey.Value.SharedSecret);
                        bW.Write((byte)tsigKey.Value.Algorithm);
                    }
                }

                //recursion
                bW.Write((byte)_dnsServer.Recursion);
                AuthZoneInfo.WriteNetworkACLTo(_dnsServer.RecursionNetworkACL, bW);

                bW.Write(_dnsServer.RandomizeName);
                bW.Write(_dnsServer.QnameMinimization);
                bW.Write(_dnsServer.NsRevalidation);

                bW.Write(_dnsServer.ResolverRetries);
                bW.Write(_dnsServer.ResolverTimeout);
                bW.Write(_dnsServer.ResolverConcurrency);
                bW.Write(_dnsServer.ResolverMaxStackCount);

                //cache
                bW.Write(_saveCache);
                bW.Write(_dnsServer.ServeStale);
                bW.Write(_dnsServer.CacheZoneManager.ServeStaleTtl);
                bW.Write(_dnsServer.CacheZoneManager.ServeStaleAnswerTtl);
                bW.Write(_dnsServer.CacheZoneManager.ServeStaleResetTtl);
                bW.Write(_dnsServer.ServeStaleMaxWaitTime);

                bW.Write(_dnsServer.CacheZoneManager.MaximumEntries);
                bW.Write(_dnsServer.CacheZoneManager.MinimumRecordTtl);
                bW.Write(_dnsServer.CacheZoneManager.MaximumRecordTtl);
                bW.Write(_dnsServer.CacheZoneManager.NegativeRecordTtl);
                bW.Write(_dnsServer.CacheZoneManager.FailureRecordTtl);

                bW.Write(_dnsServer.CachePrefetchEligibility);
                bW.Write(_dnsServer.CachePrefetchTrigger);
                bW.Write(_dnsServer.CachePrefetchSampleIntervalInMinutes);
                bW.Write(_dnsServer.CachePrefetchSampleEligibilityHitsPerHour);

                //blocking
                bW.Write(_dnsServer.EnableBlocking);
                bW.Write(_dnsServer.AllowTxtBlockingReport);

                AuthZoneInfo.WriteNetworkAddressesTo(_dnsServer.BlockingBypassList, bW);

                bW.Write((byte)_dnsServer.BlockingType);

                {
                    bW.Write(Convert.ToByte(_dnsServer.CustomBlockingARecords.Count + _dnsServer.CustomBlockingAAAARecords.Count));

                    foreach (DnsARecordData record in _dnsServer.CustomBlockingARecords)
                        record.Address.WriteTo(bW);

                    foreach (DnsAAAARecordData record in _dnsServer.CustomBlockingAAAARecords)
                        record.Address.WriteTo(bW);
                }

                {
                    bW.Write(Convert.ToByte(_dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsServer.BlockListZoneManager.BlockListUrls.Count));

                    foreach (Uri allowListUrl in _dnsServer.BlockListZoneManager.AllowListUrls)
                        bW.WriteShortString("!" + allowListUrl.AbsoluteUri);

                    foreach (Uri blockListUrl in _dnsServer.BlockListZoneManager.BlockListUrls)
                        bW.WriteShortString(blockListUrl.AbsoluteUri);

                    bW.Write(_settingsApi.BlockListUpdateIntervalHours);
                    bW.Write(_settingsApi.BlockListLastUpdatedOn);
                }

                //proxy & forwarders
                if (_dnsServer.Proxy == null)
                {
                    bW.Write((byte)NetProxyType.None);
                }
                else
                {
                    bW.Write((byte)_dnsServer.Proxy.Type);
                    bW.WriteShortString(_dnsServer.Proxy.Address);
                    bW.Write(_dnsServer.Proxy.Port);

                    NetworkCredential credential = _dnsServer.Proxy.Credential;

                    if (credential == null)
                    {
                        bW.Write(false);
                    }
                    else
                    {
                        bW.Write(true);
                        bW.WriteShortString(credential.UserName);
                        bW.WriteShortString(credential.Password);
                    }

                    //bypass list
                    {
                        bW.Write(Convert.ToByte(_dnsServer.Proxy.BypassList.Count));

                        foreach (NetProxyBypassItem item in _dnsServer.Proxy.BypassList)
                            bW.WriteShortString(item.Value);
                    }
                }

                if (_dnsServer.Forwarders == null)
                {
                    bW.Write((byte)0);
                }
                else
                {
                    bW.Write(Convert.ToByte(_dnsServer.Forwarders.Count));

                    foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                        forwarder.WriteTo(bW);
                }

                bW.Write(_dnsServer.ConcurrentForwarding);
                bW.Write(_dnsServer.ForwarderRetries);
                bW.Write(_dnsServer.ForwarderTimeout);
                bW.Write(_dnsServer.ForwarderConcurrency);

                //logging
                bW.Write(_dnsServer.ResolverLogManager is null); //ignore resolver logs
                bW.Write(_dnsServer.QueryLogManager is not null); //log all queries
                bW.Write(_dnsServer.StatsManager.EnableInMemoryStats);
                bW.Write(_dnsServer.StatsManager.MaxStatFileDays);
            }
        }

        #endregion

        #region secondary catalog zones

        private void AuthZoneManager_SecondaryCatalogZoneAdded(object sender, SecondaryCatalogEventArgs e)
        {
            AuthZoneInfo sourceZoneInfo = new AuthZoneInfo(sender as ApexZone);
            AuthZoneInfo zoneInfo = e.ZoneInfo;

            //clone user/group permissions from source zone
            Permission sourceZonePermissions = _authManager.GetPermission(PermissionSection.Zones, sourceZoneInfo.Name);

            foreach (KeyValuePair<User, PermissionFlag> userPermission in sourceZonePermissions.UserPermissions)
                _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, userPermission.Key, userPermission.Value);

            foreach (KeyValuePair<Group, PermissionFlag> groupPermissions in sourceZonePermissions.GroupPermissions)
                _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, groupPermissions.Key, groupPermissions.Value);

            //set default permissions
            _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _authManager.SaveConfigFile();
        }

        private void AuthZoneManager_SecondaryCatalogZoneRemoved(object sender, SecondaryCatalogEventArgs e)
        {
            _authManager.RemoveAllPermissions(PermissionSection.Zones, e.ZoneInfo.Name);
            _authManager.SaveConfigFile();
        }

        #endregion

        #region public

        public async Task StartAsync()
        {
            if (_disposed)
                ObjectDisposedException.ThrowIf(_disposed, this);

            try
            {
                //get initial server domain
                string dnsServerDomain = Environment.MachineName.ToLowerInvariant();
                if (!DnsClient.IsDomainNameValid(dnsServerDomain))
                    dnsServerDomain = "dns-server-1"; //use this name instead since machine name is not a valid domain name

                //init dns server
                _dnsServer = new DnsServer(dnsServerDomain, _configFolder, Path.Combine(_appFolder, "dohwww"), _log);

                //init dhcp server
                _dhcpServer = new DhcpServer(Path.Combine(_configFolder, "scopes"), _log);
                _dhcpServer.DnsServer = _dnsServer;
                _dhcpServer.AuthManager = _authManager;

                //load auth config
                _authManager.LoadConfigFile();

                //load config
                LoadConfigFile();

                //load all dns applications
                _dnsServer.DnsApplicationManager.LoadAllApplications();

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

                //load allowed zone and blocked zone
                _dnsServer.AllowedZoneManager.LoadAllowedZoneFile();
                _dnsServer.BlockedZoneManager.LoadBlockedZoneFile();

                //load block list zone async
                if ((_dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsServer.BlockListZoneManager.BlockListUrls.Count) > 0)
                {
                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            _dnsServer.BlockListZoneManager.LoadBlockLists();
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }
                    });

                    if (_settingsApi.BlockListUpdateIntervalHours > 0)
                        _settingsApi.StartBlockListUpdateTimer(false);
                }

                //load dns cache async
                if (_saveCache)
                {
                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            _dnsServer.CacheZoneManager.LoadCacheZoneFile();
                        }
                        catch (Exception ex)
                        {
                            _log.Write("Failed to fully load DNS Cache from disk\r\n" + ex.ToString());
                        }
                    });
                }

                //start web service
                await TryStartWebServiceAsync([IPAddress.Any, IPAddress.IPv6Any], 5380, 53443);

                //start dns and dhcp
                await _dnsServer.StartAsync();
                _dhcpServer.Start();

                _log.Write("DNS Server (v" + _currentVersion.ToString() + ") was started successfully.");
            }
            catch (Exception ex)
            {
                _log.Write("Failed to start DNS Server (v" + _currentVersion.ToString() + ")\r\n" + ex.ToString());
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (_disposed || (_dnsServer is null))
                return;

            try
            {
                //stop dns
                if (_dnsServer is not null)
                    await _dnsServer.DisposeAsync();

                //stop dhcp
                if (_dhcpServer is not null)
                    _dhcpServer.Dispose();

                //stop web service
                if (_settingsApi is not null)
                {
                    _settingsApi.StopBlockListUpdateTimer();
                    _settingsApi.StopTemporaryDisableBlockingTimer();
                }

                StopTlsCertificateUpdateTimer();

                await StopWebServiceAsync();

                if (_saveCache)
                {
                    try
                    {
                        _dnsServer.CacheZoneManager.SaveCacheZoneFile();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                }

                _log?.Write("DNS Server (v" + _currentVersion.ToString() + ") was stopped successfully.");
                _dnsServer = null;
            }
            catch (Exception ex)
            {
                _log?.Write("Failed to stop DNS Server (v" + _currentVersion.ToString() + ")\r\n" + ex.ToString());
                throw;
            }
        }

        public void Start()
        {
            StartAsync().Sync();
        }

        public void Stop()
        {
            StopAsync().Sync();
        }

        #endregion

        #region properties

        internal DnsServer DnsServer
        { get { return _dnsServer; } }

        internal DhcpServer DhcpServer
        { get { return _dhcpServer; } }

        public string ConfigFolder
        { get { return _configFolder; } }

        public int WebServiceHttpPort
        { get { return _webServiceHttpPort; } }

        public int WebServiceTlsPort
        { get { return _webServiceTlsPort; } }

        #endregion
    }
}
