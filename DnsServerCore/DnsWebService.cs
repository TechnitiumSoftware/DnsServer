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

using DnsServerCore.Auth;
using DnsServerCore.Dhcp;
using DnsServerCore.Dns;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.ZoneManagers;
using DnsServerCore.Dns.Zones;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
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
using TechnitiumLibrary.Net.Http;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    public sealed class DnsWebService : IDisposable
    {
        #region enum

        enum ServiceState
        {
            Stopped = 0,
            Starting = 1,
            Running = 2,
            Stopping = 3
        }

        #endregion

        #region variables

        readonly static RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        readonly LogManager _log;
        readonly AuthManager _authManager;

        readonly WebServiceAuthApi _authApi;
        readonly WebServiceDashboardApi _dashboardApi;
        readonly WebServiceZonesApi _zonesApi;
        readonly WebServiceOtherZonesApi _otherZonesApi;
        readonly WebServiceAppsApi _appsApi;
        readonly WebServiceDhcpApi _dhcpApi;
        readonly WebServiceLogsApi _logsApi;

        readonly Version _currentVersion;
        readonly string _appFolder;
        readonly string _configFolder;
        readonly Uri _updateCheckUri;

        DnsServer _dnsServer;
        DhcpServer _dhcpServer;

        IReadOnlyList<IPAddress> _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };
        int _webServiceHttpPort = 5380;
        int _webServiceTlsPort = 53443;
        bool _webServiceEnableTls;
        bool _webServiceHttpToTlsRedirect;
        bool _webServiceUseSelfSignedTlsCertificate;
        string _webServiceTlsCertificatePath;
        string _webServiceTlsCertificatePassword;
        DateTime _webServiceTlsCertificateLastModifiedOn;

        HttpListener _webService;
        IReadOnlyList<Socket> _webServiceTlsListeners;
        X509Certificate2 _webServiceTlsCertificate;
        readonly IndependentTaskScheduler _webServiceTaskScheduler = new IndependentTaskScheduler(ThreadPriority.AboveNormal);
        string _webServiceHostname;
        IPEndPoint _webServiceHttpEP;

        string _dnsTlsCertificatePath;
        string _dnsTlsCertificatePassword;
        DateTime _dnsTlsCertificateLastModifiedOn;

        Timer _tlsCertificateUpdateTimer;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

        volatile ServiceState _state = ServiceState.Stopped;

        Timer _blockListUpdateTimer;
        DateTime _blockListLastUpdatedOn;
        int _blockListUpdateIntervalHours = 24;
        const int BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL = 5000;
        const int BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL = 900000;

        Timer _temporaryDisableBlockingTimer;
        DateTime _temporaryDisableBlockingTill;

        List<string> _configDisabledZones;

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

            if (!Directory.Exists(_configFolder))
                Directory.CreateDirectory(_configFolder);

            _updateCheckUri = updateCheckUri;

            _log = new LogManager(_configFolder);
            _authManager = new AuthManager(_configFolder, _log);

            _authApi = new WebServiceAuthApi(this);
            _dashboardApi = new WebServiceDashboardApi(this);
            _zonesApi = new WebServiceZonesApi(this);
            _otherZonesApi = new WebServiceOtherZonesApi(this);
            _appsApi = new WebServiceAppsApi(this, appStoreUri);
            _dhcpApi = new WebServiceDhcpApi(this);
            _logsApi = new WebServiceLogsApi(this);

            string blockListsFolder = Path.Combine(_configFolder, "blocklists");

            if (!Directory.Exists(blockListsFolder))
                Directory.CreateDirectory(blockListsFolder);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            Stop();

            if (_appsApi is not null)
                _appsApi.Dispose();

            if (_webService is not null)
                _webService.Close();

            if (_dnsServer is not null)
                _dnsServer.Dispose();

            if (_dhcpServer is not null)
                _dhcpServer.Dispose();

            if (_authManager is not null)
                _authManager.Dispose();

            if (_log is not null)
                _log.Dispose();

            _disposed = true;
        }

        #endregion

        #region private

        #region web service

        private async Task AcceptWebRequestAsync()
        {
            try
            {
                while (true)
                {
                    HttpListenerContext context = await _webService.GetContextAsync();

                    if ((_webServiceTlsListeners != null) && (_webServiceTlsListeners.Count > 0) && _webServiceHttpToTlsRedirect)
                    {
                        IPEndPoint remoteEP = context.Request.RemoteEndPoint;

                        if ((remoteEP != null) && !IPAddress.IsLoopback(remoteEP.Address))
                        {
                            string domain = _webServiceTlsCertificate.GetNameInfo(X509NameType.DnsName, false);
                            string redirectUri = "https://" + domain + ":" + _webServiceTlsPort + context.Request.Url.PathAndQuery;

                            context.Response.Redirect(redirectUri);
                            context.Response.Close();

                            continue;
                        }
                    }

                    _ = ProcessRequestAsync(context.Request, context.Response);
                }
            }
            catch (HttpListenerException ex)
            {
                if (ex.ErrorCode == 995)
                    return; //web service stopping

                _log.Write(ex);
            }
            catch (ObjectDisposedException)
            {
                //web service stopped
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //web service stopping

                _log.Write(ex);
            }
        }

        private async Task AcceptTlsWebRequestAsync(Socket tlsListener)
        {
            try
            {
                while (true)
                {
                    Socket socket = await tlsListener.AcceptAsync();

                    _ = TlsToHttpTunnelAsync(socket);
                }
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.OperationAborted)
                    return; //web service stopping

                _log.Write(ex);
            }
            catch (ObjectDisposedException)
            {
                //web service stopped
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //web service stopping

                _log.Write(ex);
            }
        }

        private async Task TlsToHttpTunnelAsync(Socket socket)
        {
            Socket tunnel = null;

            try
            {
                if (_webServiceLocalAddresses.Count < 1)
                    return;

                string remoteIP = (socket.RemoteEndPoint as IPEndPoint).Address.ToString();

                SslStream sslStream = new SslStream(new NetworkStream(socket, true));

                await sslStream.AuthenticateAsServerAsync(_webServiceTlsCertificate);

                tunnel = new Socket(_webServiceHttpEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                tunnel.Connect(_webServiceHttpEP);

                NetworkStream tunnelStream = new NetworkStream(tunnel, true);

                //copy tunnel to ssl
                _ = tunnelStream.CopyToAsync(sslStream).ContinueWith(delegate (Task prevTask) { sslStream.Dispose(); tunnelStream.Dispose(); });

                //copy ssl to tunnel
                try
                {
                    while (true)
                    {
                        HttpRequest httpRequest = await HttpRequest.ReadRequestAsync(sslStream);
                        if (httpRequest == null)
                            return; //connection closed gracefully by client

                        //inject X-Real-IP & host header
                        httpRequest.Headers.Add("X-Real-IP", remoteIP);
                        httpRequest.Headers[HttpRequestHeader.Host] = "localhost:" + _webServiceHttpPort.ToString();

                        //relay request
                        await tunnelStream.WriteAsync(Encoding.ASCII.GetBytes(httpRequest.HttpMethod + " " + httpRequest.RequestPathAndQuery + " " + httpRequest.Protocol + "\r\n"));
                        await tunnelStream.WriteAsync(httpRequest.Headers.ToByteArray());

                        if (httpRequest.InputStream != null)
                            await httpRequest.InputStream.CopyToAsync(tunnelStream);

                        await tunnelStream.FlushAsync();
                    }
                }
                finally
                {
                    sslStream.Dispose();
                    tunnelStream.Dispose();
                }
            }
            catch (IOException)
            {
                //ignore
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
            finally
            {
                socket.Dispose();

                if (tunnel != null)
                    tunnel.Dispose();
            }
        }

        private async Task ProcessRequestAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            response.AddHeader("Server", "");
            response.AddHeader("X-Robots-Tag", "noindex, nofollow");

            try
            {
                Uri url = request.Url;
                string path = url.AbsolutePath;

                if (!path.StartsWith("/") || path.Contains("/../") || path.Contains("/.../"))
                {
                    await SendErrorAsync(response, 404);
                    return;
                }

                if (path.StartsWith("/api/"))
                {
                    using (MemoryStream mS = new MemoryStream())
                    {
                        try
                        {
                            JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                            jsonWriter.WriteStartObject();

                            switch (path)
                            {
                                case "/api/user/login":
                                case "/api/login":
                                    await _authApi.LoginAsync(request, jsonWriter, UserSessionType.Standard);
                                    break;

                                case "/api/user/createToken":
                                    await _authApi.LoginAsync(request, jsonWriter, UserSessionType.ApiToken);
                                    break;

                                case "/api/user/logout":
                                case "/api/logout":
                                    _authApi.Logout(request);
                                    break;

                                case "/api/user/session/get":
                                    _authApi.GetCurrentSessionDetails(request, jsonWriter);
                                    break;

                                default:
                                    if (!TryGetSession(request, out UserSession session))
                                        throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                                    jsonWriter.WritePropertyName("response");
                                    jsonWriter.WriteStartObject();

                                    try
                                    {
                                        switch (path)
                                        {
                                            case "/api/user/session/delete":
                                                _authApi.DeleteSession(request, false);
                                                break;

                                            case "/api/user/changePassword":
                                            case "/api/changePassword":
                                                _authApi.ChangePassword(request);
                                                break;

                                            case "/api/user/profile/get":
                                                _authApi.GetProfile(request, jsonWriter);
                                                break;

                                            case "/api/user/profile/set":
                                                _authApi.SetProfile(request, jsonWriter);
                                                break;

                                            case "/api/user/checkForUpdate":
                                            case "/api/checkForUpdate":
                                                await CheckForUpdateAsync(request, jsonWriter);
                                                break;

                                            case "/api/dashboard/stats/get":
                                            case "/api/getStats":
                                                if (!_authManager.IsPermitted(PermissionSection.Dashboard, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _dashboardApi.GetStats(request, jsonWriter);
                                                break;

                                            case "/api/dashboard/stats/getTop":
                                            case "/api/getTopStats":
                                                if (!_authManager.IsPermitted(PermissionSection.Dashboard, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _dashboardApi.GetTopStats(request, jsonWriter);
                                                break;

                                            case "/api/dashboard/stats/deleteAll":
                                            case "/api/deleteAllStats":
                                                if (!_authManager.IsPermitted(PermissionSection.Dashboard, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _logsApi.DeleteAllStats(request);
                                                break;

                                            case "/api/zones/list":
                                            case "/api/zone/list":
                                            case "/api/listZones":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.ListZones(request, jsonWriter);
                                                break;

                                            case "/api/zones/create":
                                            case "/api/zone/create":
                                            case "/api/createZone":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _zonesApi.CreateZoneAsync(request, jsonWriter);
                                                break;

                                            case "/api/zones/enable":
                                            case "/api/zone/enable":
                                            case "/api/enableZone":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.EnableZone(request);
                                                break;

                                            case "/api/zones/disable":
                                            case "/api/zone/disable":
                                            case "/api/disableZone":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.DisableZone(request);
                                                break;

                                            case "/api/zones/delete":
                                            case "/api/zone/delete":
                                            case "/api/deleteZone":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.DeleteZone(request);
                                                break;

                                            case "/api/zones/resync":
                                            case "/api/zone/resync":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.ResyncZone(request);
                                                break;

                                            case "/api/zones/options/get":
                                            case "/api/zone/options/get":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.GetZoneOptions(request, jsonWriter);
                                                break;

                                            case "/api/zones/options/set":
                                            case "/api/zone/options/set":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.SetZoneOptions(request);
                                                break;

                                            case "/api/zones/permissions/get":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.GetPermissionDetails(request, jsonWriter, PermissionSection.Zones);
                                                break;

                                            case "/api/zones/permissions/set":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.SetPermissionsDetails(request, jsonWriter, PermissionSection.Zones);
                                                break;

                                            case "/api/zones/dnssec/sign":
                                            case "/api/zone/dnssec/sign":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.SignPrimaryZone(request);
                                                break;

                                            case "/api/zones/dnssec/unsign":
                                            case "/api/zone/dnssec/unsign":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.UnsignPrimaryZone(request);
                                                break;

                                            case "/api/zones/dnssec/properties/get":
                                            case "/api/zone/dnssec/getProperties":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.GetPrimaryZoneDnssecProperties(request, jsonWriter);
                                                break;

                                            case "/api/zones/dnssec/properties/convertToNSEC":
                                            case "/api/zone/dnssec/convertToNSEC":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.ConvertPrimaryZoneToNSEC(request);
                                                break;

                                            case "/api/zones/dnssec/properties/convertToNSEC3":
                                            case "/api/zone/dnssec/convertToNSEC3":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.ConvertPrimaryZoneToNSEC3(request);
                                                break;

                                            case "/api/zones/dnssec/properties/updateNSEC3Params":
                                            case "/api/zone/dnssec/updateNSEC3Params":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.UpdatePrimaryZoneNSEC3Parameters(request);
                                                break;

                                            case "/api/zones/dnssec/properties/updateDnsKeyTtl":
                                            case "/api/zone/dnssec/updateDnsKeyTtl":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.UpdatePrimaryZoneDnssecDnsKeyTtl(request);
                                                break;

                                            case "/api/zones/dnssec/properties/generatePrivateKey":
                                            case "/api/zone/dnssec/generatePrivateKey":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.GenerateAndAddPrimaryZoneDnssecPrivateKey(request);
                                                break;

                                            case "/api/zones/dnssec/properties/updatePrivateKey":
                                            case "/api/zone/dnssec/updatePrivateKey":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.UpdatePrimaryZoneDnssecPrivateKey(request);
                                                break;

                                            case "/api/zones/dnssec/properties/deletePrivateKey":
                                            case "/api/zone/dnssec/deletePrivateKey":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.DeletePrimaryZoneDnssecPrivateKey(request);
                                                break;

                                            case "/api/zones/dnssec/properties/publishAllPrivateKeys":
                                            case "/api/zone/dnssec/publishAllPrivateKeys":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.PublishAllGeneratedPrimaryZoneDnssecPrivateKeys(request);
                                                break;

                                            case "/api/zones/dnssec/properties/rolloverDnsKey":
                                            case "/api/zone/dnssec/rolloverDnsKey":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.RolloverPrimaryZoneDnsKey(request);
                                                break;

                                            case "/api/zones/dnssec/properties/retireDnsKey":
                                            case "/api/zone/dnssec/retireDnsKey":
                                                if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _zonesApi.RetirePrimaryZoneDnsKey(request);
                                                break;

                                            case "/api/zones/records/add":
                                            case "/api/zone/addRecord":
                                            case "/api/addRecord":
                                                _zonesApi.AddRecord(request, jsonWriter);
                                                break;

                                            case "/api/zones/records/get":
                                            case "/api/zone/getRecords":
                                            case "/api/getRecords":
                                                _zonesApi.GetRecords(request, jsonWriter);
                                                break;

                                            case "/api/zones/records/update":
                                            case "/api/zone/updateRecord":
                                            case "/api/updateRecord":
                                                _zonesApi.UpdateRecord(request, jsonWriter);
                                                break;

                                            case "/api/zones/records/delete":
                                            case "/api/zone/deleteRecord":
                                            case "/api/deleteRecord":
                                                _zonesApi.DeleteRecord(request);
                                                break;

                                            case "/api/cache/list":
                                            case "/api/listCachedZones":
                                                if (!_authManager.IsPermitted(PermissionSection.Cache, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.ListCachedZones(request, jsonWriter);
                                                break;

                                            case "/api/cache/delete":
                                            case "/api/deleteCachedZone":
                                                if (!_authManager.IsPermitted(PermissionSection.Cache, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.DeleteCachedZone(request);
                                                break;

                                            case "/api/cache/flush":
                                            case "/api/flushDnsCache":
                                                if (!_authManager.IsPermitted(PermissionSection.Cache, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.FlushCache(request);
                                                break;

                                            case "/api/allowed/list":
                                            case "/api/listAllowedZones":
                                                if (!_authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.ListAllowedZones(request, jsonWriter);
                                                break;

                                            case "/api/allowed/add":
                                            case "/api/allowZone":
                                                if (!_authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.AllowZone(request);
                                                break;

                                            case "/api/allowed/delete":
                                            case "/api/deleteAllowedZone":
                                                if (!_authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.DeleteAllowedZone(request);
                                                break;

                                            case "/api/allowed/flush":
                                            case "/api/flushAllowedZone":
                                                if (!_authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.FlushAllowedZone(request);
                                                break;

                                            case "/api/allowed/import":
                                            case "/api/importAllowedZones":
                                                if (!_authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _otherZonesApi.ImportAllowedZonesAsync(request);
                                                break;

                                            case "/api/allowed/export":
                                            case "/api/exportAllowedZones":
                                                if (!_authManager.IsPermitted(PermissionSection.Allowed, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.ExportAllowedZones(response);
                                                return;

                                            case "/api/blocked/list":
                                            case "/api/listBlockedZones":
                                                if (!_authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.ListBlockedZones(request, jsonWriter);
                                                break;

                                            case "/api/blocked/add":
                                            case "/api/blockZone":
                                                if (!_authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.BlockZone(request);
                                                break;

                                            case "/api/blocked/delete":
                                            case "/api/deleteBlockedZone":
                                                if (!_authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.DeleteBlockedZone(request);
                                                break;

                                            case "/api/blocked/flush":
                                            case "/api/flushBlockedZone":
                                                if (!_authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.FlushBlockedZone(request);
                                                break;

                                            case "/api/blocked/import":
                                            case "/api/importBlockedZones":
                                                if (!_authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _otherZonesApi.ImportBlockedZonesAsync(request);
                                                break;

                                            case "/api/blocked/export":
                                            case "/api/exportBlockedZones":
                                                if (!_authManager.IsPermitted(PermissionSection.Blocked, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _otherZonesApi.ExportBlockedZones(response);
                                                return;

                                            case "/api/apps/list":
                                                if (
                                                    _authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.View) ||
                                                    _authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.View) ||
                                                    _authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.View)
                                                   )
                                                {
                                                    await _appsApi.ListInstalledAppsAsync(jsonWriter);
                                                }
                                                else
                                                {
                                                    throw new DnsWebServiceException("Access was denied.");
                                                }

                                                break;

                                            case "/api/apps/listStoreApps":
                                                if (!_authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _appsApi.ListStoreApps(jsonWriter);
                                                break;

                                            case "/api/apps/downloadAndInstall":
                                                if (!_authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _appsApi.DownloadAndInstallAppAsync(request, jsonWriter);
                                                break;

                                            case "/api/apps/downloadAndUpdate":
                                                if (!_authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _appsApi.DownloadAndUpdateAppAsync(request, jsonWriter);
                                                break;

                                            case "/api/apps/install":
                                                if (!_authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _appsApi.InstallAppAsync(request, jsonWriter);
                                                break;

                                            case "/api/apps/update":
                                                if (!_authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _appsApi.UpdateAppAsync(request, jsonWriter);
                                                break;

                                            case "/api/apps/uninstall":
                                                if (!_authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _appsApi.UninstallApp(request);
                                                break;

                                            case "/api/apps/config/get":
                                            case "/api/apps/getConfig":
                                                if (!_authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _appsApi.GetAppConfigAsync(request, jsonWriter);
                                                break;

                                            case "/api/apps/config/set":
                                            case "/api/apps/setConfig":
                                                if (!_authManager.IsPermitted(PermissionSection.Apps, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _appsApi.SetAppConfigAsync(request);
                                                break;

                                            case "/api/dnsClient/resolve":
                                            case "/api/resolveQuery":
                                                if (!_authManager.IsPermitted(PermissionSection.DnsClient, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await ResolveQueryAsync(request, jsonWriter);
                                                break;

                                            case "/api/settings/get":
                                            case "/api/getDnsSettings":
                                                if (!_authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                GetDnsSettings(jsonWriter);
                                                break;

                                            case "/api/settings/set":
                                            case "/api/setDnsSettings":
                                                if (!_authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                SetDnsSettings(request, jsonWriter);
                                                break;

                                            case "/api/settings/getTsigKeyNames":
                                                if (
                                                    _authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.View) ||
                                                    _authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify)
                                                   )
                                                {
                                                    GetTsigKeyNames(jsonWriter);
                                                }
                                                else
                                                {
                                                    throw new DnsWebServiceException("Access was denied.");
                                                }

                                                break;

                                            case "/api/settings/forceUpdateBlockLists":
                                            case "/api/forceUpdateBlockLists":
                                                if (!_authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                ForceUpdateBlockLists(request);
                                                break;

                                            case "/api/settings/temporaryDisableBlocking":
                                            case "/api/temporaryDisableBlocking":
                                                if (!_authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                TemporaryDisableBlocking(request, jsonWriter);
                                                break;

                                            case "/api/settings/backup":
                                            case "/api/backupSettings":
                                                if (!_authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await BackupSettingsAsync(request, response);
                                                return;

                                            case "/api/settings/restore":
                                            case "/api/restoreSettings":
                                                if (!_authManager.IsPermitted(PermissionSection.Settings, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await RestoreSettingsAsync(request, jsonWriter);
                                                break;

                                            case "/api/dhcp/leases/list":
                                            case "/api/listDhcpLeases":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _dhcpApi.ListDhcpLeases(jsonWriter);
                                                break;

                                            case "/api/dhcp/leases/remove":
                                            case "/api/removeDhcpLease":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _dhcpApi.RemoveDhcpLease(request);
                                                break;

                                            case "/api/dhcp/leases/convertToReserved":
                                            case "/api/convertToReservedLease":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _dhcpApi.ConvertToReservedLease(request);
                                                break;

                                            case "/api/dhcp/leases/convertToDynamic":
                                            case "/api/convertToDynamicLease":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _dhcpApi.ConvertToDynamicLease(request);
                                                break;

                                            case "/api/dhcp/scopes/list":
                                            case "/api/listDhcpScopes":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _dhcpApi.ListDhcpScopes(jsonWriter);
                                                break;

                                            case "/api/dhcp/scopes/get":
                                            case "/api/getDhcpScope":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _dhcpApi.GetDhcpScope(request, jsonWriter);
                                                break;

                                            case "/api/dhcp/scopes/set":
                                            case "/api/setDhcpScope":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _dhcpApi.SetDhcpScopeAsync(request);
                                                break;

                                            case "/api/dhcp/scopes/addReservedLease":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _dhcpApi.AddReservedLease(request);
                                                break;

                                            case "/api/dhcp/scopes/removeReservedLease":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _dhcpApi.RemoveReservedLease(request);
                                                break;

                                            case "/api/dhcp/scopes/enable":
                                            case "/api/enableDhcpScope":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _dhcpApi.EnableDhcpScopeAsync(request);
                                                break;

                                            case "/api/dhcp/scopes/disable":
                                            case "/api/disableDhcpScope":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _dhcpApi.DisableDhcpScope(request);
                                                break;

                                            case "/api/dhcp/scopes/delete":
                                            case "/api/deleteDhcpScope":
                                                if (!_authManager.IsPermitted(PermissionSection.DhcpServer, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _dhcpApi.DeleteDhcpScope(request);
                                                break;

                                            case "/api/admin/sessions/list":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.ListSessions(request, jsonWriter);
                                                break;

                                            case "/api/admin/sessions/createToken":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.CreateApiToken(request, jsonWriter);
                                                break;

                                            case "/api/admin/sessions/delete":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.DeleteSession(request, true);
                                                break;

                                            case "/api/admin/users/list":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.ListUsers(jsonWriter);
                                                break;

                                            case "/api/admin/users/create":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.CreateUser(request, jsonWriter);
                                                break;

                                            case "/api/admin/users/get":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.GetUserDetails(request, jsonWriter);
                                                break;

                                            case "/api/admin/users/set":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.SetUserDetails(request, jsonWriter);
                                                break;

                                            case "/api/admin/users/delete":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.DeleteUser(request);
                                                break;

                                            case "/api/admin/groups/list":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.ListGroups(jsonWriter);
                                                break;

                                            case "/api/admin/groups/create":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.CreateGroup(request, jsonWriter);
                                                break;

                                            case "/api/admin/groups/get":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.GetGroupDetails(request, jsonWriter);
                                                break;

                                            case "/api/admin/groups/set":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.Modify))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.SetGroupDetails(request, jsonWriter);
                                                break;

                                            case "/api/admin/groups/delete":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.DeleteGroup(request);
                                                break;

                                            case "/api/admin/permissions/list":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.ListPermissions(jsonWriter);
                                                break;

                                            case "/api/admin/permissions/get":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.GetPermissionDetails(request, jsonWriter, PermissionSection.Unknown);
                                                break;

                                            case "/api/admin/permissions/set":
                                                if (!_authManager.IsPermitted(PermissionSection.Administration, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _authApi.SetPermissionsDetails(request, jsonWriter, PermissionSection.Unknown);
                                                break;

                                            case "/api/logs/list":
                                            case "/api/listLogs":
                                                if (!_authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _logsApi.ListLogs(jsonWriter);
                                                break;

                                            case "/api/logs/download":
                                                if (!_authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _logsApi.DownloadLogAsync(request, response);
                                                return;

                                            case "/api/logs/delete":
                                            case "/api/deleteLog":
                                                if (!_authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _logsApi.DeleteLog(request);
                                                break;

                                            case "/api/logs/deleteAll":
                                            case "/api/deleteAllLogs":
                                                if (!_authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.Delete))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                _logsApi.DeleteAllLogs(request);
                                                break;

                                            case "/api/logs/query":
                                            case "/api/queryLogs":
                                                if (!_authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.View))
                                                    throw new DnsWebServiceException("Access was denied.");

                                                await _logsApi.QueryLogsAsync(request, jsonWriter);
                                                break;

                                            default:
                                                await SendErrorAsync(response, 404);
                                                return;
                                        }
                                    }
                                    finally
                                    {
                                        jsonWriter.WriteEndObject();
                                    }
                                    break;
                            }

                            jsonWriter.WritePropertyName("status");
                            jsonWriter.WriteValue("ok");

                            jsonWriter.WriteEndObject();
                            jsonWriter.Flush();
                        }
                        catch (InvalidTokenWebServiceException ex)
                        {
                            mS.SetLength(0);
                            JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                            jsonWriter.WriteStartObject();

                            jsonWriter.WritePropertyName("status");
                            jsonWriter.WriteValue("invalid-token");

                            jsonWriter.WritePropertyName("errorMessage");
                            jsonWriter.WriteValue(ex.Message);

                            jsonWriter.WriteEndObject();
                            jsonWriter.Flush();
                        }
                        catch (Exception ex)
                        {
                            UserSession session = null;

                            string strToken = request.QueryString["token"];
                            if (!string.IsNullOrEmpty(strToken))
                                session = _authManager.GetSession(strToken);

                            if (session is null)
                                _log.Write(GetRequestRemoteEndPoint(request), ex);
                            else
                                _log.Write(GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] " + ex.ToString());

                            mS.SetLength(0);
                            JsonTextWriter jsonWriter = new JsonTextWriter(new StreamWriter(mS));
                            jsonWriter.WriteStartObject();

                            jsonWriter.WritePropertyName("status");
                            jsonWriter.WriteValue("error");

                            jsonWriter.WritePropertyName("errorMessage");
                            jsonWriter.WriteValue(ex.Message);

                            jsonWriter.WritePropertyName("stackTrace");
                            jsonWriter.WriteValue(ex.StackTrace);

                            if (ex.InnerException != null)
                            {
                                jsonWriter.WritePropertyName("innerErrorMessage");
                                jsonWriter.WriteValue(ex.InnerException.Message);
                            }

                            jsonWriter.WriteEndObject();
                            jsonWriter.Flush();
                        }

                        response.ContentType = "application/json; charset=utf-8";
                        response.ContentEncoding = Encoding.UTF8;
                        response.ContentLength64 = mS.Length;

                        mS.Position = 0;
                        using (Stream stream = response.OutputStream)
                        {
                            await mS.CopyToAsync(stream);
                        }
                    }
                }
                else if (path.StartsWith("/log/"))
                {
                    if (!TryGetSession(request, out UserSession session))
                    {
                        await SendErrorAsync(response, 403, "Invalid token or session expired.");
                        return;
                    }

                    if (!_authManager.IsPermitted(PermissionSection.Logs, session.User, PermissionFlag.View))
                        throw new DnsWebServiceException("Access was denied.");

                    string[] pathParts = path.Split('/');
                    string logFileName = pathParts[2];

                    int limit = 0;
                    string strLimit = request.QueryString["limit"];
                    if (!string.IsNullOrEmpty(strLimit))
                        limit = int.Parse(strLimit);

                    await _log.DownloadLogAsync(request, response, logFileName, limit * 1024 * 1024);
                }
                else
                {
                    if (path == "/")
                    {
                        path = "/index.html";
                    }
                    else if ((path == "/blocklist.txt") && !IPAddress.IsLoopback(GetRequestRemoteEndPoint(request).Address))
                    {
                        await SendErrorAsync(response, 403);
                        return;
                    }

                    string wwwroot = Path.Combine(_appFolder, "www");
                    path = Path.GetFullPath(wwwroot + path.Replace('/', Path.DirectorySeparatorChar));

                    if (!path.StartsWith(wwwroot) || !File.Exists(path))
                    {
                        await SendErrorAsync(response, 404);
                        return;
                    }

                    await SendFileAsync(request, response, path);
                }
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //web service stopping

                UserSession session = null;

                string strToken = request.QueryString["token"];
                if (!string.IsNullOrEmpty(strToken))
                    session = _authManager.GetSession(strToken);

                if (session is null)
                    _log.Write(GetRequestRemoteEndPoint(request), ex);
                else
                    _log.Write(GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] " + ex.ToString());

                await SendError(response, ex);
            }
        }

        internal static IPEndPoint GetRequestRemoteEndPoint(HttpListenerRequest request)
        {
            try
            {
                if (request.RemoteEndPoint == null)
                    return new IPEndPoint(IPAddress.Any, 0);

                if (NetUtilities.IsPrivateIP(request.RemoteEndPoint.Address))
                {
                    string xRealIp = request.Headers["X-Real-IP"];
                    if (IPAddress.TryParse(xRealIp, out IPAddress address))
                    {
                        //get the real IP address of the requesting client from X-Real-IP header set in nginx proxy_pass block
                        return new IPEndPoint(address, 0);
                    }
                }

                return request.RemoteEndPoint;
            }
            catch
            {
                return new IPEndPoint(IPAddress.Any, 0);
            }
        }

        public static Stream GetOutputStream(HttpListenerRequest request, HttpListenerResponse response)
        {
            string strAcceptEncoding = request.Headers["Accept-Encoding"];
            if (string.IsNullOrEmpty(strAcceptEncoding))
            {
                return response.OutputStream;
            }
            else
            {
                if (strAcceptEncoding.Contains("gzip"))
                {
                    response.AddHeader("Content-Encoding", "gzip");
                    return new GZipStream(response.OutputStream, CompressionMode.Compress);
                }
                else if (strAcceptEncoding.Contains("deflate"))
                {
                    response.AddHeader("Content-Encoding", "deflate");
                    return new DeflateStream(response.OutputStream, CompressionMode.Compress);
                }
                else
                {
                    return response.OutputStream;
                }
            }
        }

        private static Task SendError(HttpListenerResponse response, Exception ex)
        {
            return SendErrorAsync(response, 500, ex.ToString());
        }

        private static async Task SendErrorAsync(HttpListenerResponse response, int statusCode, string message = null)
        {
            try
            {
                string statusString = statusCode + " " + DnsServer.GetHttpStatusString((HttpStatusCode)statusCode);
                byte[] buffer = Encoding.UTF8.GetBytes("<html><head><title>" + statusString + "</title></head><body><h1>" + statusString + "</h1>" + (message == null ? "" : "<p>" + message + "</p>") + "</body></html>");

                response.StatusCode = statusCode;
                response.ContentType = "text/html";
                response.ContentLength64 = buffer.Length;

                using (Stream stream = response.OutputStream)
                {
                    await stream.WriteAsync(buffer);
                }
            }
            catch
            { }
        }

        private static async Task SendFileAsync(HttpListenerRequest request, HttpListenerResponse response, string filePath)
        {
            using (FileStream fS = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                response.ContentType = WebUtilities.GetContentType(filePath).MediaType;
                response.AddHeader("Cache-Control", "private, max-age=300");

                using (Stream stream = GetOutputStream(request, response))
                {
                    try
                    {
                        await fS.CopyToAsync(stream);
                    }
                    catch (HttpListenerException)
                    {
                        //ignore this error
                    }
                }
            }
        }

        internal UserSession GetSession(HttpListenerRequest request)
        {
            string strToken = request.QueryString["token"];
            if (string.IsNullOrEmpty(strToken))
                throw new DnsWebServiceException("Parameter 'token' missing.");

            return _authManager.GetSession(strToken);
        }

        internal bool TryGetSession(HttpListenerRequest request, out UserSession session)
        {
            session = GetSession(request);
            if ((session is null) || session.User.Disabled)
                return false;

            if (session.HasExpired())
            {
                _authManager.DeleteSession(session.Token);
                _authManager.SaveConfigFile();
                return false;
            }

            IPEndPoint remoteEP = GetRequestRemoteEndPoint(request);

            session.UpdateLastSeen(remoteEP.Address, request.UserAgent);
            return true;
        }

        #endregion

        #region update api

        private async Task CheckForUpdateAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            if (_updateCheckUri is null)
            {
                jsonWriter.WritePropertyName("updateAvailable");
                jsonWriter.WriteValue(false);
                return;
            }

            try
            {
                SocketsHttpHandler handler = new SocketsHttpHandler();
                handler.Proxy = _dnsServer.Proxy;
                handler.UseProxy = _dnsServer.Proxy is not null;

                using (HttpClient http = new HttpClient(handler))
                {
                    string response = await http.GetStringAsync(_updateCheckUri);
                    dynamic jsonResponse = JsonConvert.DeserializeObject(response);

                    string updateVersion = jsonResponse.updateVersion.Value;
                    string updateTitle = jsonResponse.updateTitle?.Value;
                    string updateMessage = jsonResponse.updateMessage?.Value;
                    string downloadLink = jsonResponse.downloadLink?.Value;
                    string instructionsLink = jsonResponse.instructionsLink?.Value;
                    string changeLogLink = jsonResponse.changeLogLink?.Value;

                    bool updateAvailable = new Version(updateVersion) > _currentVersion;

                    jsonWriter.WritePropertyName("updateAvailable");
                    jsonWriter.WriteValue(updateAvailable);

                    jsonWriter.WritePropertyName("updateVersion");
                    jsonWriter.WriteValue(updateVersion);

                    jsonWriter.WritePropertyName("currentVersion");
                    jsonWriter.WriteValue(GetCleanVersion(_currentVersion));

                    if (updateAvailable)
                    {
                        jsonWriter.WritePropertyName("updateTitle");
                        jsonWriter.WriteValue(updateTitle);

                        jsonWriter.WritePropertyName("updateMessage");
                        jsonWriter.WriteValue(updateMessage);

                        jsonWriter.WritePropertyName("downloadLink");
                        jsonWriter.WriteValue(downloadLink);

                        jsonWriter.WritePropertyName("instructionsLink");
                        jsonWriter.WriteValue(instructionsLink);

                        jsonWriter.WritePropertyName("changeLogLink");
                        jsonWriter.WriteValue(changeLogLink);
                    }

                    string strLog = "Check for update was done {updateAvailable: " + updateAvailable + "; updateVersion: " + updateVersion + ";";

                    if (!string.IsNullOrEmpty(updateTitle))
                        strLog += " updateTitle: " + updateTitle + ";";

                    if (!string.IsNullOrEmpty(updateMessage))
                        strLog += " updateMessage: " + updateMessage + ";";

                    if (!string.IsNullOrEmpty(downloadLink))
                        strLog += " downloadLink: " + downloadLink + ";";

                    if (!string.IsNullOrEmpty(instructionsLink))
                        strLog += " instructionsLink: " + instructionsLink + ";";

                    if (!string.IsNullOrEmpty(changeLogLink))
                        strLog += " changeLogLink: " + changeLogLink + ";";

                    strLog += "}";

                    _log.Write(GetRequestRemoteEndPoint(request), strLog);
                }
            }
            catch (Exception ex)
            {
                _log.Write(GetRequestRemoteEndPoint(request), "Check for update was done {updateAvailable: False;}\r\n" + ex.ToString());

                jsonWriter.WritePropertyName("updateAvailable");
                jsonWriter.WriteValue(false);
            }
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

        internal string GetServerVersion()
        {
            return GetCleanVersion(_currentVersion);
        }

        #endregion

        #region settings api

        private void GetDnsSettings(JsonTextWriter jsonWriter)
        {
            jsonWriter.WritePropertyName("version");
            jsonWriter.WriteValue(GetServerVersion());

            jsonWriter.WritePropertyName("dnsServerDomain");
            jsonWriter.WriteValue(_dnsServer.ServerDomain);

            jsonWriter.WritePropertyName("dnsServerLocalEndPoints");
            jsonWriter.WriteStartArray();

            foreach (IPEndPoint localEP in _dnsServer.LocalEndPoints)
                jsonWriter.WriteValue(localEP.ToString());

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("webServiceLocalAddresses");
            jsonWriter.WriteStartArray();

            foreach (IPAddress localAddress in _webServiceLocalAddresses)
            {
                if (localAddress.AddressFamily == AddressFamily.InterNetworkV6)
                    jsonWriter.WriteValue("[" + localAddress.ToString() + "]");
                else
                    jsonWriter.WriteValue(localAddress.ToString());
            }

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("webServiceHttpPort");
            jsonWriter.WriteValue(_webServiceHttpPort);

            jsonWriter.WritePropertyName("webServiceEnableTls");
            jsonWriter.WriteValue(_webServiceEnableTls);

            jsonWriter.WritePropertyName("webServiceHttpToTlsRedirect");
            jsonWriter.WriteValue(_webServiceHttpToTlsRedirect);

            jsonWriter.WritePropertyName("webServiceTlsPort");
            jsonWriter.WriteValue(_webServiceTlsPort);

            jsonWriter.WritePropertyName("webServiceUseSelfSignedTlsCertificate");
            jsonWriter.WriteValue(_webServiceUseSelfSignedTlsCertificate);

            jsonWriter.WritePropertyName("webServiceTlsCertificatePath");
            jsonWriter.WriteValue(_webServiceTlsCertificatePath);

            jsonWriter.WritePropertyName("webServiceTlsCertificatePassword");
            jsonWriter.WriteValue("************");

            jsonWriter.WritePropertyName("enableDnsOverHttp");
            jsonWriter.WriteValue(_dnsServer.EnableDnsOverHttp);

            jsonWriter.WritePropertyName("enableDnsOverTls");
            jsonWriter.WriteValue(_dnsServer.EnableDnsOverTls);

            jsonWriter.WritePropertyName("enableDnsOverHttps");
            jsonWriter.WriteValue(_dnsServer.EnableDnsOverHttps);

            jsonWriter.WritePropertyName("dnsTlsCertificatePath");
            jsonWriter.WriteValue(_dnsTlsCertificatePath);

            jsonWriter.WritePropertyName("dnsTlsCertificatePassword");
            jsonWriter.WriteValue("************");

            jsonWriter.WritePropertyName("tsigKeys");
            {
                jsonWriter.WriteStartArray();

                if (_dnsServer.TsigKeys is not null)
                {
                    foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsServer.TsigKeys)
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WritePropertyName("keyName");
                        jsonWriter.WriteValue(tsigKey.Key);

                        jsonWriter.WritePropertyName("sharedSecret");
                        jsonWriter.WriteValue(tsigKey.Value.SharedSecret);

                        jsonWriter.WritePropertyName("algorithmName");
                        jsonWriter.WriteValue(tsigKey.Value.AlgorithmName);

                        jsonWriter.WriteEndObject();
                    }
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("defaultRecordTtl");
            jsonWriter.WriteValue(_zonesApi.DefaultRecordTtl);

            jsonWriter.WritePropertyName("dnsAppsEnableAutomaticUpdate");
            jsonWriter.WriteValue(_appsApi.EnableAutomaticUpdate);

            jsonWriter.WritePropertyName("preferIPv6");
            jsonWriter.WriteValue(_dnsServer.PreferIPv6);

            jsonWriter.WritePropertyName("udpPayloadSize");
            jsonWriter.WriteValue(_dnsServer.UdpPayloadSize);

            jsonWriter.WritePropertyName("dnssecValidation");
            jsonWriter.WriteValue(_dnsServer.DnssecValidation);

            jsonWriter.WritePropertyName("resolverRetries");
            jsonWriter.WriteValue(_dnsServer.ResolverRetries);

            jsonWriter.WritePropertyName("resolverTimeout");
            jsonWriter.WriteValue(_dnsServer.ResolverTimeout);

            jsonWriter.WritePropertyName("resolverMaxStackCount");
            jsonWriter.WriteValue(_dnsServer.ResolverMaxStackCount);

            jsonWriter.WritePropertyName("forwarderRetries");
            jsonWriter.WriteValue(_dnsServer.ForwarderRetries);

            jsonWriter.WritePropertyName("forwarderTimeout");
            jsonWriter.WriteValue(_dnsServer.ForwarderTimeout);

            jsonWriter.WritePropertyName("forwarderConcurrency");
            jsonWriter.WriteValue(_dnsServer.ForwarderConcurrency);

            jsonWriter.WritePropertyName("clientTimeout");
            jsonWriter.WriteValue(_dnsServer.ClientTimeout);

            jsonWriter.WritePropertyName("tcpSendTimeout");
            jsonWriter.WriteValue(_dnsServer.TcpSendTimeout);

            jsonWriter.WritePropertyName("tcpReceiveTimeout");
            jsonWriter.WriteValue(_dnsServer.TcpReceiveTimeout);

            jsonWriter.WritePropertyName("enableLogging");
            jsonWriter.WriteValue(_log.EnableLogging);

            jsonWriter.WritePropertyName("logQueries");
            jsonWriter.WriteValue(_dnsServer.QueryLogManager != null);

            jsonWriter.WritePropertyName("useLocalTime");
            jsonWriter.WriteValue(_log.UseLocalTime);

            jsonWriter.WritePropertyName("logFolder");
            jsonWriter.WriteValue(_log.LogFolder);

            jsonWriter.WritePropertyName("maxLogFileDays");
            jsonWriter.WriteValue(_log.MaxLogFileDays);

            jsonWriter.WritePropertyName("maxStatFileDays");
            jsonWriter.WriteValue(_dnsServer.StatsManager.MaxStatFileDays);

            jsonWriter.WritePropertyName("recursion");
            jsonWriter.WriteValue(_dnsServer.Recursion.ToString());

            jsonWriter.WritePropertyName("recursionDeniedNetworks");
            {
                jsonWriter.WriteStartArray();

                if (_dnsServer.RecursionDeniedNetworks is not null)
                {
                    foreach (NetworkAddress networkAddress in _dnsServer.RecursionDeniedNetworks)
                        jsonWriter.WriteValue(networkAddress.ToString());
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("recursionAllowedNetworks");
            {
                jsonWriter.WriteStartArray();

                if (_dnsServer.RecursionAllowedNetworks is not null)
                {
                    foreach (NetworkAddress networkAddress in _dnsServer.RecursionAllowedNetworks)
                        jsonWriter.WriteValue(networkAddress.ToString());
                }

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("randomizeName");
            jsonWriter.WriteValue(_dnsServer.RandomizeName);

            jsonWriter.WritePropertyName("qnameMinimization");
            jsonWriter.WriteValue(_dnsServer.QnameMinimization);

            jsonWriter.WritePropertyName("nsRevalidation");
            jsonWriter.WriteValue(_dnsServer.NsRevalidation);

            jsonWriter.WritePropertyName("qpmLimitRequests");
            jsonWriter.WriteValue(_dnsServer.QpmLimitRequests);

            jsonWriter.WritePropertyName("qpmLimitErrors");
            jsonWriter.WriteValue(_dnsServer.QpmLimitErrors);

            jsonWriter.WritePropertyName("qpmLimitSampleMinutes");
            jsonWriter.WriteValue(_dnsServer.QpmLimitSampleMinutes);

            jsonWriter.WritePropertyName("qpmLimitIPv4PrefixLength");
            jsonWriter.WriteValue(_dnsServer.QpmLimitIPv4PrefixLength);

            jsonWriter.WritePropertyName("qpmLimitIPv6PrefixLength");
            jsonWriter.WriteValue(_dnsServer.QpmLimitIPv6PrefixLength);

            jsonWriter.WritePropertyName("serveStale");
            jsonWriter.WriteValue(_dnsServer.ServeStale);

            jsonWriter.WritePropertyName("serveStaleTtl");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.ServeStaleTtl);

            jsonWriter.WritePropertyName("cacheMaximumEntries");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.MaximumEntries);

            jsonWriter.WritePropertyName("cacheMinimumRecordTtl");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.MinimumRecordTtl);

            jsonWriter.WritePropertyName("cacheMaximumRecordTtl");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.MaximumRecordTtl);

            jsonWriter.WritePropertyName("cacheNegativeRecordTtl");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.NegativeRecordTtl);

            jsonWriter.WritePropertyName("cacheFailureRecordTtl");
            jsonWriter.WriteValue(_dnsServer.CacheZoneManager.FailureRecordTtl);

            jsonWriter.WritePropertyName("cachePrefetchEligibility");
            jsonWriter.WriteValue(_dnsServer.CachePrefetchEligibility);

            jsonWriter.WritePropertyName("cachePrefetchTrigger");
            jsonWriter.WriteValue(_dnsServer.CachePrefetchTrigger);

            jsonWriter.WritePropertyName("cachePrefetchSampleIntervalInMinutes");
            jsonWriter.WriteValue(_dnsServer.CachePrefetchSampleIntervalInMinutes);

            jsonWriter.WritePropertyName("cachePrefetchSampleEligibilityHitsPerHour");
            jsonWriter.WriteValue(_dnsServer.CachePrefetchSampleEligibilityHitsPerHour);

            jsonWriter.WritePropertyName("proxy");
            if (_dnsServer.Proxy == null)
            {
                jsonWriter.WriteNull();
            }
            else
            {
                jsonWriter.WriteStartObject();

                NetProxy proxy = _dnsServer.Proxy;

                jsonWriter.WritePropertyName("type");
                jsonWriter.WriteValue(proxy.Type.ToString());

                jsonWriter.WritePropertyName("address");
                jsonWriter.WriteValue(proxy.Address);

                jsonWriter.WritePropertyName("port");
                jsonWriter.WriteValue(proxy.Port);

                NetworkCredential credential = proxy.Credential;

                if (credential != null)
                {
                    jsonWriter.WritePropertyName("username");
                    jsonWriter.WriteValue(credential.UserName);

                    jsonWriter.WritePropertyName("password");
                    jsonWriter.WriteValue(credential.Password);
                }

                jsonWriter.WritePropertyName("bypass");
                jsonWriter.WriteStartArray();

                foreach (NetProxyBypassItem item in proxy.BypassList)
                    jsonWriter.WriteValue(item.Value);

                jsonWriter.WriteEndArray();

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WritePropertyName("forwarders");

            DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;

            if (_dnsServer.Forwarders == null)
            {
                jsonWriter.WriteNull();
            }
            else
            {
                forwarderProtocol = _dnsServer.Forwarders[0].Protocol;

                jsonWriter.WriteStartArray();

                foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                    jsonWriter.WriteValue(forwarder.OriginalAddress);

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("forwarderProtocol");
            jsonWriter.WriteValue(forwarderProtocol.ToString());

            jsonWriter.WritePropertyName("enableBlocking");
            jsonWriter.WriteValue(_dnsServer.EnableBlocking);

            jsonWriter.WritePropertyName("allowTxtBlockingReport");
            jsonWriter.WriteValue(_dnsServer.AllowTxtBlockingReport);

            if (!_dnsServer.EnableBlocking && (DateTime.UtcNow < _temporaryDisableBlockingTill))
            {
                jsonWriter.WritePropertyName("temporaryDisableBlockingTill");
                jsonWriter.WriteValue(_temporaryDisableBlockingTill);
            }

            jsonWriter.WritePropertyName("blockingType");
            jsonWriter.WriteValue(_dnsServer.BlockingType.ToString());

            jsonWriter.WritePropertyName("customBlockingAddresses");
            jsonWriter.WriteStartArray();

            foreach (DnsARecordData record in _dnsServer.CustomBlockingARecords)
                jsonWriter.WriteValue(record.Address.ToString());

            foreach (DnsAAAARecordData record in _dnsServer.CustomBlockingAAAARecords)
                jsonWriter.WriteValue(record.Address.ToString());

            jsonWriter.WriteEndArray();

            jsonWriter.WritePropertyName("blockListUrls");

            if ((_dnsServer.BlockListZoneManager.AllowListUrls.Count == 0) && (_dnsServer.BlockListZoneManager.BlockListUrls.Count == 0))
            {
                jsonWriter.WriteNull();
            }
            else
            {
                jsonWriter.WriteStartArray();

                foreach (Uri allowListUrl in _dnsServer.BlockListZoneManager.AllowListUrls)
                    jsonWriter.WriteValue("!" + allowListUrl.AbsoluteUri);

                foreach (Uri blockListUrl in _dnsServer.BlockListZoneManager.BlockListUrls)
                    jsonWriter.WriteValue(blockListUrl.AbsoluteUri);

                jsonWriter.WriteEndArray();
            }

            jsonWriter.WritePropertyName("blockListUpdateIntervalHours");
            jsonWriter.WriteValue(_blockListUpdateIntervalHours);

            if (_blockListUpdateTimer is not null)
            {
                DateTime blockListNextUpdatedOn = _blockListLastUpdatedOn.AddHours(_blockListUpdateIntervalHours);

                jsonWriter.WritePropertyName("blockListNextUpdatedOn");
                jsonWriter.WriteValue(blockListNextUpdatedOn);
            }
        }

        private void SetDnsSettings(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            bool serverDomainChanged = false;
            bool restartDnsService = false;
            bool restartWebService = false;

            string strDnsServerDomain = request.QueryString["dnsServerDomain"];
            if (!string.IsNullOrEmpty(strDnsServerDomain))
            {
                serverDomainChanged = !_dnsServer.ServerDomain.Equals(strDnsServerDomain, StringComparison.OrdinalIgnoreCase);
                _dnsServer.ServerDomain = strDnsServerDomain;
            }

            string strDnsServerLocalEndPoints = request.QueryString["dnsServerLocalEndPoints"];
            if (strDnsServerLocalEndPoints != null)
            {
                if (string.IsNullOrEmpty(strDnsServerLocalEndPoints))
                    strDnsServerLocalEndPoints = "0.0.0.0:53,[::]:53";

                string[] strLocalEndPoints = strDnsServerLocalEndPoints.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                List<IPEndPoint> localEndPoints = new List<IPEndPoint>(strLocalEndPoints.Length);

                for (int i = 0; i < strLocalEndPoints.Length; i++)
                {
                    NameServerAddress nameServer = new NameServerAddress(strLocalEndPoints[i]);
                    if (nameServer.IPEndPoint != null)
                        localEndPoints.Add(nameServer.IPEndPoint);
                }

                if (localEndPoints.Count > 0)
                {
                    if (_dnsServer.LocalEndPoints.Count != localEndPoints.Count)
                    {
                        restartDnsService = true;
                    }
                    else
                    {
                        foreach (IPEndPoint currentLocalEP in _dnsServer.LocalEndPoints)
                        {
                            if (!localEndPoints.Contains(currentLocalEP))
                            {
                                restartDnsService = true;
                                break;
                            }
                        }
                    }

                    _dnsServer.LocalEndPoints = localEndPoints;
                }
            }

            string strWebServiceLocalAddresses = request.QueryString["webServiceLocalAddresses"];
            if (strWebServiceLocalAddresses != null)
            {
                if (string.IsNullOrEmpty(strWebServiceLocalAddresses))
                    strWebServiceLocalAddresses = "0.0.0.0,[::]";

                string[] strLocalAddresses = strWebServiceLocalAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                List<IPAddress> localAddresses = new List<IPAddress>(strLocalAddresses.Length);

                for (int i = 0; i < strLocalAddresses.Length; i++)
                {
                    if (IPAddress.TryParse(strLocalAddresses[i], out IPAddress localAddress))
                        localAddresses.Add(localAddress);
                }

                if (localAddresses.Count > 0)
                {
                    if (_webServiceLocalAddresses.Count != localAddresses.Count)
                    {
                        restartWebService = true;
                    }
                    else
                    {
                        foreach (IPAddress currentlocalAddress in _webServiceLocalAddresses)
                        {
                            if (!localAddresses.Contains(currentlocalAddress))
                            {
                                restartWebService = true;
                                break;
                            }
                        }
                    }

                    _webServiceLocalAddresses = localAddresses;
                }
            }

            int oldWebServiceHttpPort = _webServiceHttpPort;

            string strWebServiceHttpPort = request.QueryString["webServiceHttpPort"];
            if (!string.IsNullOrEmpty(strWebServiceHttpPort))
            {
                _webServiceHttpPort = int.Parse(strWebServiceHttpPort);

                if (oldWebServiceHttpPort != _webServiceHttpPort)
                    restartWebService = true;
            }

            string strWebServiceEnableTls = request.QueryString["webServiceEnableTls"];
            if (!string.IsNullOrEmpty(strWebServiceEnableTls))
            {
                bool oldWebServiceEnableTls = _webServiceEnableTls;

                _webServiceEnableTls = bool.Parse(strWebServiceEnableTls);

                if (oldWebServiceEnableTls != _webServiceEnableTls)
                    restartWebService = true;
            }

            string strWebServiceHttpToTlsRedirect = request.QueryString["webServiceHttpToTlsRedirect"];
            if (!string.IsNullOrEmpty(strWebServiceHttpToTlsRedirect))
                _webServiceHttpToTlsRedirect = bool.Parse(strWebServiceHttpToTlsRedirect);

            string strWebServiceTlsPort = request.QueryString["webServiceTlsPort"];
            if (!string.IsNullOrEmpty(strWebServiceTlsPort))
            {
                int oldWebServiceTlsPort = _webServiceTlsPort;

                _webServiceTlsPort = int.Parse(strWebServiceTlsPort);

                if (oldWebServiceTlsPort != _webServiceTlsPort)
                    restartWebService = true;
            }

            string strWebServiceUseSelfSignedTlsCertificate = request.QueryString["webServiceUseSelfSignedTlsCertificate"];
            if (!string.IsNullOrEmpty(strWebServiceUseSelfSignedTlsCertificate))
                _webServiceUseSelfSignedTlsCertificate = bool.Parse(strWebServiceUseSelfSignedTlsCertificate);

            string strWebServiceTlsCertificatePath = request.QueryString["webServiceTlsCertificatePath"];
            string strWebServiceTlsCertificatePassword = request.QueryString["webServiceTlsCertificatePassword"];
            if (string.IsNullOrEmpty(strWebServiceTlsCertificatePath))
            {
                _webServiceTlsCertificatePath = null;
                _webServiceTlsCertificatePassword = "";
            }
            else
            {
                if (strWebServiceTlsCertificatePassword == "************")
                    strWebServiceTlsCertificatePassword = _webServiceTlsCertificatePassword;

                if ((strWebServiceTlsCertificatePath != _webServiceTlsCertificatePath) || (strWebServiceTlsCertificatePassword != _webServiceTlsCertificatePassword))
                {
                    LoadWebServiceTlsCertificate(strWebServiceTlsCertificatePath, strWebServiceTlsCertificatePassword);

                    _webServiceTlsCertificatePath = strWebServiceTlsCertificatePath;
                    _webServiceTlsCertificatePassword = strWebServiceTlsCertificatePassword;

                    StartTlsCertificateUpdateTimer();
                }
            }

            string enableDnsOverHttp = request.QueryString["enableDnsOverHttp"];
            if (!string.IsNullOrEmpty(enableDnsOverHttp))
            {
                bool oldEnableDnsOverHttp = _dnsServer.EnableDnsOverHttp;

                _dnsServer.EnableDnsOverHttp = bool.Parse(enableDnsOverHttp);

                if (oldEnableDnsOverHttp != _dnsServer.EnableDnsOverHttp)
                    restartDnsService = true;
            }

            string strEnableDnsOverTls = request.QueryString["enableDnsOverTls"];
            if (!string.IsNullOrEmpty(strEnableDnsOverTls))
            {
                bool oldEnableDnsOverTls = _dnsServer.EnableDnsOverTls;

                _dnsServer.EnableDnsOverTls = bool.Parse(strEnableDnsOverTls);

                if (oldEnableDnsOverTls != _dnsServer.EnableDnsOverTls)
                    restartDnsService = true;
            }

            string strEnableDnsOverHttps = request.QueryString["enableDnsOverHttps"];
            if (!string.IsNullOrEmpty(strEnableDnsOverHttps))
            {
                bool oldEnableDnsOverHttps = _dnsServer.EnableDnsOverHttps;

                _dnsServer.EnableDnsOverHttps = bool.Parse(strEnableDnsOverHttps);

                if (oldEnableDnsOverHttps != _dnsServer.EnableDnsOverHttps)
                    restartDnsService = true;
            }

            string strDnsTlsCertificatePath = request.QueryString["dnsTlsCertificatePath"];
            string strDnsTlsCertificatePassword = request.QueryString["dnsTlsCertificatePassword"];
            if (string.IsNullOrEmpty(strDnsTlsCertificatePath))
            {
                _dnsTlsCertificatePath = null;
                _dnsTlsCertificatePassword = "";
            }
            else
            {
                if (strDnsTlsCertificatePassword == "************")
                    strDnsTlsCertificatePassword = _dnsTlsCertificatePassword;

                if ((strDnsTlsCertificatePath != _dnsTlsCertificatePath) || (strDnsTlsCertificatePassword != _dnsTlsCertificatePassword))
                {
                    LoadDnsTlsCertificate(strDnsTlsCertificatePath, strDnsTlsCertificatePassword);

                    _dnsTlsCertificatePath = strDnsTlsCertificatePath;
                    _dnsTlsCertificatePassword = strDnsTlsCertificatePassword;

                    StartTlsCertificateUpdateTimer();
                }
            }

            string strTsigKeys = request.QueryString["tsigKeys"];
            if (!string.IsNullOrEmpty(strTsigKeys))
            {
                if (strTsigKeys == "false")
                {
                    _dnsServer.TsigKeys = null;
                }
                else
                {
                    string[] strTsigKeyParts = strTsigKeys.Split('|');
                    Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(strTsigKeyParts.Length);

                    for (int i = 0; i < strTsigKeyParts.Length; i += 3)
                    {
                        string keyName = strTsigKeyParts[i + 0].ToLower();
                        string sharedSecret = strTsigKeyParts[i + 1];
                        string algorithmName = strTsigKeyParts[i + 2];

                        if (sharedSecret.Length == 0)
                        {
                            byte[] key = new byte[32];
                            _rng.GetBytes(key);

                            tsigKeys.Add(keyName, new TsigKey(keyName, Convert.ToBase64String(key), algorithmName));
                        }
                        else
                        {
                            tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, algorithmName));
                        }
                    }

                    _dnsServer.TsigKeys = tsigKeys;
                }
            }

            string strDefaultRecordTtl = request.QueryString["defaultRecordTtl"];
            if (!string.IsNullOrEmpty(strDefaultRecordTtl))
                _zonesApi.DefaultRecordTtl = uint.Parse(strDefaultRecordTtl);

            string strDnsAppsEnableAutomaticUpdate = request.QueryString["dnsAppsEnableAutomaticUpdate"];
            if (!string.IsNullOrEmpty(strDnsAppsEnableAutomaticUpdate))
                _appsApi.EnableAutomaticUpdate = bool.Parse(strDnsAppsEnableAutomaticUpdate);

            string strPreferIPv6 = request.QueryString["preferIPv6"];
            if (!string.IsNullOrEmpty(strPreferIPv6))
                _dnsServer.PreferIPv6 = bool.Parse(strPreferIPv6);

            string strUdpPayloadSize = request.QueryString["udpPayloadSize"];
            if (!string.IsNullOrEmpty(strUdpPayloadSize))
                _dnsServer.UdpPayloadSize = ushort.Parse(strUdpPayloadSize);

            string strDnssecValidation = request.QueryString["dnssecValidation"];
            if (!string.IsNullOrEmpty(strDnssecValidation))
                _dnsServer.DnssecValidation = bool.Parse(strDnssecValidation);

            string strResolverRetries = request.QueryString["resolverRetries"];
            if (!string.IsNullOrEmpty(strResolverRetries))
                _dnsServer.ResolverRetries = int.Parse(strResolverRetries);

            string strResolverTimeout = request.QueryString["resolverTimeout"];
            if (!string.IsNullOrEmpty(strResolverTimeout))
                _dnsServer.ResolverTimeout = int.Parse(strResolverTimeout);

            string strResolverMaxStackCount = request.QueryString["resolverMaxStackCount"];
            if (!string.IsNullOrEmpty(strResolverMaxStackCount))
                _dnsServer.ResolverMaxStackCount = int.Parse(strResolverMaxStackCount);

            string strForwarderRetries = request.QueryString["forwarderRetries"];
            if (!string.IsNullOrEmpty(strForwarderRetries))
                _dnsServer.ForwarderRetries = int.Parse(strForwarderRetries);

            string strForwarderTimeout = request.QueryString["forwarderTimeout"];
            if (!string.IsNullOrEmpty(strForwarderTimeout))
                _dnsServer.ForwarderTimeout = int.Parse(strForwarderTimeout);

            string strForwarderConcurrency = request.QueryString["forwarderConcurrency"];
            if (!string.IsNullOrEmpty(strForwarderConcurrency))
                _dnsServer.ForwarderConcurrency = int.Parse(strForwarderConcurrency);

            string strClientTimeout = request.QueryString["clientTimeout"];
            if (!string.IsNullOrEmpty(strClientTimeout))
                _dnsServer.ClientTimeout = int.Parse(strClientTimeout);

            string strTcpSendTimeout = request.QueryString["tcpSendTimeout"];
            if (!string.IsNullOrEmpty(strTcpSendTimeout))
                _dnsServer.TcpSendTimeout = int.Parse(strTcpSendTimeout);

            string strTcpReceiveTimeout = request.QueryString["tcpReceiveTimeout"];
            if (!string.IsNullOrEmpty(strTcpReceiveTimeout))
                _dnsServer.TcpReceiveTimeout = int.Parse(strTcpReceiveTimeout);

            string strEnableLogging = request.QueryString["enableLogging"];
            if (!string.IsNullOrEmpty(strEnableLogging))
                _log.EnableLogging = bool.Parse(strEnableLogging);

            string strLogQueries = request.QueryString["logQueries"];
            if (!string.IsNullOrEmpty(strLogQueries))
            {
                if (bool.Parse(strLogQueries))
                    _dnsServer.QueryLogManager = _log;
                else
                    _dnsServer.QueryLogManager = null;
            }

            string strUseLocalTime = request.QueryString["useLocalTime"];
            if (!string.IsNullOrEmpty(strUseLocalTime))
                _log.UseLocalTime = bool.Parse(strUseLocalTime);

            string strLogFolder = request.QueryString["logFolder"];
            if (!string.IsNullOrEmpty(strLogFolder))
                _log.LogFolder = strLogFolder;

            string strMaxLogFileDays = request.QueryString["maxLogFileDays"];
            if (!string.IsNullOrEmpty(strMaxLogFileDays))
                _log.MaxLogFileDays = int.Parse(strMaxLogFileDays);

            string strMaxStatFileDays = request.QueryString["maxStatFileDays"];
            if (!string.IsNullOrEmpty(strMaxStatFileDays))
                _dnsServer.StatsManager.MaxStatFileDays = int.Parse(strMaxStatFileDays);

            string strRecursion = request.QueryString["recursion"];
            if (!string.IsNullOrEmpty(strRecursion))
                _dnsServer.Recursion = Enum.Parse<DnsServerRecursion>(strRecursion, true);

            string strRecursionDeniedNetworks = request.QueryString["recursionDeniedNetworks"];
            if (!string.IsNullOrEmpty(strRecursionDeniedNetworks))
            {
                if (strRecursionDeniedNetworks == "false")
                {
                    _dnsServer.RecursionDeniedNetworks = null;
                }
                else
                {
                    string[] strNetworks = strRecursionDeniedNetworks.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    NetworkAddress[] networks = new NetworkAddress[strNetworks.Length];

                    for (int i = 0; i < networks.Length; i++)
                        networks[i] = NetworkAddress.Parse(strNetworks[i]);

                    _dnsServer.RecursionDeniedNetworks = networks;
                }
            }

            string strRecursionAllowedNetworks = request.QueryString["recursionAllowedNetworks"];
            if (!string.IsNullOrEmpty(strRecursionAllowedNetworks))
            {
                if (strRecursionAllowedNetworks == "false")
                {
                    _dnsServer.RecursionAllowedNetworks = null;
                }
                else
                {
                    string[] strNetworks = strRecursionAllowedNetworks.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    NetworkAddress[] networks = new NetworkAddress[strNetworks.Length];

                    for (int i = 0; i < networks.Length; i++)
                        networks[i] = NetworkAddress.Parse(strNetworks[i]);

                    _dnsServer.RecursionAllowedNetworks = networks;
                }
            }

            string strRandomizeName = request.QueryString["randomizeName"];
            if (!string.IsNullOrEmpty(strRandomizeName))
                _dnsServer.RandomizeName = bool.Parse(strRandomizeName);

            string strQnameMinimization = request.QueryString["qnameMinimization"];
            if (!string.IsNullOrEmpty(strQnameMinimization))
                _dnsServer.QnameMinimization = bool.Parse(strQnameMinimization);

            string strNsRevalidation = request.QueryString["nsRevalidation"];
            if (!string.IsNullOrEmpty(strNsRevalidation))
                _dnsServer.NsRevalidation = bool.Parse(strNsRevalidation);

            string strQpmLimitRequests = request.QueryString["qpmLimitRequests"];
            if (!string.IsNullOrEmpty(strQpmLimitRequests))
                _dnsServer.QpmLimitRequests = int.Parse(strQpmLimitRequests);

            string strQpmLimitErrors = request.QueryString["qpmLimitErrors"];
            if (!string.IsNullOrEmpty(strQpmLimitErrors))
                _dnsServer.QpmLimitErrors = int.Parse(strQpmLimitErrors);

            string strQpmLimitSampleMinutes = request.QueryString["qpmLimitSampleMinutes"];
            if (!string.IsNullOrEmpty(strQpmLimitSampleMinutes))
                _dnsServer.QpmLimitSampleMinutes = int.Parse(strQpmLimitSampleMinutes);

            string strQpmLimitIPv4PrefixLength = request.QueryString["qpmLimitIPv4PrefixLength"];
            if (!string.IsNullOrEmpty(strQpmLimitIPv4PrefixLength))
                _dnsServer.QpmLimitIPv4PrefixLength = int.Parse(strQpmLimitIPv4PrefixLength);

            string strQpmLimitIPv6PrefixLength = request.QueryString["qpmLimitIPv6PrefixLength"];
            if (!string.IsNullOrEmpty(strQpmLimitIPv6PrefixLength))
                _dnsServer.QpmLimitIPv6PrefixLength = int.Parse(strQpmLimitIPv6PrefixLength);

            string strServeStale = request.QueryString["serveStale"];
            if (!string.IsNullOrEmpty(strServeStale))
                _dnsServer.ServeStale = bool.Parse(strServeStale);

            string strServeStaleTtl = request.QueryString["serveStaleTtl"];
            if (!string.IsNullOrEmpty(strServeStaleTtl))
                _dnsServer.CacheZoneManager.ServeStaleTtl = uint.Parse(strServeStaleTtl);

            string strCacheMaximumEntries = request.QueryString["cacheMaximumEntries"];
            if (!string.IsNullOrEmpty(strCacheMaximumEntries))
                _dnsServer.CacheZoneManager.MaximumEntries = long.Parse(strCacheMaximumEntries);

            string strCacheMinimumRecordTtl = request.QueryString["cacheMinimumRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheMinimumRecordTtl))
                _dnsServer.CacheZoneManager.MinimumRecordTtl = uint.Parse(strCacheMinimumRecordTtl);

            string strCacheMaximumRecordTtl = request.QueryString["cacheMaximumRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheMaximumRecordTtl))
                _dnsServer.CacheZoneManager.MaximumRecordTtl = uint.Parse(strCacheMaximumRecordTtl);

            string strCacheNegativeRecordTtl = request.QueryString["cacheNegativeRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheNegativeRecordTtl))
                _dnsServer.CacheZoneManager.NegativeRecordTtl = uint.Parse(strCacheNegativeRecordTtl);

            string strCacheFailureRecordTtl = request.QueryString["cacheFailureRecordTtl"];
            if (!string.IsNullOrEmpty(strCacheFailureRecordTtl))
                _dnsServer.CacheZoneManager.FailureRecordTtl = uint.Parse(strCacheFailureRecordTtl);

            string strCachePrefetchEligibility = request.QueryString["cachePrefetchEligibility"];
            if (!string.IsNullOrEmpty(strCachePrefetchEligibility))
                _dnsServer.CachePrefetchEligibility = int.Parse(strCachePrefetchEligibility);

            string strCachePrefetchTrigger = request.QueryString["cachePrefetchTrigger"];
            if (!string.IsNullOrEmpty(strCachePrefetchTrigger))
                _dnsServer.CachePrefetchTrigger = int.Parse(strCachePrefetchTrigger);

            string strCachePrefetchSampleIntervalInMinutes = request.QueryString["cachePrefetchSampleIntervalInMinutes"];
            if (!string.IsNullOrEmpty(strCachePrefetchSampleIntervalInMinutes))
                _dnsServer.CachePrefetchSampleIntervalInMinutes = int.Parse(strCachePrefetchSampleIntervalInMinutes);

            string strCachePrefetchSampleEligibilityHitsPerHour = request.QueryString["cachePrefetchSampleEligibilityHitsPerHour"];
            if (!string.IsNullOrEmpty(strCachePrefetchSampleEligibilityHitsPerHour))
                _dnsServer.CachePrefetchSampleEligibilityHitsPerHour = int.Parse(strCachePrefetchSampleEligibilityHitsPerHour);

            string strProxyType = request.QueryString["proxyType"];
            if (!string.IsNullOrEmpty(strProxyType))
            {
                NetProxyType proxyType = Enum.Parse<NetProxyType>(strProxyType, true);
                if (proxyType == NetProxyType.None)
                {
                    _dnsServer.Proxy = null;
                }
                else
                {
                    NetworkCredential credential = null;

                    string strUsername = request.QueryString["proxyUsername"];
                    if (!string.IsNullOrEmpty(strUsername))
                        credential = new NetworkCredential(strUsername, request.QueryString["proxyPassword"]);

                    _dnsServer.Proxy = NetProxy.CreateProxy(proxyType, request.QueryString["proxyAddress"], int.Parse(request.QueryString["proxyPort"]), credential);

                    string strProxyBypass = request.QueryString["proxyBypass"];
                    if (!string.IsNullOrEmpty(strProxyBypass))
                    {
                        string[] strBypassList = strProxyBypass.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                        List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(strBypassList.Length);

                        for (int i = 0; i < strBypassList.Length; i++)
                            bypassList.Add(new NetProxyBypassItem(strBypassList[i]));

                        _dnsServer.Proxy.BypassList = bypassList;
                    }
                }
            }

            DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;
            string strForwarderProtocol = request.QueryString["forwarderProtocol"];
            if (!string.IsNullOrEmpty(strForwarderProtocol))
                forwarderProtocol = Enum.Parse<DnsTransportProtocol>(strForwarderProtocol, true);

            string strForwarders = request.QueryString["forwarders"];
            if (!string.IsNullOrEmpty(strForwarders))
            {
                if (strForwarders == "false")
                {
                    _dnsServer.Forwarders = null;
                }
                else
                {
                    string[] strForwardersList = strForwarders.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    NameServerAddress[] forwarders = new NameServerAddress[strForwardersList.Length];

                    for (int i = 0; i < strForwardersList.Length; i++)
                    {
                        NameServerAddress forwarder = new NameServerAddress(strForwardersList[i]);

                        if (forwarder.Protocol != forwarderProtocol)
                            forwarder = forwarder.ChangeProtocol(forwarderProtocol);

                        forwarders[i] = forwarder;
                    }

                    _dnsServer.Forwarders = forwarders;
                }
            }

            string strEnableBlocking = request.QueryString["enableBlocking"];
            if (!string.IsNullOrEmpty(strEnableBlocking))
            {
                _dnsServer.EnableBlocking = bool.Parse(strEnableBlocking);
                if (_dnsServer.EnableBlocking)
                {
                    if (_temporaryDisableBlockingTimer is not null)
                        _temporaryDisableBlockingTimer.Dispose();
                }
            }

            string strAllowTxtBlockingReport = request.QueryString["allowTxtBlockingReport"];
            if (!string.IsNullOrEmpty(strAllowTxtBlockingReport))
                _dnsServer.AllowTxtBlockingReport = bool.Parse(strAllowTxtBlockingReport);

            string strBlockingType = request.QueryString["blockingType"];
            if (!string.IsNullOrEmpty(strBlockingType))
                _dnsServer.BlockingType = Enum.Parse<DnsServerBlockingType>(strBlockingType, true);

            string strCustomBlockingAddresses = request.QueryString["customBlockingAddresses"];
            if (!string.IsNullOrEmpty(strCustomBlockingAddresses))
            {
                if (strCustomBlockingAddresses == "false")
                {
                    _dnsServer.CustomBlockingARecords = null;
                    _dnsServer.CustomBlockingAAAARecords = null;
                }
                else
                {
                    string[] strAddresses = strCustomBlockingAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                    List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

                    foreach (string strAddress in strAddresses)
                    {
                        if (IPAddress.TryParse(strAddress, out IPAddress customAddress))
                        {
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
                    }

                    _dnsServer.CustomBlockingARecords = dnsARecords;
                    _dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                }
            }

            bool blockListUrlsUpdated = false;
            string strBlockListUrls = request.QueryString["blockListUrls"];
            if (!string.IsNullOrEmpty(strBlockListUrls))
            {
                if (strBlockListUrls == "false")
                {
                    _dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                    _dnsServer.BlockListZoneManager.BlockListUrls.Clear();
                    _dnsServer.BlockListZoneManager.Flush();
                }
                else
                {
                    string[] strBlockListUrlList = strBlockListUrls.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    if (oldWebServiceHttpPort != _webServiceHttpPort)
                    {
                        for (int i = 0; i < strBlockListUrlList.Length; i++)
                        {
                            if (strBlockListUrlList[i].Contains("http://localhost:" + oldWebServiceHttpPort + "/blocklist.txt"))
                            {
                                strBlockListUrlList[i] = "http://localhost:" + _webServiceHttpPort + "/blocklist.txt";
                                blockListUrlsUpdated = true;
                                break;
                            }
                        }
                    }

                    if (!blockListUrlsUpdated)
                    {
                        if (strBlockListUrlList.Length != (_dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsServer.BlockListZoneManager.BlockListUrls.Count))
                        {
                            blockListUrlsUpdated = true;
                        }
                        else
                        {
                            foreach (string strBlockListUrl in strBlockListUrlList)
                            {
                                if (strBlockListUrl.StartsWith("!"))
                                {
                                    string strAllowListUrl = strBlockListUrl.Substring(1);

                                    if (!_dnsServer.BlockListZoneManager.AllowListUrls.Contains(new Uri(strAllowListUrl)))
                                    {
                                        blockListUrlsUpdated = true;
                                        break;
                                    }
                                }
                                else
                                {
                                    if (!_dnsServer.BlockListZoneManager.BlockListUrls.Contains(new Uri(strBlockListUrl)))
                                    {
                                        blockListUrlsUpdated = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (blockListUrlsUpdated)
                    {
                        _dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                        _dnsServer.BlockListZoneManager.BlockListUrls.Clear();

                        foreach (string strBlockListUrl in strBlockListUrlList)
                        {
                            if (strBlockListUrl.StartsWith("!"))
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
                }
            }

            string strBlockListUpdateIntervalHours = request.QueryString["blockListUpdateIntervalHours"];
            if (!string.IsNullOrEmpty(strBlockListUpdateIntervalHours))
            {
                int blockListUpdateIntervalHours = int.Parse(strBlockListUpdateIntervalHours);

                if ((blockListUpdateIntervalHours < 0) || (blockListUpdateIntervalHours > 168))
                    throw new DnsWebServiceException("Parameter `blockListUpdateIntervalHours` must be between 1 hour and 168 hours (7 days) or 0 to disable automatic update.");

                _blockListUpdateIntervalHours = blockListUpdateIntervalHours;
            }

            if ((_blockListUpdateIntervalHours > 0) && ((_dnsServer.BlockListZoneManager.AllowListUrls.Count + _dnsServer.BlockListZoneManager.BlockListUrls.Count) > 0))
            {
                if (blockListUrlsUpdated || (_blockListUpdateTimer is null))
                    ForceUpdateBlockLists();

                StartBlockListUpdateTimer();
            }
            else
            {
                StopBlockListUpdateTimer();
            }

            if ((_webServiceTlsCertificatePath == null) && (_dnsTlsCertificatePath == null))
                StopTlsCertificateUpdateTimer();

            SelfSignedCertCheck(serverDomainChanged, true);

            if (_webServiceEnableTls && string.IsNullOrEmpty(_webServiceTlsCertificatePath) && !_webServiceUseSelfSignedTlsCertificate)
            {
                //disable TLS
                _webServiceEnableTls = false;
                restartWebService = true;
            }

            SaveConfigFile();
            _log.Save();

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).User.Username + "] DNS Settings were updated {dnsServerDomain: " + _dnsServer.ServerDomain + "; dnsServerLocalEndPoints: " + strDnsServerLocalEndPoints + "; webServiceLocalAddresses: " + strWebServiceLocalAddresses + "; webServiceHttpPort: " + _webServiceHttpPort + "; webServiceEnableTls: " + strWebServiceEnableTls + "; webServiceHttpToTlsRedirect: " + strWebServiceHttpToTlsRedirect + "; webServiceTlsPort: " + strWebServiceTlsPort + "; webServiceUseSelfSignedTlsCertificate: " + _webServiceUseSelfSignedTlsCertificate + "; webServiceTlsCertificatePath: " + strWebServiceTlsCertificatePath + "; enableDnsOverHttp: " + _dnsServer.EnableDnsOverHttp + "; enableDnsOverTls: " + _dnsServer.EnableDnsOverTls + "; enableDnsOverHttps: " + _dnsServer.EnableDnsOverHttps + "; dnsTlsCertificatePath: " + _dnsTlsCertificatePath + "; defaultRecordTtl: " + _zonesApi.DefaultRecordTtl + "; preferIPv6: " + _dnsServer.PreferIPv6 + "; enableLogging: " + strEnableLogging + "; logQueries: " + (_dnsServer.QueryLogManager != null) + "; useLocalTime: " + strUseLocalTime + "; logFolder: " + strLogFolder + "; maxLogFileDays: " + strMaxLogFileDays + "; recursion: " + _dnsServer.Recursion.ToString() + "; randomizeName: " + strRandomizeName + "; qnameMinimization: " + strQnameMinimization + "; serveStale: " + strServeStale + "; serveStaleTtl: " + strServeStaleTtl + "; cachePrefetchEligibility: " + strCachePrefetchEligibility + "; cachePrefetchTrigger: " + strCachePrefetchTrigger + "; cachePrefetchSampleIntervalInMinutes: " + strCachePrefetchSampleIntervalInMinutes + "; cachePrefetchSampleEligibilityHitsPerHour: " + strCachePrefetchSampleEligibilityHitsPerHour + "; proxyType: " + strProxyType + "; forwarders: " + strForwarders + "; forwarderProtocol: " + strForwarderProtocol + "; enableBlocking: " + _dnsServer.EnableBlocking + "; allowTxtBlockingReport: " + _dnsServer.AllowTxtBlockingReport + "; blockingType: " + _dnsServer.BlockingType.ToString() + "; blockListUrl: " + strBlockListUrls + "; blockListUpdateIntervalHours: " + strBlockListUpdateIntervalHours + ";}");

            GetDnsSettings(jsonWriter);

            RestartService(restartDnsService, restartWebService);
        }

        private void GetTsigKeyNames(JsonTextWriter jsonWriter)
        {
            jsonWriter.WritePropertyName("tsigKeyNames");
            {
                jsonWriter.WriteStartArray();

                if (_dnsServer.TsigKeys is not null)
                {
                    foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsServer.TsigKeys)
                        jsonWriter.WriteValue(tsigKey.Key);
                }

                jsonWriter.WriteEndArray();
            }
        }

        private void SelfSignedCertCheck(bool generateNew, bool throwException)
        {
            string selfSignedCertificateFilePath = Path.Combine(_configFolder, "cert.pfx");

            if (_webServiceUseSelfSignedTlsCertificate)
            {
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

        private void RestartService(bool restartDnsService, bool restartWebService)
        {
            if (restartDnsService)
            {
                _ = Task.Run(delegate ()
                {
                    _log.Write("Attempting to restart DNS service.");

                    try
                    {
                        _dnsServer.Stop();
                        _dnsServer.Start();

                        _log.Write("DNS service was restarted successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write("Failed to restart DNS service.");
                        _log.Write(ex);
                    }
                });
            }

            if (restartWebService)
            {
                _ = Task.Run(async delegate ()
                {
                    await Task.Delay(2000); //wait for this HTTP response to be delivered before stopping web server

                    _log.Write("Attempting to restart web service.");

                    try
                    {
                        StopDnsWebService();
                        StartDnsWebService();

                        _log.Write("Web service was restarted successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write("Failed to restart web service.");
                        _log.Write(ex);
                    }
                });
            }
        }

        private async Task BackupSettingsAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            bool blockLists = false;
            bool logs = false;
            bool scopes = false;
            bool apps = false;
            bool stats = false;
            bool zones = false;
            bool allowedZones = false;
            bool blockedZones = false;
            bool dnsSettings = false;
            bool authConfig = false;
            bool logSettings = false;

            string strBlockLists = request.QueryString["blockLists"];
            if (!string.IsNullOrEmpty(strBlockLists))
                blockLists = bool.Parse(strBlockLists);

            string strLogs = request.QueryString["logs"];
            if (!string.IsNullOrEmpty(strLogs))
                logs = bool.Parse(strLogs);

            string strScopes = request.QueryString["scopes"];
            if (!string.IsNullOrEmpty(strScopes))
                scopes = bool.Parse(strScopes);

            string strApps = request.QueryString["apps"];
            if (!string.IsNullOrEmpty(strApps))
                apps = bool.Parse(strApps);

            string strStats = request.QueryString["stats"];
            if (!string.IsNullOrEmpty(strStats))
                stats = bool.Parse(strStats);

            string strZones = request.QueryString["zones"];
            if (!string.IsNullOrEmpty(strZones))
                zones = bool.Parse(strZones);

            string strAllowedZones = request.QueryString["allowedZones"];
            if (!string.IsNullOrEmpty(strAllowedZones))
                allowedZones = bool.Parse(strAllowedZones);

            string strBlockedZones = request.QueryString["blockedZones"];
            if (!string.IsNullOrEmpty(strBlockedZones))
                blockedZones = bool.Parse(strBlockedZones);

            string strDnsSettings = request.QueryString["dnsSettings"];
            if (!string.IsNullOrEmpty(strDnsSettings))
                dnsSettings = bool.Parse(strDnsSettings);

            string strAuthConfig = request.QueryString["authConfig"];
            if (!string.IsNullOrEmpty(strAuthConfig))
                authConfig = bool.Parse(strAuthConfig);

            string strLogSettings = request.QueryString["logSettings"];
            if (!string.IsNullOrEmpty(strLogSettings))
                logSettings = bool.Parse(strLogSettings);

            string tmpFile = Path.GetTempFileName();
            try
            {
                using (FileStream backupZipStream = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //create backup zip
                    using (ZipArchive backupZip = new ZipArchive(backupZipStream, ZipArchiveMode.Create, true, Encoding.UTF8))
                    {
                        if (blockLists)
                        {
                            string[] blockListFiles = Directory.GetFiles(Path.Combine(_configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);
                            foreach (string blockListFile in blockListFiles)
                            {
                                string entryName = "blocklists/" + Path.GetFileName(blockListFile);
                                backupZip.CreateEntryFromFile(blockListFile, entryName);
                            }
                        }

                        if (logs)
                        {
                            string[] logFiles = Directory.GetFiles(_log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);
                            foreach (string logFile in logFiles)
                            {
                                string entryName = "logs/" + Path.GetFileName(logFile);

                                if (logFile.Equals(_log.CurrentLogFile, StringComparison.OrdinalIgnoreCase))
                                {
                                    await CreateBackupEntryFromFileAsync(backupZip, logFile, entryName);
                                }
                                else
                                {
                                    backupZip.CreateEntryFromFile(logFile, entryName);
                                }
                            }
                        }

                        if (scopes)
                        {
                            string[] scopeFiles = Directory.GetFiles(Path.Combine(_configFolder, "scopes"), "*.scope", SearchOption.TopDirectoryOnly);
                            foreach (string scopeFile in scopeFiles)
                            {
                                string entryName = "scopes/" + Path.GetFileName(scopeFile);
                                backupZip.CreateEntryFromFile(scopeFile, entryName);
                            }
                        }

                        if (apps)
                        {
                            string[] appFiles = Directory.GetFiles(Path.Combine(_configFolder, "apps"), "*", SearchOption.AllDirectories);
                            foreach (string appFile in appFiles)
                            {
                                string entryName = appFile.Substring(_configFolder.Length);

                                if (Path.DirectorySeparatorChar != '/')
                                    entryName = entryName.Replace(Path.DirectorySeparatorChar, '/');

                                entryName = entryName.TrimStart('/');

                                await CreateBackupEntryFromFileAsync(backupZip, appFile, entryName);
                            }
                        }

                        if (stats)
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

                        if (zones)
                        {
                            string[] zoneFiles = Directory.GetFiles(Path.Combine(_configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);
                            foreach (string zoneFile in zoneFiles)
                            {
                                string entryName = "zones/" + Path.GetFileName(zoneFile);
                                backupZip.CreateEntryFromFile(zoneFile, entryName);
                            }
                        }

                        if (allowedZones)
                        {
                            string allowedZonesFile = Path.Combine(_configFolder, "allowed.config");

                            if (File.Exists(allowedZonesFile))
                                backupZip.CreateEntryFromFile(allowedZonesFile, "allowed.config");
                        }

                        if (blockedZones)
                        {
                            string blockedZonesFile = Path.Combine(_configFolder, "blocked.config");

                            if (File.Exists(blockedZonesFile))
                                backupZip.CreateEntryFromFile(blockedZonesFile, "blocked.config");
                        }

                        if (dnsSettings)
                        {
                            string dnsSettingsFile = Path.Combine(_configFolder, "dns.config");

                            if (File.Exists(dnsSettingsFile))
                                backupZip.CreateEntryFromFile(dnsSettingsFile, "dns.config");
                        }

                        if (authConfig)
                        {
                            string authSettingsFile = Path.Combine(_configFolder, "auth.config");

                            if (File.Exists(authSettingsFile))
                                backupZip.CreateEntryFromFile(authSettingsFile, "auth.config");
                        }

                        if (logSettings)
                        {
                            string logSettingsFile = Path.Combine(_configFolder, "log.config");

                            if (File.Exists(logSettingsFile))
                                backupZip.CreateEntryFromFile(logSettingsFile, "log.config");
                        }
                    }

                    //send zip file
                    backupZipStream.Position = 0;

                    response.ContentType = "application/zip";
                    response.ContentLength64 = backupZipStream.Length;
                    response.AddHeader("Content-Disposition", "attachment;filename=DnsServerBackup.zip");

                    using (Stream output = response.OutputStream)
                    {
                        await backupZipStream.CopyToAsync(output);
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
                    _log.Write(ex);
                }
            }

            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).User.Username + "] Settings backup zip file was exported.");
        }

        private static async Task CreateBackupEntryFromFileAsync(ZipArchive backupZip, string sourceFileName, string entryName)
        {
            using (FileStream fS = new FileStream(sourceFileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                ZipArchiveEntry entry = backupZip.CreateEntry(entryName);

                DateTime lastWrite = File.GetLastWriteTime(sourceFileName);

                // If file to be archived has an invalid last modified time, use the first datetime representable in the Zip timestamp format
                // (midnight on January 1, 1980):
                if (lastWrite.Year < 1980 || lastWrite.Year > 2107)
                    lastWrite = new DateTime(1980, 1, 1, 0, 0, 0);

                entry.LastWriteTime = lastWrite;

                using (Stream sE = entry.Open())
                {
                    await fS.CopyToAsync(sE);
                }
            }
        }

        private async Task RestoreSettingsAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            bool blockLists = false;
            bool logs = false;
            bool scopes = false;
            bool apps = false;
            bool stats = false;
            bool zones = false;
            bool allowedZones = false;
            bool blockedZones = false;
            bool dnsSettings = false;
            bool authConfig = false;
            bool logSettings = false;

            bool deleteExistingFiles = false;

            string strBlockLists = request.QueryString["blockLists"];
            if (!string.IsNullOrEmpty(strBlockLists))
                blockLists = bool.Parse(strBlockLists);

            string strLogs = request.QueryString["logs"];
            if (!string.IsNullOrEmpty(strLogs))
                logs = bool.Parse(strLogs);

            string strScopes = request.QueryString["scopes"];
            if (!string.IsNullOrEmpty(strScopes))
                scopes = bool.Parse(strScopes);

            string strApps = request.QueryString["apps"];
            if (!string.IsNullOrEmpty(strApps))
                apps = bool.Parse(strApps);

            string strStats = request.QueryString["stats"];
            if (!string.IsNullOrEmpty(strStats))
                stats = bool.Parse(strStats);

            string strZones = request.QueryString["zones"];
            if (!string.IsNullOrEmpty(strZones))
                zones = bool.Parse(strZones);

            string strAllowedZones = request.QueryString["allowedZones"];
            if (!string.IsNullOrEmpty(strAllowedZones))
                allowedZones = bool.Parse(strAllowedZones);

            string strBlockedZones = request.QueryString["blockedZones"];
            if (!string.IsNullOrEmpty(strBlockedZones))
                blockedZones = bool.Parse(strBlockedZones);

            string strDnsSettings = request.QueryString["dnsSettings"];
            if (!string.IsNullOrEmpty(strDnsSettings))
                dnsSettings = bool.Parse(strDnsSettings);

            string strAuthConfig = request.QueryString["authConfig"];
            if (!string.IsNullOrEmpty(strAuthConfig))
                authConfig = bool.Parse(strAuthConfig);

            string strLogSettings = request.QueryString["logSettings"];
            if (!string.IsNullOrEmpty(strLogSettings))
                logSettings = bool.Parse(strLogSettings);

            string strDeleteExistingFiles = request.QueryString["deleteExistingFiles"];
            if (!string.IsNullOrEmpty(strDeleteExistingFiles))
                deleteExistingFiles = bool.Parse(strDeleteExistingFiles);

            #region skip to content

            int crlfCount = 0;
            int byteRead;

            while (crlfCount != 4)
            {
                byteRead = await request.InputStream.ReadByteValueAsync();
                switch (byteRead)
                {
                    case 13: //CR
                    case 10: //LF
                        crlfCount++;
                        break;

                    default:
                        crlfCount = 0;
                        break;
                }
            }

            #endregion

            //write to temp file
            string tmpFile = Path.GetTempFileName();
            try
            {
                using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    await request.InputStream.CopyToAsync(fS);

                    fS.Position = 0;
                    using (ZipArchive backupZip = new ZipArchive(fS, ZipArchiveMode.Read, false, Encoding.UTF8))
                    {
                        UserSession session = GetSession(request);

                        if (logSettings || logs)
                        {
                            //stop logging
                            _log.StopLogging();
                        }

                        try
                        {
                            if (logSettings)
                            {
                                ZipArchiveEntry entry = backupZip.GetEntry("log.config");
                                if (entry != null)
                                    entry.ExtractToFile(Path.Combine(_configFolder, entry.Name), true);

                                //reload config
                                _log.LoadConfig();
                            }

                            if (logs)
                            {
                                if (deleteExistingFiles)
                                {
                                    //delete existing log files
                                    string[] logFiles = Directory.GetFiles(_log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);
                                    foreach (string logFile in logFiles)
                                    {
                                        File.Delete(logFile);
                                    }
                                }

                                //extract log files from backup
                                foreach (ZipArchiveEntry entry in backupZip.Entries)
                                {
                                    if (entry.FullName.StartsWith("logs/"))
                                        entry.ExtractToFile(Path.Combine(_log.LogFolderAbsolutePath, entry.Name), true);
                                }
                            }
                        }
                        finally
                        {
                            if (logSettings || logs)
                            {
                                //start logging
                                if (_log.EnableLogging)
                                    _log.StartLogging();
                            }
                        }

                        if (authConfig)
                        {
                            ZipArchiveEntry entry = backupZip.GetEntry("auth.config");
                            if (entry != null)
                                entry.ExtractToFile(Path.Combine(_configFolder, entry.Name), true);

                            //reload auth config
                            _authManager.LoadConfigFile(session);
                        }

                        if (dnsSettings)
                        {
                            ZipArchiveEntry entry = backupZip.GetEntry("dns.config");
                            if (entry != null)
                                entry.ExtractToFile(Path.Combine(_configFolder, entry.Name), true);

                            //reload settings and block list zone
                            LoadConfigFile();
                            _dnsServer.BlockListZoneManager.LoadBlockLists();
                        }

                        if (blockLists)
                        {
                            if (deleteExistingFiles)
                            {
                                //delete existing block list files
                                string[] blockListFiles = Directory.GetFiles(Path.Combine(_configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);
                                foreach (string blockListFile in blockListFiles)
                                {
                                    File.Delete(blockListFile);
                                }
                            }

                            //extract block list files from backup
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (entry.FullName.StartsWith("blocklists/"))
                                    entry.ExtractToFile(Path.Combine(_configFolder, "blocklists", entry.Name), true);
                            }
                        }

                        if (apps)
                        {
                            //unload apps
                            _dnsServer.DnsApplicationManager.UnloadAllApplications();

                            if (deleteExistingFiles)
                            {
                                //delete existing apps
                                string appFolder = Path.Combine(_configFolder, "apps");
                                if (Directory.Exists(appFolder))
                                    Directory.Delete(appFolder, true);

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

                                    entry.ExtractToFile(filePath, true);
                                }
                            }

                            //reload apps
                            _dnsServer.DnsApplicationManager.LoadAllApplications();
                        }

                        if (zones)
                        {
                            if (deleteExistingFiles)
                            {
                                //delete existing zone files
                                string[] zoneFiles = Directory.GetFiles(Path.Combine(_configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);
                                foreach (string zoneFile in zoneFiles)
                                {
                                    File.Delete(zoneFile);
                                }
                            }

                            //extract zone files from backup
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (entry.FullName.StartsWith("zones/"))
                                    entry.ExtractToFile(Path.Combine(_configFolder, "zones", entry.Name), true);
                            }

                            //reload zones
                            _dnsServer.AuthZoneManager.LoadAllZoneFiles();
                            InspectAndFixZonePermissions();
                        }

                        if (allowedZones)
                        {
                            ZipArchiveEntry entry = backupZip.GetEntry("allowed.config");
                            if (entry == null)
                            {
                                string fileName = Path.Combine(_configFolder, "allowed.config");
                                if (File.Exists(fileName))
                                    File.Delete(fileName);
                            }
                            else
                            {
                                entry.ExtractToFile(Path.Combine(_configFolder, entry.Name), true);
                            }

                            //reload
                            _dnsServer.AllowedZoneManager.LoadAllowedZoneFile();
                        }

                        if (blockedZones)
                        {
                            ZipArchiveEntry entry = backupZip.GetEntry("blocked.config");
                            if (entry == null)
                            {
                                string fileName = Path.Combine(_configFolder, "allowed.config");
                                if (File.Exists(fileName))
                                    File.Delete(fileName);
                            }
                            else
                            {
                                entry.ExtractToFile(Path.Combine(_configFolder, entry.Name), true);
                            }

                            //reload
                            _dnsServer.BlockedZoneManager.LoadBlockedZoneFile();
                        }

                        if (scopes)
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
                                        File.Delete(scopeFile);
                                    }
                                }

                                //extract scope files from backup
                                foreach (ZipArchiveEntry entry in backupZip.Entries)
                                {
                                    if (entry.FullName.StartsWith("scopes/"))
                                        entry.ExtractToFile(Path.Combine(_configFolder, "scopes", entry.Name), true);
                                }
                            }
                            finally
                            {
                                //start dhcp server
                                _dhcpServer.Start();
                            }
                        }

                        if (stats)
                        {
                            if (deleteExistingFiles)
                            {
                                //delete existing stats files
                                string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);
                                foreach (string hourlyStatsFile in hourlyStatsFiles)
                                {
                                    File.Delete(hourlyStatsFile);
                                }

                                string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);
                                foreach (string dailyStatsFile in dailyStatsFiles)
                                {
                                    File.Delete(dailyStatsFile);
                                }
                            }

                            //extract stats files from backup
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (entry.FullName.StartsWith("stats/"))
                                    entry.ExtractToFile(Path.Combine(_configFolder, "stats", entry.Name), true);
                            }

                            //reload stats
                            _dnsServer.StatsManager.ReloadStats();
                        }

                        _log.Write(GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] Settings backup zip file was restored.");
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
                    _log.Write(ex);
                }
            }

            if (dnsSettings)
                RestartService(true, true);

            GetDnsSettings(jsonWriter);
        }

        private void ForceUpdateBlockLists(HttpListenerRequest request)
        {
            ForceUpdateBlockLists();
            _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).User.Username + "] Block list update was triggered.");
        }

        private void TemporaryDisableBlocking(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string strMinutes = request.QueryString["minutes"];
            if (string.IsNullOrEmpty(strMinutes))
                throw new DnsWebServiceException("Parameter 'minutes' missing.");

            int minutes = int.Parse(strMinutes);

            Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
            if (temporaryDisableBlockingTimer is not null)
                temporaryDisableBlockingTimer.Dispose();

            Timer newTemporaryDisableBlockingTimer = new Timer(delegate (object state)
            {
                try
                {
                    _dnsServer.EnableBlocking = true;
                    _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).User.Username + "] Blocking was enabled after " + minutes + " minute(s) being temporarily disabled.");
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            });

            Timer originalTimer = Interlocked.CompareExchange(ref _temporaryDisableBlockingTimer, newTemporaryDisableBlockingTimer, temporaryDisableBlockingTimer);
            if (ReferenceEquals(originalTimer, temporaryDisableBlockingTimer))
            {
                newTemporaryDisableBlockingTimer.Change(minutes * 60 * 1000, Timeout.Infinite);
                _dnsServer.EnableBlocking = false;
                _temporaryDisableBlockingTill = DateTime.UtcNow.AddMinutes(minutes);

                _log.Write(GetRequestRemoteEndPoint(request), "[" + GetSession(request).User.Username + "] Blocking was temporarily disabled for " + minutes + " minute(s).");
            }
            else
            {
                newTemporaryDisableBlockingTimer.Dispose();
            }

            jsonWriter.WritePropertyName("temporaryDisableBlockingTill");
            jsonWriter.WriteValue(_temporaryDisableBlockingTill);
        }

        #endregion

        #region dns client api

        private async Task ResolveQueryAsync(HttpListenerRequest request, JsonTextWriter jsonWriter)
        {
            string server = request.QueryString["server"];
            if (string.IsNullOrEmpty(server))
                throw new DnsWebServiceException("Parameter 'server' missing.");

            string domain = request.QueryString["domain"];
            if (string.IsNullOrEmpty(domain))
                throw new DnsWebServiceException("Parameter 'domain' missing.");

            domain = domain.Trim(new char[] { '\t', ' ', '.' });

            string strType = request.QueryString["type"];
            if (string.IsNullOrEmpty(strType))
                throw new DnsWebServiceException("Parameter 'type' missing.");

            DnsResourceRecordType type = Enum.Parse<DnsResourceRecordType>(strType, true);

            string strProtocol = request.QueryString["protocol"];
            if (string.IsNullOrEmpty(strProtocol))
                strProtocol = "Udp";

            bool dnssecValidation = false;
            string strDnssecValidation = request.QueryString["dnssec"];
            if (!string.IsNullOrEmpty(strDnssecValidation))
                dnssecValidation = bool.Parse(strDnssecValidation);

            bool importResponse = false;
            string strImport = request.QueryString["import"];
            if (!string.IsNullOrEmpty(strImport))
                importResponse = bool.Parse(strImport);

            NetProxy proxy = _dnsServer.Proxy;
            bool preferIPv6 = _dnsServer.PreferIPv6;
            ushort udpPayloadSize = _dnsServer.UdpPayloadSize;
            bool randomizeName = false;
            bool qnameMinimization = _dnsServer.QnameMinimization;
            DnsTransportProtocol protocol = Enum.Parse<DnsTransportProtocol>(strProtocol, true);
            const int RETRIES = 1;
            const int TIMEOUT = 10000;

            DnsDatagram dnsResponse;
            string dnssecErrorMessage = null;

            if (server.Equals("recursive-resolver", StringComparison.OrdinalIgnoreCase))
            {
                if (type == DnsResourceRecordType.AXFR)
                    throw new DnsServerException("Cannot do zone transfer (AXFR) for 'recursive-resolver'.");

                DnsQuestionRecord question;

                if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                    question = new DnsQuestionRecord(address, DnsClass.IN);
                else
                    question = new DnsQuestionRecord(domain, type, DnsClass.IN);

                DnsCache dnsCache = new DnsCache();
                dnsCache.MinimumRecordTtl = 0;
                dnsCache.MaximumRecordTtl = 7 * 24 * 60 * 60;

                try
                {
                    dnsResponse = await DnsClient.RecursiveResolveAsync(question, dnsCache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, false, dnssecValidation, RETRIES, TIMEOUT);
                }
                catch (DnsClientResponseDnssecValidationException ex)
                {
                    dnsResponse = ex.Response;
                    dnssecErrorMessage = ex.Message;
                    importResponse = false;
                }
            }
            else
            {
                if ((type == DnsResourceRecordType.AXFR) && (protocol == DnsTransportProtocol.Udp))
                    protocol = DnsTransportProtocol.Tcp;

                NameServerAddress nameServer;

                if (server.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                {
                    switch (protocol)
                    {
                        case DnsTransportProtocol.Udp:
                            nameServer = _dnsServer.ThisServer;
                            break;

                        case DnsTransportProtocol.Tcp:
                            nameServer = _dnsServer.ThisServer.ChangeProtocol(DnsTransportProtocol.Tcp);
                            break;

                        case DnsTransportProtocol.Tls:
                            throw new DnsServerException("Cannot use DNS-over-TLS protocol for 'this-server'. Please use the TLS certificate domain name as the server.");

                        case DnsTransportProtocol.Https:
                            throw new DnsServerException("Cannot use DNS-over-HTTPS protocol for 'this-server'. Please use the TLS certificate domain name with a url as the server.");

                        case DnsTransportProtocol.HttpsJson:
                            throw new DnsServerException("Cannot use DNS-over-HTTPS (JSON) protocol for 'this-server'. Please use the TLS certificate domain name with a url as the server.");

                        default:
                            throw new InvalidOperationException();
                    }

                    proxy = null; //no proxy required for this server
                }
                else
                {
                    nameServer = new NameServerAddress(server);

                    if (nameServer.Protocol != protocol)
                        nameServer = nameServer.ChangeProtocol(protocol);

                    if (nameServer.IsIPEndPointStale)
                    {
                        if (proxy is null)
                            await nameServer.ResolveIPAddressAsync(_dnsServer, _dnsServer.PreferIPv6);
                    }
                    else if (protocol != DnsTransportProtocol.Tls)
                    {
                        try
                        {
                            await nameServer.ResolveDomainNameAsync(_dnsServer);
                        }
                        catch
                        { }
                    }
                }

                DnsClient dnsClient = new DnsClient(nameServer);

                dnsClient.Proxy = proxy;
                dnsClient.PreferIPv6 = preferIPv6;
                dnsClient.RandomizeName = randomizeName;
                dnsClient.Retries = RETRIES;
                dnsClient.Timeout = TIMEOUT;
                dnsClient.UdpPayloadSize = udpPayloadSize;
                dnsClient.DnssecValidation = dnssecValidation;

                if (dnssecValidation)
                {
                    //load trust anchors into dns client if domain is locally hosted
                    _dnsServer.AuthZoneManager.LoadTrustAnchorsTo(dnsClient, domain, type);
                }

                try
                {
                    dnsResponse = await dnsClient.ResolveAsync(domain, type);
                }
                catch (DnsClientResponseDnssecValidationException ex)
                {
                    dnsResponse = ex.Response;
                    dnssecErrorMessage = ex.Message;
                    importResponse = false;
                }

                if (type == DnsResourceRecordType.AXFR)
                    dnsResponse = dnsResponse.Join();
            }

            if (importResponse)
            {
                UserSession session = GetSession(request);

                AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.FindAuthZoneInfo(domain);
                if ((zoneInfo is null) || ((zoneInfo.Type == AuthZoneType.Secondary) && !zoneInfo.Name.Equals(domain, StringComparison.OrdinalIgnoreCase)))
                {
                    if (!_authManager.IsPermitted(PermissionSection.Zones, session.User, PermissionFlag.Modify))
                        throw new DnsWebServiceException("Access was denied.");

                    zoneInfo = _dnsServer.AuthZoneManager.CreatePrimaryZone(domain, _dnsServer.ServerDomain, false);
                    if (zoneInfo is null)
                        throw new DnsServerException("Cannot import records: failed to create primary zone.");

                    //set permissions
                    _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.ViewModifyDelete);
                    _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _authManager.SetPermission(PermissionSection.Zones, zoneInfo.Name, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _authManager.SaveConfigFile();
                }
                else
                {
                    if (!_authManager.IsPermitted(PermissionSection.Zones, zoneInfo.Name, session.User, PermissionFlag.Modify))
                        throw new DnsWebServiceException("Access was denied.");

                    switch (zoneInfo.Type)
                    {
                        case AuthZoneType.Primary:
                            break;

                        case AuthZoneType.Forwarder:
                            if (type == DnsResourceRecordType.AXFR)
                                throw new DnsServerException("Cannot import records via zone transfer: import zone must be of primary type.");

                            break;

                        default:
                            throw new DnsServerException("Cannot import records: import zone must be of primary or forwarder type.");
                    }
                }

                if (type == DnsResourceRecordType.AXFR)
                {
                    _dnsServer.AuthZoneManager.SyncZoneTransferRecords(zoneInfo.Name, dnsResponse.Answer);
                }
                else
                {
                    List<DnsResourceRecord> importRecords = new List<DnsResourceRecord>(dnsResponse.Answer.Count + dnsResponse.Authority.Count);

                    foreach (DnsResourceRecord record in dnsResponse.Answer)
                    {
                        if (record.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneInfo.Name, StringComparison.OrdinalIgnoreCase) || (zoneInfo.Name.Length == 0))
                        {
                            record.RemoveExpiry();
                            importRecords.Add(record);

                            if (record.Type == DnsResourceRecordType.NS)
                                record.SyncGlueRecords(dnsResponse.Additional);
                        }
                    }

                    foreach (DnsResourceRecord record in dnsResponse.Authority)
                    {
                        if (record.Name.Equals(zoneInfo.Name, StringComparison.OrdinalIgnoreCase) || record.Name.EndsWith("." + zoneInfo.Name, StringComparison.OrdinalIgnoreCase) || (zoneInfo.Name.Length == 0))
                        {
                            record.RemoveExpiry();
                            importRecords.Add(record);

                            if (record.Type == DnsResourceRecordType.NS)
                                record.SyncGlueRecords(dnsResponse.Additional);
                        }
                    }

                    _dnsServer.AuthZoneManager.ImportRecords(zoneInfo.Name, importRecords);
                }

                _log.Write(GetRequestRemoteEndPoint(request), "[" + session.User.Username + "] DNS Client imported record(s) for authoritative zone {server: " + server + "; zone: " + zoneInfo.Name + "; type: " + type + ";}");

                _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
            }

            if (dnssecErrorMessage is not null)
            {
                jsonWriter.WritePropertyName("warningMessage");
                jsonWriter.WriteValue(dnssecErrorMessage);
            }

            jsonWriter.WritePropertyName("result");
            jsonWriter.WriteRawValue(JsonConvert.SerializeObject(dnsResponse, new StringEnumConverter()));
        }

        #endregion

        #region block list

        private void ForceUpdateBlockLists()
        {
            Task.Run(async delegate ()
            {
                if (await _dnsServer.BlockListZoneManager.UpdateBlockListsAsync())
                {
                    //block lists were updated
                    //save last updated on time
                    _blockListLastUpdatedOn = DateTime.UtcNow;
                    SaveConfigFile();
                }
            });
        }

        private void StartBlockListUpdateTimer()
        {
            if (_blockListUpdateTimer is null)
            {
                _blockListUpdateTimer = new Timer(async delegate (object state)
                {
                    try
                    {
                        if (DateTime.UtcNow > _blockListLastUpdatedOn.AddHours(_blockListUpdateIntervalHours))
                        {
                            if (await _dnsServer.BlockListZoneManager.UpdateBlockListsAsync())
                            {
                                //block lists were updated
                                //save last updated on time
                                _blockListLastUpdatedOn = DateTime.UtcNow;
                                SaveConfigFile();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while updating block lists.\r\n" + ex.ToString());
                    }

                }, null, BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL);
            }
        }

        private void StopBlockListUpdateTimer()
        {
            if (_blockListUpdateTimer is not null)
            {
                _blockListUpdateTimer.Dispose();
                _blockListUpdateTimer = null;
            }
        }

        #endregion

        #region tls

        private void StartTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer == null)
            {
                _tlsCertificateUpdateTimer = new Timer(delegate (object state)
                {
                    if (!string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                    {
                        try
                        {
                            FileInfo fileInfo = new FileInfo(_webServiceTlsCertificatePath);

                            if (fileInfo.Exists && (fileInfo.LastWriteTimeUtc != _webServiceTlsCertificateLastModifiedOn))
                                LoadWebServiceTlsCertificate(_webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                        }
                        catch (Exception ex)
                        {
                            _log.Write("DNS Server encountered an error while updating Web Service TLS Certificate: " + _webServiceTlsCertificatePath + "\r\n" + ex.ToString());
                        }
                    }

                    if (!string.IsNullOrEmpty(_dnsTlsCertificatePath))
                    {
                        try
                        {
                            FileInfo fileInfo = new FileInfo(_dnsTlsCertificatePath);

                            if (fileInfo.Exists && (fileInfo.LastWriteTimeUtc != _dnsTlsCertificateLastModifiedOn))
                                LoadDnsTlsCertificate(_dnsTlsCertificatePath, _dnsTlsCertificatePassword);
                        }
                        catch (Exception ex)
                        {
                            _log.Write("DNS Server encountered an error while updating DNS Server TLS Certificate: " + _dnsTlsCertificatePath + "\r\n" + ex.ToString());
                        }
                    }

                }, null, TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL, TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL);
            }
        }

        private void StopTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer != null)
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

            if (Path.GetExtension(tlsCertificatePath) != ".pfx")
                throw new ArgumentException("Web Service TLS certificate file must be PKCS #12 formatted with .pfx extension: " + tlsCertificatePath);

            X509Certificate2 certificate = new X509Certificate2(tlsCertificatePath, tlsCertificatePassword);

            _webServiceTlsCertificate = certificate;
            _webServiceTlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

            _log.Write("Web Service TLS certificate was loaded: " + tlsCertificatePath);
        }

        private void LoadDnsTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword)
        {
            FileInfo fileInfo = new FileInfo(tlsCertificatePath);

            if (!fileInfo.Exists)
                throw new ArgumentException("DNS Server TLS certificate file does not exists: " + tlsCertificatePath);

            if (Path.GetExtension(tlsCertificatePath) != ".pfx")
                throw new ArgumentException("DNS Server TLS certificate file must be PKCS #12 formatted with .pfx extension: " + tlsCertificatePath);

            X509Certificate2 certificate = new X509Certificate2(tlsCertificatePath, tlsCertificatePassword);

            _dnsServer.Certificate = certificate;
            _dnsTlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

            _log.Write("DNS Server TLS certificate was loaded: " + tlsCertificatePath);
        }

        #endregion

        #region config

        private void LoadConfigFile()
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
                    SaveConfigFile(); //save as new config version to avoid loading old version next time
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

                string strRecursionDeniedNetworks = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION_DENIED_NETWORKS");
                if (!string.IsNullOrEmpty(strRecursionDeniedNetworks))
                {
                    string[] strRecursionDeniedNetworkAddresses = strRecursionDeniedNetworks.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    NetworkAddress[] networks = new NetworkAddress[strRecursionDeniedNetworkAddresses.Length];

                    for (int i = 0; i < networks.Length; i++)
                        networks[i] = NetworkAddress.Parse(strRecursionDeniedNetworkAddresses[i].Trim());

                    _dnsServer.RecursionDeniedNetworks = networks;
                }

                string strRecursionAllowedNetworks = Environment.GetEnvironmentVariable("DNS_SERVER_RECURSION_ALLOWED_NETWORKS");
                if (!string.IsNullOrEmpty(strRecursionAllowedNetworks))
                {
                    string[] strRecursionAllowedNetworkAddresses = strRecursionAllowedNetworks.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    NetworkAddress[] networks = new NetworkAddress[strRecursionAllowedNetworkAddresses.Length];

                    for (int i = 0; i < networks.Length; i++)
                        networks[i] = NetworkAddress.Parse(strRecursionAllowedNetworkAddresses[i].Trim());

                    _dnsServer.RecursionAllowedNetworks = networks;
                }

                _dnsServer.RandomizeName = true; //default true to enable security feature
                _dnsServer.QnameMinimization = true; //default true to enable privacy feature
                _dnsServer.NsRevalidation = true; //default true for security reasons

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
                    string[] strBlockListUrlList = strBlockListUrls.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    foreach (string strBlockListUrl in strBlockListUrlList)
                    {
                        if (strBlockListUrl.StartsWith("!"))
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
                        forwarderProtocol = DnsTransportProtocol.Udp;
                    else
                        forwarderProtocol = Enum.Parse<DnsTransportProtocol>(strForwarderProtocol, true);

                    List<NameServerAddress> forwarders = new List<NameServerAddress>();
                    string[] strForwardersAddresses = strForwarders.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    foreach (string strForwarderAddress in strForwardersAddresses)
                        forwarders.Add(new NameServerAddress(strForwarderAddress.Trim(), forwarderProtocol));

                    _dnsServer.Forwarders = forwarders;
                }

                //logging
                string strUseLocalTime = Environment.GetEnvironmentVariable("DNS_SERVER_LOG_USING_LOCAL_TIME");
                if (!string.IsNullOrEmpty(strUseLocalTime))
                    _log.UseLocalTime = bool.Parse(strUseLocalTime);

                SaveConfigFile();
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading config file: " + configFile + "\r\n" + ex.ToString());
                _log.Write("Note: You may try deleting the config file to fix this issue. However, you will lose DNS settings but, zone data wont be affected.");
                throw;
            }
        }

        private void CreateForwarderZoneToDisableDnssecForNTP()
        {
            if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                //adding a conditional forwarder zone for disabling DNSSEC validation for ntp.org so that systems with no real-time clock can sync time
                string ntpDomain = "ntp.org";
                string fwdRecordComments = "This forwarder zone was automatically created to disable DNSSEC validation for ntp.org to allow systems with no real-time clock (e.g. Raspberry Pi) to sync time via NTP when booting.";
                if (_dnsServer.AuthZoneManager.CreateForwarderZone(ntpDomain, DnsTransportProtocol.Udp, "this-server", false, NetProxyType.None, null, 0, null, null, fwdRecordComments) is not null)
                {
                    //set permissions
                    _authManager.SetPermission(PermissionSection.Zones, ntpDomain, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _authManager.SetPermission(PermissionSection.Zones, ntpDomain, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _authManager.SaveConfigFile();

                    Directory.CreateDirectory(Path.Combine(_dnsServer.ConfigFolder, "zones"));
                    _dnsServer.AuthZoneManager.SaveZoneFile(ntpDomain);
                }
            }
        }

        private void SaveConfigFile()
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

        private void InspectAndFixZonePermissions()
        {
            Permission permission = _authManager.GetPermission(PermissionSection.Zones);
            IReadOnlyDictionary<string, Permission> subItemPermissions = permission.SubItemPermissions;

            //remove ghost permissions
            foreach (KeyValuePair<string, Permission> subItemPermission in subItemPermissions)
            {
                string zoneName = subItemPermission.Key;

                if (_dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName) is null)
                    permission.RemoveAllSubItemPermissions(zoneName); //no such zone exists; remove permissions
            }

            //add missing admin permissions
            List<AuthZoneInfo> zones = _dnsServer.AuthZoneManager.ListZones();
            Group admins = _authManager.GetGroup(Group.ADMINISTRATORS);
            Group dnsAdmins = _authManager.GetGroup(Group.DNS_ADMINISTRATORS);

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

            if (version == 28)
            {
                ReadConfigFrom(bR, version);
            }
            else if ((version >= 2) && (version <= 27))
            {
                ReadOldConfigFrom(bR, version);

                //new default settings
                _appsApi.EnableAutomaticUpdate = true;
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
                            localAddresses[i] = IPAddressExtension.ReadFrom(bR);

                        _webServiceLocalAddresses = localAddresses;
                    }
                }

                _webServiceEnableTls = bR.ReadBoolean();
                _webServiceHttpToTlsRedirect = bR.ReadBoolean();
                _webServiceUseSelfSignedTlsCertificate = bR.ReadBoolean();

                _webServiceTlsCertificatePath = bR.ReadShortString();
                _webServiceTlsCertificatePassword = bR.ReadShortString();

                if (_webServiceTlsCertificatePath.Length == 0)
                    _webServiceTlsCertificatePath = null;

                if (_webServiceTlsCertificatePath != null)
                {
                    try
                    {
                        LoadWebServiceTlsCertificate(_webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + _webServiceTlsCertificatePath + "\r\n" + ex.ToString());
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
                            localEndPoints[i] = (IPEndPoint)EndPointExtension.ReadFrom(bR);

                        _dnsServer.LocalEndPoints = localEndPoints;
                    }
                }

                _zonesApi.DefaultRecordTtl = bR.ReadUInt32();
                _appsApi.EnableAutomaticUpdate = bR.ReadBoolean();

                _dnsServer.PreferIPv6 = bR.ReadBoolean();
                _dnsServer.UdpPayloadSize = bR.ReadUInt16();
                _dnsServer.DnssecValidation = bR.ReadBoolean();

                _dnsServer.QpmLimitRequests = bR.ReadInt32();
                _dnsServer.QpmLimitErrors = bR.ReadInt32();
                _dnsServer.QpmLimitSampleMinutes = bR.ReadInt32();
                _dnsServer.QpmLimitIPv4PrefixLength = bR.ReadInt32();
                _dnsServer.QpmLimitIPv6PrefixLength = bR.ReadInt32();

                _dnsServer.ClientTimeout = bR.ReadInt32();
                _dnsServer.TcpSendTimeout = bR.ReadInt32();
                _dnsServer.TcpReceiveTimeout = bR.ReadInt32();

                //optional protocols
                _dnsServer.EnableDnsOverHttp = bR.ReadBoolean();
                _dnsServer.EnableDnsOverTls = bR.ReadBoolean();
                _dnsServer.EnableDnsOverHttps = bR.ReadBoolean();

                _dnsTlsCertificatePath = bR.ReadShortString();
                _dnsTlsCertificatePassword = bR.ReadShortString();

                if (_dnsTlsCertificatePath.Length == 0)
                    _dnsTlsCertificatePath = null;

                if (_dnsTlsCertificatePath != null)
                {
                    try
                    {
                        LoadDnsTlsCertificate(_dnsTlsCertificatePath, _dnsTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading DNS Server TLS certificate: " + _dnsTlsCertificatePath + "\r\n" + ex.ToString());
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

                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NetworkAddress[] networks = new NetworkAddress[count];

                        for (int i = 0; i < count; i++)
                            networks[i] = NetworkAddress.ReadFrom(bR);

                        _dnsServer.RecursionDeniedNetworks = networks;
                    }
                }

                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NetworkAddress[] networks = new NetworkAddress[count];

                        for (int i = 0; i < count; i++)
                            networks[i] = NetworkAddress.ReadFrom(bR);

                        _dnsServer.RecursionAllowedNetworks = networks;
                    }
                }

                _dnsServer.RandomizeName = bR.ReadBoolean();
                _dnsServer.QnameMinimization = bR.ReadBoolean();
                _dnsServer.NsRevalidation = bR.ReadBoolean();

                _dnsServer.ResolverRetries = bR.ReadInt32();
                _dnsServer.ResolverTimeout = bR.ReadInt32();
                _dnsServer.ResolverMaxStackCount = bR.ReadInt32();

                //cache
                _dnsServer.ServeStale = bR.ReadBoolean();
                _dnsServer.CacheZoneManager.ServeStaleTtl = bR.ReadUInt32();

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
                            IPAddress customAddress = IPAddressExtension.ReadFrom(bR);

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
                }

                {
                    //read block list urls
                    int count = bR.ReadByte();

                    for (int i = 0; i < count; i++)
                    {
                        string listUrl = bR.ReadShortString();

                        if (listUrl.StartsWith("!"))
                            _dnsServer.BlockListZoneManager.AllowListUrls.Add(new Uri(listUrl.Substring(1)));
                        else
                            _dnsServer.BlockListZoneManager.BlockListUrls.Add(new Uri(listUrl));
                    }

                    _blockListUpdateIntervalHours = bR.ReadInt32();
                    _blockListLastUpdatedOn = bR.ReadDateTime();
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
                            forwarders[i] = new NameServerAddress(bR);

                        _dnsServer.Forwarders = forwarders;
                    }
                }

                _dnsServer.ForwarderRetries = bR.ReadInt32();
                _dnsServer.ForwarderTimeout = bR.ReadInt32();
                _dnsServer.ForwarderConcurrency = bR.ReadInt32();

                //logging
                if (bR.ReadBoolean()) //log all queries
                    _dnsServer.QueryLogManager = _log;
                else
                    _dnsServer.QueryLogManager = null;

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
                            localAddresses[i] = IPAddressExtension.ReadFrom(bR);

                        _webServiceLocalAddresses = localAddresses;
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
                    try
                    {
                        LoadWebServiceTlsCertificate(_webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + _webServiceTlsCertificatePath + "\r\n" + ex.ToString());
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

                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NetworkAddress[] networks = new NetworkAddress[count];

                        for (int i = 0; i < count; i++)
                            networks[i] = NetworkAddress.ReadFrom(bR);

                        _dnsServer.RecursionDeniedNetworks = networks;
                    }
                }


                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NetworkAddress[] networks = new NetworkAddress[count];

                        for (int i = 0; i < count; i++)
                            networks[i] = NetworkAddress.ReadFrom(bR);

                        _dnsServer.RecursionAllowedNetworks = networks;
                    }
                }
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
                _dnsServer.RandomizeName = true; //default true to enable security feature

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
                        forwarders[i] = new NameServerAddress(bR);

                    _dnsServer.Forwarders = forwarders;
                }
            }

            if (version <= 10)
            {
                DnsTransportProtocol forwarderProtocol = (DnsTransportProtocol)bR.ReadByte();

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
                        IPAddress customAddress = IPAddressExtension.ReadFrom(bR);

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

                for (int i = 0; i < count; i++)
                {
                    string listUrl = bR.ReadShortString();

                    if (listUrl.StartsWith("!"))
                        _dnsServer.BlockListZoneManager.AllowListUrls.Add(new Uri(listUrl.Substring(1)));
                    else
                        _dnsServer.BlockListZoneManager.BlockListUrls.Add(new Uri(listUrl));
                }

                _blockListLastUpdatedOn = bR.ReadDateTime();

                if (version >= 13)
                    _blockListUpdateIntervalHours = bR.ReadInt32();
            }
            else
            {
                _dnsServer.BlockListZoneManager.AllowListUrls.Clear();
                _dnsServer.BlockListZoneManager.BlockListUrls.Clear();
                _blockListLastUpdatedOn = DateTime.MinValue;
                _blockListUpdateIntervalHours = 24;
            }

            if (version >= 11)
            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    IPEndPoint[] localEndPoints = new IPEndPoint[count];

                    for (int i = 0; i < count; i++)
                        localEndPoints[i] = (IPEndPoint)EndPointExtension.ReadFrom(bR);

                    _dnsServer.LocalEndPoints = localEndPoints;
                }
            }
            else if (version >= 6)
            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    IPEndPoint[] localEndPoints = new IPEndPoint[count];

                    for (int i = 0; i < count; i++)
                        localEndPoints[i] = new IPEndPoint(IPAddressExtension.ReadFrom(bR), 53);

                    _dnsServer.LocalEndPoints = localEndPoints;
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
                    try
                    {
                        LoadDnsTlsCertificate(_dnsTlsCertificatePath, _dnsTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading DNS Server TLS certificate: " + _dnsTlsCertificatePath + "\r\n" + ex.ToString());
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
                _dnsServer.NsRevalidation = true; //default true for security reasons

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
                _dnsServer.TcpSendTimeout = bR.ReadInt32();
                _dnsServer.TcpReceiveTimeout = bR.ReadInt32();
            }
            else
            {
                _dnsServer.DnssecValidation = true;
                CreateForwarderZoneToDisableDnssecForNTP();

                _dnsServer.ResolverRetries = 2;
                _dnsServer.ResolverTimeout = 2000;
                _dnsServer.ResolverMaxStackCount = 16;

                _dnsServer.ForwarderRetries = 3;
                _dnsServer.ForwarderTimeout = 2000;
                _dnsServer.ForwarderConcurrency = 2;

                _dnsServer.ClientTimeout = 4000;
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
            bW.Write((byte)28); //version

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

                bW.Write(_zonesApi.DefaultRecordTtl);
                bW.Write(_appsApi.EnableAutomaticUpdate);

                bW.Write(_dnsServer.PreferIPv6);
                bW.Write(_dnsServer.UdpPayloadSize);
                bW.Write(_dnsServer.DnssecValidation);

                bW.Write(_dnsServer.QpmLimitRequests);
                bW.Write(_dnsServer.QpmLimitErrors);
                bW.Write(_dnsServer.QpmLimitSampleMinutes);
                bW.Write(_dnsServer.QpmLimitIPv4PrefixLength);
                bW.Write(_dnsServer.QpmLimitIPv6PrefixLength);

                bW.Write(_dnsServer.ClientTimeout);
                bW.Write(_dnsServer.TcpSendTimeout);
                bW.Write(_dnsServer.TcpReceiveTimeout);

                //optional protocols
                bW.Write(_dnsServer.EnableDnsOverHttp);
                bW.Write(_dnsServer.EnableDnsOverTls);
                bW.Write(_dnsServer.EnableDnsOverHttps);

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

                if (_dnsServer.RecursionDeniedNetworks is null)
                {
                    bW.Write((byte)0);
                }
                else
                {
                    bW.Write(Convert.ToByte(_dnsServer.RecursionDeniedNetworks.Count));
                    foreach (NetworkAddress networkAddress in _dnsServer.RecursionDeniedNetworks)
                        networkAddress.WriteTo(bW);
                }

                if (_dnsServer.RecursionAllowedNetworks is null)
                {
                    bW.Write((byte)0);
                }
                else
                {
                    bW.Write(Convert.ToByte(_dnsServer.RecursionAllowedNetworks.Count));
                    foreach (NetworkAddress networkAddress in _dnsServer.RecursionAllowedNetworks)
                        networkAddress.WriteTo(bW);
                }

                bW.Write(_dnsServer.RandomizeName);
                bW.Write(_dnsServer.QnameMinimization);
                bW.Write(_dnsServer.NsRevalidation);

                bW.Write(_dnsServer.ResolverRetries);
                bW.Write(_dnsServer.ResolverTimeout);
                bW.Write(_dnsServer.ResolverMaxStackCount);

                //cache
                bW.Write(_dnsServer.ServeStale);
                bW.Write(_dnsServer.CacheZoneManager.ServeStaleTtl);

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

                    bW.Write(_blockListUpdateIntervalHours);
                    bW.Write(_blockListLastUpdatedOn);
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

                bW.Write(_dnsServer.ForwarderRetries);
                bW.Write(_dnsServer.ForwarderTimeout);
                bW.Write(_dnsServer.ForwarderConcurrency);

                //logging
                bW.Write(_dnsServer.QueryLogManager is not null); //log all queries
                bW.Write(_dnsServer.StatsManager.MaxStatFileDays);
            }
        }

        #endregion

        #region web service start stop

        private void StartDnsWebService()
        {
            int acceptTasks = Math.Max(1, Environment.ProcessorCount);

            //HTTP service
            try
            {
                string webServiceHostname = null;

                _webService = new HttpListener();
                IPAddress httpAddress = null;

                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                {
                    string host;

                    if (webServiceLocalAddress.Equals(IPAddress.Any))
                    {
                        host = "+";

                        httpAddress = IPAddress.Loopback;
                    }
                    else if (webServiceLocalAddress.Equals(IPAddress.IPv6Any))
                    {
                        host = "+";

                        if ((httpAddress == null) || !IPAddress.IsLoopback(httpAddress))
                            httpAddress = IPAddress.IPv6Loopback;
                    }
                    else
                    {
                        if (webServiceLocalAddress.AddressFamily == AddressFamily.InterNetworkV6)
                            host = "[" + webServiceLocalAddress.ToString() + "]";
                        else
                            host = webServiceLocalAddress.ToString();

                        if (httpAddress == null)
                            httpAddress = webServiceLocalAddress;

                        if (webServiceHostname == null)
                            webServiceHostname = host;
                    }

                    _webService.Prefixes.Add("http://" + host + ":" + _webServiceHttpPort + "/");
                }

                _webService.Start();

                if (httpAddress == null)
                    httpAddress = IPAddress.Loopback;

                _webServiceHttpEP = new IPEndPoint(httpAddress, _webServiceHttpPort);

                _webServiceHostname = webServiceHostname ?? Environment.MachineName.ToLower();
            }
            catch (Exception ex)
            {
                _log.Write("Web Service failed to bind using default hostname. Attempting to bind again using 'localhost' hostname.\r\n" + ex.ToString());

                try
                {
                    _webService = new HttpListener();
                    _webService.Prefixes.Add("http://localhost:" + _webServiceHttpPort + "/");
                    _webService.Prefixes.Add("http://127.0.0.1:" + _webServiceHttpPort + "/");
                    _webService.Start();
                }
                catch
                {
                    _webService = new HttpListener();
                    _webService.Prefixes.Add("http://localhost:" + _webServiceHttpPort + "/");
                    _webService.Start();
                }

                _webServiceHttpEP = new IPEndPoint(IPAddress.Loopback, _webServiceHttpPort);

                _webServiceHostname = "localhost";
            }

            _webService.IgnoreWriteExceptions = true;

            for (int i = 0; i < acceptTasks; i++)
            {
                _ = Task.Factory.StartNew(delegate ()
                {
                    return AcceptWebRequestAsync();
                }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _webServiceTaskScheduler);
            }

            _log.Write(new IPEndPoint(IPAddress.Any, _webServiceHttpPort), "HTTP Web Service was started successfully.");

            //TLS service
            if (_webServiceEnableTls && (_webServiceTlsCertificate != null))
            {
                List<Socket> webServiceTlsListeners = new List<Socket>();

                try
                {
                    foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                    {
                        Socket tlsListener = new Socket(webServiceLocalAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        tlsListener.Bind(new IPEndPoint(webServiceLocalAddress, _webServiceTlsPort));
                        tlsListener.Listen(10);

                        webServiceTlsListeners.Add(tlsListener);
                    }

                    foreach (Socket tlsListener in webServiceTlsListeners)
                    {
                        for (int i = 0; i < acceptTasks; i++)
                        {
                            _ = Task.Factory.StartNew(delegate ()
                            {
                                return AcceptTlsWebRequestAsync(tlsListener);
                            }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _webServiceTaskScheduler);
                        }
                    }

                    _webServiceTlsListeners = webServiceTlsListeners;

                    _log.Write(new IPEndPoint(IPAddress.Any, _webServiceHttpPort), "TLS Web Service was started successfully.");
                }
                catch (Exception ex)
                {
                    _log.Write("TLS Web Service failed to start.\r\n" + ex.ToString());

                    foreach (Socket tlsListener in webServiceTlsListeners)
                        tlsListener.Dispose();
                }
            }
        }

        private void StopDnsWebService()
        {
            _webService.Stop();

            if (_webServiceTlsListeners != null)
            {
                foreach (Socket tlsListener in _webServiceTlsListeners)
                    tlsListener.Dispose();

                _webServiceTlsListeners = null;
            }
        }

        #endregion

        #endregion

        #region public

        public void Start()
        {
            if (_disposed)
                throw new ObjectDisposedException("WebService");

            if (_state != ServiceState.Stopped)
                throw new InvalidOperationException("Web Service is already running.");

            _state = ServiceState.Starting;

            try
            {
                //get initial server domain
                string dnsServerDomain = Environment.MachineName.ToLower();
                if (!DnsClient.IsDomainNameValid(dnsServerDomain))
                    dnsServerDomain = "dns-server-1"; //use this name instead since machine name is not a valid domain name

                //init dns server
                _dnsServer = new DnsServer(dnsServerDomain, _configFolder, Path.Combine(_appFolder, "dohwww"), _log);

                //init dhcp server
                _dhcpServer = new DhcpServer(Path.Combine(_configFolder, "scopes"), _log);
                _dhcpServer.AuthZoneManager = _dnsServer.AuthZoneManager;
                _dhcpServer.AuthManager = _authManager;

                //load auth config
                _authManager.LoadConfigFile();

                //load config
                LoadConfigFile();

                //load all dns applications
                _dnsServer.DnsApplicationManager.LoadAllApplications();

                //load all zones files
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
                if ((_blockListUpdateIntervalHours > 0) && (_dnsServer.BlockListZoneManager.BlockListUrls.Count > 0))
                {
                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            _dnsServer.BlockListZoneManager.LoadBlockLists();
                            StartBlockListUpdateTimer();
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }
                    });
                }

                //start dns and dhcp
                _dnsServer.Start();
                _dhcpServer.Start();

                //start web service
                StartDnsWebService();

                _state = ServiceState.Running;

                _log.Write("DNS Server (v" + _currentVersion.ToString() + ") was started successfully.");
            }
            catch (Exception ex)
            {
                _log.Write("Failed to start DNS Server (v" + _currentVersion.ToString() + ")\r\n" + ex.ToString());
                throw;
            }
        }

        public void Stop()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            try
            {
                StopDnsWebService();
                _dnsServer.Dispose();
                _dhcpServer.Dispose();

                StopBlockListUpdateTimer();
                StopTlsCertificateUpdateTimer();

                if (_temporaryDisableBlockingTimer is not null)
                    _temporaryDisableBlockingTimer.Dispose();

                _state = ServiceState.Stopped;

                _log.Write("DNS Server (v" + _currentVersion.ToString() + ") was stopped successfully.");
            }
            catch (Exception ex)
            {
                _log.Write("Failed to stop DNS Server (v" + _currentVersion.ToString() + ")\r\n" + ex.ToString());
                throw;
            }
        }

        #endregion

        #region properties

        internal LogManager Log
        { get { return _log; } }

        internal AuthManager AuthManager
        { get { return _authManager; } }

        internal WebServiceZonesApi ZonesApi
        { get { return _zonesApi; } }

        internal DnsServer DnsServer
        { get { return _dnsServer; } }

        internal DhcpServer DhcpServer
        { get { return _dhcpServer; } }

        internal Version ServerVersion
        { get { return _currentVersion; } }

        public string ConfigFolder
        { get { return _configFolder; } }

        public int WebServiceHttpPort
        { get { return _webServiceHttpPort; } }

        public int WebServiceTlsPort
        { get { return _webServiceTlsPort; } }

        public string WebServiceHostname
        { get { return _webServiceHostname; } }

        #endregion
    }
}
