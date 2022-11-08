using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using DnsServerCore;
using DnsServerCore.Auth;
using DnsServerCore.Dns;
using DnsServerNew.Auth.Models;
using DnsServerNew.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace DnsServerNew.Auth;

[Route("api")]
internal class AuthController : Controller
{
    private readonly DnsServer _dnsServer;
    private readonly WebServiceZonesApi _zonesApi;
    private readonly AuthManager _authManager;
    private readonly ILogger<AuthController> _logger;

    public AuthController(DnsServer dnsServer, WebServiceZonesApi zonesApi, AuthManager authManager, ILogger<AuthController> logger)
    {
        _dnsServer = dnsServer;
        _zonesApi = zonesApi;
        _authManager = authManager;
        _logger = logger;
    }
    
    [Route("login")]
    [Route("user/login")]
    public async Task<LoginResponse> Login([FromQuery] [Required] string user, [FromQuery] [Required] string pass, [FromQuery] bool? includeInfo)
    {
        if (!ModelState.IsValid)
        {
            return default;
        }

        var endPoint = Request.GetRemoteEndPoint();
        var session = await _authManager.CreateSessionAsync(UserSessionType.Standard,
            default, user, pass, endPoint.Address, Request.Headers.UserAgent);

        _logger.Write(this, "[" + session.User.Username + "] User logged in.");
        _authManager.SaveConfigFile();

        return new UserLoginResponse
        {
            Username = user,
            DisplayName = session.User.DisplayName,
            Token = session.Token,
            Info = includeInfo.GetValueOrDefault(false) ? AddInfo(session) : default
        };
    }

    private InfoResponse AddInfo(UserSession userSession)
    {
        return new InfoResponse
        {
            //Version = _dnsWebService.GetServerVersion(),
            DnsServerDomain = _dnsServer.ServerDomain,
            DefaultRecordTtl = _zonesApi.DefaultRecordTtl,
            Permissions = AddPermissions(userSession)
        };
    }

    private PermissionsResponse AddPermissions(UserSession userSession)
    {
        return new PermissionsResponse
        {
            Dashboard = PermissionsResponse.Render(_authManager, PermissionSection.Dashboard,
                userSession),
            Zones = PermissionsResponse.Render(_authManager, PermissionSection.Zones,
                userSession),
            Cache = PermissionsResponse.Render(_authManager, PermissionSection.Cache,
                userSession),
            Allowed = PermissionsResponse.Render(_authManager, PermissionSection.Allowed,
                userSession),
            Blocked = PermissionsResponse.Render(_authManager, PermissionSection.Blocked,
                userSession),
            Apps = PermissionsResponse.Render(_authManager, PermissionSection.Apps,
                userSession),
            DnsClient = PermissionsResponse.Render(_authManager, PermissionSection.DnsClient,
                userSession),
            Settings = PermissionsResponse.Render(_authManager, PermissionSection.Settings,
                userSession),
            DhcpServer = PermissionsResponse.Render(_authManager, PermissionSection.DhcpServer,
                userSession),
            Administration = PermissionsResponse.Render(_authManager, PermissionSection.Administration,
                userSession),
            Logs = PermissionsResponse.Render(_authManager, PermissionSection.Logs,
                userSession),
        };
    }
}