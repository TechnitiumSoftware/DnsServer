using DnsServerCore.Auth;

namespace DnsServerNew.Auth.Models;

internal class PermissionsResponse
{
    public Permissions? Dashboard { get; set; }
    public Permissions? Zones  { get; set; }
    public Permissions? Cache  { get; set; }
    public Permissions? Allowed  { get; set; }
    public Permissions? Blocked  { get; set; }
    public Permissions? Apps  { get; set; }
    public Permissions? DnsClient  { get; set; }
    public Permissions? Settings  { get; set; }
    public Permissions? DhcpServer  { get; set; }
    public Permissions? Administration  { get; set; }
    public Permissions? Logs  { get; set; }

    public static Permissions Render(AuthManager authManager, PermissionSection section, UserSession userSession)
    {
        return new Permissions
        {
            CanView = authManager.IsPermitted(section, userSession.User, PermissionFlag.View),
            CanModify = authManager.IsPermitted(section, userSession.User, PermissionFlag.Modify),
            CanDelete = authManager.IsPermitted(section, userSession.User, PermissionFlag.Delete),
        };
    }
}