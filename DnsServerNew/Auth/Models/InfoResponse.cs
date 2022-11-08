namespace DnsServerNew.Auth.Models;

internal class InfoResponse
{
    public string Version { get; set; } = default!;
    public string DnsServerDomain { get; set; } = default!;
    public uint DefaultRecordTtl { get; set; } = default!;
    public PermissionsResponse Permissions { get; set; } = default!;
}