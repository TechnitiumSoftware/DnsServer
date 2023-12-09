using System.Collections.Generic;

namespace DnsRebindBlocking;

public class AppConfig
{
    public required bool Enabled { get; set; }
    public required List<string> PrivateNetworks { get; init; } = new();
    public required HashSet<string> PrivateDomains { get; init; } = new();
}